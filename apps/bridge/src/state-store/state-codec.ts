import { createHash } from 'node:crypto';
import {
  base64UrlDecode,
  buildCommandReceiptEnvelopeBindingBytes,
  buildEncryptedCommandEnvelopeBindingBytes,
  isCanonicalTimestamp,
  validateCommandReceiptEnvelopeV1,
  validateCommandResult,
  validateEncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import type {
  CanonicalEvent,
  CanonicalSessionState,
  CommandResult,
  HostProjection,
} from '@ariava/protocol';
import type {
  CommandReceiptOutboxInputV1,
  DriverRuntimeHealth,
  EventUploadCompletionV1,
  PendingSessionHandle,
  PersistedBridgeState,
  PersistedCommandExecutionV4,
  PersistedCommandPinReferenceV1,
  PersistedCurrentSessionsSnapshotState,
  PersistedTerminalCancellationV1,
  PersistedProducerEventReservationV1,
} from '../types';
import { isRecognizedLocalSpoolPayloadKind, type LocalSpoolFileV2 } from '../e2e/local-spool';
import { sessionHandleKey } from './session-transitions';

/** Current Bridge runtime state schema. */
export const BRIDGE_RUNTIME_STATE_SCHEMA_VERSION = 5 as const;
export const PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION = 4 as const;
export const PRIOR_RUNTIME_STATE_SCHEMA_VERSION = 3 as const;
export const OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION = 2 as const;
export const LEGACY_RUNTIME_STATE_SCHEMA_VERSION = 1 as const;
const PRIOR_V2_SPOOL_KINDS = new Set([
  'event-source-v2', 'event-reservation-v2', 'event-dead-letter-v2', 'session-source-v2',
  'event-upload-v2', 'session-upload-v2', 'terminal-cancellation-v2',
]);

/** Schema 4 Bridge runtime state: identical shape to schema 5, only the version literal differs. */
export type PriorV4BridgeState = Omit<PersistedBridgeState, 'schemaVersion'> & { schemaVersion: 4 };


const EMPTY_SNAPSHOT: PersistedCurrentSessionsSnapshotState = {
  version: 1,
  lastAllocatedRevision: 0,
  lastAcceptedRevision: 0,
};

/** Pure schema-v5 state constructor; entropy is supplied by the lifecycle shell. */
export function emptyState(runtimeResetEpoch: string): PersistedBridgeState {
  return {
    schemaVersion: BRIDGE_RUNTIME_STATE_SCHEMA_VERSION,
    runtimeResetEpoch,
    host: null,
    sessions: {},
    sessionDrivers: {},
    reconciledDrivers: {},
    recentEvents: [],
    sessionRevisions: {},
    pendingHandles: {},
    commandExecutions: {},
    currentSessionsSnapshot: structuredClone(EMPTY_SNAPSHOT),
    runtimeHealth: { status: 'healthy', drivers: [] },
  };
}

export function producerReservationKey(sessionId: string, fingerprint: string): string {
  return `${sessionId}\n${fingerprint}`;
}

export function assertReceiptOutboxForExecution(
  execution: PersistedCommandExecutionV4,
  terminalResult: CommandResult,
  outbox: CommandReceiptOutboxInputV1,
): void {
  if (!validateCommandResult(terminalResult) || !validateCommandReceiptEnvelopeV1(outbox.receipt)
    || JSON.stringify(outbox.receipt) !== outbox.canonicalBody
    || hashBytes(buildCommandReceiptEnvelopeBindingBytes(outbox.receipt)) !== outbox.receiptDigest) {
    throw new TypeError('command receipt outbox input is invalid');
  }
  const receipt = outbox.receipt;
  const command = execution.originalEncryptedCommand;
  if (terminalResult.commandId !== command.commandId || terminalResult.hostId !== command.hostId
    || terminalResult.sessionId !== command.sessionId || receipt.hostId !== command.hostId
    || receipt.watchDeviceId !== command.watchDeviceId || receipt.sessionId !== command.sessionId
    || receipt.commandId !== command.commandId || receipt.commandType !== command.type
    || receipt.commandDigest !== execution.commandDigest || receipt.completedAt !== terminalResult.updatedAt
    || receipt.linkId !== execution.pinReference.linkId
    || receipt.linkGeneration !== execution.pinReference.linkGeneration || receipt.epoch !== execution.pinReference.epoch
    || receipt.keyWrap.senderEncryptionKeyId !== execution.pinReference.hostEncryptionKeyId
    || receipt.keyWrap.recipientEncryptionKeyId !== execution.pinReference.watchEncryptionKeyId) {
    throw new TypeError('command receipt does not match its execution');
  }
}

export function assertCommandExecution(value: unknown): asserts value is PersistedCommandExecutionV4 {
  if (!isRecord(value) || !hasExactOptionalKeys(value, [
    'version', 'originalEncryptedCommand', 'commandDigest', 'pinReference', 'watchDeviceId', 'nonce', 'expiresAt',
    'state', 'claimedAt',
  ], ['dispatchStartedAt', 'terminalResult', 'receiptOutbox']) || value.version !== 1
    || !validateEncryptedCommandEnvelopeV1(value.originalEncryptedCommand)
    || !isVerifier(value.commandDigest) || !isPersistedCommandPinReference(value.pinReference)
    || value.watchDeviceId !== value.originalEncryptedCommand.watchDeviceId
    || value.nonce !== value.originalEncryptedCommand.nonce || value.expiresAt !== value.originalEncryptedCommand.expiresAt
    || !isCanonicalTimestamp(value.claimedAt)
    || !['claimed', 'dispatch_started', 'outcome_unknown', 'terminal_receipt_blocked', 'terminal'].includes(value.state as string)) {
    throw new TypeError('command execution is invalid');
  }
  const execution = value as unknown as PersistedCommandExecutionV4;
  const recomputedDigest = hashBytes(buildEncryptedCommandEnvelopeBindingBytes(execution.originalEncryptedCommand));
  if (execution.commandDigest !== recomputedDigest
    || execution.pinReference.linkId !== execution.originalEncryptedCommand.linkId
    || execution.pinReference.linkGeneration !== execution.originalEncryptedCommand.linkGeneration
    || execution.pinReference.epoch !== execution.originalEncryptedCommand.epoch
    || execution.pinReference.hostEncryptionKeyId !== execution.originalEncryptedCommand.payload.keyWrap.recipientEncryptionKeyId
    || execution.pinReference.watchEncryptionKeyId !== execution.originalEncryptedCommand.payload.keyWrap.senderEncryptionKeyId) {
    throw new TypeError('command execution binding is invalid');
  }
  if (execution.dispatchStartedAt !== undefined && !isCanonicalTimestamp(execution.dispatchStartedAt)) {
    throw new TypeError('command dispatch timestamp is invalid');
  }
  if (execution.terminalResult !== undefined && (!validateCommandResult(execution.terminalResult)
    || execution.terminalResult.commandId !== execution.originalEncryptedCommand.commandId
    || execution.terminalResult.hostId !== execution.originalEncryptedCommand.hostId
    || execution.terminalResult.sessionId !== execution.originalEncryptedCommand.sessionId)) {
    throw new TypeError('command terminal result binding is invalid');
  }
  if (execution.receiptOutbox !== undefined && !isPersistedReceiptOutbox(execution.receiptOutbox)) {
    throw new TypeError('command receipt outbox is invalid');
  }
  switch (execution.state) {
    case 'claimed':
      if (execution.dispatchStartedAt || execution.terminalResult || execution.receiptOutbox) throw new TypeError('claimed command shape is invalid');
      break;
    case 'dispatch_started':
      if (!execution.dispatchStartedAt || execution.terminalResult || execution.receiptOutbox) throw new TypeError('dispatch-started command shape is invalid');
      break;
    case 'outcome_unknown':
      if (execution.terminalResult || execution.receiptOutbox) throw new TypeError('outcome-unknown command shape is invalid');
      break;
    case 'terminal_receipt_blocked':
      if (!execution.terminalResult || execution.receiptOutbox) throw new TypeError('receipt-blocked command shape is invalid');
      break;
    case 'terminal':
      if (!execution.terminalResult || !execution.receiptOutbox) throw new TypeError('terminal command shape is invalid');
      assertPersistedReceiptMatchesExecution(execution);
      break;
  }
}

function assertPersistedReceiptMatchesExecution(execution: PersistedCommandExecutionV4): void {
  const outbox = execution.receiptOutbox!;
  const receipt = JSON.parse(outbox.canonicalBody);
  assertReceiptOutboxForExecution(execution, execution.terminalResult!, {
    canonicalBody: outbox.canonicalBody,
    receiptDigest: outbox.receiptDigest,
    receipt,
  });
}

function isPersistedCommandPinReference(value: unknown): value is PersistedCommandPinReferenceV1 {
  return isRecord(value) && hasExactKeys(value, [
    'version', 'linkId', 'linkGeneration', 'epoch', 'transcriptDigest', 'hostEncryptionKeyId', 'watchEncryptionKeyId',
  ]) && value.version === 1 && isNonEmptyString(value.linkId) && isPositiveSafeInteger(value.linkGeneration)
    && isPositiveSafeInteger(value.epoch) && isVerifier(value.transcriptDigest)
    && typeof value.hostEncryptionKeyId === 'string' && /^ekey_[A-Za-z0-9_-]{43}$/u.test(value.hostEncryptionKeyId)
    && typeof value.watchEncryptionKeyId === 'string' && /^ekey_[A-Za-z0-9_-]{43}$/u.test(value.watchEncryptionKeyId);
}

function isPersistedReceiptOutbox(value: unknown): boolean {
  if (!isRecord(value) || !hasExactKeys(value, ['version', 'state', 'canonicalBody', 'receiptDigest'])
    || value.version !== 1 || !['pending', 'acknowledged', 'undeliverable'].includes(value.state as string)
    || !isNonEmptyString(value.canonicalBody) || !isVerifier(value.receiptDigest)) return false;
  try {
    const receipt = JSON.parse(value.canonicalBody);
    return validateCommandReceiptEnvelopeV1(receipt) && JSON.stringify(receipt) === value.canonicalBody
      && hashBytes(buildCommandReceiptEnvelopeBindingBytes(receipt)) === value.receiptDigest;
  } catch { return false; }
}

export function hashBytes(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('base64url');
}

export function isVerifier(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

export function isPositiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

export function hasExactKeys(value: Record<string, unknown>, required: readonly string[]): boolean {
  return Object.keys(value).length === required.length && required.every((key) => key in value);
}

export function hasExactOptionalKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[]): boolean {
  return required.every((key) => key in value) && hasOnlyKeys(value, [...required, ...optional]);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(value).every((key) => allowedSet.has(key));
}

export function terminalCancellationItemId(eventId: string): string { return `cancel:terminal:${eventId}`; }

/** Deterministic key, digest, ordering, and bounded-history helpers (spec §6.1). */

export function isRuntimeEpoch(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}

function isNonNegativeSafeInteger(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 0; }

function isValueMap(value: unknown, predicate: (item: unknown) => boolean): boolean {
  return isRecord(value) && Object.values(value).every(predicate);
}

function isKeyedValueMap(
  value: unknown, predicate: (item: unknown, hostId: string) => boolean, idKey: string, hostId: string,
): boolean {
  return isRecord(value) && Object.entries(value).every(([key, item]) => predicate(item, hostId)
    && isRecord(item) && item[idKey] === key);
}

function isStringMap(value: unknown): boolean {
  return isRecord(value) && Object.entries(value).every(([key, item]) => isNonEmptyString(key) && isNonEmptyString(item));
}

function isTrueMap(value: unknown): boolean {
  return isRecord(value) && Object.entries(value).every(([key, item]) => isNonEmptyString(key) && item === true);
}

function isNonNegativeIntegerMap(value: unknown): boolean {
  return isRecord(value) && Object.values(value).every(isNonNegativeSafeInteger);
}

const SESSION_REQUIRED_KEYS = [
  'sessionId', 'hostId', 'provider', 'projectName', 'nameText', 'status', 'updatedAt',
] as const;
const PRIOR_SESSION_REQUIRED_KEYS = [...SESSION_REQUIRED_KEYS, 'stateLabel'] as const;
const SESSION_OPTIONAL_KEYS = [
  'openingText', 'latestActivityText', 'workingDirectory', 'harnessProvider', 'lastEventId', 'snoozedUntil',
] as const;
const OBSOLETE_SESSION_OPTIONAL_KEYS = [
  ...SESSION_OPTIONAL_KEYS, 'hbaseSessionKey', 'actionablePrompt',
] as const;

function isCurrentHost(value: unknown): boolean {
  return isRecord(value) && hasExactOptionalKeys(value,
    ['hostId', 'hostName', 'platform', 'bridgeVersion', 'registeredAt', 'lastSeenAt', 'bridgeStatus'], ['status'])
    && ['hostId', 'hostName', 'bridgeVersion', 'registeredAt', 'lastSeenAt'].every((key) => isNonEmptyString(value[key]))
    && (value.platform === 'macos' || value.platform === 'linux')
    && (value.bridgeStatus === 'online' || value.bridgeStatus === 'offline' || value.bridgeStatus === 'degraded')
    && (value.status === undefined || value.status === 'active' || value.status === 'revoked');
}

function isCurrentSession(value: unknown): boolean {
  return isSessionForKeys(value, SESSION_OPTIONAL_KEYS);
}

function isObsoleteSession(value: unknown): boolean {
  return isSessionForKeys(value, OBSOLETE_SESSION_OPTIONAL_KEYS);
}

function isSessionForKeys(value: unknown, optionalKeys: readonly string[]): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, SESSION_REQUIRED_KEYS, optionalKeys)
    || !SESSION_REQUIRED_KEYS.filter((key) => key !== 'status').every((key) => isNonEmptyString(value[key]))
    || !['idle', 'working', 'need_human'].includes(value.status as string)) return false;
  return optionalKeys.every((key) => value[key] === undefined
    || (key === 'actionablePrompt' ? isCurrentActionablePrompt(value[key]) : typeof value[key] === 'string'));
}

const EVENT_REQUIRED_KEYS = [
  'eventId', 'hostId', 'sessionId', 'provider', 'type', 'status', 'agentText', 'createdAt',
] as const;
const EVENT_OPTIONAL_KEYS = [
  'humanText', 'projectName', 'workingDirectory', 'harnessProvider', 'needHuman',
] as const;

function isCurrentEvent(value: unknown): boolean {
  return isEventForKeys(value, EVENT_OPTIONAL_KEYS);
}

function isEventForKeys(value: unknown, optionalKeys: readonly string[]): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, EVENT_REQUIRED_KEYS, optionalKeys)
    || !EVENT_REQUIRED_KEYS.filter((key) => key !== 'type' && key !== 'status').every((key) => isNonEmptyString(value[key]))) return false;
  if (value.type === 'done') { if (value.status !== 'idle' || value.needHuman !== undefined) return false; }
  else if (value.type === 'need_human') { if (value.status !== 'need_human' || !isCurrentNeedHuman(value.needHuman)) return false; }
  else return false;
  return optionalKeys.every((key) => value[key] === undefined || key === 'needHuman'
    || (key === 'actionablePrompt' ? isCurrentActionablePrompt(value[key]) : typeof value[key] === 'string'));
}

function isCurrentActionablePrompt(value: unknown): boolean {
  return isRecord(value) && hasExactOptionalKeys(value, ['promptId', 'type', 'label'], ['options', 'expiresAt'])
    && isNonEmptyString(value.promptId) && value.type === 'question' && isNonEmptyString(value.label)
    && (value.options === undefined || (Array.isArray(value.options) && value.options.every(isNonEmptyString)))
    && (value.expiresAt === undefined || isNonEmptyString(value.expiresAt));
}

function isCurrentNeedHuman(value: unknown): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, ['reason'], ['error'])
    || !['question', 'blocked', 'error'].includes(value.reason as string)) return false;
  if (value.reason !== 'error') return value.error === undefined;
  return isRecord(value.error) && hasExactOptionalKeys(value.error, ['kind', 'message', 'retryExhausted'], ['providerCode'])
    && ['context_overflow', 'provider_failure', 'response_length', 'incomplete_tool_use', 'unknown'].includes(value.error.kind as string)
    && isNonEmptyString(value.error.message) && value.error.retryExhausted === true
    && (value.error.providerCode === undefined || isNonEmptyString(value.error.providerCode));
}

function isCurrentPendingHandle(value: unknown): boolean {
  return isRecord(value) && hasExactOptionalKeys(value,
    ['hostId', 'sessionId', 'handledThroughEventId', 'handledAt', 'action', 'updatedAt'], ['handledThroughEventCreatedAt'])
    && ['hostId', 'sessionId', 'handledThroughEventId', 'handledAt', 'updatedAt'].every((key) => isNonEmptyString(value[key]))
    && (value.action === 'pi_input' || value.action === 'bridge_recovery')
    && (value.handledThroughEventCreatedAt === undefined || isNonEmptyString(value.handledThroughEventCreatedAt));
}

function isPriorCommandResult(value: unknown): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value,
    ['commandId', 'hostId', 'sessionId', 'accepted', 'status', 'message', 'updatedAt'], ['correlationId'])
    || !['commandId', 'hostId', 'sessionId', 'message', 'updatedAt'].every((key) => isNonEmptyString(value[key]))
    || typeof value.accepted !== 'boolean'
    || !['queued', 'delivered', 'executed', 'expired', 'rejected', 'failed'].includes(value.status as string)
    || (value.correlationId !== undefined && !isNonEmptyString(value.correlationId))) return false;
  return true;
}

function isCurrentCommandExecution(value: unknown): boolean {
  try { assertCommandExecution(value); return true; } catch { return false; }
}

function isCurrentEventCompletion(value: unknown): boolean {
  return isRecord(value) && hasExactOptionalKeys(value,
    ['version', 'eventId', 'sessionId', 'revision', 'eventContentId', 'sessionContentId', 'committedAt'],
    ['revisionCommitted', 'inflightRemoved', 'sourceRemoved']) && value.version === 1
    && ['eventId', 'sessionId', 'eventContentId', 'sessionContentId', 'committedAt'].every((key) => isNonEmptyString(value[key]))
    && isPositiveSafeInteger(value.revision) && ['revisionCommitted', 'inflightRemoved', 'sourceRemoved']
      .every((key) => value[key] === undefined || typeof value[key] === 'boolean');
}

function isCurrentProducerReservation(value: unknown): boolean {
  return isRecord(value) && hasExactKeys(value, ['version', 'eventId', 'sessionId', 'fingerprint', 'createdAt'])
    && value.version === 1 && ['eventId', 'sessionId', 'fingerprint', 'createdAt'].every((key) => isNonEmptyString(value[key]));
}

function isCurrentTerminalCancellation(value: unknown): boolean {
  return isRecord(value) && hasExactKeys(value, ['version', 'sessionId', 'eventId', 'fingerprint', 'removeSession', 'createdAt'])
    && value.version === 1 && ['sessionId', 'eventId', 'fingerprint', 'createdAt'].every((key) => isNonEmptyString(value[key]))
    && typeof value.removeSession === 'boolean';
}

function isObsoleteSnapshot(value: unknown): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, ['version', 'lastAllocatedRevision', 'lastAcceptedRevision'],
    ['lastAcceptedDigest', 'lastAcceptedContentDigest', 'lastAcceptedRecipientSetVersion']) || value.version !== 1
    || !isNonNegativeSafeInteger(value.lastAllocatedRevision) || !isNonNegativeSafeInteger(value.lastAcceptedRevision)) return false;
  if (value.lastAcceptedDigest !== undefined && typeof value.lastAcceptedDigest !== 'string') return false;
  if (value.lastAcceptedContentDigest !== undefined && typeof value.lastAcceptedContentDigest !== 'string') return false;
  return value.lastAcceptedRecipientSetVersion === undefined || isPositiveSafeInteger(value.lastAcceptedRecipientSetVersion);
}

function isCurrentSnapshot(value: unknown): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, ['version', 'lastAllocatedRevision', 'lastAcceptedRevision'],
    ['lastAcceptedDigest', 'lastAcceptedContentDigest', 'lastAcceptedRecipientSetVersion']) || value.version !== 1
    || !isNonNegativeSafeInteger(value.lastAllocatedRevision) || !isNonNegativeSafeInteger(value.lastAcceptedRevision)
    || (value.lastAcceptedRevision as number) > (value.lastAllocatedRevision as number)) return false;
  if (value.lastAcceptedDigest !== undefined && typeof value.lastAcceptedDigest !== 'string') return false;
  if (value.lastAcceptedContentDigest !== undefined && typeof value.lastAcceptedContentDigest !== 'string') return false;
  return value.lastAcceptedRecipientSetVersion === undefined || isPositiveSafeInteger(value.lastAcceptedRecipientSetVersion);
}

function isCurrentRuntimeHealth(value: unknown): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, ['status', 'drivers'], ['relayPresence'])
    || !Array.isArray(value.drivers) || value.drivers.length > 32 || !value.drivers.every(isCurrentDriverHealth)
    || new Set(value.drivers.map((item) => (item as DriverRuntimeHealth).driver)).size !== value.drivers.length) return false;
  const degraded = value.drivers.length > 0 || value.relayPresence !== undefined;
  return value.status === (degraded ? 'degraded' : 'healthy')
    && (value.relayPresence === undefined || isCurrentRelayPresenceHealth(value.relayPresence));
}

function isCurrentDriverHealth(value: unknown): boolean {
  return isRecord(value) && hasExactOptionalKeys(value,
    ['driver', 'code', 'count', 'firstSeenAt', 'lastSeenAt', 'nextRetryAt'], ['lastSuccessAt'])
    && isStableDriverId(value.driver) && value.code === 'driver_reconciliation_failed'
    && isPositiveSafeInteger(value.count) && healthTimestampsValid(value);
}

function isCurrentRelayPresenceHealth(value: unknown): boolean {
  return isRecord(value) && hasExactOptionalKeys(value,
    ['code', 'count', 'firstSeenAt', 'lastSeenAt', 'nextRetryAt'], ['lastSuccessAt'])
    && value.code === 'relay_presence_refresh_failed' && isPositiveSafeInteger(value.count)
    && healthTimestampsValid(value);
}

function healthTimestampsValid(value: Record<string, unknown>): boolean {
  return ['firstSeenAt', 'lastSeenAt', 'nextRetryAt'].every((key) => isCanonicalHealthTimestamp(value[key]))
    && (value.lastSuccessAt === undefined || isCanonicalHealthTimestamp(value.lastSuccessAt));
}

function isStableDriverId(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9._-]{1,64}$/u.test(value);
}

function isCanonicalHealthTimestamp(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    && Number.isFinite(Date.parse(value));
}

const CURRENT_STATE_REQUIRED_KEYS = [
  'schemaVersion', 'runtimeResetEpoch', 'host', 'sessions', 'sessionDrivers', 'reconciledDrivers', 'recentEvents',
  'sessionRevisions', 'pendingHandles', 'commandExecutions', 'currentSessionsSnapshot',
] as const;
const PRIOR_V3_STATE_REQUIRED_KEYS = [
  'schemaVersion', 'runtimeResetEpoch', 'host', 'sessions', 'sessionDrivers', 'reconciledDrivers', 'recentEvents',
  'sessionRevisions', 'pendingHandles', 'commandResults', 'seenCommands', 'currentSessionsSnapshot',
] as const;
const CURRENT_STATE_OPTIONAL_KEYS = [
  'recipientSetVersion', 'eventUploadCompletions', 'producerEventReservations', 'terminalCancellations', 'runtimeHealth',
] as const;
const PRIOR_STATE_KEYS = [
  'schemaVersion', 'host', 'sessions', 'sessionDrivers', 'reconciledDrivers', 'recentEvents', 'pendingEvents',
  'sessionRevisions', 'recipientSetVersion', 'spoolMigration', 'eventUploadCompletions', 'producerEventReservations',
  'terminalCancellations', 'pendingHandles', 'pendingReads', 'commandResults', 'seenCommands', 'currentSessionsSnapshot',
] as const;
const PRIOR_V1_SPOOL_KINDS = new Set([
  'event-source-v1', 'event-dead-letter-v1', 'session-source-v1', 'event-upload-v1', 'session-upload-v1',
]);

/** Exact state/spool decode and persisted-relationship validation (spec §6.1). */

function isStateRecordOfShape(value: Record<string, unknown>, schemaVersion: number): boolean {
  if (!hasExactOptionalKeys(value, CURRENT_STATE_REQUIRED_KEYS, CURRENT_STATE_OPTIONAL_KEYS)
    || value.schemaVersion !== schemaVersion || !isRuntimeEpoch(value.runtimeResetEpoch)
    || !(value.host === null || isCurrentHost(value.host)) || !isValueMap(value.sessions, isCurrentSession)
    || !isStringMap(value.sessionDrivers) || !isTrueMap(value.reconciledDrivers)
    || !Array.isArray(value.recentEvents) || !value.recentEvents.every(isCurrentEvent)
    || !isNonNegativeIntegerMap(value.sessionRevisions) || !isValueMap(value.pendingHandles, isCurrentPendingHandle)
    || !isValueMap(value.commandExecutions, isCurrentCommandExecution)
    || !isCurrentSnapshot(value.currentSessionsSnapshot)) return false;
  if (value.recipientSetVersion !== undefined && !isPositiveSafeInteger(value.recipientSetVersion)) return false;
  return (value.eventUploadCompletions === undefined || isValueMap(value.eventUploadCompletions, isCurrentEventCompletion))
    && (value.producerEventReservations === undefined || isValueMap(value.producerEventReservations, isCurrentProducerReservation))
    && (value.terminalCancellations === undefined || isValueMap(value.terminalCancellations, isCurrentTerminalCancellation))
    && (value.runtimeHealth === undefined || isCurrentRuntimeHealth(value.runtimeHealth));
}

export function isCurrentStateRecord(value: Record<string, unknown>): boolean {
  return isStateRecordOfShape(value, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION);
}

/** Schema4 record: the exact current-state shape with the v4 version literal. */
export function isPriorStateRecordV4(value: Record<string, unknown>, hostId: string): boolean {
  if (!isStateRecordOfShape(value, PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION)) return false;
  try {
    assertCurrentStateRelationships(value as unknown as PersistedBridgeState, hostId);
    return true;
  } catch { return false; }
}

export function parseCurrentState(value: unknown, hostId?: string): PersistedBridgeState {
  if (!isRecord(value) || !isCurrentStateRecord(value)) throw new Error('Bridge runtime state schema is invalid');
  const state = structuredClone(value) as unknown as PersistedBridgeState;
  const relationshipHostId = hostId ?? inferCurrentStateHostId(state);
  assertCurrentStateRelationships(state, relationshipHostId);
  return state;
}

function inferCurrentStateHostId(state: PersistedBridgeState): string {
  const hostIds = new Set<string>();
  if (state.host) hostIds.add(state.host.hostId);
  for (const session of Object.values(state.sessions)) hostIds.add(session.hostId);
  for (const event of state.recentEvents) hostIds.add(event.hostId);
  for (const handle of Object.values(state.pendingHandles)) hostIds.add(handle.hostId);
  for (const execution of Object.values(state.commandExecutions)) hostIds.add(execution.originalEncryptedCommand.hostId);
  if (hostIds.size > 1) throw new Error('Bridge runtime Host relationships are inconsistent');
  return hostIds.values().next().value ?? '';
}

export function isPriorStateRecordV3(value: Record<string, unknown>, hostId: string): boolean {
  if (!hasExactOptionalKeys(value, PRIOR_V3_STATE_REQUIRED_KEYS, CURRENT_STATE_OPTIONAL_KEYS)
    || value.schemaVersion !== PRIOR_RUNTIME_STATE_SCHEMA_VERSION || !isRuntimeEpoch(value.runtimeResetEpoch)
    || !(value.host === null || isCurrentHost(value.host)) || !isValueMap(value.sessions, isObsoleteSession)
    || !isStringMap(value.sessionDrivers) || !isTrueMap(value.reconciledDrivers)
    || !Array.isArray(value.recentEvents) || !value.recentEvents.every(isObsoleteEvent)
    || !isNonNegativeIntegerMap(value.sessionRevisions) || !isValueMap(value.pendingHandles, isCurrentPendingHandle)
    || !isValueMap(value.commandResults, isPriorCommandResult) || !isStringMap(value.seenCommands)
    || !isObsoleteSnapshot(value.currentSessionsSnapshot)) return false;
  if (value.recipientSetVersion !== undefined && !isPositiveSafeInteger(value.recipientSetVersion)) return false;
  if ((value.eventUploadCompletions !== undefined && !isValueMap(value.eventUploadCompletions, isCurrentEventCompletion))
    || (value.producerEventReservations !== undefined && !isValueMap(value.producerEventReservations, isCurrentProducerReservation))
    || (value.terminalCancellations !== undefined && !isValueMap(value.terminalCancellations, isCurrentTerminalCancellation))
    || (value.runtimeHealth !== undefined && !isCurrentRuntimeHealth(value.runtimeHealth))) return false;
  try { assertPriorStateV3Relationships(value, hostId); return true; } catch { return false; }
}

function assertPriorStateV3Relationships(state: Record<string, unknown>, hostId: string): void {
  const sessions = state.sessions as Record<string, Record<string, unknown>>;
  const drivers = state.sessionDrivers as Record<string, string>;
  const events = new Map<string, Record<string, unknown>>();
  const handles = state.pendingHandles as Record<string, PendingSessionHandle>;
  const results = state.commandResults as Record<string, Record<string, unknown>>;
  const seen = state.seenCommands as Record<string, string>;
  if (state.host && (state.host as HostProjection).hostId !== hostId) throw new Error('prior Host projection belongs to another Host');
  for (const [sessionId, session] of Object.entries(sessions)) {
    if (sessionId !== session.sessionId || session.hostId !== hostId) throw new Error('prior Session binding is invalid');
  }
  for (const [sessionId, driver] of Object.entries(drivers)) {
    if (!sessions[sessionId] || sessions[sessionId]!.provider !== driver) throw new Error('prior driver binding is invalid');
  }
  for (const event of state.recentEvents as Record<string, unknown>[]) {
    const eventId = event.eventId as string;
    if (event.hostId !== hostId || events.has(eventId)) throw new Error('prior Event binding is invalid');
    const session = sessions[event.sessionId as string];
    if (session && session.provider !== event.provider) throw new Error('prior Event Session binding is invalid');
    events.set(eventId, event);
  }
  for (const revision of Object.values(state.sessionRevisions as Record<string, number>)) {
    if (revision < 1) throw new Error('prior revision is invalid');
  }
  for (const [key, handle] of Object.entries(handles)) {
    const event = events.get(handle.handledThroughEventId);
    if (key !== sessionHandleKey(hostId, handle.sessionId) || handle.hostId !== hostId || !event
      || event.sessionId !== handle.sessionId
      || (handle.handledThroughEventCreatedAt !== undefined && handle.handledThroughEventCreatedAt !== event.createdAt)) {
      throw new Error('prior handle binding is invalid');
    }
  }
  for (const [commandId, result] of Object.entries(results)) {
    const session = sessions[result.sessionId as string];
    const lastEventId = session?.lastEventId as string | undefined;
    if (commandId !== result.commandId || result.hostId !== hostId
      || (lastEventId !== undefined && events.get(lastEventId)?.sessionId !== result.sessionId)
      || seen[commandId] !== result.updatedAt) throw new Error('prior command result binding is invalid');
  }
  if (Object.keys(seen).some((commandId) => !results[commandId])) throw new Error('prior seen-command binding is invalid');
  for (const [eventId, completion] of Object.entries(state.eventUploadCompletions as Record<string, EventUploadCompletionV1> | undefined ?? {})) {
    const revision = (state.sessionRevisions as Record<string, number>)[completion.sessionId] ?? 0;
    const event = events.get(eventId);
    const revisionIsValid = revision === completion.revision
      || (completion.revisionCommitted !== true && revision === completion.revision - 1);
    if (eventId !== completion.eventId || (event && event.sessionId !== completion.sessionId) || !revisionIsValid
      || (completion.inflightRemoved === true && completion.revisionCommitted !== true)
      || (completion.sourceRemoved === true && completion.inflightRemoved !== true)) {
      throw new Error('prior Event completion binding is invalid');
    }
  }
  for (const [key, reservation] of Object.entries(state.producerEventReservations as Record<string, PersistedProducerEventReservationV1> | undefined ?? {})) {
    const event = events.get(reservation.eventId);
    if (key !== producerReservationKey(reservation.sessionId, reservation.fingerprint)
      || (event && (event.sessionId !== reservation.sessionId || event.createdAt !== reservation.createdAt))) {
      throw new Error('prior producer fingerprint binding is invalid');
    }
  }
  for (const [eventId, cancellation] of Object.entries(state.terminalCancellations as Record<string, PersistedTerminalCancellationV1> | undefined ?? {})) {
    const event = events.get(eventId);
    if (eventId !== cancellation.eventId || (event && event.sessionId !== cancellation.sessionId)) {
      throw new Error('prior terminal cancellation binding is invalid');
    }
  }
  const snapshot = state.currentSessionsSnapshot as PersistedCurrentSessionsSnapshotState;
  const acceptedFields = [snapshot.lastAcceptedDigest, snapshot.lastAcceptedContentDigest, snapshot.lastAcceptedRecipientSetVersion];
  if (snapshot.lastAcceptedRevision === 0 ? acceptedFields.some((value) => value !== undefined)
    : acceptedFields.some((value) => value === undefined) || state.recipientSetVersion === undefined
      || snapshot.lastAcceptedRecipientSetVersion! > (state.recipientSetVersion as number)) {
    throw new Error('prior publication binding is invalid');
  }
}

export function migrateStateV3ToV4(value: Record<string, unknown>, hostId: string): PersistedBridgeState {
  if (!isPriorStateRecordV3(value, hostId)) throw new Error('Bridge runtime schema v3 is invalid');
  const sessions = Object.fromEntries(Object.entries(value.sessions as Record<string, Record<string, unknown>>).map(([sessionId, session]) => [
    sessionId, {
      sessionId: session.sessionId, hostId: session.hostId, provider: session.provider, projectName: session.projectName,
      nameText: session.nameText,
      ...(session.openingText === undefined ? {} : { openingText: session.openingText }),
      ...(session.latestActivityText === undefined ? {} : { latestActivityText: session.latestActivityText }),
      ...(session.workingDirectory === undefined ? {} : { workingDirectory: session.workingDirectory }),
      ...(session.harnessProvider === undefined ? {} : { harnessProvider: session.harnessProvider }),
      status: session.status, updatedAt: session.updatedAt,
      ...(session.snoozedUntil === undefined ? {} : { snoozedUntil: session.snoozedUntil }),
    },
  ]));
  const snapshot = value.currentSessionsSnapshot as PersistedCurrentSessionsSnapshotState;
  const target = {
    schemaVersion: PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION, runtimeResetEpoch: value.runtimeResetEpoch, host: structuredClone(value.host),
    sessions, sessionDrivers: structuredClone(value.sessionDrivers), reconciledDrivers: structuredClone(value.reconciledDrivers),
    recentEvents: [], sessionRevisions: structuredClone(value.sessionRevisions),
    ...(value.recipientSetVersion === undefined ? {} : { recipientSetVersion: value.recipientSetVersion }),
    pendingHandles: {}, commandExecutions: {},
    currentSessionsSnapshot: { version: 1,
      lastAllocatedRevision: Math.max(snapshot.lastAllocatedRevision, snapshot.lastAcceptedRevision), lastAcceptedRevision: 0 },
    ...(value.runtimeHealth === undefined ? {} : { runtimeHealth: structuredClone(value.runtimeHealth) }),
  };
  if (!isPriorStateRecordV4(target, hostId)) throw new Error('migrated Bridge runtime schema v4 is invalid');
  return target as unknown as PriorV4BridgeState;
}

export function migrateSpoolV3ToV4(value: Record<string, unknown>, hostId: string, epoch: string): LocalSpoolFileV2 {
  if (!isSpoolRecordForSchema(value, PRIOR_RUNTIME_STATE_SCHEMA_VERSION, hostId, epoch, 'current')) {
    throw new Error('Bridge runtime spool schema v3 is invalid');
  }
  return { ...(structuredClone(value) as unknown as LocalSpoolFileV2), runtimeStateSchemaVersion: 4, items: [] };
}

export function migrateStateV4ToV5(value: Record<string, unknown>, hostId: string): PersistedBridgeState {
  if (!isPriorStateRecordV4(value, hostId)) throw new Error('Bridge runtime schema v4 is invalid');
  const state = structuredClone(value) as Record<string, unknown>;
  state.schemaVersion = BRIDGE_RUNTIME_STATE_SCHEMA_VERSION;
  return parseCurrentState(state, hostId);
}

export function migrateSpoolV4ToV5(value: Record<string, unknown>, hostId: string, epoch: string): LocalSpoolFileV2 {
  if (!isSpoolRecordForSchema(value, PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION, hostId, epoch, 'current')) {
    throw new Error('Bridge runtime spool schema v4 is invalid');
  }
  return { ...(structuredClone(value) as unknown as LocalSpoolFileV2), runtimeStateSchemaVersion: BRIDGE_RUNTIME_STATE_SCHEMA_VERSION };
}

export function isRecognizedPriorStateRecord(value: Record<string, unknown> | undefined, hostId: string): boolean {
  if (!value || !hasOnlyKeys(value, PRIOR_STATE_KEYS)) return false;
  if (value.schemaVersion !== undefined && value.schemaVersion !== LEGACY_RUNTIME_STATE_SCHEMA_VERSION) return false;
  if (value.host !== undefined && value.host !== null && !isRecognizedPriorHost(value.host, hostId)) return false;
  if (value.sessions !== undefined && !isKeyedValueMap(value.sessions, isRecognizedPriorSession, 'sessionId', hostId)) return false;
  if (value.sessionDrivers !== undefined && !isStringMap(value.sessionDrivers)) return false;
  if (value.reconciledDrivers !== undefined && !isTrueMap(value.reconciledDrivers)) return false;
  if (value.recentEvents !== undefined && (!Array.isArray(value.recentEvents)
    || !value.recentEvents.every((event) => isRecognizedPriorEvent(event, hostId)))) return false;
  if (value.pendingEvents !== undefined && (!Array.isArray(value.pendingEvents)
    || !value.pendingEvents.every((event) => isRecognizedPriorEvent(event, hostId)))) return false;
  if (value.sessionRevisions !== undefined && !isNonNegativeIntegerMap(value.sessionRevisions)) return false;
  if (value.recipientSetVersion !== undefined && !isPositiveSafeInteger(value.recipientSetVersion)) return false;
  if (value.spoolMigration !== undefined && !isRecognizedPriorSpoolMigration(value.spoolMigration)) return false;
  if (value.eventUploadCompletions !== undefined && !isValueMap(value.eventUploadCompletions, isCurrentEventCompletion)) return false;
  if (value.producerEventReservations !== undefined && !isValueMap(value.producerEventReservations, isCurrentProducerReservation)) return false;
  if (value.terminalCancellations !== undefined && !isValueMap(value.terminalCancellations, isCurrentTerminalCancellation)) return false;
  if (value.pendingHandles !== undefined && !isValueMap(value.pendingHandles, isCurrentPendingHandle)) return false;
  if (value.pendingReads !== undefined && !isValueMap(value.pendingReads, isRecognizedPriorRead)) return false;
  if (value.commandResults !== undefined && !isValueMap(value.commandResults, isPriorCommandResult)) return false;
  if (value.seenCommands !== undefined && !isStringMap(value.seenCommands)) return false;
  if (value.currentSessionsSnapshot !== undefined && !isRecognizedPriorSnapshot(value.currentSessionsSnapshot, hostId)) return false;
  return hasRecognizedPriorStateRelationships(value, hostId);
}

export function isRecognizedLegacyRuntime(
  state: Record<string, unknown> | undefined, spool: Record<string, unknown> | undefined, hostId: string,
): boolean {
  if ((state && !isRecognizedPriorStateRecord(state, hostId)) || (spool && !isRecognizedPriorSpoolRecord(spool, hostId))) {
    return false;
  }
  return !state || !spool || hasRecognizedPriorRuntimeRelationships(state, spool);
}

export function isRecognizedObsoleteRuntime(
  state: Record<string, unknown> | undefined, spool: Record<string, unknown> | undefined, hostId: string,
): boolean {
  if (!state || !spool || !isObsoleteStateRecord(state, hostId)
    || !isSpoolRecordForSchema(spool, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, hostId, state.runtimeResetEpoch as string, 'current')) return false;
  return hasRecognizedPriorRuntimeRelationships(state, spool);
}

export function isObsoleteStateRecord(value: Record<string, unknown>, hostId: string): boolean {
  if (!hasExactOptionalKeys(value, PRIOR_V3_STATE_REQUIRED_KEYS, CURRENT_STATE_OPTIONAL_KEYS)
    || value.schemaVersion !== OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION || !isRuntimeEpoch(value.runtimeResetEpoch)
    || !(value.host === null || isCurrentHost(value.host)) || !isValueMap(value.sessions, isCurrentSession)
    || !isStringMap(value.sessionDrivers) || !isTrueMap(value.reconciledDrivers)
    || !Array.isArray(value.recentEvents) || !value.recentEvents.every(isSchema2Event)
    || !isNonNegativeIntegerMap(value.sessionRevisions) || !isValueMap(value.pendingHandles, isCurrentPendingHandle)
    || !isValueMap(value.commandResults, isPriorCommandResult) || !isStringMap(value.seenCommands)
    || !isCurrentSnapshot(value.currentSessionsSnapshot)) return false;
  if (value.recipientSetVersion !== undefined && !isPositiveSafeInteger(value.recipientSetVersion)) return false;
  if ((value.eventUploadCompletions !== undefined && !isValueMap(value.eventUploadCompletions, isCurrentEventCompletion))
    || (value.producerEventReservations !== undefined && !isValueMap(value.producerEventReservations, isCurrentProducerReservation))
    || (value.terminalCancellations !== undefined && !isValueMap(value.terminalCancellations, isCurrentTerminalCancellation))
    || (value.runtimeHealth !== undefined && !isCurrentRuntimeHealth(value.runtimeHealth))) return false;
  try { assertPriorStateV3Relationships(value, hostId); return true; } catch { return false; }
}

export function parseCurrentSpoolRecord(value: Record<string, unknown>, hostId: string, epoch: string): LocalSpoolFileV2 {
  if (!isSpoolRecordForSchema(value, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION, hostId, epoch, 'current')) {
    throw new Error('current Bridge runtime spool schema is invalid');
  }
  return structuredClone(value) as unknown as LocalSpoolFileV2;
}

export function parsePriorV4SpoolRecord(value: Record<string, unknown>, hostId: string, epoch: string): LocalSpoolFileV2 {
  if (!isSpoolRecordForSchema(value, PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION, hostId, epoch, 'current')) {
    throw new Error('prior Bridge runtime spool schema is invalid');
  }
  return structuredClone(value) as unknown as LocalSpoolFileV2;
}

export function isSpoolRecordForSchema(
  value: Record<string, unknown>, schemaVersion: 2 | 3 | 4 | 5, hostId: string, epoch: string, kind: 'current' | 'standalone-v2',
): boolean {
  // Schema4 and schema5 spools both carry the current v3 payload kinds; only
  // schemas 2/3 use the obsolete-v2 kinds.
  const spoolKind = schemaVersion === BRIDGE_RUNTIME_STATE_SCHEMA_VERSION || schemaVersion === PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION ? 'current' : 'obsolete-v2';
  return hasExactKeys(value, ['version', 'runtimeStateSchemaVersion', 'runtimeResetEpoch', 'hostId', 'keyId', 'items'])
    && value.version === 2 && value.runtimeStateSchemaVersion === schemaVersion
    && value.runtimeResetEpoch === epoch && value.hostId === hostId && isVerifier(value.keyId)
    && Array.isArray(value.items) && value.items.every((item) => isRawSpoolItem(item, hostId, spoolKind));
}

export function isRecognizedPriorSpoolRecord(value: Record<string, unknown>, hostId: string): boolean {
  if (hasExactKeys(value, ['version', 'items']) && value.version === 1 && Array.isArray(value.items)
    && value.items.every((item) => isRawSpoolItem(item, hostId, 'v1'))) {
    return hasRecognizedPriorSpoolRelationships(value.items);
  }
  return isSpoolRecordForSchema(value, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, hostId, 'standalone', 'standalone-v2')
    && hasRecognizedPriorSpoolRelationships(value.items as unknown[]);
}

function isRawSpoolItem(value: unknown, hostId: string, kind: 'current' | 'v1' | 'standalone-v2' | 'obsolete-v2'): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value,
    ['version', 'spoolItemId', 'hostId', 'sessionId', 'payloadKind', 'nonce', 'ciphertext', 'aadVersion', 'createdAt'],
    ['eventId'])) return false;
  if (value.version !== 1 || value.hostId !== hostId || !isNonEmptyString(value.spoolItemId)
    || !isNonEmptyString(value.sessionId) || (value.eventId !== undefined && !isNonEmptyString(value.eventId))
    || !isRecognizedRawSpoolPayloadKind(kind, value.payloadKind)
    || !isNonEmptyString(value.nonce) || !isNonEmptyString(value.ciphertext) || value.aadVersion !== 1
    || !isNonEmptyString(value.createdAt)) return false;
  try {
    base64UrlDecode(value.nonce, 12, 'spool nonce');
    return base64UrlDecode(value.ciphertext, undefined, 'spool ciphertext').length >= 16;
  } catch { return false; }
}

function isRecognizedRawSpoolPayloadKind(kind: 'current' | 'v1' | 'standalone-v2' | 'obsolete-v2', payloadKind: unknown): boolean {
  if (kind === 'v1') return PRIOR_V1_SPOOL_KINDS.has(payloadKind as string);
  if (kind === 'current') return isRecognizedLocalSpoolPayloadKind(payloadKind);
  return PRIOR_V2_SPOOL_KINDS.has(payloadKind as string);
}

export function assertCurrentStateRelationships(state: PersistedBridgeState, hostId: string): void {
  if (state.host && state.host.hostId !== hostId) throw new Error('Bridge runtime Host projection belongs to another Host');
  const sessions = new Set(Object.keys(state.sessions));
  const events = new Map<string, CanonicalEvent>();
  for (const [sessionId, session] of Object.entries(state.sessions)) {
    if (session.sessionId !== sessionId || session.hostId !== hostId) throw new Error('Bridge runtime Session binding is invalid');
  }
  for (const [sessionId, driver] of Object.entries(state.sessionDrivers)) {
    const session = state.sessions[sessionId];
    if (!session || session.sessionId !== sessionId || session.provider !== driver) {
      throw new Error('Bridge runtime Session driver binding is invalid');
    }
  }
  for (const event of state.recentEvents) {
    if (event.hostId !== hostId || events.has(event.eventId)) throw new Error('Bridge runtime Event binding is invalid');
    const session = state.sessions[event.sessionId];
    if (session && session.provider !== event.provider) throw new Error('Bridge runtime Event references an invalid Session');
    events.set(event.eventId, event);
  }
  for (const revision of Object.values(state.sessionRevisions)) {
    if (revision < 1) throw new Error('Bridge runtime Session revision binding is invalid');
  }
  for (const [key, handle] of Object.entries(state.pendingHandles)) {
    const event = events.get(handle.handledThroughEventId);
    if (key !== sessionHandleKey(hostId, handle.sessionId) || handle.hostId !== hostId
      || !event || event.hostId !== hostId || event.sessionId !== handle.sessionId
      || (handle.handledThroughEventCreatedAt !== undefined && handle.handledThroughEventCreatedAt !== event.createdAt)) {
      throw new Error('Bridge runtime handle binding is invalid');
    }
  }
  const nonceBindings = new Set<string>();
  for (const [commandId, execution] of Object.entries(state.commandExecutions)) {
    assertCommandExecution(execution);
    if (commandId !== execution.originalEncryptedCommand.commandId
      || execution.originalEncryptedCommand.hostId !== hostId) throw new Error('Bridge runtime command execution binding is invalid');
    const nonceBinding = `${execution.watchDeviceId}\n${execution.nonce}`;
    if (nonceBindings.has(nonceBinding)) throw new Error('Bridge runtime command nonce binding is duplicated');
    nonceBindings.add(nonceBinding);
  }
  for (const [eventId, completion] of Object.entries(state.eventUploadCompletions ?? {})) {
    const currentRevision = state.sessionRevisions[completion.sessionId] ?? 0;
    const event = events.get(eventId);
    const revisionIsValid = currentRevision === completion.revision
      || (completion.revisionCommitted !== true && currentRevision === completion.revision - 1);
    if (eventId !== completion.eventId
      || (event && event.sessionId !== completion.sessionId)
      || !revisionIsValid
      || (completion.inflightRemoved === true && completion.revisionCommitted !== true)
      || (completion.sourceRemoved === true && completion.inflightRemoved !== true)) {
      throw new Error('Bridge runtime Event completion binding is invalid');
    }
  }
  for (const [key, reservation] of Object.entries(state.producerEventReservations ?? {})) {
    const event = events.get(reservation.eventId);
    if (key !== producerReservationKey(reservation.sessionId, reservation.fingerprint)
      || (event && (event.sessionId !== reservation.sessionId || event.createdAt !== reservation.createdAt))) {
      throw new Error('Bridge runtime producer fingerprint binding is invalid');
    }
  }
  for (const [eventId, cancellation] of Object.entries(state.terminalCancellations ?? {})) {
    const event = events.get(eventId);
    if (eventId !== cancellation.eventId
      || (!cancellation.removeSession && !sessions.has(cancellation.sessionId))
      || (event && event.sessionId !== cancellation.sessionId)) {
      throw new Error('Bridge runtime terminal cancellation binding is invalid');
    }
  }
  assertCurrentPublicationRelationships(state);
}

export function assertCurrentPublicationRelationships(state: PersistedBridgeState): void {
  const snapshot = state.currentSessionsSnapshot;
  const acceptedFields = [snapshot.lastAcceptedDigest, snapshot.lastAcceptedContentDigest, snapshot.lastAcceptedRecipientSetVersion];
  if (snapshot.lastAcceptedRevision === 0) {
    if (acceptedFields.some((value) => value !== undefined)) throw new Error('Bridge runtime current publication binding is invalid');
    return;
  }
  if (acceptedFields.some((value) => value === undefined)
    || state.recipientSetVersion === undefined
    || snapshot.lastAcceptedRecipientSetVersion! > state.recipientSetVersion) {
    throw new Error('Bridge runtime current publication binding is invalid');
  }
}

export function assertCurrentRuntimeRelationships(state: PersistedBridgeState, spool: LocalSpoolFileV2, hostId: string): void {
  assertCurrentStateRelationships(state, hostId);
  const ids = new Set<string>();
  for (const item of spool.items) {
    if (ids.has(item.spoolItemId)) throw new Error('Bridge runtime spool item ID is duplicated');
    ids.add(item.spoolItemId);
    const eventKind = item.payloadKind !== 'session-source-v3' && item.payloadKind !== 'session-upload-v3';
    if (eventKind && !item.eventId) throw new Error('Bridge runtime spool Event binding is invalid');
    if (item.payloadKind === 'event-source-v3') {
      const event = state.recentEvents.find((candidate) => candidate.eventId === item.eventId);
      if (item.spoolItemId !== item.eventId || (event && event.sessionId !== item.sessionId)) {
        throw new Error('Bridge runtime Event source binding is invalid');
      }
    }
    if (item.payloadKind === 'event-reservation-v3') {
      const reservation = Object.values(state.producerEventReservations ?? {})
        .find((candidate) => candidate.eventId === item.eventId);
      const cancellation = state.terminalCancellations?.[item.eventId!];
      if (item.spoolItemId !== item.eventId
        || (reservation && reservation.sessionId !== item.sessionId)
        || (cancellation && cancellation.sessionId !== item.sessionId)) {
        throw new Error('Bridge runtime Event reservation binding is invalid');
      }
    }
    if (item.payloadKind === 'event-upload-v3') {
      const event = state.recentEvents.find((candidate) => candidate.eventId === item.eventId);
      if (item.spoolItemId !== `inflight:event:${item.eventId}` || (event && event.sessionId !== item.sessionId)) {
        throw new Error('Bridge runtime Event upload binding is invalid');
      }
    }
    if (item.payloadKind === 'event-dead-letter-v3') {
      const event = state.recentEvents.find((candidate) => candidate.eventId === item.eventId);
      if (item.spoolItemId !== `dead-letter:event:${item.eventId}` || (event && event.sessionId !== item.sessionId)) {
        throw new Error('Bridge runtime Event dead-letter binding is invalid');
      }
    }
    if (item.payloadKind === 'session-upload-v3' && item.spoolItemId !== `inflight:session:${item.sessionId}`) {
      throw new Error('Bridge runtime Session upload binding is invalid');
    }
    if (item.payloadKind === 'terminal-cancellation-v3') {
      const cancellation = state.terminalCancellations?.[item.eventId!];
      const source = spool.items.find((candidate) => candidate.spoolItemId === item.eventId);
      const reservation = Object.values(state.producerEventReservations ?? {})
        .find((candidate) => candidate.eventId === item.eventId);
      const recoverableIntentOnly = !cancellation
        && reservation?.sessionId === item.sessionId
        && source?.payloadKind === 'event-reservation-v3'
        && source.eventId === item.eventId
        && source.sessionId === item.sessionId;
      if (item.spoolItemId !== terminalCancellationItemId(item.eventId!)
        || (!cancellation && !recoverableIntentOnly)
        || (cancellation && cancellation.sessionId !== item.sessionId)) {
        throw new Error('Bridge runtime terminal cancellation spool binding is invalid');
      }
    }
  }
  for (const completion of Object.values(state.eventUploadCompletions ?? {})) {
    const inflight = spool.items.find((item) => item.spoolItemId === `inflight:event:${completion.eventId}`);
    const source = spool.items.find((item) => item.spoolItemId === completion.eventId);
    if ((inflight && (inflight.payloadKind !== 'event-upload-v3' || inflight.sessionId !== completion.sessionId))
      || (source && (source.payloadKind !== 'event-source-v3' || source.sessionId !== completion.sessionId))
      || (completion.inflightRemoved === true && inflight)
      || (completion.sourceRemoved === true && source)) {
      throw new Error('Bridge runtime Event completion spool binding is invalid');
    }
  }
}

function hasRecognizedPriorStateRelationships(state: Record<string, unknown>, hostId: string): boolean {
  const sessions = state.sessions as Record<string, Record<string, unknown>> | undefined ?? {};
  const recentEvents = state.recentEvents as Record<string, unknown>[] | undefined ?? [];
  const pendingEvents = state.pendingEvents as Record<string, unknown>[] | undefined ?? [];
  const events = new Map<string, Record<string, unknown>>();
  for (const event of [...recentEvents, ...pendingEvents]) {
    const existing = events.get(event.eventId as string);
    if (existing && JSON.stringify(existing) !== JSON.stringify(event)) return false;
    const session = sessions[event.sessionId as string];
    if (session && session.provider !== event.provider) return false;
    events.set(event.eventId as string, event);
  }
  if (new Set(recentEvents.map((event) => event.eventId)).size !== recentEvents.length
    || new Set(pendingEvents.map((event) => event.eventId)).size !== pendingEvents.length) return false;
  for (const [sessionId, driver] of Object.entries(state.sessionDrivers as Record<string, string> | undefined ?? {})) {
    if (!sessions[sessionId] || sessions[sessionId].provider !== driver) return false;
  }
  for (const revision of Object.values(state.sessionRevisions as Record<string, number> | undefined ?? {})) {
    if (revision < 1) return false;
  }
  const pendingEventIds = new Set(pendingEvents.map((event) => event.eventId));
  if (state.spoolMigration) {
    const remaining = (state.spoolMigration as { remainingEventIds: string[] }).remainingEventIds;
    if (new Set(remaining).size !== remaining.length || remaining.some((eventId) => !pendingEventIds.has(eventId))) return false;
  }
  for (const [eventId, completion] of Object.entries(state.eventUploadCompletions as Record<string, Record<string, unknown>> | undefined ?? {})) {
    const event = events.get(eventId);
    if (eventId !== completion.eventId || !sessions[completion.sessionId as string]
      || !event || event.sessionId !== completion.sessionId) return false;
    const revision = (state.sessionRevisions as Record<string, number> | undefined)?.[completion.sessionId as string] ?? 0;
    const revisionCommitted = completion.revisionCommitted === true;
    if (revision < (completion.revision as number) - 1 || revision > (completion.revision as number)
      || (completion.inflightRemoved === true && !revisionCommitted)
      || (completion.sourceRemoved === true && completion.inflightRemoved !== true)) return false;
  }
  for (const [key, reservation] of Object.entries(state.producerEventReservations as Record<string, Record<string, unknown>> | undefined ?? {})) {
    const event = events.get(reservation.eventId as string);
    if (key !== producerReservationKey(reservation.sessionId as string, reservation.fingerprint as string)
      || !sessions[reservation.sessionId as string] || !event || event.sessionId !== reservation.sessionId) return false;
  }
  const reservations = state.producerEventReservations as Record<string, Record<string, unknown>> | undefined ?? {};
  for (const [eventId, cancellation] of Object.entries(state.terminalCancellations as Record<string, Record<string, unknown>> | undefined ?? {})) {
    const event = events.get(eventId);
    if (eventId !== cancellation.eventId || !event || event.sessionId !== cancellation.sessionId
      || (cancellation.removeSession !== true && !sessions[cancellation.sessionId as string])) return false;
    const related = Object.values(reservations).find((reservation) => reservation.eventId === eventId);
    if (related && (related.sessionId !== cancellation.sessionId || related.fingerprint !== cancellation.fingerprint)) return false;
  }
  for (const [key, handle] of Object.entries(state.pendingHandles as Record<string, Record<string, unknown>> | undefined ?? {})) {
    const event = events.get(handle.handledThroughEventId as string);
    if (key !== sessionHandleKey(hostId, handle.sessionId as string) || handle.hostId !== hostId
      || !event || event.hostId !== hostId || event.sessionId !== handle.sessionId
      || (handle.handledThroughEventCreatedAt !== undefined && handle.handledThroughEventCreatedAt !== event.createdAt)) return false;
  }
  for (const [key, read] of Object.entries(state.pendingReads as Record<string, Record<string, unknown>> | undefined ?? {})) {
    const event = events.get(read.latestReadEventId as string);
    if (key !== sessionHandleKey(hostId, read.sessionId as string) || read.hostId !== hostId
      || !sessions[read.sessionId as string] || !event || event.sessionId !== read.sessionId) return false;
  }
  const results = state.commandResults as Record<string, Record<string, unknown>> | undefined ?? {};
  const seen = state.seenCommands as Record<string, string> | undefined ?? {};
  for (const [commandId, result] of Object.entries(results)) {
    const session = sessions[result.sessionId as string];
    const eventId = session?.lastEventId as string | undefined;
    if (commandId !== result.commandId || result.hostId !== hostId
      || (session && eventId !== undefined && events.get(eventId)?.sessionId !== result.sessionId)
      || seen[commandId] !== result.updatedAt) return false;
  }
  if (Object.keys(seen).some((commandId) => !results[commandId])) return false;
  return hasRecognizedPriorPublicationRelationships(state, sessions);
}

function hasRecognizedPriorPublicationRelationships(
  state: Record<string, unknown>, sessions: Record<string, Record<string, unknown>>,
): boolean {
  if (!state.currentSessionsSnapshot) return true;
  const snapshot = state.currentSessionsSnapshot as Record<string, unknown>;
  const allocated = snapshot.lastAllocatedRevision as number;
  const accepted = snapshot.lastAcceptedRevision as number;
  if (accepted > allocated) return false;
  const acceptedFields = [snapshot.lastAcceptedDigest, snapshot.lastAcceptedContentDigest, snapshot.lastAcceptedRecipientSetVersion];
  if (accepted === 0 ? acceptedFields.some((value) => value !== undefined) : acceptedFields.some((value) => value === undefined)) return false;
  const recipientSetVersion = state.recipientSetVersion as number | undefined;
  if (accepted > 0 && (recipientSetVersion === undefined
    || (snapshot.lastAcceptedRecipientSetVersion as number) > recipientSetVersion)) return false;
  if (!snapshot.pending) return true;
  const request = (snapshot.pending as { request: Record<string, unknown> }).request;
  if ((request.revision as number) > allocated || recipientSetVersion === undefined
    || (request.recipientSetVersion as number) > recipientSetVersion) return false;
  const publishedSessions = request.sessions as Array<Record<string, unknown>>;
  if (new Set(publishedSessions.map((session) => session.sessionId)).size !== publishedSessions.length) return false;
  return publishedSessions.every((session) => sessions[session.sessionId as string]
    && (state.sessionRevisions as Record<string, number> | undefined)?.[session.sessionId as string] === session.sessionRevision);
}

function hasRecognizedPriorSpoolRelationships(items: unknown[]): boolean {
  const ids = new Set<string>();
  for (const value of items) {
    const item = value as Record<string, unknown>;
    const itemId = item.spoolItemId as string;
    const eventId = item.eventId as string | undefined;
    if (ids.has(itemId)) return false;
    ids.add(itemId);
    switch (item.payloadKind) {
      case 'event-source-v1':
      case 'event-source-v2':
      case 'event-reservation-v2':
        if (!eventId || itemId !== eventId) return false;
        break;
      case 'event-dead-letter-v1':
      case 'event-dead-letter-v2':
        if (!eventId || itemId !== `dead-letter:event:${eventId}`) return false;
        break;
      case 'session-source-v1':
      case 'session-source-v2':
        if (eventId !== undefined || itemId !== item.sessionId) return false;
        break;
      case 'event-upload-v1':
      case 'event-upload-v2':
        if (!eventId || itemId !== `inflight:event:${eventId}`) return false;
        break;
      case 'session-upload-v1':
      case 'session-upload-v2':
        if (eventId !== undefined || itemId !== `inflight:session:${item.sessionId}`) return false;
        break;
      case 'terminal-cancellation-v2':
        if (!eventId || itemId !== terminalCancellationItemId(eventId)) return false;
        break;
      default: return false;
    }
  }
  return true;
}

export function hasResetSourceRelationships(
  fromSchemaVersion: 1 | 2, state: Record<string, unknown>, spool: Record<string, unknown>, hostId: string,
): boolean {
  if (fromSchemaVersion === LEGACY_RUNTIME_STATE_SCHEMA_VERSION) {
    return hasRecognizedPriorRuntimeRelationships(state, spool);
  }
  return isObsoleteStateRecord(state, hostId)
    && isSpoolRecordForSchema(spool, fromSchemaVersion, hostId,
      state.runtimeResetEpoch as string, 'current')
    && hasRecognizedPriorRuntimeRelationships(state, spool);
}

function hasRecognizedPriorRuntimeRelationships(state: Record<string, unknown>, spool: Record<string, unknown>): boolean {
  const sessions = state.sessions as Record<string, Record<string, unknown>> | undefined ?? {};
  const events = new Map<string, Record<string, unknown>>();
  for (const event of [
    ...(state.recentEvents as Record<string, unknown>[] | undefined ?? []),
    ...(state.pendingEvents as Record<string, unknown>[] | undefined ?? []),
  ]) events.set(event.eventId as string, event);
  const itemIds = new Set((spool.items as Array<Record<string, unknown>>).map((item) => item.spoolItemId as string));
  for (const value of spool.items as unknown[]) {
    const item = value as Record<string, unknown>;
    if (!sessions[item.sessionId as string]) return false;
    if (item.eventId !== undefined) {
      const event = events.get(item.eventId as string);
      if (!event || event.sessionId !== item.sessionId) return false;
    }
  }
  for (const completion of Object.values(state.eventUploadCompletions as Record<string, Record<string, unknown>> | undefined ?? {})) {
    if (completion.inflightRemoved !== true && !itemIds.has(`inflight:event:${completion.eventId}`)) return false;
    if (completion.sourceRemoved !== true && !itemIds.has(completion.eventId as string)) return false;
  }
  for (const cancellation of Object.values(state.terminalCancellations as Record<string, Record<string, unknown>> | undefined ?? {})) {
    if (!itemIds.has(cancellation.eventId as string)) return false;
  }
  return true;
}

function isRecognizedPriorHost(value: unknown, hostId: string): boolean {
  if (!isRecord(value) || value.hostId !== hostId || !hasOnlyKeys(value, [
    'hostId', 'hostName', 'platform', 'bridgeVersion', 'registeredAt', 'lastSeenAt', 'bridgeStatus', 'status',
    'claimCode', 'claimCodeExpiresAt', 'ownerUserId',
  ])) return false;
  return Object.entries(value).every(([key, item]) => key === 'hostId' || item === undefined
    || (key === 'platform' ? item === 'macos' || item === 'linux'
      : key === 'bridgeStatus' ? item === 'online' || item === 'offline' || item === 'degraded'
        : key === 'status' ? item === 'active' || item === 'revoked' : typeof item === 'string'));
}

function isRecognizedPriorSession(value: unknown, hostId: string): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, PRIOR_SESSION_REQUIRED_KEYS, OBSOLETE_SESSION_OPTIONAL_KEYS)
    || value.hostId !== hostId || !PRIOR_SESSION_REQUIRED_KEYS.filter((key) => key !== 'status').every((key) => isNonEmptyString(value[key]))
    || !['idle', 'working', 'blocked', 'done', 'unknown'].includes(value.status as string)) return false;
  return OBSOLETE_SESSION_OPTIONAL_KEYS.every((key) => value[key] === undefined
    || (key === 'actionablePrompt' ? isCurrentActionablePrompt(value[key]) : typeof value[key] === 'string'));
}

const OBSOLETE_EVENT_REQUIRED_KEYS = [...EVENT_REQUIRED_KEYS, 'typeLabel'] as const;
const OBSOLETE_EVENT_OPTIONAL_KEYS = [
  ...EVENT_OPTIONAL_KEYS, 'contextText', 'hbaseSessionKey', 'actionablePrompt', 'correlationId',
] as const;

function isSchema2Event(value: unknown): boolean {
  return isRecord(value) && value.typeLabel !== undefined && isObsoleteEvent(value);
}

function isObsoleteEvent(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const required = value.typeLabel === undefined ? EVENT_REQUIRED_KEYS : OBSOLETE_EVENT_REQUIRED_KEYS;
  return isEventForKeys(value, [...OBSOLETE_EVENT_OPTIONAL_KEYS, ...(value.typeLabel === undefined ? [] : ['typeLabel'])])
    || (hasExactOptionalKeys(value, required, OBSOLETE_EVENT_OPTIONAL_KEYS)
      && required.filter((key) => key !== 'type' && key !== 'status').every((key) => isNonEmptyString(value[key]))
      && ((value.type === 'done' && value.status === 'idle' && value.needHuman === undefined)
        || (value.type === 'need_human' && value.status === 'need_human' && isCurrentNeedHuman(value.needHuman)))
      && OBSOLETE_EVENT_OPTIONAL_KEYS.every((key) => value[key] === undefined || key === 'needHuman'
        || (key === 'actionablePrompt' ? isCurrentActionablePrompt(value[key]) : typeof value[key] === 'string')));
}

function isRecognizedPriorEvent(value: unknown, hostId: string): boolean {
  return isRecord(value)
    && hasExactOptionalKeys(value, OBSOLETE_EVENT_REQUIRED_KEYS, OBSOLETE_EVENT_OPTIONAL_KEYS.filter((key) => key !== 'needHuman'))
    && value.hostId === hostId && OBSOLETE_EVENT_REQUIRED_KEYS.filter((key) => key !== 'type' && key !== 'status')
      .every((key) => isNonEmptyString(value[key]))
    && ['working', 'blocked', 'done', 'question_requested'].includes(value.type as string)
    && ['idle', 'working', 'blocked', 'done', 'unknown'].includes(value.status as string)
    && OBSOLETE_EVENT_OPTIONAL_KEYS.filter((key) => key !== 'needHuman').every((key) => value[key] === undefined
      || (key === 'actionablePrompt' ? isCurrentActionablePrompt(value[key]) : typeof value[key] === 'string'));
}

function isRecognizedPriorSpoolMigration(value: unknown): boolean {
  return isRecord(value) && hasExactKeys(value, ['version', 'remainingEventIds', 'startedAt']) && value.version === 1
    && Array.isArray(value.remainingEventIds) && value.remainingEventIds.every(isNonEmptyString) && isNonEmptyString(value.startedAt);
}

function isRecognizedPriorRead(value: unknown): boolean {
  return isRecord(value) && hasExactOptionalKeys(value,
    ['hostId', 'sessionId', 'latestReadEventId', 'readAt', 'source', 'updatedAt'], ['latestReadEventCreatedAt'])
    && ['hostId', 'sessionId', 'latestReadEventId', 'readAt', 'updatedAt'].every((key) => isNonEmptyString(value[key]))
    && (value.source === 'pi_local_interaction' || value.source === 'bridge_recovery')
    && (value.latestReadEventCreatedAt === undefined || isNonEmptyString(value.latestReadEventCreatedAt));
}

function isRecognizedPriorSnapshot(value: unknown, hostId: string): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, ['version', 'lastAllocatedRevision', 'lastAcceptedRevision'],
    ['lastAcceptedDigest', 'lastAcceptedContentDigest', 'lastAcceptedRecipientSetVersion', 'pending'])
    || value.version !== 1 || !isNonNegativeSafeInteger(value.lastAllocatedRevision)
    || !isNonNegativeSafeInteger(value.lastAcceptedRevision)) return false;
  if (value.pending !== undefined && !isRecognizedPriorPublication(value.pending, hostId)) return false;
  return ['lastAcceptedDigest', 'lastAcceptedContentDigest'].every((key) => value[key] === undefined || typeof value[key] === 'string')
    && (value.lastAcceptedRecipientSetVersion === undefined || isPositiveSafeInteger(value.lastAcceptedRecipientSetVersion));
}

function isRecognizedPriorPublication(value: unknown, hostId: string): boolean {
  if (!isRecord(value) || !hasExactKeys(value, ['request', 'digest', 'contentDigest'])
    || !isNonEmptyString(value.digest) || !isNonEmptyString(value.contentDigest) || !isRecord(value.request)) return false;
  const request = value.request;
  return hasExactKeys(request, ['hostId', 'revision', 'observedAt', 'recipientSetVersion', 'sessions'])
    && request.hostId === hostId && isPositiveSafeInteger(request.revision) && isNonEmptyString(request.observedAt)
    && isPositiveSafeInteger(request.recipientSetVersion) && Array.isArray(request.sessions)
    && request.sessions.every((session) => isRecord(session) && hasExactKeys(session, ['sessionId', 'sessionRevision'])
      && isNonEmptyString(session.sessionId) && isPositiveSafeInteger(session.sessionRevision));
}

/** §5.2: an Event/session tuple must be self-consistent before journaling. */
export function assertEventSessionBinding(event: CanonicalEvent, session: CanonicalSessionState): void {
  if (event.hostId !== session.hostId || event.sessionId !== session.sessionId || event.provider !== session.provider
    || event.status !== session.status || session.lastEventId !== event.eventId) {
    throw new TypeError('pending Event requires its corresponding terminal Session snapshot');
  }
}
