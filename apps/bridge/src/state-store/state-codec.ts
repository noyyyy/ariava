import { createHash } from 'node:crypto';
import type { CommandResult } from '@ariava/protocol';
import {
  buildCommandReceiptEnvelopeBindingBytes,
  buildEncryptedCommandEnvelopeBindingBytes,
  isCanonicalTimestamp,
  validateCommandReceiptEnvelopeV1,
  validateCommandResult,
  validateEncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import type {
  CommandReceiptOutboxInputV1,
  PersistedBridgeState,
  PersistedCommandExecutionV4,
  PersistedCommandPinReferenceV1,
  PersistedCurrentSessionsSnapshotState,
} from '../types';

export const BRIDGE_RUNTIME_STATE_SCHEMA_VERSION = 5 as const;

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

function hashBytes(bytes: Uint8Array): string {
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

function hasExactKeys(value: Record<string, unknown>, required: readonly string[]): boolean {
  return Object.keys(value).length === required.length && required.every((key) => key in value);
}

function hasExactOptionalKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[]): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => key in value) && Object.keys(value).every((key) => allowed.has(key));
}
