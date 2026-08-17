import { randomUUID } from 'node:crypto';
import {
  pathHasFilesystemEvidence,
  readSecureJson,
  writeSecureJson,
  type SecureFileWriteHooks,
  type SecureFileRemoveHooks,
} from './host-manager/secure-files';
import type {
  CanonicalEvent, CanonicalSessionState, CommandResult, E2EEventAndSessionUploadV3, EncryptedCommandEnvelopeV1,
  EncryptedSessionSnapshotUploadV3, HostProjection, ReplaceE2ECurrentSessionsRequestV1,
} from '@ariava/protocol';
import {
  base64UrlEncode, e2eCurrentSessionsSemanticDigestV1, isCanonicalTimestamp,
  validateCanonicalEventInvariant, validateEncryptedContentV1, validateNotificationPreviewEnvelopeV2,
  validateRecipientKeyWrapV1,
} from '@ariava/protocol';
import type {
  BridgeRuntimeHealth,
  CommandReceiptOutboxInputV1,
  DriverRuntimeHealth,
  EventUploadCompletionV1,
  PendingSessionHandle,
  PersistedBridgeState,
  PersistedCommandExecutionV4,
  PersistedCommandPinReferenceV1,
  PersistedCurrentSessionsSnapshotState,
  PersistedProducerEventReservationV1,
} from './types';
import {
  LocalEncryptedSpool,
  createRuntimeSpoolKeyStore,
  spoolPathForState,
  type SpoolKeyStore,
} from './e2e/local-spool';
import {
  type RuntimeCoordinator,
} from './runtime-lock';
import {
  acceptCurrentSessionsPublicationTransition,
  createCurrentSessionsPublicationTransition,
  noteCurrentSessionsSnapshotRevisionLowerBoundTransition,
  setRecipientSetVersionTransition,
} from './state-store/current-sessions-transitions';
import {
  claimCommandExecutionTransition,
  collectEncryptedUploadPinReferences,
  markCommandDispatchStartedTransition,
  markCommandOutcomeUnknownTransition,
  markCommandReceiptOutboxTransition,
  persistTerminalCommandReceiptTransition,
  persistTerminalReceiptBlockedTransition,
  pruneEligibleCommandExecutionsTransition,
  readCommandExecutionPinRetentionReferences,
  recoverOrphanedCommandExecutionsTransition,
  validateCommandExecutionPinsState,
  type CommandExecutionPinResolver,
} from './state-store/command-transitions';
import { appendRecentEventTransition } from './state-store/event-transitions';
import {
  readRuntimeHealth,
  recordDriverReconciliationFailureTransition,
  recordDriverReconciliationSuccessTransition,
  recordRelayPresenceFailureTransition,
  recordRelayPresenceSuccessTransition,
  setHostTransition,
} from './state-store/host-health-transitions';
import {
  commitSessionRevisionTransition,
  queuePendingSessionHandleTransition,
  readCurrentSessionRevision,
  readNextSessionRevision,
  removePendingSessionHandleTransition,
  removeSessionDriverTransition,
  removeSessionTransition,
  replaceDriverSessionsTransition,
  setSessionDriverTransition,
  updateSessionTransition,
} from './state-store/session-transitions';
import { commitState, type StateTransition } from './state-store/state-transitions';
import {
  BRIDGE_RUNTIME_STATE_SCHEMA_VERSION,
  LEGACY_RUNTIME_STATE_SCHEMA_VERSION,
  OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION,
  PRIOR_RUNTIME_STATE_SCHEMA_VERSION,
  assertCurrentRuntimeRelationships,
  assertEventSessionBinding,
  emptyState,
  hasExactOptionalKeys,
  isCurrentStateRecord,
  isPriorStateRecordV3,
  isRecognizedLegacyRuntime,
  isRecognizedObsoleteRuntime,
  isRecord,
  isSpoolRecordForSchema,
  parseCurrentSpoolRecord,
  parseCurrentState,
  producerReservationKey,
} from './state-store/state-codec';
import {
  acquireRuntimeCoordinatorForState,
  assertRuntimeCoordinatorForState,
  assertStateStoreAccess,
  loadCurrentOrFresh as loadFreshState,
} from './state-store/runtime-lifecycle';
import * as spoolTransactions from './state-store/spool-transactions';
import type { PendingEventDescriptor, PendingEventSource } from './state-store/spool-transactions';
import {
  isRuntimeResetHooks,
  parseRawJson,
  readOptionalSecureBytes,
  type RuntimeResetHooks,
} from './state-store/state-persistence';
import {
  beginRuntimeMigration,
  beginRuntimeReset,
  parseRuntimeSchemaFloor,
  resumeRuntimeMigration,
  resumeRuntimeReset,
  runtimeMigrationIntentPathForState,
  runtimeResetIntentPathForState,
  runtimeSchemaFloor,
  runtimeSchemaFloorPathForState,
  type RuntimeResetPhase,
} from './state-store/runtime-reset';

export { BRIDGE_RUNTIME_STATE_SCHEMA_VERSION, emptyState };
export type { RuntimeResetHooks };
export type { PendingEventDescriptor, PendingEventSource } from './state-store/spool-transactions';
export { COMMAND_RECEIPT_RETENTION_DAYS, COMMAND_RECEIPT_RETENTION_MS } from './state-store/command-transitions';
export type { CommandExecutionPinResolver };
export {
  assertCurrentRuntimeArtifacts,
  readCurrentRuntimeHealth,
  runtimeMigrationIntentPathForState,
  runtimeResetIntentPathForState,
  runtimeSchemaFloorPathForState,
} from './state-store/runtime-reset';

export interface BridgeStateStoreOptions { deferRuntimePreflight?: boolean; runtimeCoordinator?: RuntimeCoordinator }


/** New inflight inner wrapper introduced by the 64 KiB spec (§4.3). */
export interface EventInflightRecordV2 {
  version: 2;
  sourceDigest: string;
  upload: E2EEventAndSessionUploadV3;
}

export interface SessionInflightRecordV2 {
  version: 2;
  sourceDigest: string;
  upload: EncryptedSessionSnapshotUploadV3;
}

/**
 * Parsed inflight event evidence plus its raw AEAD-opened bytes (retained for
 * the dead-letter archive only). Caller zeroes `raw` after use.
 */
export type LoadedEventInflight =
  | { kind: 'v2'; raw: Uint8Array; sourceDigest: string; upload: E2EEventAndSessionUploadV3 }
  | { kind: 'legacy'; raw: Uint8Array; upload: E2EEventAndSessionUploadV3 };

/**
 * Per-item load result (§5.2). Inflight is parsed first; a malformed inflight
 * short-circuits with an `inflight-*` reason (recovery-required, never quarantined).
 * A malformed source still carries the parsed inflight so the caller can reconcile
 * it before deciding to dead-letter.
 */
export type LoadPendingEventPartsResult =
  | { ok: true; source: PendingEventSource; inflight?: LoadedEventInflight }
  | { ok: false; reason: 'source-utf8-invalid' | 'source-json-invalid' | 'source-shape-invalid' | 'source-binding-invalid' | 'source-missing'; inflight?: LoadedEventInflight }
  | { ok: false; reason: 'inflight-utf8-invalid' | 'inflight-json-invalid' | 'inflight-shape-invalid' };

/** Fixed dead-letter reason codes (§5.3); no exception text is ever stored. */
export type EventDeadLetterReasonCode =
  | 'protected-content-invalid'
  | 'event-session-binding-invalid'
  | 'source-utf8-invalid'
  | 'source-json-invalid'
  | 'relay-permanent-conflict';

export interface EventDeadLetterRecordV2 {
  version: 2;
  eventId: string;
  sessionId: string;
  reasonCode: EventDeadLetterReasonCode;
  quarantinedAt: string;
  sourceArchive: { encoding: 'base64url'; bytes: string };
  inflightArchive?: { encoding: 'base64url'; bytes: string };
}

const SOURCE_DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function isSourceDigest(value: unknown): value is string {
  return typeof value === 'string' && SOURCE_DIGEST_PATTERN.test(value);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}


/** Exact encrypted-upload shape guards (§4.3/§5.2): a shallow or structurally
 * broken inflight must classify as malformed (recovery-required), never be
 * completed, wrapped, or dead-lettered under a different identity. */
function isEncryptedContentShape(value: unknown): boolean {
  return validateEncryptedContentV1(value);
}

function isKeyWrapArrayShape(value: unknown): boolean {
  return Array.isArray(value) && value.every((wrap) => validateRecipientKeyWrapV1(wrap));
}

function isPreviewArrayShape(value: unknown): boolean {
  return Array.isArray(value) && value.every((preview) => validateNotificationPreviewEnvelopeV2(preview));
}

function isEncryptedEventUploadShape(value: unknown): value is E2EEventAndSessionUploadV3 {
  if (!isRecord(value) || !hasExactOptionalKeys(value, ['event', 'session'], [])
    || !isRecord(value.event) || !isRecord(value.session)) return false;
  const event = value.event as Record<string, unknown>;
  const session = value.session as Record<string, unknown>;
  return hasExactOptionalKeys(event, ['eventId', 'hostId', 'sessionId', 'provider', 'type', 'status', 'createdAt', 'recipientSetVersion', 'content', 'keyWraps'], ['notificationPreviews'])
    && typeof event.eventId === 'string' && typeof event.hostId === 'string' && typeof event.sessionId === 'string'
    && typeof event.provider === 'string'
    && (event.type === 'done' ? event.status === 'idle' : event.type === 'need_human' ? event.status === 'need_human' : false)
    && typeof event.createdAt === 'string' && isCanonicalTimestamp(event.createdAt)
    && Number.isSafeInteger(event.recipientSetVersion) && (event.recipientSetVersion as number) >= 1
    && isEncryptedContentShape(event.content) && (event.content as { payloadKind?: unknown }).payloadKind === 'event-content-v3'
    && isKeyWrapArrayShape(event.keyWraps)
    && (event.notificationPreviews === undefined || isPreviewArrayShape(event.notificationPreviews))
    && hasExactOptionalKeys(session, ['hostId', 'sessionId', 'provider', 'status', 'updatedAt', 'revision', 'recipientSetVersion', 'content', 'keyWraps'], ['lastEventId', 'snoozedUntil'])
    && typeof session.hostId === 'string' && typeof session.sessionId === 'string' && typeof session.provider === 'string'
    && (session.status === 'idle' || session.status === 'working' || session.status === 'need_human')
    && typeof session.updatedAt === 'string' && isCanonicalTimestamp(session.updatedAt)
    && (session.lastEventId === undefined || (typeof session.lastEventId === 'string' && session.lastEventId.length > 0))
    && (session.snoozedUntil === undefined || isCanonicalTimestamp(session.snoozedUntil))
    && Number.isSafeInteger(session.revision) && (session.revision as number) >= 1
    && Number.isSafeInteger(session.recipientSetVersion) && (session.recipientSetVersion as number) >= 1
    && isEncryptedContentShape(session.content) && (session.content as { payloadKind?: unknown }).payloadKind === 'session-content-v3'
    && isKeyWrapArrayShape(session.keyWraps);
}

function isEncryptedSessionUploadShape(value: unknown): value is EncryptedSessionSnapshotUploadV3 {
  if (!isRecord(value)) return false;
  return hasExactOptionalKeys(value, ['hostId', 'sessionId', 'provider', 'status', 'updatedAt', 'revision', 'recipientSetVersion', 'content', 'keyWraps'], ['lastEventId', 'snoozedUntil'])
    && typeof value.hostId === 'string' && typeof value.sessionId === 'string' && typeof value.provider === 'string'
    && (value.status === 'idle' || value.status === 'working' || value.status === 'need_human')
    && typeof value.updatedAt === 'string' && isCanonicalTimestamp(value.updatedAt)
    && (value.lastEventId === undefined || (typeof value.lastEventId === 'string' && value.lastEventId.length > 0))
    && (value.snoozedUntil === undefined || isCanonicalTimestamp(value.snoozedUntil))
    && Number.isSafeInteger(value.revision) && (value.revision as number) >= 1
    && Number.isSafeInteger(value.recipientSetVersion) && (value.recipientSetVersion as number) >= 1
    && isEncryptedContentShape(value.content) && (value.content as { payloadKind?: unknown }).payloadKind === 'session-content-v3'
    && isKeyWrapArrayShape(value.keyWraps);
}

function isEventInflightRecordV2(value: unknown): value is EventInflightRecordV2 {
  return isRecord(value) && hasExactOptionalKeys(value, ['version', 'sourceDigest', 'upload'], [])
    && value.version === 2 && isSourceDigest(value.sourceDigest)
    && isEncryptedEventUploadShape(value.upload);
}

function isSessionInflightRecordV2(value: unknown): value is SessionInflightRecordV2 {
  return isRecord(value) && hasExactOptionalKeys(value, ['version', 'sourceDigest', 'upload'], [])
    && value.version === 2 && isSourceDigest(value.sourceDigest)
    && isEncryptedSessionUploadShape(value.upload);
}

function isEncryptedEventUploadRecord(value: unknown): boolean {
  return isEncryptedEventUploadShape(value);
}

/** §5.2: exact canonical Event shape — every key known, types and the
 * type/status/needHuman invariant canonical. Unknown fields are rejected so a
 * source can never be silently stripped and uploaded under a different shape.
 */
function isCanonicalEventShape(value: unknown): value is CanonicalEvent {
  if (!isRecord(value)) return false;
  if (!hasExactOptionalKeys(value, ['eventId', 'hostId', 'sessionId', 'provider', 'agentText', 'createdAt', 'type', 'status'],
    ['humanText', 'projectName', 'workingDirectory', 'harnessProvider', 'needHuman'])) return false;
  if (typeof value.eventId !== 'string' || typeof value.hostId !== 'string' || typeof value.sessionId !== 'string'
    || typeof value.provider !== 'string' || typeof value.agentText !== 'string'
    || typeof value.createdAt !== 'string' || !isCanonicalTimestamp(value.createdAt)) return false;
  for (const key of ['humanText', 'projectName', 'workingDirectory', 'harnessProvider'] as const) {
    if (value[key] !== undefined && typeof value[key] !== 'string') return false;
  }
  const invariant: Record<string, unknown> = { type: value.type, status: value.status };
  if (value.needHuman !== undefined) invariant.needHuman = value.needHuman;
  return validateCanonicalEventInvariant(invariant).success;
}

/** §5.2: exact canonical Session shape — every key known and typed; unknown
 * fields are rejected for the same reason as the Event shape. */
function isCanonicalSessionShape(value: unknown): value is CanonicalSessionState {
  if (!isRecord(value)) return false;
  if (!hasExactOptionalKeys(value, ['sessionId', 'hostId', 'provider', 'projectName', 'nameText', 'status', 'updatedAt'],
    ['openingText', 'latestActivityText', 'workingDirectory', 'harnessProvider', 'lastEventId', 'snoozedUntil'])) return false;
  return typeof value.sessionId === 'string' && typeof value.hostId === 'string' && typeof value.provider === 'string'
    && typeof value.projectName === 'string' && typeof value.nameText === 'string'
    && (value.status === 'idle' || value.status === 'working' || value.status === 'need_human')
    && typeof value.updatedAt === 'string' && isCanonicalTimestamp(value.updatedAt)
    && (value.lastEventId === undefined || (typeof value.lastEventId === 'string' && value.lastEventId.length > 0))
    && (value.snoozedUntil === undefined || isCanonicalTimestamp(value.snoozedUntil));
}

/** §5.1: discriminated Session inflight lookup. `malformed` (unparseable or
 * non-shape bytes) and `cross-bound` (a parseable upload whose inner sessionId
 * differs from the outer spool key) are evidence that must stay byte-preserved
 * and be surfaced as recovery-required — never silently rebuilt or removed.
 */
export type SessionInflightLookup =
  | { kind: 'missing' }
  | { kind: 'v2'; upload: EncryptedSessionSnapshotUploadV3 }
  | { kind: 'legacy'; upload: EncryptedSessionSnapshotUploadV3 }
  | { kind: 'cross-bound'; upload: EncryptedSessionSnapshotUploadV3 }
  | { kind: 'malformed' };

/** §4.4/§5.2: the encrypted tuple must be self-consistent AND bound to the outer
 * spool descriptor; a cross-bound inflight (B's upload under A's key) must never
 * be completed or wrapped under A's identity. */
function uploadMatchesDescriptor(upload: E2EEventAndSessionUploadV3, descriptor: PendingEventDescriptor): boolean {
  return upload.event.eventId === descriptor.eventId
    && upload.session.sessionId === descriptor.sessionId
    && upload.event.sessionId === upload.session.sessionId
    && upload.event.hostId === upload.session.hostId
    && upload.event.provider === upload.session.provider
    && upload.event.status === upload.session.status
    && upload.session.lastEventId === upload.event.eventId;
}


/** §4.3 inflight wrapper: bind the immutable source digest when available;
 * absent digests keep the byte-preserved legacy unwrapped record. */
function withSourceDigestWrapper(upload: unknown, sourceDigest?: string): unknown {
  return isSourceDigest(sourceDigest) ? { version: 2 as const, sourceDigest, upload } : upload;
}

export class BridgeStateStore {

  private storedState: PersistedBridgeState;
  private spool?: LocalEncryptedSpool;
  private runtimeReady: boolean;
  private commandExecutionPinsReady: boolean;
  private readonly runtimeCoordinator: RuntimeCoordinator;
  private readonly releaseStateWriter: () => void;
  private readonly ownsRuntimeCoordinator: boolean;
  private disposed = false;
  private get state(): PersistedBridgeState {
    this.assertRuntimeAccess();
    if (!this.runtimeReady) throw new Error('Bridge runtime state is unavailable before startup preflight');
    return this.storedState;
  }
  private set state(value: PersistedBridgeState) { this.storedState = value; }
  constructor(
    private readonly filePath: string,
    private readonly writeState: (path: string, value: unknown) => void = writeSecureJson,
    options: BridgeStateStoreOptions = {},
  ) {
    this.ownsRuntimeCoordinator = options.runtimeCoordinator === undefined;
    this.runtimeCoordinator = options.runtimeCoordinator ?? acquireRuntimeCoordinatorForState(this.filePath);
    assertRuntimeCoordinatorForState(this.runtimeCoordinator, this.filePath);
    let releaseStateWriter: (() => void) | undefined;
    try {
      releaseStateWriter = this.runtimeCoordinator.claimStateWriter();
      this.releaseStateWriter = releaseStateWriter;
      this.assertRuntimeAccess();
      this.runtimeReady = options.deferRuntimePreflight !== true;
      this.commandExecutionPinsReady = options.deferRuntimePreflight !== true;
      this.storedState = this.runtimeReady ? this.loadCurrentOrFresh() : emptyState('preflight-pending');
    } catch (error) {
      releaseStateWriter?.();
      if (this.ownsRuntimeCoordinator) this.runtimeCoordinator.dispose();
      throw error;
    }
  }

  initializeEncryptedSpool(
    hostId: string,
    identityPath: string,
    platform: NodeJS.Platform | string,
    keyStore?: SpoolKeyStore,
    resetStep?: (phase: RuntimeResetPhase) => void,
    resetHooks?: SecureFileWriteHooks | RuntimeResetHooks,
  ): { droppedUnreadableItems: number } {
    this.assertRuntimeAccess();
    const resolvedKeyStore = keyStore ?? createRuntimeSpoolKeyStore(identityPath, platform);
    const writeHooks = isRuntimeResetHooks(resetHooks) ? resetHooks.write : resetHooks;
    const removeHooks = isRuntimeResetHooks(resetHooks) ? resetHooks.remove : undefined;
    this.state = this.preflightRuntime(hostId, resolvedKeyStore, resetStep, writeHooks, removeHooks);
    this.runtimeReady = true;
    this.spool = new LocalEncryptedSpool(
      spoolPathForState(this.filePath), hostId, resolvedKeyStore,
      BRIDGE_RUNTIME_STATE_SCHEMA_VERSION, this.state.runtimeResetEpoch, () => this.assertRuntimeAccess(),
    );
    const recovery = this.spool.recoverUnreadable();
    if (isRuntimeResetHooks(resetHooks)) resetHooks.recoveryStep?.('after-unreadable-recovery');
    this.reconcileTerminalCancellations();
    this.reconcileProducerEventReservations();
    this.reconcilePendingEventJournal();
    this.resumeEventUploadCompletions();
    return recovery;
  }

  private loadCurrentOrFresh(): PersistedBridgeState {
    if (!this.filePath) return loadFreshState(this.filePath);
    if (!pathHasFilesystemEvidence(this.filePath)) return emptyState(randomUUID());
    try {
      return parseCurrentState(readSecureJson<unknown>(this.filePath));
    } catch (error) {
      throw new Error('Bridge state file is invalid or insecure', { cause: error });
    }
  }

  private preflightRuntime(
    hostId: string,
    keyStore: SpoolKeyStore,
    resetStep?: (phase: RuntimeResetPhase) => void,
    resetWriteHooks?: SecureFileWriteHooks,
    resetRemoveHooks?: SecureFileRemoveHooks,
  ): PersistedBridgeState {
    try {
      const migrationIntentPath = runtimeMigrationIntentPathForState(this.filePath);
      if (pathHasFilesystemEvidence(migrationIntentPath)) {
        const resumed = resumeRuntimeMigration({ filePath: this.filePath }, hostId, resetStep, resetWriteHooks, resetRemoveHooks);
        return parseCurrentState(resumed, hostId);
      }
      const floorPath = runtimeSchemaFloorPathForState(this.filePath);
      const floorBytes = readOptionalSecureBytes(floorPath);
      const floor = floorBytes ? parseRuntimeSchemaFloor(parseRawJson(floorBytes, 'Bridge runtime schema floor'), this.filePath, hostId) : undefined;
      const intentPath = runtimeResetIntentPathForState(this.filePath);
      if (pathHasFilesystemEvidence(intentPath)) {
        if (floor) throw new Error('Bridge runtime reset intent exists after the schema floor was established');
        const resumed = resumeRuntimeReset({ filePath: this.filePath }, hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
        if (resumed.schemaVersion === BRIDGE_RUNTIME_STATE_SCHEMA_VERSION) {
          return parseCurrentState(resumed, hostId);
        }
        return this.preflightRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
      }
      const stateBytes = readOptionalSecureBytes(this.filePath);
      const spoolPath = spoolPathForState(this.filePath);
      const spoolBytes = readOptionalSecureBytes(spoolPath);
      const stateRecord = parseRawJson(stateBytes, 'Bridge runtime state');
      const spoolRecord = parseRawJson(spoolBytes, 'Bridge runtime spool');
      if (floor) {
        if (!stateRecord || !spoolRecord || !isCurrentStateRecord(stateRecord)) {
          throw new Error('Bridge runtime artifacts violate the established schema floor');
        }
        const state = parseCurrentState(stateRecord, hostId);
        const spool = parseCurrentSpoolRecord(spoolRecord, hostId, state.runtimeResetEpoch);
        assertCurrentRuntimeRelationships(state, spool, hostId);
        return state;
      }
      if (stateRecord && isCurrentStateRecord(stateRecord)) {
        const state = parseCurrentState(stateRecord, hostId);
        if (!spoolRecord) throw new Error('current Bridge runtime spool is missing');
        const spool = parseCurrentSpoolRecord(spoolRecord, hostId, state.runtimeResetEpoch);
        assertCurrentRuntimeRelationships(state, spool, hostId);
        writeSecureJson(floorPath, runtimeSchemaFloor(this.filePath, hostId, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION), undefined, resetWriteHooks);
        return state;
      }
      if (stateRecord && spoolRecord && isPriorStateRecordV3(stateRecord, hostId)
        && isSpoolRecordForSchema(spoolRecord, PRIOR_RUNTIME_STATE_SCHEMA_VERSION, hostId, stateRecord.runtimeResetEpoch as string, 'current')) {
        beginRuntimeMigration(
          { filePath: this.filePath }, hostId, stateRecord, spoolRecord, stateBytes!, spoolBytes!, resetStep, resetWriteHooks, resetRemoveHooks,
        );
        // v3→v4 converges to the current schema4 + floor4; the recursive preflight
        // then opens it directly.
        return this.preflightRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
      }
      if (!stateRecord && !spoolRecord) {
        return this.initializeFreshRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
      }
      if (isRecognizedObsoleteRuntime(stateRecord, spoolRecord, hostId)) {
        beginRuntimeReset({ filePath: this.filePath }, hostId, keyStore, stateBytes, spoolBytes,
          OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, PRIOR_RUNTIME_STATE_SCHEMA_VERSION,
          resetStep, resetWriteHooks, resetRemoveHooks);
        return this.preflightRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
      }
      if (!isRecognizedLegacyRuntime(stateRecord, spoolRecord, hostId)) {
        throw new Error('Bridge runtime schema is unknown, malformed, or internally inconsistent');
      }
      beginRuntimeReset({ filePath: this.filePath }, hostId, keyStore, stateBytes, spoolBytes,
        LEGACY_RUNTIME_STATE_SCHEMA_VERSION, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION,
        resetStep, resetWriteHooks, resetRemoveHooks);
      return this.preflightRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
    } catch (error) {
      throw new Error('Bridge runtime preflight failed closed', { cause: error });
    }
  }
  private initializeFreshRuntime(
    hostId: string, keyStore: SpoolKeyStore, resetStep?: (phase: RuntimeResetPhase) => void,
    resetWriteHooks?: SecureFileWriteHooks,
    resetRemoveHooks?: SecureFileRemoveHooks,
  ): PersistedBridgeState {
    beginRuntimeReset({ filePath: this.filePath }, hostId, keyStore, undefined, undefined,
      OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, PRIOR_RUNTIME_STATE_SCHEMA_VERSION,
      resetStep, resetWriteHooks, resetRemoveHooks);
    return this.preflightRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
  }


  private assertRuntimeAccess(): void {
    assertStateStoreAccess(this.disposed, this.runtimeCoordinator);
  }
  dispose(): void {
    if (this.disposed) return;
    this.releaseStateWriter();
    if (this.ownsRuntimeCoordinator) this.runtimeCoordinator.dispose();
    this.disposed = true;
  }
  private persist(): void {
    this.assertRuntimeAccess();
    if (this.filePath) this.writeState(this.filePath, this.state);
  }
  private commit(nextState: PersistedBridgeState): void {
    this.assertRuntimeAccess();
    if (this.filePath) this.writeState(this.filePath, nextState);
    this.state = nextState;
  }
  private commitTransition<Result>(
    transition: (state: PersistedBridgeState) => StateTransition<Result>,
  ): Result {
    return commitState(
      { state: this.state, commit: (nextState) => this.commit(nextState) },
      transition,
    );
  }

  private applyTransition<Result>(transition: StateTransition<Result>): Result {
    if (transition.state !== this.state) {
      this.state = transition.state;
      this.persist();
    }
    return transition.result;
  }

  /** Narrow shell the cross-medium spool transaction workflows drive (§6.2). */
  private transactionShell(): spoolTransactions.SpoolTransactionShell {
    const store = this;
    return {
      get spool() { return store.spool; },
      filePath: this.filePath,
      readState: () => this.state,
      setState: (nextState) => { this.state = nextState; },
      persist: () => this.persist(),
      commit: (nextState) => this.commit(nextState),
      openSpoolJson: (itemId) => this.openSpoolJson(itemId),
      openProducerTuple: (kind, eventId, fingerprint) => this.openProducerTuple(kind, eventId, fingerprint),
      getProducerEventReservation: (sessionId, fingerprint) => this.getProducerEventReservation(sessionId, fingerprint),
      listPendingEventDescriptors: () => this.listPendingEventDescriptors(),
      openPendingEventSource: (descriptor) => this.openPendingEventSource(descriptor),
      commitSessionRevision: (sessionId, revision) => this.commitSessionRevision(sessionId, revision),
    };
  }
  private reconcileTerminalCancellations(): void {
    spoolTransactions.reconcileTerminalCancellations(this.transactionShell());
  }
  private reconcileProducerEventReservations(): void {
    spoolTransactions.reconcileProducerEventReservations(this.transactionShell());
  }
  private reconcilePendingEventJournal(): void {
    spoolTransactions.reconcilePendingEventJournal(this.transactionShell());
  }
  private resumeEventUploadCompletions(): void {
    spoolTransactions.resumeEventUploadCompletions(this.transactionShell());
  }

  setHost(host: HostProjection): void { this.applyTransition(setHostTransition(this.state, host)); }
  getHost(): HostProjection | null { return this.state.host; }

  getRuntimeHealth(): BridgeRuntimeHealth { return readRuntimeHealth(this.state); }
  recordDriverReconciliationFailure(driver: string, seenAt: string, nextRetryAt: string): DriverRuntimeHealth {
    return this.commitTransition((state) => recordDriverReconciliationFailureTransition(state, driver, seenAt, nextRetryAt));
  }
  recordDriverReconciliationSuccess(driver: string): { count: number } | undefined {
    return this.commitTransition((state) => recordDriverReconciliationSuccessTransition(state, driver));
  }
  recordRelayPresenceFailure(seenAt: string, nextRetryAt: string): void {
    this.commitTransition((state) => recordRelayPresenceFailureTransition(state, seenAt, nextRetryAt));
  }
  recordRelayPresenceSuccess(): { count: number } | undefined {
    return this.commitTransition((state) => recordRelayPresenceSuccessTransition(state));
  }

  replaceDriverSessions(driverName: string, sessions: CanonicalSessionState[]): void {
    this.commitTransition((state) => replaceDriverSessionsTransition(state, driverName, sessions));
  }
  listSessions(): CanonicalSessionState[] { return Object.values(this.state.sessions).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)); }
  hasReconciledDriver(driverName: string): boolean { return this.state.reconciledDrivers[driverName] === true; }
  getSession(sessionId: string): CanonicalSessionState | undefined { return this.state.sessions[sessionId]; }
  getDriverNameForSession(sessionId: string): string | undefined { return this.state.sessionDrivers[sessionId]; }
  setSessionDriver(sessionId: string, driverName: string, session?: CanonicalSessionState): void {
    this.commitTransition((state) => setSessionDriverTransition(state, sessionId, driverName, session));
  }
  removeSession(sessionId: string, expectedDriverName?: string): boolean {
    return this.commitTransition((state) => removeSessionTransition(state, sessionId, expectedDriverName));
  }
  removeSessionDriver(sessionId: string): void {
    this.commitTransition((state) => removeSessionDriverTransition(state, sessionId));
  }
  updateSession(sessionId: string, patch: Partial<CanonicalSessionState>): CanonicalSessionState | undefined {
    return this.applyTransition(updateSessionTransition(this.state, sessionId, patch));
  }

  async createCurrentSessionsPublication(hostId: string, sessions: CanonicalSessionState[], recipientSetVersion: number, observedAt: string, minimumRevision = 0): Promise<{ request: ReplaceE2ECurrentSessionsRequestV1; contentDigest: string } | undefined> {
    const contentDigest = await e2eCurrentSessionsSemanticDigestV1(hostId, sessions);
    return this.applyTransition(createCurrentSessionsPublicationTransition(this.state, {
      hostId, contentDigest, recipientSetVersion, observedAt, minimumRevision,
    }));
  }
  getCurrentSessionsSnapshotState(): PersistedCurrentSessionsSnapshotState { return structuredClone(this.state.currentSessionsSnapshot); }
  acceptCurrentSessionsPublication(request: ReplaceE2ECurrentSessionsRequestV1, digest: string, contentDigest: string): boolean {
    return this.applyTransition(acceptCurrentSessionsPublicationTransition(this.state, request, digest, contentDigest));
  }
  noteCurrentSessionsSnapshotRevisionLowerBound(revision: number): void {
    this.applyTransition(noteCurrentSessionsSnapshotRevisionLowerBoundTransition(this.state, revision));
  }
  getProducerEventReservation(sessionId: string, fingerprint: string): PersistedProducerEventReservationV1 | undefined {
    const reservation = this.state.producerEventReservations?.[producerReservationKey(sessionId, fingerprint)];
    return reservation && structuredClone(reservation);
  }
  reserveProducerEvent(reservation: PersistedProducerEventReservationV1): void {
    spoolTransactions.reserveProducerEvent(this.transactionShell(), reservation);
  }
  getProducerEventTuple(eventId: string, fingerprint: string): { event: CanonicalEvent; session: CanonicalSessionState } | undefined {
    return this.openProducerTuple('event-reservation-v3', eventId, fingerprint)
      ?? this.openProducerTuple('event-source-v3', eventId, fingerprint);
  }
  reserveProducerEventTuple(event: CanonicalEvent, terminalSession: CanonicalSessionState, fingerprint: string): void {
    spoolTransactions.reserveProducerEventTuple(this.transactionShell(), event, terminalSession, fingerprint);
  }
  getTerminalEventCancellation(sessionId: string): PersistedProducerEventReservationV1 | undefined {
    const reservation = Object.values(this.state.producerEventReservations ?? {}).find((candidate) => {
      if (candidate.sessionId !== sessionId) return false;
      return this.spool?.get(candidate.eventId)?.payloadKind === 'event-reservation-v3';
    });
    return reservation && structuredClone(reservation);
  }
  cancelTerminalEvent(input: { eventId: string; sessionId: string; fingerprint: string; removeSession?: boolean;
    nextDriverName?: string; createdAt?: string }): void {
    spoolTransactions.cancelTerminalEvent(this.transactionShell(), input);
  }

  appendRecentEvent(event: CanonicalEvent): void {
    this.commitTransition((state) => appendRecentEventTransition(state, event));
  }
  queuePendingEvent(event: CanonicalEvent, terminalSession: CanonicalSessionState, producerFingerprint?: string): void {
    spoolTransactions.queuePendingEvent(this.transactionShell(), event, terminalSession, producerFingerprint);
  }
  private openProducerTuple(kind: 'event-source-v3' | 'event-reservation-v3', eventId: string, fingerprint: string):
    { event: CanonicalEvent; session: CanonicalSessionState } | undefined {
    if (!this.spool) return undefined;
    const item = this.spool.list(kind).find((candidate) => candidate.eventId === eventId);
    if (!item) return undefined;
    const bytes = this.spool.open(item);
    try {
      const pending = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as {
        event: CanonicalEvent; session: CanonicalSessionState; producerFingerprint?: string;
      };
      assertEventSessionBinding(pending.event, pending.session);
      if (pending.producerFingerprint !== fingerprint) throw new TypeError('pending Event producer fingerprint is invalid');
      return { event: pending.event, session: pending.session };
    } finally { bytes.fill(0); }
  }
  peekPendingEvents(): CanonicalEvent[] {
    return this.peekPendingUploads().map(({ event }) => event);
  }
  peekPendingUploads(): Array<{ event: CanonicalEvent; session: CanonicalSessionState }> {
    return this.peekPendingUploadRecords().map(({ event, session }) => ({ event, session }));
  }
  private peekPendingUploadRecords(): Array<{ event: CanonicalEvent; session: CanonicalSessionState; producerFingerprint?: string }> {
    if (!this.spool) return [];
    return this.spool.list('event-source-v3')
      .filter((item) => !item.eventId || !this.state.terminalCancellations?.[item.eventId])
      .map((item) => { const bytes = this.spool!.open(item); try {
        const pending = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as {
          event: CanonicalEvent; session: CanonicalSessionState; producerFingerprint?: string;
        };
        assertEventSessionBinding(pending.event, pending.session);
        if (pending.producerFingerprint !== undefined && typeof pending.producerFingerprint !== 'string') {
          throw new TypeError('pending Event producer fingerprint is invalid');
        }
        return pending;
      } finally { bytes.fill(0); } });
  }
  cancelPendingEventRetry(eventId: string): void {
    if (!this.spool?.get(eventId)) return;
    if (this.state.recentEvents.some((event) => event.eventId === eventId)) return;
    this.spool.remove(eventId);
  }
  /**
   * §5.1 storage API: pending Event descriptors passing the current outer spool
   * schema/relationship preflight, in stable order, WITHOUT decoding payloads.
   */
  listPendingEventDescriptors(): PendingEventDescriptor[] {
    if (!this.spool) return [];
    return this.spool.list('event-source-v3')
      .filter((item) => !item.eventId || !this.state.terminalCancellations?.[item.eventId])
      .map((item) => ({ eventId: item.eventId ?? item.spoolItemId, sessionId: item.sessionId }));
  }

  /**
   * §4.5.5: every event-upload-v3 inflight item classified without opening the
   * source: 'v2' (already converted), 'legacy' (parseable raw upload), or
   * 'malformed' (unparseable/unsupported shape — byte-preserved, fail-closed).
   */
  listEventInflightRecords(): Array<{ eventId: string; sessionId: string; kind: 'v2' | 'legacy' | 'malformed' }> {
    if (!this.spool) return [];
    const records: Array<{ eventId: string; sessionId: string; kind: 'v2' | 'legacy' | 'malformed' }> = [];
    for (const item of this.spool.list('event-upload-v3')) {
      const eventId = item.eventId ?? item.spoolItemId.replace(/^inflight:event:/, '');
      let parsed: unknown;
      try { parsed = this.openSpoolJson(item.spoolItemId); } catch { parsed = undefined; }
      let kind: 'v2' | 'legacy' | 'malformed';
      if (isEventInflightRecordV2(parsed)) kind = 'v2';
      else if (isEncryptedEventUploadRecord(parsed)) kind = 'legacy';
      else kind = 'malformed';
      records.push({ eventId, sessionId: item.sessionId ?? '', kind });
    }
    return records;
  }


  /**
   * §5.1 storage API: open source and optional inflight for one descriptor and
   * return an exact discriminated result. Inflight is parsed first (§5.2 step 2):
   * a malformed inflight short-circuits to recovery-required. Spool AEAD / item
   * invariant failures propagate (fail-closed) and are never mapped to a
   * quarantine reason.
   */
  loadPendingEventParts(descriptor: PendingEventDescriptor): LoadPendingEventPartsResult {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const sourceResult = this.openPendingEventSource(descriptor);
    const inflightItem = this.spool.get(`inflight:event:${descriptor.eventId}`);
    let inflight: LoadedEventInflight | undefined;
    if (inflightItem) {
      const raw = this.spool.open(inflightItem);
      let text: string;
      try {
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); }
        catch { raw.fill(0); return { ok: false, reason: 'inflight-utf8-invalid' }; }
        let parsed: unknown;
        try { parsed = JSON.parse(text); } catch { raw.fill(0); return { ok: false, reason: 'inflight-json-invalid' }; }
        if (isEventInflightRecordV2(parsed)) {
          if (!uploadMatchesDescriptor(parsed.upload, descriptor)) {
            raw.fill(0); return { ok: false, reason: 'inflight-shape-invalid' };
          }
          inflight = { kind: 'v2', raw, sourceDigest: parsed.sourceDigest, upload: parsed.upload };
        } else if (isEncryptedEventUploadRecord(parsed)) {
          if (!uploadMatchesDescriptor(parsed as E2EEventAndSessionUploadV3, descriptor)) {
            raw.fill(0); return { ok: false, reason: 'inflight-shape-invalid' };
          }
          inflight = { kind: 'legacy', raw, upload: parsed as E2EEventAndSessionUploadV3 };
        } else {
          raw.fill(0); return { ok: false, reason: 'inflight-shape-invalid' };
        }
      } catch (error) {
        raw.fill(0);
        throw error;
      }
    }
    if (!sourceResult.ok) return { ok: false, reason: sourceResult.reason, inflight };
    return { ok: true, source: sourceResult.source, inflight };
  }

  /**
   * §5.1 storage API: atomic raw dead-letter that does NOT depend on parsing the
   * source JSON. Replaces the source (and the inflight only when its raw bytes
   * are proven uncommitted) with one `event-dead-letter-v3` item via a SINGLE
   * durable `spool.replace()`; no unrelated state persist follows.
   */
  quarantinePendingEventRaw(
    descriptor: PendingEventDescriptor,
    reasonCode: EventDeadLetterReasonCode,
    provenUncommittedInflight?: Uint8Array,
    quarantinedAt = new Date().toISOString(),
  ): boolean {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const sourceItem = this.spool.get(descriptor.eventId);
    if (!sourceItem) return false;
    const inflightItem = this.spool.get(`inflight:event:${descriptor.eventId}`);
    if (inflightItem && !provenUncommittedInflight) {
      throw new TypeError('pending Event inflight must be proven uncommitted before quarantine');
    }
    let currentInflight: Uint8Array | undefined;
    if (inflightItem) {
      currentInflight = this.spool.open(inflightItem);
      if (!provenUncommittedInflight || !equalBytes(currentInflight, provenUncommittedInflight)) {
        currentInflight.fill(0);
        throw new TypeError('pending Event inflight evidence changed before quarantine');
      }
    }
    const sourceRaw = this.spool.open(sourceItem);
    try {
      const record: EventDeadLetterRecordV2 = {
        version: 2,
        eventId: descriptor.eventId,
        sessionId: descriptor.sessionId,
        reasonCode,
        quarantinedAt,
        sourceArchive: { encoding: 'base64url', bytes: base64UrlEncode(sourceRaw) },
        ...(provenUncommittedInflight ? { inflightArchive: { encoding: 'base64url', bytes: base64UrlEncode(provenUncommittedInflight) } } : {}),
      };
      this.spool.replace(
        [descriptor.eventId, `inflight:event:${descriptor.eventId}`],
        [{ spoolItemId: `dead-letter:event:${descriptor.eventId}`, sessionId: descriptor.sessionId, eventId: descriptor.eventId,
          payloadKind: 'event-dead-letter-v3', createdAt: quarantinedAt,
          plaintext: new TextEncoder().encode(JSON.stringify(record)) }],
      );
      return true;
    } finally {
      sourceRaw.fill(0);
      currentInflight?.fill(0);
      provenUncommittedInflight?.fill(0);
    }
  }

  hasEventUploadCompletion(eventId: string): boolean {
    return this.state.eventUploadCompletions?.[eventId] !== undefined;
  }

  private openPendingEventSource(
    descriptor: PendingEventDescriptor,
  ): { ok: true; source: PendingEventSource } | { ok: false; reason: 'source-utf8-invalid' | 'source-json-invalid' | 'source-shape-invalid' | 'source-binding-invalid' | 'source-missing' } {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const item = this.spool.get(descriptor.eventId);
    if (!item) return { ok: false, reason: 'source-missing' };
    const raw = this.spool.open(item);
    try {
      let text: string;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); }
      catch { return { ok: false, reason: 'source-utf8-invalid' }; }
      let parsed: unknown;
      try { parsed = JSON.parse(text); } catch { return { ok: false, reason: 'source-json-invalid' }; }
      // §5.2 exact canonical shape: unknown fields, wrong types, or a broken
      // type/status/needHuman invariant are NOT silently stripped — the tuple
      // is rejected as shape-invalid and handled by the dead-letter/recovery path.
      if (!isRecord(parsed) || !hasExactOptionalKeys(parsed, ['event', 'session'], ['producerFingerprint'])
        || !isCanonicalEventShape(parsed.event) || !isCanonicalSessionShape(parsed.session)) {
        return { ok: false, reason: 'source-shape-invalid' };
      }
      try {
        assertEventSessionBinding(parsed.event as CanonicalEvent, parsed.session as CanonicalSessionState);
      } catch {
        return { ok: false, reason: 'source-binding-invalid' };
      }
      // §5.2: the decoded tuple must also be bound to the OUTER spool descriptor;
      // an internally valid tuple B under descriptor A must never be published or
      // journaled under A's identity.
      if ((parsed.event as CanonicalEvent).eventId !== descriptor.eventId
        || (parsed.session as CanonicalSessionState).sessionId !== descriptor.sessionId) {
        return { ok: false, reason: 'source-binding-invalid' };
      }
      if (parsed.producerFingerprint !== undefined && typeof parsed.producerFingerprint !== 'string') {
        return { ok: false, reason: 'source-json-invalid' };
      }
      return {
        ok: true,
        source: {
          event: parsed.event as CanonicalEvent,
          session: parsed.session as CanonicalSessionState,
          ...(typeof parsed.producerFingerprint === 'string' ? { producerFingerprint: parsed.producerFingerprint } : {}),
        },
      };
    } finally { raw.fill(0); }
  }

  openInflightEventRaw(eventId: string): Uint8Array | undefined {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const item = this.spool.get(`inflight:event:${eventId}`);
    return item ? this.spool.open(item) : undefined;
  }

  getInflightEventUpload(eventId: string): unknown | undefined {
    let parsed: unknown;
    try { parsed = this.openSpoolJson(`inflight:event:${eventId}`); } catch { return undefined; }
    if (parsed === undefined) return undefined;
    return isEventInflightRecordV2(parsed) ? parsed.upload : parsed;
  }
  persistInflightEventUpload(eventId: string, sessionId: string, upload: unknown, sourceDigest?: string): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const record = withSourceDigestWrapper(upload, sourceDigest);
    this.spool.enqueue({ spoolItemId: `inflight:event:${eventId}`, sessionId, eventId, payloadKind: 'event-upload-v3',
      createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(record)) });
  }
  replaceInflightEventUpload(eventId: string, sessionId: string, upload: unknown, sourceDigest?: string): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const record = withSourceDigestWrapper(upload, sourceDigest);
    this.spool.replace([`inflight:event:${eventId}`], [{ spoolItemId: `inflight:event:${eventId}`, sessionId, eventId,
      payloadKind: 'event-upload-v3', createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(record)) }]);
  }
  removeInflightEventUpload(eventId: string): void { this.spool?.remove(`inflight:event:${eventId}`); }
  listInflightSessionIds(): string[] { return this.spool?.list('session-upload-v3').map((item) => item.sessionId) ?? []; }
  getInflightSessionUpload(sessionId: string): unknown | undefined {
    const lookup = this.getSessionInflightLookup(sessionId);
    if (lookup.kind === 'missing') return undefined;
    if (lookup.kind === 'v2' || lookup.kind === 'legacy') return lookup.upload;
    // §4.4/§5.1: malformed or cross-bound evidence must never be silently
    // rebuilt over; the publication flow fails closed so recovery surfaces it.
    throw new TypeError('Session inflight evidence is malformed or cross-bound (recovery required)');
  }
  /**
   * §5.1: discriminated Session inflight lookup. `malformed` (unparseable or
   * non-shape bytes) and `cross-bound` (inner sessionId != outer spool key)
   * stay byte-preserved and fail closed; `v2`/`legacy` are the usable forms.
   */
  getSessionInflightLookup(sessionId: string): SessionInflightLookup {
    let parsed: unknown;
    try { parsed = this.openSpoolJson(`inflight:session:${sessionId}`); } catch { return { kind: 'malformed' }; }
    if (parsed === undefined) return { kind: 'missing' };
    if (isSessionInflightRecordV2(parsed)) {
      const upload = (parsed as SessionInflightRecordV2).upload;
      return upload.sessionId === sessionId ? { kind: 'v2', upload } : { kind: 'cross-bound', upload };
    }
    if (isEncryptedSessionUploadShape(parsed)) {
      const upload = parsed as unknown as EncryptedSessionSnapshotUploadV3;
      return upload.sessionId === sessionId ? { kind: 'legacy', upload } : { kind: 'cross-bound', upload };
    }
    return { kind: 'malformed' };
  }
  /**
   * §6.1/§4.4: returns the V2 source-digest wrapper for an existing Session inflight
   * so the publication flow can prove whether the inflight matches the immutable
   * current source before reuse or rebuild. Legacy (unwrapped) records and malformed
   * bytes return undefined; the legacy raw record stays byte-preserved.
   */
  getSessionInflightRecordV2(sessionId: string): SessionInflightRecordV2 | undefined {
    let parsed: unknown;
    try { parsed = this.openSpoolJson(`inflight:session:${sessionId}`); } catch { return undefined; }
    if (parsed === undefined || !isSessionInflightRecordV2(parsed)) return undefined;
    return parsed as SessionInflightRecordV2;
  }
  /**
   * §4.5.5 online conversion: returns the session inflight upload only when the
   * persisted record is still the legacy raw form (no V2 source-digest wrapper).
   * Malformed records return undefined and stay byte-preserved (recovery-required
   * surfaces through the normal flows); the V2 wrapper is never returned here.
   */
  getLegacyInflightSessionUpload(sessionId: string): EncryptedSessionSnapshotUploadV3 | undefined {
    const lookup = this.getSessionInflightLookup(sessionId);
    return lookup.kind === 'legacy' ? lookup.upload : undefined;
  }
  persistInflightSessionUpload(sessionId: string, upload: unknown, sourceDigest?: string): void {
    this.assertSessionUploadBoundTo(sessionId, upload);
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const record = withSourceDigestWrapper(upload, sourceDigest);
    this.spool.enqueue({ spoolItemId: `inflight:session:${sessionId}`, sessionId, payloadKind: 'session-upload-v3',
      createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(record)) });
  }
  replaceInflightSessionUpload(sessionId: string, upload: unknown, sourceDigest?: string): void {
    this.assertSessionUploadBoundTo(sessionId, upload);
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const record = withSourceDigestWrapper(upload, sourceDigest);
    this.spool.replace([`inflight:session:${sessionId}`], [{ spoolItemId: `inflight:session:${sessionId}`, sessionId,
      payloadKind: 'session-upload-v3', createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(record)) }]);
  }
  /** §4.4/§5.1: an inflight upload written under `sessionId` must carry the same
   * inner sessionId — a cross-bound write is a local invariant violation and
   * fails closed instead of corrupting the evidence cursor. */
  private assertSessionUploadBoundTo(sessionId: string, upload: unknown): void {
    if (isRecord(upload) && typeof upload.sessionId === 'string' && upload.sessionId !== sessionId) {
      throw new TypeError('Session inflight upload is bound to a different Session');
    }
  }
  removeInflightSessionUpload(sessionId: string): void { this.spool?.remove(`inflight:session:${sessionId}`); }

  private openSpoolJson(itemId: string): unknown | undefined {
    const item = this.spool?.get(itemId); if (!item) return undefined; const bytes = this.spool!.open(item);
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } finally { bytes.fill(0); }
  }
  removePendingEvent(eventId: string): void {
    this.spool?.remove(eventId);
    this.persist();
  }
  quarantinePendingEvent(eventId: string, sessionId: string, reason: string, quarantinedAt = new Date().toISOString()): boolean {
    if (!this.spool) return false;
    const source = this.openSpoolJson(eventId);
    if (!source) return false;

    const inflightItemId = `inflight:event:${eventId}`;
    const inflight = this.openSpoolJson(inflightItemId);
    const record = {
      version: 1 as const,
      eventId,
      sessionId,
      reason,
      quarantinedAt,
      source,
      ...(inflight ? { inflight } : {}),
    };
    this.spool.replace([eventId, inflightItemId], [{
      spoolItemId: `dead-letter:event:${eventId}`,
      sessionId,
      eventId,
      payloadKind: 'event-dead-letter-v3',
      createdAt: quarantinedAt,
      plaintext: new TextEncoder().encode(JSON.stringify(record)),
    }]);
    this.persist();
    return true;
  }
  getQuarantinedEventRecord(eventId: string): unknown | undefined { return this.openSpoolJson(`dead-letter:event:${eventId}`); }
  currentSessionRevision(sessionId: string): number { return readCurrentSessionRevision(this.state, sessionId); }
  nextSessionRevision(sessionId: string): number { return readNextSessionRevision(this.state, sessionId); }
  commitSessionRevision(sessionId: string, revision: number): void {
    this.applyTransition(commitSessionRevisionTransition(this.state, sessionId, revision));
  }
  beginEventUploadCompletion(completion: EventUploadCompletionV1): void {
    spoolTransactions.beginEventUploadCompletion(this.transactionShell(), completion);
  }
  completeEventUpload(eventId: string, step?: (phase: 'revision-committed' | 'inflight-removed' | 'source-removed' | 'journal-removed') => void): void {
    spoolTransactions.completeEventUpload(this.transactionShell(), eventId, step);
  }
  getRecipientSetVersion(): number | undefined { return this.state.recipientSetVersion; }
  setRecipientSetVersion(version: number): void {
    this.applyTransition(setRecipientSetVersionTransition(this.state, version));
  }
  queuePendingSessionHandle(handle: PendingSessionHandle): void {
    this.commitTransition((state) => queuePendingSessionHandleTransition(state, handle));
  }
  peekPendingSessionHandles(): PendingSessionHandle[] { return Object.values(this.state.pendingHandles); }
  removePendingSessionHandle(hostId: string, sessionId: string, handledThroughEventId?: string): void {
    this.commitTransition((state) => removePendingSessionHandleTransition(state, hostId, sessionId, handledThroughEventId));
  }
  getCommandExecution(commandId: string): PersistedCommandExecutionV4 | undefined {
    const execution = this.state.commandExecutions[commandId];
    return execution ? structuredClone(execution) : undefined;
  }
  listCommandExecutions(): PersistedCommandExecutionV4[] {
    return Object.values(this.state.commandExecutions).map((execution) => structuredClone(execution));
  }
  commandExecutionPinRetentionReferences(): import('./e2e/link-keyring').PinRetentionReferences {
    return readCommandExecutionPinRetentionReferences(this.state);
  }
  durableContentPinRetentionReferences(retainThrough: string): import('./e2e/link-keyring').PinRetentionReferences {
    if (!isCanonicalTimestamp(retainThrough)) throw new TypeError('content retention cutoff is invalid');
    const contentRetainedThrough: Record<string, string> = {};
    const uploads = [
      ...this.peekPendingUploads(),
      ...this.state.recentEvents.flatMap((event) => [this.getInflightEventUpload(event.eventId)]),
      ...this.listInflightSessionIds().map((sessionId) => {
        // §4.4/§5.1: malformed/cross-bound evidence must not break retention
        // pinning; it contributes no decryptable upload references.
        const lookup = this.getSessionInflightLookup(sessionId);
        return lookup.kind === 'v2' || lookup.kind === 'legacy' ? lookup.upload : undefined;
      }),
    ];
    for (const upload of uploads) collectEncryptedUploadPinReferences(upload, contentRetainedThrough, retainThrough);
    return Object.keys(contentRetainedThrough).length === 0 ? {} : { contentRetainedThrough };
  }
  pruneEligibleCommandExecutions(now: string): PersistedCommandExecutionV4[] {
    return this.commitTransition((state) => pruneEligibleCommandExecutionsTransition(state, now));
  }
  validateCommandExecutionPins(
    resolver: CommandExecutionPinResolver,
    options: { allowUnavailableForTerminal?: boolean } = {},
  ): void {
    validateCommandExecutionPinsState(this.state, resolver, options);
    this.commandExecutionPinsReady = true;
  }
  claimCommandExecution(input: {
    originalEncryptedCommand: EncryptedCommandEnvelopeV1; commandDigest: string;
    pinReference: PersistedCommandPinReferenceV1; claimedAt: string;
  }): { status: 'claimed' | 'duplicate'; execution: PersistedCommandExecutionV4 } | { status: 'conflict' } {
    this.assertCommandExecutionPinsReady();
    return this.commitTransition((state) => claimCommandExecutionTransition(state, input));
  }
  markCommandDispatchStarted(commandId: string, dispatchStartedAt: string): PersistedCommandExecutionV4 {
    this.assertCommandExecutionPinsReady();
    return this.commitTransition((state) => markCommandDispatchStartedTransition(state, commandId, dispatchStartedAt));
  }
  recoverOrphanedCommandExecutions(): number {
    this.assertCommandExecutionPinsReady();
    return this.commitTransition((state) => recoverOrphanedCommandExecutionsTransition(state));
  }
  markCommandOutcomeUnknown(commandId: string): PersistedCommandExecutionV4 {
    this.assertCommandExecutionPinsReady();
    return this.commitTransition((state) => markCommandOutcomeUnknownTransition(state, commandId));
  }
  persistTerminalReceiptBlocked(commandId: string, terminalResult: CommandResult): PersistedCommandExecutionV4 {
    this.assertCommandExecutionPinsReady();
    return this.commitTransition((state) => persistTerminalReceiptBlockedTransition(state, commandId, terminalResult));
  }
  persistTerminalCommandReceipt(
    commandId: string, terminalResult: CommandResult, outbox: CommandReceiptOutboxInputV1,
  ): PersistedCommandExecutionV4 {
    this.assertCommandExecutionPinsReady();
    return this.commitTransition((state) => persistTerminalCommandReceiptTransition(state, commandId, terminalResult, outbox));
  }
  markCommandReceiptOutbox(commandId: string, state: 'acknowledged' | 'undeliverable'): PersistedCommandExecutionV4 {
    this.assertCommandExecutionPinsReady();
    return this.commitTransition((current) => markCommandReceiptOutboxTransition(current, commandId, state));
  }
  private assertCommandExecutionPinsReady(): void {
    if (!this.commandExecutionPinsReady) {
      throw new Error('Bridge runtime command execution pins are unavailable before startup validation');
    }
  }
}
