import { createHash, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import {
  pathHasFilesystemEvidence,
  readSecureFile,
  readSecureJson,
  removeSecureFile,
  writeSecureJson,
  writeSecureJsonExclusive,
  type SecureFileWriteHooks,
  type SecureFileRemoveHooks,
} from './host-manager/secure-files';
import type {
  CanonicalEvent, CanonicalSessionState, CommandResult, E2EEventAndSessionUploadV3, EncryptedCommandEnvelopeV1,
  EncryptedSessionSnapshotUploadV3, HostProjection, ReplaceE2ECurrentSessionsRequestV1,
} from '@ariava/protocol';
import {
  base64UrlDecode, base64UrlEncode, e2eCurrentSessionsSemanticDigestV1, isCanonicalTimestamp,
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
  PersistedTerminalCancellationV1,
} from './types';
import {
  LocalEncryptedSpool,
  createRuntimeSpoolKeyStore,
  isRecognizedLocalSpoolPayloadKind,
  spoolKeyIdForKey,
  spoolPathForState,
  type LocalSpoolFileV2,
  type SpoolKeyStore,
} from './e2e/local-spool';
import {
  acquireRuntimeCoordinator,
  assertRuntimeCoordinatorPaths,
  assertRuntimeWriterAllowed,
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
import { appendRecentEventTransition, reserveProducerEventTransition } from './state-store/event-transitions';
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
  assertCommandExecution,
  emptyState,
  isNonEmptyString,
  isPositiveSafeInteger,
  isRecord,
  isVerifier,
  producerReservationKey,
} from './state-store/state-codec';
import { loadCurrentOrFresh as loadFreshState } from './state-store/runtime-lifecycle';

export { BRIDGE_RUNTIME_STATE_SCHEMA_VERSION, emptyState };
export { COMMAND_RECEIPT_RETENTION_DAYS, COMMAND_RECEIPT_RETENTION_MS } from './state-store/command-transitions';
export type { CommandExecutionPinResolver };

export const PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION = 4 as const;
const PRIOR_RUNTIME_STATE_SCHEMA_VERSION = 3 as const;
const OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION = 2 as const;
const LEGACY_RUNTIME_STATE_SCHEMA_VERSION = 1 as const;
const RESET_INTENT_VERSION = 1 as const;
const MIGRATION_INTENT_VERSION = 1 as const;
const MIGRATION_INTENT_V2_VERSION = 2 as const;
const ABSENT_HASH = 'absent';
const PRIOR_V2_SPOOL_KINDS = new Set([
  'event-source-v2', 'event-reservation-v2', 'event-dead-letter-v2', 'session-source-v2',
  'event-upload-v2', 'session-upload-v2', 'terminal-cancellation-v2',
]);
const MAX_RECENT_EVENTS = 200;

interface RuntimeResetIntentV1 {
  version: 1;
  fromSchemaVersion: 1 | 2;
  toSchemaVersion: 2 | 3;
  hostId: string;
  epoch: string;
  keyId: string;
  statePath: string;
  spoolPath: string;
  intentPath: string;
  stateSourceHash: string;
  spoolSourceHash: string;
  stateTargetHash: string;
  spoolTargetHash: string;
  createdAt: string;
}

/** Schema 4 Bridge runtime state: identical shape to schema 5, only the version literal differs. */
export type PriorV4BridgeState = Omit<PersistedBridgeState, 'schemaVersion'> & { schemaVersion: 4 };

interface RuntimeSchemaFloorV1 {
  version: 1;
  hostId: string;
  minSchemaVersion: 4 | 5;
  statePath: string;
  spoolPath: string;
}

interface RuntimeMigrationIntentV1 {
  version: 1;
  fromSchemaVersion: 3;
  toSchemaVersion: 4;
  hostId: string;
  statePath: string;
  spoolPath: string;
  floorPath: string;
  intentPath: string;
  stateSourceHash: string;
  spoolSourceHash: string;
  floorSourceHash: string;
  stateTargetHash: string;
  spoolTargetHash: string;
  floorTargetHash: string;
  stateTarget: PriorV4BridgeState;
  spoolTarget: LocalSpoolFileV2;
  floorTarget: RuntimeSchemaFloorV1;
  createdAt: string;
}

/** v4→v5 two-phase migration intent (§4.5): hash-bound exact evidence written
 * atomically (temp + fsync + exclusive rename) so a crash never leaves a
 * partial intent; recovery proceeds from the intent only. The offline targets
 * bump only the state schema version and the spool outer runtime schema while
 * byte-preserving every schema4 spool item. */
interface RuntimeMigrationIntentV2 {
  version: 2;
  fromSchemaVersion: 4;
  toSchemaVersion: 5;
  hostId: string;
  statePath: string;
  spoolPath: string;
  floorPath: string;
  intentPath: string;
  stateSourceHash: string;
  spoolSourceHash: string;
  floorSourceHash: string;
  stateTargetHash: string;
  spoolTargetHash: string;
  floorTargetHash: string;
  stateTarget: PersistedBridgeState;
  spoolTarget: LocalSpoolFileV2;
  floorTarget: RuntimeSchemaFloorV1;
  createdAt: string;
}

type RuntimeResetPhase = 'before-intent' | 'after-intent' | 'after-spool' | 'after-state' | 'after-cleanup';
type RuntimeRecoveryPhase = 'after-unreadable-recovery';
export interface BridgeStateStoreOptions { deferRuntimePreflight?: boolean; runtimeCoordinator?: RuntimeCoordinator }
export interface RuntimeResetHooks {
  write?: SecureFileWriteHooks;
  remove?: SecureFileRemoveHooks;
  recoveryStep?: (phase: RuntimeRecoveryPhase) => void;
}

/** Minimal descriptor for one pending Event source item (§5.1); no payload decode. */
export interface PendingEventDescriptor {
  eventId: string;
  sessionId: string;
}

/** Decoded pending Event source tuple (§5.2 step 4). */
export interface PendingEventSource {
  event: CanonicalEvent;
  session: CanonicalSessionState;
  producerFingerprint?: string;
}

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
    this.runtimeCoordinator = options.runtimeCoordinator
      ?? acquireRuntimeCoordinator(filePath || undefined, filePath ? spoolPathForState(filePath) : undefined);
    assertRuntimeCoordinatorPaths(this.runtimeCoordinator, filePath || undefined, filePath ? spoolPathForState(filePath) : undefined);
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
        const resumed = this.resumeRuntimeMigration(hostId, resetStep, resetWriteHooks, resetRemoveHooks);
        if (resumed.schemaVersion === BRIDGE_RUNTIME_STATE_SCHEMA_VERSION) {
          return parseCurrentState(resumed, hostId);
        }
        // A resumed v3→v4 intent converges to schema4; continue to the v4→v5
        // migration (§4.5: v3→v4 completes strictly before the independent v4→v5
        // intent is evaluated).
        return this.preflightRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
      }
      const floorPath = runtimeSchemaFloorPathForState(this.filePath);
      const floorBytes = readOptionalSecureBytes(floorPath);
      const floor = floorBytes ? parseRuntimeSchemaFloor(parseRawJson(floorBytes, 'Bridge runtime schema floor'), this.filePath, hostId) : undefined;
      const intentPath = runtimeResetIntentPathForState(this.filePath);
      if (pathHasFilesystemEvidence(intentPath)) {
        if (floor) throw new Error('Bridge runtime reset intent exists after the schema floor was established');
        const resumed = this.resumeRuntimeReset(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
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
        if (floor.minSchemaVersion === PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION) {
          // Established floor4: only an exact verified schema4 runtime may continue,
          // and it must now migrate to schema5 (§4.5 allowed source: verified
          // schema4/floor4). Everything else violates the established floor.
          if (!stateRecord || !spoolRecord || !isPriorStateRecordV4(stateRecord, hostId)
            || !isSpoolRecordForSchema(spoolRecord, PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION, hostId,
              stateRecord.runtimeResetEpoch as string, 'current')) {
            throw new Error('Bridge runtime artifacts violate the established schema floor');
          }
          return this.beginRuntimeMigrationV4ToV5(
            hostId, stateRecord, spoolRecord, floorBytes, stateBytes!, spoolBytes!, resetStep, resetWriteHooks, resetRemoveHooks,
          );
        }
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
      if (stateRecord && spoolRecord && isPriorStateRecordV4(stateRecord, hostId)
        && isSpoolRecordForSchema(spoolRecord, PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION, hostId,
          stateRecord.runtimeResetEpoch as string, 'current')) {
        // Schema4 runtime without an established floor (defensive): begin the
        // independent v4→v5 intent with an absent floor source.
        return this.beginRuntimeMigrationV4ToV5(
          hostId, stateRecord, spoolRecord, undefined, stateBytes!, spoolBytes!, resetStep, resetWriteHooks, resetRemoveHooks,
        );
      }
      if (stateRecord && spoolRecord && isPriorStateRecordV3(stateRecord, hostId)
        && isSpoolRecordForSchema(spoolRecord, PRIOR_RUNTIME_STATE_SCHEMA_VERSION, hostId, stateRecord.runtimeResetEpoch as string, 'current')) {
        this.beginRuntimeMigration(
          hostId, stateRecord, spoolRecord, stateBytes!, spoolBytes!, resetStep, resetWriteHooks, resetRemoveHooks,
        );
        // v3→v4 converges to schema4 + floor4; the chain continues with the
        // independent v4→v5 migration. Never merge 3→5 into one un-reviewed step.
        return this.preflightRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
      }
      if (!stateRecord && !spoolRecord) {
        return this.initializeFreshRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
      }
      if (isRecognizedObsoleteRuntime(stateRecord, spoolRecord, hostId)) {
        this.beginRuntimeReset(hostId, keyStore, stateBytes, spoolBytes,
          OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, PRIOR_RUNTIME_STATE_SCHEMA_VERSION,
          resetStep, resetWriteHooks, resetRemoveHooks);
        return this.preflightRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
      }
      if (!isRecognizedLegacyRuntime(stateRecord, spoolRecord, hostId)) {
        throw new Error('Bridge runtime schema is unknown, malformed, or internally inconsistent');
      }
      this.beginRuntimeReset(hostId, keyStore, stateBytes, spoolBytes,
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
    this.beginRuntimeReset(hostId, keyStore, undefined, undefined,
      OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, PRIOR_RUNTIME_STATE_SCHEMA_VERSION,
      resetStep, resetWriteHooks, resetRemoveHooks);
    return this.preflightRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
  }

  private beginRuntimeReset(
    hostId: string, keyStore: SpoolKeyStore, stateSource: Buffer | undefined, spoolSource: Buffer | undefined,
    fromSchemaVersion: 1 | 2, toSchemaVersion: 2 | 3,
    resetStep?: (phase: RuntimeResetPhase) => void,
    resetWriteHooks?: SecureFileWriteHooks,
    resetRemoveHooks?: SecureFileRemoveHooks,
  ): Record<string, unknown> {
    resetStep?.('before-intent');
    const key = keyStore.loadOrCreate(hostId, { allowCreate: spoolSource === undefined });
    let keyId: string;
    try { keyId = spoolKeyIdForKey(key); } finally { key.fill(0); }
    const priorSpool = parseRawJson(spoolSource, 'Bridge runtime spool');
    if (priorSpool && priorSpool.version === 2 && priorSpool.keyId !== keyId) {
      throw new Error('Bridge runtime spool key mismatch');
    }
    const epoch = randomUUID();
    const stateTarget = emptyStateForSchema(toSchemaVersion, epoch);
    const spoolTarget = spoolFileForSchema(toSchemaVersion, hostId, epoch, keyId);
    const statePath = resolve(this.filePath);
    const spoolPath = resolve(spoolPathForState(this.filePath));
    const intentPath = resolve(runtimeResetIntentPathForState(this.filePath));
    const intent: RuntimeResetIntentV1 = {
      version: RESET_INTENT_VERSION, fromSchemaVersion, toSchemaVersion, hostId, epoch, keyId,
      statePath, spoolPath, intentPath,
      stateSourceHash: hashOptional(stateSource), spoolSourceHash: hashOptional(spoolSource),
      stateTargetHash: hashBytes(serializeSecureJson(stateTarget)), spoolTargetHash: hashBytes(serializeSecureJson(spoolTarget)),
      createdAt: new Date().toISOString(),
    };
    writeSecureJsonExclusive(intentPath, intent, undefined, resetWriteHooks);
    resetStep?.('after-intent');
    return this.finishRuntimeReset(intent, stateTarget, spoolTarget, resetStep, resetWriteHooks, resetRemoveHooks);
  }

  private resumeRuntimeReset(
    hostId: string, keyStore: SpoolKeyStore, resetStep?: (phase: RuntimeResetPhase) => void,
    resetWriteHooks?: SecureFileWriteHooks,
    resetRemoveHooks?: SecureFileRemoveHooks,
  ): Record<string, unknown> {
    const intent = parseResetIntent(readSecureJson<unknown>(runtimeResetIntentPathForState(this.filePath)));
    if (intent.hostId !== hostId) throw new Error('Bridge runtime reset intent Host mismatch');
    assertResetIntentPaths(intent, this.filePath);
    const stateTarget = emptyStateForSchema(intent.toSchemaVersion, intent.epoch);
    const spoolTarget = spoolFileForSchema(intent.toSchemaVersion, hostId, intent.epoch, intent.keyId);
    assertRuntimeResetTargets(intent, stateTarget, spoolTarget);
    this.assertRuntimeResetMembers(intent, hostId, stateTarget, spoolTarget);
    const key = keyStore.loadOrCreate(hostId, { allowCreate: false });
    try {
      if (spoolKeyIdForKey(key) !== intent.keyId) throw new Error('Bridge runtime reset intent key mismatch');
    } finally { key.fill(0); }
    return this.finishRuntimeReset(intent, stateTarget, spoolTarget, resetStep, resetWriteHooks, resetRemoveHooks);
  }

  private assertRuntimeResetMembers(
    intent: RuntimeResetIntentV1, hostId: string, stateTarget: Record<string, unknown>, spoolTarget: LocalSpoolFileV2,
  ): { stateBytes: Buffer | undefined; spoolBytes: Buffer | undefined } {
    const stateBytes = readOptionalSecureBytes(this.filePath);
    const spoolBytes = readOptionalSecureBytes(spoolPathForState(this.filePath));
    assertResetStateMember(stateBytes, intent, hostId, stateTarget);
    assertResetSpoolMember(spoolBytes, intent, hostId, spoolTarget);
    if (hashOptional(stateBytes) === intent.stateSourceHash && hashOptional(spoolBytes) === intent.spoolSourceHash
      && stateBytes && spoolBytes) {
      const state = parseRawJson(stateBytes, 'Bridge runtime reset state source');
      const spool = parseRawJson(spoolBytes, 'Bridge runtime reset spool source');
      if (!state || !spool || !hasResetSourceRelationships(intent, state, spool, hostId)) {
        throw new Error('Bridge runtime reset source relationships are invalid');
      }
    }
    return { stateBytes, spoolBytes };
  }

  private finishRuntimeReset(
    intent: RuntimeResetIntentV1, stateTarget: Record<string, unknown>, spoolTarget: LocalSpoolFileV2,
    resetStep?: (phase: RuntimeResetPhase) => void,
    resetWriteHooks?: SecureFileWriteHooks,
    resetRemoveHooks?: SecureFileRemoveHooks,
  ): Record<string, unknown> {
    assertRuntimeResetTargets(intent, stateTarget, spoolTarget);
    const { stateBytes, spoolBytes } = this.assertRuntimeResetMembers(intent, intent.hostId, stateTarget, spoolTarget);
    if (hashOptional(spoolBytes) !== intent.spoolTargetHash) {
      writeSecureJson(spoolPathForState(this.filePath), spoolTarget, undefined, resetWriteHooks);
    }
    resetStep?.('after-spool');
    if (hashOptional(stateBytes) !== intent.stateTargetHash) writeSecureJson(this.filePath, stateTarget, undefined, resetWriteHooks);
    resetStep?.('after-state');
    removeSecureFile(runtimeResetIntentPathForState(this.filePath), undefined, resetRemoveHooks);
    resetStep?.('after-cleanup');
    return stateTarget;
  }

  private beginRuntimeMigration(
    hostId: string, stateSource: Record<string, unknown>, spoolSource: Record<string, unknown>,
    stateSourceBytes: Buffer, spoolSourceBytes: Buffer, resetStep?: (phase: RuntimeResetPhase) => void,
    writeHooks?: SecureFileWriteHooks, removeHooks?: SecureFileRemoveHooks,
  ): PriorV4BridgeState {
    const stateTarget = migrateStateV3ToV4(stateSource, hostId);
    const spoolTarget = migrateSpoolV3ToV4(spoolSource, hostId, stateTarget.runtimeResetEpoch);
    const floorTarget = runtimeSchemaFloor(this.filePath, hostId, PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION);
    const intent: RuntimeMigrationIntentV1 = {
      version: MIGRATION_INTENT_VERSION, fromSchemaVersion: PRIOR_RUNTIME_STATE_SCHEMA_VERSION,
      toSchemaVersion: PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION, hostId,
      statePath: resolve(this.filePath), spoolPath: resolve(spoolPathForState(this.filePath)),
      floorPath: resolve(runtimeSchemaFloorPathForState(this.filePath)),
      intentPath: resolve(runtimeMigrationIntentPathForState(this.filePath)),
      stateSourceHash: hashBytes(stateSourceBytes), spoolSourceHash: hashBytes(spoolSourceBytes), floorSourceHash: ABSENT_HASH,
      stateTargetHash: hashBytes(serializeSecureJson(stateTarget)), spoolTargetHash: hashBytes(serializeSecureJson(spoolTarget)),
      floorTargetHash: hashBytes(serializeSecureJson(floorTarget)), stateTarget, spoolTarget, floorTarget,
      createdAt: new Date().toISOString(),
    };
    resetStep?.('before-intent');
    writeSecureJsonExclusive(intent.intentPath, intent, undefined, writeHooks);
    resetStep?.('after-intent');
    return this.finishRuntimeMigration(intent, resetStep, writeHooks, removeHooks);
  }
  private resumeRuntimeMigration(
    hostId: string, resetStep?: (phase: RuntimeResetPhase) => void,
    writeHooks?: SecureFileWriteHooks, removeHooks?: SecureFileRemoveHooks,
  ): Record<string, unknown> {
    const value = readSecureJson<unknown>(runtimeMigrationIntentPathForState(this.filePath));
    if (!isRecord(value)) throw new Error('Bridge runtime migration intent is invalid');
    if (value.version === MIGRATION_INTENT_VERSION) {
      const intent = parseMigrationIntent(value, this.filePath);
      if (intent.hostId !== hostId) throw new Error('Bridge runtime migration intent Host mismatch');
      return this.finishRuntimeMigration(intent, resetStep, writeHooks, removeHooks);
    }
    if (value.version === MIGRATION_INTENT_V2_VERSION) {
      const intent = parseMigrationIntentV2(value, this.filePath);
      if (intent.hostId !== hostId) throw new Error('Bridge runtime migration intent Host mismatch');
      return this.finishRuntimeMigrationV2(intent, resetStep, writeHooks, removeHooks);
    }
    throw new Error('Bridge runtime migration intent version is unknown');
  }
  private finishRuntimeMigration(
    intent: RuntimeMigrationIntentV1, resetStep?: (phase: RuntimeResetPhase) => void,
    writeHooks?: SecureFileWriteHooks, removeHooks?: SecureFileRemoveHooks,
  ): PriorV4BridgeState {
    assertMigrationIntentTargets(intent);
    const stateBytes = readOptionalSecureBytes(this.filePath);
    const spoolBytes = readOptionalSecureBytes(spoolPathForState(this.filePath));
    const floorBytes = readOptionalSecureBytes(runtimeSchemaFloorPathForState(this.filePath));
    assertMigrationMemberHash('state', stateBytes, intent.stateSourceHash, intent.stateTargetHash);
    assertMigrationMemberHash('spool', spoolBytes, intent.spoolSourceHash, intent.spoolTargetHash);
    assertMigrationMemberHash('schema floor', floorBytes, intent.floorSourceHash, intent.floorTargetHash);
    if (hashOptional(spoolBytes) !== intent.spoolTargetHash) {
      writeSecureJson(spoolPathForState(this.filePath), intent.spoolTarget, undefined, writeHooks);
    }
    resetStep?.('after-spool');
    if (hashOptional(stateBytes) !== intent.stateTargetHash) {
      writeSecureJson(this.filePath, intent.stateTarget, undefined, writeHooks);
    }
    resetStep?.('after-state');
    if (hashOptional(floorBytes) !== intent.floorTargetHash) {
      writeSecureJson(runtimeSchemaFloorPathForState(this.filePath), intent.floorTarget, undefined, writeHooks);
    }
    removeSecureFile(runtimeMigrationIntentPathForState(this.filePath), undefined, removeHooks);
    resetStep?.('after-cleanup');
    return intent.stateTarget;
  }

  /**
   * v4→v5 offline phase (§4.5.2-4): builds the independent hash-bound intent whose
   * spool target byte-preserves every schema4 item and whose state target only
   * bumps the schema version. Floor source may be absent (defensive) or the
   * established floor4 bytes. The intent is written atomically (temp + fsync +
   * exclusive rename via `writeSecureJsonExclusive`).
   */
  private beginRuntimeMigrationV4ToV5(
    hostId: string, stateSource: Record<string, unknown>, spoolSource: Record<string, unknown>,
    floorSourceBytes: Buffer | undefined, stateSourceBytes: Buffer, spoolSourceBytes: Buffer,
    resetStep?: (phase: RuntimeResetPhase) => void,
    writeHooks?: SecureFileWriteHooks, removeHooks?: SecureFileRemoveHooks,
  ): PersistedBridgeState {
    const stateTarget = migrateStateV4ToV5(stateSource, hostId);
    const spoolTarget = migrateSpoolV4ToV5(spoolSource, hostId, stateTarget.runtimeResetEpoch);
    const floorTarget = runtimeSchemaFloor(this.filePath, hostId, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION);
    const intent: RuntimeMigrationIntentV2 = {
      version: MIGRATION_INTENT_V2_VERSION, fromSchemaVersion: PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION,
      toSchemaVersion: BRIDGE_RUNTIME_STATE_SCHEMA_VERSION, hostId,
      statePath: resolve(this.filePath), spoolPath: resolve(spoolPathForState(this.filePath)),
      floorPath: resolve(runtimeSchemaFloorPathForState(this.filePath)),
      intentPath: resolve(runtimeMigrationIntentPathForState(this.filePath)),
      stateSourceHash: hashBytes(stateSourceBytes), spoolSourceHash: hashBytes(spoolSourceBytes),
      floorSourceHash: hashOptional(floorSourceBytes),
      stateTargetHash: hashBytes(serializeSecureJson(stateTarget)), spoolTargetHash: hashBytes(serializeSecureJson(spoolTarget)),
      floorTargetHash: hashBytes(serializeSecureJson(floorTarget)), stateTarget, spoolTarget, floorTarget,
      createdAt: new Date().toISOString(),
    };
    resetStep?.('before-intent');
    writeSecureJsonExclusive(intent.intentPath, intent, undefined, writeHooks);
    resetStep?.('after-intent');
    return this.finishRuntimeMigrationV2(intent, resetStep, writeHooks, removeHooks);
  }

  /**
   * v4→v5 offline write order (§4.5.3): spool target → state target → floor5 target →
   * intent removal, validating source/target hashes before and after every step;
   * recovery after a crash proceeds from the intent only, never re-deriving targets.
   */
  private finishRuntimeMigrationV2(
    intent: RuntimeMigrationIntentV2, resetStep?: (phase: RuntimeResetPhase) => void,
    writeHooks?: SecureFileWriteHooks, removeHooks?: SecureFileRemoveHooks,
  ): PersistedBridgeState {
    assertMigrationIntentV2Targets(intent);
    const stateBytes = readOptionalSecureBytes(this.filePath);
    const spoolBytes = readOptionalSecureBytes(spoolPathForState(this.filePath));
    const floorBytes = readOptionalSecureBytes(runtimeSchemaFloorPathForState(this.filePath));
    assertMigrationMemberHash('state', stateBytes, intent.stateSourceHash, intent.stateTargetHash);
    assertMigrationMemberHash('spool', spoolBytes, intent.spoolSourceHash, intent.spoolTargetHash);
    assertMigrationMemberHash('schema floor', floorBytes, intent.floorSourceHash, intent.floorTargetHash);
    if (hashOptional(spoolBytes) !== intent.spoolTargetHash) {
      writeSecureJson(spoolPathForState(this.filePath), intent.spoolTarget, undefined, writeHooks);
    }
    resetStep?.('after-spool');
    if (hashOptional(stateBytes) !== intent.stateTargetHash) {
      writeSecureJson(this.filePath, intent.stateTarget, undefined, writeHooks);
    }
    resetStep?.('after-state');
    if (hashOptional(floorBytes) !== intent.floorTargetHash) {
      writeSecureJson(runtimeSchemaFloorPathForState(this.filePath), intent.floorTarget, undefined, writeHooks);
    }
    removeSecureFile(runtimeMigrationIntentPathForState(this.filePath), undefined, removeHooks);
    resetStep?.('after-cleanup');
    return intent.stateTarget;
  }

  private assertRuntimeAccess(): void {
    if (this.disposed) throw new Error('Bridge state store is disposed');
    assertRuntimeWriterAllowed(this.runtimeCoordinator);
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
    this.commitTransition((state) => reserveProducerEventTransition(state, reservation));
  }
  getProducerEventTuple(eventId: string, fingerprint: string): { event: CanonicalEvent; session: CanonicalSessionState } | undefined {
    return this.openProducerTuple('event-reservation-v3', eventId, fingerprint)
      ?? this.openProducerTuple('event-source-v3', eventId, fingerprint);
  }
  reserveProducerEventTuple(event: CanonicalEvent, terminalSession: CanonicalSessionState, fingerprint: string): void {
    this.enqueuePendingEvent(event, terminalSession, fingerprint, 'event-reservation-v3');
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
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const reservationKey = producerReservationKey(input.sessionId, input.fingerprint);
    const reservation = this.state.producerEventReservations?.[reservationKey];
    const source = this.spool.get(input.eventId);
    if ((!reservation || reservation.eventId !== input.eventId) && source?.payloadKind !== 'event-reservation-v3') return;
    const requested: PersistedTerminalCancellationV1 = {
      version: 1, sessionId: input.sessionId, eventId: input.eventId, fingerprint: input.fingerprint,
      removeSession: input.removeSession === true, createdAt: input.createdAt ?? new Date().toISOString(),
    };
    const itemId = terminalCancellationItemId(input.eventId);
    const existingIntent = this.openSpoolJson(itemId) as PersistedTerminalCancellationV1 | undefined;
    if (existingIntent && (existingIntent.version !== 1 || existingIntent.sessionId !== requested.sessionId
      || existingIntent.eventId !== requested.eventId || existingIntent.fingerprint !== requested.fingerprint
      || existingIntent.removeSession !== requested.removeSession)) {
      throw new TypeError('terminal cancellation journal conflict');
    }
    const cancellation = existingIntent ?? requested;
    if (!existingIntent) this.spool.enqueue({ spoolItemId: itemId, sessionId: input.sessionId, eventId: input.eventId,
      payloadKind: 'terminal-cancellation-v3', createdAt: cancellation.createdAt,
      plaintext: new TextEncoder().encode(JSON.stringify(cancellation)) });
    const nextState = structuredClone(this.state);
    delete nextState.producerEventReservations?.[reservationKey];
    if (nextState.producerEventReservations && Object.keys(nextState.producerEventReservations).length === 0) {
      delete nextState.producerEventReservations;
    }
    (nextState.terminalCancellations ??= {})[input.eventId] = cancellation;
    if (input.removeSession) {
      delete nextState.sessions[input.sessionId];
      delete nextState.sessionDrivers[input.sessionId];
    } else if (input.nextDriverName !== undefined) {
      nextState.sessionDrivers[input.sessionId] = input.nextDriverName;
    }
    try {
      this.commit(nextState);
    } catch (error) {
      if (!this.diskHasTerminalCancellation(cancellation)) throw error;
      this.state = nextState;
    }
    this.finishTerminalCancellation(cancellation);
  }
  private assertTerminalCancellationSource(cancellation: PersistedTerminalCancellationV1): void {
    if (!this.spool) return;
    const source = this.spool.get(cancellation.eventId);
    if (!source) return;
    if (source.payloadKind !== 'event-reservation-v3'
      || source.eventId !== cancellation.eventId
      || source.sessionId !== cancellation.sessionId) {
      throw new TypeError('terminal cancellation source conflicts with state');
    }
    const tuple = this.openProducerTuple('event-reservation-v3', cancellation.eventId, cancellation.fingerprint);
    if (!tuple || tuple.event.eventId !== cancellation.eventId || tuple.event.sessionId !== cancellation.sessionId
      || tuple.session.sessionId !== cancellation.sessionId) {
      throw new TypeError('terminal cancellation source conflicts with state');
    }
  }
  private finishTerminalCancellation(cancellation: PersistedTerminalCancellationV1): void {
    if (!this.spool) return;
    const itemId = terminalCancellationItemId(cancellation.eventId);
    const sourceExists = this.spool.get(cancellation.eventId) !== undefined;
    const intentExists = this.spool.get(itemId) !== undefined;
    if (sourceExists || intentExists) {
      try { this.spool.removeMany([cancellation.eventId, itemId]); } catch { return; }
    }
    const nextState = structuredClone(this.state);
    delete nextState.terminalCancellations?.[cancellation.eventId];
    if (nextState.terminalCancellations && Object.keys(nextState.terminalCancellations).length === 0) {
      delete nextState.terminalCancellations;
    }
    try { this.commit(nextState); } catch {}
  }
  private diskHasTerminalCancellation(cancellation: PersistedTerminalCancellationV1): boolean {
    try {
      const disk = readSecureJson<PersistedBridgeState>(this.filePath);
      return JSON.stringify(disk.terminalCancellations?.[cancellation.eventId]) === JSON.stringify(cancellation);
    } catch {
      return false;
    }
  }
  private reconcileTerminalCancellations(): void {
    if (!this.spool) return;
    const intents = new Map(this.spool.list('terminal-cancellation-v3').map((item) => [item.eventId, item]));
    for (const cancellation of Object.values(this.state.terminalCancellations ?? {})) {
      const item = intents.get(cancellation.eventId);
      if (item) {
        const persisted = this.openSpoolJson(item.spoolItemId);
        if (JSON.stringify(persisted) !== JSON.stringify(cancellation)) {
          throw new TypeError('terminal cancellation recovery journal conflicts with state');
        }
      }
      this.assertTerminalCancellationSource(cancellation);
      this.finishTerminalCancellation(cancellation);
      if (this.state.terminalCancellations?.[cancellation.eventId]) {
        throw new Error('terminal cancellation recovery requires retry');
      }
      intents.delete(cancellation.eventId);
    }
    for (const item of intents.values()) {
      const cancellation = this.openSpoolJson(item.spoolItemId) as PersistedTerminalCancellationV1;
      const reservationKey = producerReservationKey(cancellation.sessionId, cancellation.fingerprint);
      const reservation = this.state.producerEventReservations?.[reservationKey];
      const source = this.spool.get(cancellation.eventId);
      if (!reservation || reservation.eventId !== cancellation.eventId
        || source?.payloadKind !== 'event-reservation-v3' || source.sessionId !== cancellation.sessionId) {
        throw new TypeError('terminal cancellation recovery journal conflicts with pending Event evidence');
      }
      this.assertTerminalCancellationSource(cancellation);
      const nextState = structuredClone(this.state);
      delete nextState.producerEventReservations?.[reservationKey];
      if (nextState.producerEventReservations && Object.keys(nextState.producerEventReservations).length === 0) {
        delete nextState.producerEventReservations;
      }
      (nextState.terminalCancellations ??= {})[cancellation.eventId] = cancellation;
      if (cancellation.removeSession) {
        delete nextState.sessions[cancellation.sessionId];
        delete nextState.sessionDrivers[cancellation.sessionId];
      }
      this.commit(nextState);
      this.finishTerminalCancellation(cancellation);
      if (this.state.terminalCancellations?.[cancellation.eventId]) {
        throw new Error('terminal cancellation recovery requires retry');
      }
    }
  }

  appendRecentEvent(event: CanonicalEvent): void {
    this.commitTransition((state) => appendRecentEventTransition(state, event));
  }
  queuePendingEvent(event: CanonicalEvent, terminalSession: CanonicalSessionState, producerFingerprint?: string): void {
    assertEventSessionBinding(event, terminalSession);
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const existingKind = this.spool.get(event.eventId)?.payloadKind;
    if (producerFingerprint && existingKind === 'event-reservation-v3') {
      this.promoteProducerEventTuple(event, terminalSession, producerFingerprint);
    } else if (producerFingerprint && existingKind === 'event-source-v3') {
      const existing = this.openProducerTuple('event-source-v3', event.eventId, producerFingerprint);
      if (!existing || JSON.stringify(existing) !== JSON.stringify({ event, session: terminalSession })) {
        throw new TypeError('pending Event retry journal conflicts with the bound tuple');
      }
    } else {
      this.enqueuePendingEvent(event, terminalSession, producerFingerprint);
    }
    const previousState = this.state;
    const nextState = structuredClone(this.state);
    this.state = nextState;
    this.applyPendingEventState(event, terminalSession);
    if (producerFingerprint) this.applyProducerReservation(event, producerFingerprint);
    try {
      this.persist();
    } catch (error) {
      this.state = previousState;
      throw error;
    }
  }

  private applyPendingEventState(event: CanonicalEvent, terminalSession: CanonicalSessionState): void {
    this.state.recentEvents = retainRecentEvents(
      [event, ...this.state.recentEvents.filter((candidate) => candidate.eventId !== event.eventId)],
      this.state.pendingHandles,
    );
    this.state.sessions[event.sessionId] = terminalSession;
    this.state.sessionDrivers[event.sessionId] = event.provider;
  }
  private applyProducerReservation(event: CanonicalEvent, fingerprint: string): void {
    const key = producerReservationKey(event.sessionId, fingerprint);
    const existing = this.state.producerEventReservations?.[key];
    if (existing && existing.eventId !== event.eventId) throw new TypeError('producer Event reservation conflict');
    (this.state.producerEventReservations ??= {})[key] = {
      version: 1, eventId: event.eventId, sessionId: event.sessionId, fingerprint, createdAt: event.createdAt,
    };
  }
  private enqueuePendingEvent(event: CanonicalEvent, terminalSession: CanonicalSessionState, producerFingerprint?: string,
    payloadKind: 'event-source-v3' | 'event-reservation-v3' = 'event-source-v3'): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const serialized = JSON.stringify({ event, session: terminalSession, ...(producerFingerprint ? { producerFingerprint } : {}) });
    const payload = new TextEncoder().encode(serialized);
    const item = this.spool.enqueue({ spoolItemId: event.eventId, sessionId: event.sessionId, eventId: event.eventId,
      payloadKind, createdAt: event.createdAt, plaintext: payload });
    const stored = this.spool.open(item);
    try {
      if (new TextDecoder('utf-8', { fatal: true }).decode(stored) !== serialized) {
        throw new TypeError('pending Event retry journal conflicts with the bound tuple');
      }
    } finally { stored.fill(0); }
  }
  private promoteProducerEventTuple(event: CanonicalEvent, terminalSession: CanonicalSessionState, fingerprint: string): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const serialized = JSON.stringify({ event, session: terminalSession, producerFingerprint: fingerprint });
    const existing = this.openProducerTuple('event-reservation-v3', event.eventId, fingerprint);
    if (!existing || JSON.stringify(existing) !== JSON.stringify({ event, session: terminalSession })) {
      throw new TypeError('pending Event retry journal conflicts with the bound tuple');
    }
    this.spool.replace([event.eventId], [{ spoolItemId: event.eventId, sessionId: event.sessionId, eventId: event.eventId,
      payloadKind: 'event-source-v3', createdAt: event.createdAt, plaintext: new TextEncoder().encode(serialized) }]);
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
  private reconcileProducerEventReservations(): void {
    if (!this.spool) return;
    let changed = false;
    for (const item of this.spool.list('event-reservation-v3')) {
      const bytes = this.spool.open(item);
      try {
        const pending = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as {
          event: CanonicalEvent; session: CanonicalSessionState; producerFingerprint?: string;
        };
        assertEventSessionBinding(pending.event, pending.session);
        if (typeof pending.producerFingerprint !== 'string') throw new TypeError('pending Event producer fingerprint is invalid');
        const existing = this.getProducerEventReservation(pending.event.sessionId, pending.producerFingerprint);
        if (!existing) { this.applyProducerReservation(pending.event, pending.producerFingerprint); changed = true; }
        else if (existing.eventId !== pending.event.eventId) throw new TypeError('pending Event producer reservation conflicts with state');
      } finally { bytes.fill(0); }
    }
    if (changed) this.persist();
  }

  private reconcilePendingEventJournal(): void {
    if (!this.spool) return;
    let changed = false;
    // Per-item safe decode: malformed sources are left untouched for the upload
    // processor (§5.2) instead of failing the whole startup, which is exactly the
    // eager-decode head-of-line failure the 64 KiB spec eliminates.
    for (const descriptor of this.listPendingEventDescriptors()) {
      const loaded = this.openPendingEventSource(descriptor);
      if (!loaded.ok) continue;
      const { event, session, producerFingerprint } = loaded.source;
      const current = this.state.sessions[event.sessionId];
      const recent = this.state.recentEvents.some((candidate) => candidate.eventId === event.eventId);
      if (producerFingerprint) {
        const reservation = this.getProducerEventReservation(event.sessionId, producerFingerprint);
        if (!reservation) { this.applyProducerReservation(event, producerFingerprint); changed = true; }
        else if (reservation.eventId !== event.eventId) throw new TypeError('pending Event producer reservation conflicts with state');
      }
      if (recent && current?.lastEventId === event.eventId) continue;
      if (current && isNewerTerminalSession(current, session)) continue;
      this.applyPendingEventState(event, session);
      changed = true;
    }
    if (changed) this.persist();
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
    const existing = this.state.eventUploadCompletions?.[completion.eventId];
    if (existing && !sameEventCompletion(existing, completion)) throw new TypeError('event completion journal conflict');
    if (!existing) { (this.state.eventUploadCompletions ??= {})[completion.eventId] = structuredClone(completion); this.persist(); }
  }
  completeEventUpload(eventId: string, step?: (phase: 'revision-committed' | 'inflight-removed' | 'source-removed' | 'journal-removed') => void): void {
    let completion = this.state.eventUploadCompletions?.[eventId];
    if (!completion) return;
    if (!completion.revisionCommitted) {
      this.commitSessionRevision(completion.sessionId, completion.revision);
      completion = this.updateEventCompletion(eventId, { revisionCommitted: true });
    }
    step?.('revision-committed');
    if (!completion.inflightRemoved) {
      this.removeInflightEventUpload(eventId);
      completion = this.updateEventCompletion(eventId, { inflightRemoved: true });
    }
    step?.('inflight-removed');
    if (!completion.sourceRemoved) {
      this.spool?.remove(eventId);
      completion = this.updateEventCompletion(eventId, { sourceRemoved: true });
    }
    step?.('source-removed');
    delete this.state.eventUploadCompletions?.[eventId];
    if (this.state.eventUploadCompletions && Object.keys(this.state.eventUploadCompletions).length === 0) delete this.state.eventUploadCompletions;
    this.persist();
    step?.('journal-removed');
  }
  private updateEventCompletion(eventId: string, patch: Partial<EventUploadCompletionV1>): EventUploadCompletionV1 {
    const current = this.state.eventUploadCompletions?.[eventId];
    if (!current) throw new TypeError('event completion journal is missing');
    const next = { ...current, ...patch }; this.state.eventUploadCompletions![eventId] = next; this.persist(); return next;
  }
  private resumeEventUploadCompletions(): void {
    for (const eventId of Object.keys(this.state.eventUploadCompletions ?? {})) this.completeEventUpload(eventId);
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


function retainRecentEvents(
  events: CanonicalEvent[], pendingHandles: Record<string, PendingSessionHandle>,
): CanonicalEvent[] {
  const unique = events.filter((event, index) => events.findIndex((candidate) => candidate.eventId === event.eventId) === index);
  const protectedIds = new Set(Object.values(pendingHandles).map((handle) => handle.handledThroughEventId));
  const retainedProtected = unique.filter((event) => protectedIds.has(event.eventId));
  const available = Math.max(0, MAX_RECENT_EVENTS - retainedProtected.length);
  return [...retainedProtected, ...unique.filter((event) => !protectedIds.has(event.eventId)).slice(0, available)]
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}
function sessionHandleKey(hostId: string, sessionId: string): string { return `${hostId}:${sessionId}`; }
function comparePendingHandles(left: PendingSessionHandle, right: PendingSessionHandle): number {
  const cursorCompare = (left.handledThroughEventCreatedAt ?? left.handledAt).localeCompare(right.handledThroughEventCreatedAt ?? right.handledAt);
  if (cursorCompare !== 0) return cursorCompare; const eventCompare = left.handledThroughEventId.localeCompare(right.handledThroughEventId);
  return eventCompare !== 0 ? eventCompare : left.updatedAt.localeCompare(right.updatedAt);
}
function terminalCancellationItemId(eventId: string): string { return `cancel:terminal:${eventId}`; }
function sanitizePersistedHost(host: HostProjection | null): HostProjection | null {
  if (!host) return null;
  const value = { ...host } as HostProjection & Record<string, unknown>;
  delete value.claimCode; delete value.claimCodeExpiresAt; delete value.ownerUserId;
  return value;
}

function sameEventCompletion(left: EventUploadCompletionV1, right: EventUploadCompletionV1): boolean {
  return left.version === right.version && left.eventId === right.eventId && left.sessionId === right.sessionId
    && left.revision === right.revision && left.eventContentId === right.eventContentId
    && left.sessionContentId === right.sessionContentId;
}

export function runtimeResetIntentPathForState(statePath: string): string {
  return `${statePath}.runtime-reset.json`;
}
export function runtimeMigrationIntentPathForState(statePath: string): string {
  return `${statePath}.runtime-migration.json`;
}
export function runtimeSchemaFloorPathForState(statePath: string): string {
  return `${statePath}.schema-floor.json`;
}

function readOptionalSecureBytes(path: string): Buffer | undefined {
  return pathHasFilesystemEvidence(path) ? readSecureFile(path) : undefined;
}

function parseRawJson(bytes: Buffer | undefined, label: string): Record<string, unknown> | undefined {
  if (!bytes) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(`${label} JSON is malformed`, { cause: error });
  }
  if (!isRecord(parsed)) throw new Error(`${label} must be a JSON object`);
  return parsed;
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

export function readCurrentRuntimeHealth(statePath: string): BridgeRuntimeHealth | undefined {
  if (!pathHasFilesystemEvidence(statePath)) return undefined;
  try {
    const state = parseCurrentState(readSecureJson<unknown>(statePath));
    return state.runtimeHealth ? structuredClone(state.runtimeHealth) : { status: 'healthy', drivers: [] };
  } catch { return undefined; }
}

export function assertCurrentRuntimeArtifacts(statePath: string, hostId: string): void {
  const state = parseCurrentState(readSecureJson<unknown>(statePath), hostId);
  const spool = parseCurrentSpoolRecord(
    readSecureJson<Record<string, unknown>>(spoolPathForState(statePath)), hostId, state.runtimeResetEpoch,
  );
  assertCurrentRuntimeRelationships(state, spool, hostId);
}

function isRuntimeResetHooks(value: SecureFileWriteHooks | RuntimeResetHooks | undefined): value is RuntimeResetHooks {
  return value !== undefined && ('write' in value || 'remove' in value || 'recoveryStep' in value);
}

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

function isCurrentStateRecord(value: Record<string, unknown>): boolean {
  return isStateRecordOfShape(value, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION);
}

/** Schema4 record: the exact current-state shape with the v4 version literal. */
function isPriorStateRecordV4(value: Record<string, unknown>, hostId: string): boolean {
  if (!isStateRecordOfShape(value, PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION)) return false;
  try {
    assertCurrentStateRelationships(value as unknown as PersistedBridgeState, hostId);
    return true;
  } catch { return false; }
}

function parseCurrentState(value: unknown, hostId?: string): PersistedBridgeState {
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

function isPriorStateRecordV3(value: Record<string, unknown>, hostId: string): boolean {
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
function migrateStateV3ToV4(value: Record<string, unknown>, hostId: string): PersistedBridgeState {
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
function migrateSpoolV3ToV4(value: Record<string, unknown>, hostId: string, epoch: string): LocalSpoolFileV2 {
  if (!isSpoolRecordForSchema(value, PRIOR_RUNTIME_STATE_SCHEMA_VERSION, hostId, epoch, 'current')) {
    throw new Error('Bridge runtime spool schema v3 is invalid');
  }
  return { ...(structuredClone(value) as unknown as LocalSpoolFileV2), runtimeStateSchemaVersion: 4, items: [] };
}

function migrateStateV4ToV5(value: Record<string, unknown>, hostId: string): PersistedBridgeState {
  if (!isPriorStateRecordV4(value, hostId)) throw new Error('Bridge runtime schema v4 is invalid');
  const state = structuredClone(value) as Record<string, unknown>;
  state.schemaVersion = BRIDGE_RUNTIME_STATE_SCHEMA_VERSION;
  return parseCurrentState(state, hostId);
}

function migrateSpoolV4ToV5(value: Record<string, unknown>, hostId: string, epoch: string): LocalSpoolFileV2 {
  if (!isSpoolRecordForSchema(value, PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION, hostId, epoch, 'current')) {
    throw new Error('Bridge runtime spool schema v4 is invalid');
  }
  return { ...(structuredClone(value) as unknown as LocalSpoolFileV2), runtimeStateSchemaVersion: BRIDGE_RUNTIME_STATE_SCHEMA_VERSION };
}

function isRecognizedPriorStateRecord(value: Record<string, unknown> | undefined, hostId: string): boolean {
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

function isRecognizedLegacyRuntime(
  state: Record<string, unknown> | undefined, spool: Record<string, unknown> | undefined, hostId: string,
): boolean {
  if ((state && !isRecognizedPriorStateRecord(state, hostId)) || (spool && !isRecognizedPriorSpoolRecord(spool, hostId))) {
    return false;
  }
  return !state || !spool || hasRecognizedPriorRuntimeRelationships(state, spool);
}

function isRecognizedObsoleteRuntime(
  state: Record<string, unknown> | undefined, spool: Record<string, unknown> | undefined, hostId: string,
): boolean {
  if (!state || !spool || !isObsoleteStateRecord(state, hostId)
    || !isSpoolRecordForSchema(spool, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, hostId, state.runtimeResetEpoch as string, 'current')) return false;
  return hasRecognizedPriorRuntimeRelationships(state, spool);
}

function isObsoleteStateRecord(value: Record<string, unknown>, hostId: string): boolean {
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

function parseCurrentSpoolRecord(value: Record<string, unknown>, hostId: string, epoch: string): LocalSpoolFileV2 {
  if (!isSpoolRecordForSchema(value, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION, hostId, epoch, 'current')) {
    throw new Error('current Bridge runtime spool schema is invalid');
  }
  return structuredClone(value) as unknown as LocalSpoolFileV2;
}

function parsePriorV4SpoolRecord(value: Record<string, unknown>, hostId: string, epoch: string): LocalSpoolFileV2 {
  if (!isSpoolRecordForSchema(value, PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION, hostId, epoch, 'current')) {
    throw new Error('prior Bridge runtime spool schema is invalid');
  }
  return structuredClone(value) as unknown as LocalSpoolFileV2;
}

function isSpoolRecordForSchema(
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

function isRecognizedPriorSpoolRecord(value: Record<string, unknown>, hostId: string): boolean {
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

function parseResetIntent(value: unknown): RuntimeResetIntentV1 {
  if (!isRecord(value) || !hasExactKeys(value, [
    'version', 'fromSchemaVersion', 'toSchemaVersion', 'hostId', 'epoch', 'keyId', 'statePath', 'spoolPath',
    'intentPath', 'stateSourceHash', 'spoolSourceHash', 'stateTargetHash', 'spoolTargetHash', 'createdAt',
  ]) || value.version !== RESET_INTENT_VERSION || !isValidResetTransition(value.fromSchemaVersion, value.toSchemaVersion)
    || !isNonEmptyString(value.hostId)
    || !isRuntimeEpoch(value.epoch) || !isVerifier(value.keyId)
    || !isAbsoluteResolvedPath(value.statePath) || !isAbsoluteResolvedPath(value.spoolPath)
    || !isAbsoluteResolvedPath(value.intentPath)
    || !isRuntimeHash(value.stateSourceHash) || !isRuntimeHash(value.spoolSourceHash)
    || !isRuntimeHash(value.stateTargetHash) || !isRuntimeHash(value.spoolTargetHash)
    || !isNonEmptyString(value.createdAt) || !Number.isFinite(Date.parse(value.createdAt))) {
    throw new Error('Bridge runtime reset intent is invalid');
  }
  return value as unknown as RuntimeResetIntentV1;
}

function isValidResetTransition(from: unknown, to: unknown): boolean {
  return (from === LEGACY_RUNTIME_STATE_SCHEMA_VERSION && to === OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION)
    || (from === OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION && to === PRIOR_RUNTIME_STATE_SCHEMA_VERSION);
}

function emptyStateForSchema(schemaVersion: 2 | 3, epoch: string): Record<string, unknown> {
  const { commandExecutions: _commandExecutions, ...state } = emptyState(epoch);
  return { ...state, schemaVersion, commandResults: {}, seenCommands: {} };
}

function spoolFileForSchema(schemaVersion: 2 | 3, hostId: string, epoch: string, keyId: string): LocalSpoolFileV2 {
  return { version: 2, runtimeStateSchemaVersion: schemaVersion, runtimeResetEpoch: epoch, hostId, keyId, items: [] };
}

function assertResetIntentPaths(intent: RuntimeResetIntentV1, statePath: string): void {
  const expectedStatePath = resolve(statePath);
  if (intent.statePath !== expectedStatePath || intent.spoolPath !== resolve(spoolPathForState(expectedStatePath))
    || intent.intentPath !== resolve(runtimeResetIntentPathForState(expectedStatePath))) {
    throw new Error('Bridge runtime reset intent path binding is invalid');
  }
}

function assertRuntimeResetTargets(
  intent: RuntimeResetIntentV1, stateTarget: Record<string, unknown>, spoolTarget: LocalSpoolFileV2,
 ): void {
  if (hashBytes(serializeSecureJson(stateTarget)) !== intent.stateTargetHash
    || hashBytes(serializeSecureJson(spoolTarget)) !== intent.spoolTargetHash) {
    throw new Error('Bridge runtime reset intent target hash is invalid');
  }
  if (intent.toSchemaVersion === PRIOR_RUNTIME_STATE_SCHEMA_VERSION) {
    if (!isPriorStateRecordV3(stateTarget, intent.hostId) || !isSpoolRecordForSchema(
      spoolTarget as unknown as Record<string, unknown>, PRIOR_RUNTIME_STATE_SCHEMA_VERSION, intent.hostId, intent.epoch, 'current',
    )) throw new Error('Bridge runtime reset intent prior target is invalid');
  } else if (!isObsoleteStateRecord(stateTarget, intent.hostId) || !isSpoolRecordForSchema(
    spoolTarget as unknown as Record<string, unknown>, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, intent.hostId, intent.epoch, 'current',
  )) {
    throw new Error('Bridge runtime reset intent obsolete target is invalid');
  }
}

function assertResetStateMember(
  bytes: Buffer | undefined, intent: RuntimeResetIntentV1, hostId: string, target: Record<string, unknown>,
): void {
  const actual = hashOptional(bytes);
  assertResetMemberHash('state', actual, intent.stateSourceHash, intent.stateTargetHash);
  if (actual === intent.stateTargetHash) {
    const parsed = parseRawJson(bytes, 'Bridge runtime reset state target');
    const valid = intent.toSchemaVersion === PRIOR_RUNTIME_STATE_SCHEMA_VERSION
      ? !!parsed && isPriorStateRecordV3(parsed, hostId)
      : !!parsed && isObsoleteStateRecord(parsed, hostId);
    if (!valid || JSON.stringify(parsed) !== JSON.stringify(target)) {
      throw new Error('Bridge runtime reset state target is invalid');
    }
  } else if (bytes) {
    const state = parseRawJson(bytes, 'Bridge runtime reset state source');
    const valid = intent.fromSchemaVersion === LEGACY_RUNTIME_STATE_SCHEMA_VERSION
      ? isRecognizedPriorStateRecord(state, hostId)
      : !!state && isObsoleteStateRecord(state, hostId);
    if (!valid) throw new Error('Bridge runtime reset state source schema is invalid');
  }
}

function assertResetSpoolMember(
  bytes: Buffer | undefined, intent: RuntimeResetIntentV1, hostId: string, target: LocalSpoolFileV2,
): void {
  const actual = hashOptional(bytes);
  assertResetMemberHash('spool', actual, intent.spoolSourceHash, intent.spoolTargetHash);
  if (actual === intent.spoolTargetHash) {
    const spool = parseRawJson(bytes, 'Bridge runtime reset spool target');
    if (!spool || !isSpoolRecordForSchema(spool, intent.toSchemaVersion, hostId, intent.epoch, 'current')
      || JSON.stringify(spool) !== JSON.stringify(target)) {
      throw new Error('Bridge runtime reset spool target is invalid');
    }
  } else if (bytes) {
    const spool = parseRawJson(bytes, 'Bridge runtime reset spool source');
    const valid = intent.fromSchemaVersion === LEGACY_RUNTIME_STATE_SCHEMA_VERSION
      ? !!spool && isRecognizedPriorSpoolRecord(spool, hostId)
      : !!spool && isSpoolRecordForSchema(spool, intent.fromSchemaVersion, hostId,
        (spool.runtimeResetEpoch as string), 'current');
    if (!valid) throw new Error('Bridge runtime reset spool source schema is invalid');
  }
}

function runtimeSchemaFloor(statePath: string, hostId: string, minSchemaVersion: 4 | 5): RuntimeSchemaFloorV1 {
  const resolvedStatePath = resolve(statePath);
  return {
    version: 1, hostId, minSchemaVersion,
    statePath: resolvedStatePath, spoolPath: resolve(spoolPathForState(resolvedStatePath)),
  };
}

function parseRuntimeSchemaFloor(
  value: Record<string, unknown> | undefined, statePath: string, hostId: string,
 ): RuntimeSchemaFloorV1 {
  if (!value || !hasExactKeys(value, ['version', 'hostId', 'minSchemaVersion', 'statePath', 'spoolPath'])
    || value.version !== 1 || value.hostId !== hostId
    || (value.minSchemaVersion !== PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION
      && value.minSchemaVersion !== BRIDGE_RUNTIME_STATE_SCHEMA_VERSION)) {
    throw new Error('Bridge runtime schema floor is invalid');
  }
  const expected = runtimeSchemaFloor(statePath, hostId, value.minSchemaVersion as 4 | 5);
  if (value.statePath !== expected.statePath || value.spoolPath !== expected.spoolPath) {
    throw new Error('Bridge runtime schema floor path binding is invalid');
  }
  return value as unknown as RuntimeSchemaFloorV1;
}

function parseMigrationIntent(value: unknown, statePath: string): RuntimeMigrationIntentV1 {
  if (!isRecord(value) || !hasExactKeys(value, [
    'version', 'fromSchemaVersion', 'toSchemaVersion', 'hostId', 'statePath', 'spoolPath', 'floorPath', 'intentPath',
    'stateSourceHash', 'spoolSourceHash', 'floorSourceHash', 'stateTargetHash', 'spoolTargetHash', 'floorTargetHash',
    'stateTarget', 'spoolTarget', 'floorTarget', 'createdAt',
  ]) || value.version !== MIGRATION_INTENT_VERSION || value.fromSchemaVersion !== PRIOR_RUNTIME_STATE_SCHEMA_VERSION
    || value.toSchemaVersion !== PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION || !isNonEmptyString(value.hostId)
    || !isAbsoluteResolvedPath(value.statePath) || !isAbsoluteResolvedPath(value.spoolPath)
    || !isAbsoluteResolvedPath(value.floorPath) || !isAbsoluteResolvedPath(value.intentPath)
    || !isRuntimeHash(value.stateSourceHash) || !isRuntimeHash(value.spoolSourceHash) || !isRuntimeHash(value.floorSourceHash)
    || !isRuntimeHash(value.stateTargetHash) || !isRuntimeHash(value.spoolTargetHash) || !isRuntimeHash(value.floorTargetHash)
    || !isNonEmptyString(value.createdAt) || !isCanonicalTimestamp(value.createdAt)) {
    throw new Error('Bridge runtime migration intent is invalid');
  }
  const intent = value as unknown as RuntimeMigrationIntentV1;
  const expectedStatePath = resolve(statePath);
  if (intent.statePath !== expectedStatePath || intent.spoolPath !== resolve(spoolPathForState(expectedStatePath))
    || intent.floorPath !== resolve(runtimeSchemaFloorPathForState(expectedStatePath))
    || intent.intentPath !== resolve(runtimeMigrationIntentPathForState(expectedStatePath))) {
    throw new Error('Bridge runtime migration intent path binding is invalid');
  }
  assertMigrationIntentTargets(intent);
  return intent;
}

function assertMigrationIntentTargets(intent: RuntimeMigrationIntentV1): void {
  if (!isPriorStateRecordV4(intent.stateTarget, intent.hostId)) throw new Error('Bridge runtime migration intent target is invalid');
  const spool = parsePriorV4SpoolRecord(
    intent.spoolTarget as unknown as Record<string, unknown>, intent.hostId, intent.stateTarget.runtimeResetEpoch,
  );
  const floor = parseRuntimeSchemaFloor(intent.floorTarget as unknown as Record<string, unknown>, intent.statePath, intent.hostId);
  if (floor.minSchemaVersion !== PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION) throw new Error('Bridge runtime migration intent target is invalid');
  assertCurrentRuntimeRelationships(intent.stateTarget as unknown as PersistedBridgeState, spool, intent.hostId);
  if (hashBytes(serializeSecureJson(intent.stateTarget)) !== intent.stateTargetHash
    || hashBytes(serializeSecureJson(intent.spoolTarget)) !== intent.spoolTargetHash
    || hashBytes(serializeSecureJson(floor)) !== intent.floorTargetHash || intent.floorSourceHash !== ABSENT_HASH) {
    throw new Error('Bridge runtime migration intent target hash is invalid');
  }
}

function parseMigrationIntentV2(value: unknown, statePath: string): RuntimeMigrationIntentV2 {
  if (!isRecord(value) || !hasExactKeys(value, [
    'version', 'fromSchemaVersion', 'toSchemaVersion', 'hostId', 'statePath', 'spoolPath', 'floorPath', 'intentPath',
    'stateSourceHash', 'spoolSourceHash', 'floorSourceHash', 'stateTargetHash', 'spoolTargetHash', 'floorTargetHash',
    'stateTarget', 'spoolTarget', 'floorTarget', 'createdAt',
  ]) || value.version !== MIGRATION_INTENT_V2_VERSION
    || value.fromSchemaVersion !== PRIOR_V4_RUNTIME_STATE_SCHEMA_VERSION
    || value.toSchemaVersion !== BRIDGE_RUNTIME_STATE_SCHEMA_VERSION || !isNonEmptyString(value.hostId)
    || !isAbsoluteResolvedPath(value.statePath) || !isAbsoluteResolvedPath(value.spoolPath)
    || !isAbsoluteResolvedPath(value.floorPath) || !isAbsoluteResolvedPath(value.intentPath)
    || !isRuntimeHash(value.stateSourceHash) || !isRuntimeHash(value.spoolSourceHash) || !isRuntimeHash(value.floorSourceHash)
    || !isRuntimeHash(value.stateTargetHash) || !isRuntimeHash(value.spoolTargetHash) || !isRuntimeHash(value.floorTargetHash)
    || !isNonEmptyString(value.createdAt) || !isCanonicalTimestamp(value.createdAt)) {
    throw new Error('Bridge runtime migration intent is invalid');
  }
  const intent = value as unknown as RuntimeMigrationIntentV2;
  const expectedStatePath = resolve(statePath);
  if (intent.statePath !== expectedStatePath || intent.spoolPath !== resolve(spoolPathForState(expectedStatePath))
    || intent.floorPath !== resolve(runtimeSchemaFloorPathForState(expectedStatePath))
    || intent.intentPath !== resolve(runtimeMigrationIntentPathForState(expectedStatePath))) {
    throw new Error('Bridge runtime migration intent path binding is invalid');
  }
  assertMigrationIntentV2Targets(intent);
  return intent;
}

function assertMigrationIntentV2Targets(intent: RuntimeMigrationIntentV2): void {
  const state = parseCurrentState(intent.stateTarget, intent.hostId);
  const spool = parseCurrentSpoolRecord(
    intent.spoolTarget as unknown as Record<string, unknown>, intent.hostId, state.runtimeResetEpoch,
  );
  const floor = parseRuntimeSchemaFloor(intent.floorTarget as unknown as Record<string, unknown>, intent.statePath, intent.hostId);
  if (floor.minSchemaVersion !== BRIDGE_RUNTIME_STATE_SCHEMA_VERSION) throw new Error('Bridge runtime migration intent target is invalid');
  assertCurrentRuntimeRelationships(state, spool, intent.hostId);
  if (hashBytes(serializeSecureJson(intent.stateTarget)) !== intent.stateTargetHash
    || hashBytes(serializeSecureJson(intent.spoolTarget)) !== intent.spoolTargetHash
    || hashBytes(serializeSecureJson(floor)) !== intent.floorTargetHash) {
    throw new Error('Bridge runtime migration intent target hash is invalid');
  }
}

function assertMigrationMemberHash(name: string, bytes: Buffer | undefined, source: string, target: string): void {
  const actual = hashOptional(bytes);
  if (actual !== source && actual !== target) {
    throw new Error(`Bridge runtime migration ${name} changed outside the migration journal`);
  }
}

function assertResetMemberHash(name: string, actual: string, source: string, target: string): void {
  if (actual !== source && actual !== target) throw new Error(`Bridge runtime reset ${name} changed outside the reset journal`);
}

function serializeSecureJson(value: unknown): Buffer { return Buffer.from(`${JSON.stringify(value, null, 2)}\n`); }
function hashBytes(bytes: Uint8Array): string { return createHash('sha256').update(bytes).digest('base64url'); }
function hashOptional(bytes: Uint8Array | undefined): string { return bytes ? hashBytes(bytes) : ABSENT_HASH; }
function isRuntimeHash(value: unknown): boolean {
  return value === ABSENT_HASH || (typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value));
}
function isAbsoluteResolvedPath(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith('/') && resolve(value) === value;
}
function isRuntimeEpoch(value: unknown): value is string {
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
function isCurrentHost(value: unknown): boolean {
  return isRecord(value) && hasExactOptionalKeys(value,
    ['hostId', 'hostName', 'platform', 'bridgeVersion', 'registeredAt', 'lastSeenAt', 'bridgeStatus'], ['status'])
    && ['hostId', 'hostName', 'bridgeVersion', 'registeredAt', 'lastSeenAt'].every((key) => isNonEmptyString(value[key]))
    && (value.platform === 'macos' || value.platform === 'linux')
    && (value.bridgeStatus === 'online' || value.bridgeStatus === 'offline' || value.bridgeStatus === 'degraded')
    && (value.status === undefined || value.status === 'active' || value.status === 'revoked');
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

function assertCurrentStateRelationships(state: PersistedBridgeState, hostId: string): void {
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

function assertCurrentPublicationRelationships(state: PersistedBridgeState): void {
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

function assertCurrentRuntimeRelationships(state: PersistedBridgeState, spool: LocalSpoolFileV2, hostId: string): void {
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

function hasResetSourceRelationships(
  intent: RuntimeResetIntentV1, state: Record<string, unknown>, spool: Record<string, unknown>, hostId: string,
): boolean {
  if (intent.fromSchemaVersion === LEGACY_RUNTIME_STATE_SCHEMA_VERSION) {
    return hasRecognizedPriorRuntimeRelationships(state, spool);
  }
  return isObsoleteStateRecord(state, hostId)
    && isSpoolRecordForSchema(spool, intent.fromSchemaVersion, hostId,
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
function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(value).every((key) => allowedSet.has(key));
}
function hasExactKeys(value: Record<string, unknown>, required: readonly string[]): boolean {
  return Object.keys(value).length === required.length && required.every((key) => key in value);
}
function hasExactOptionalKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[]): boolean {
  return required.every((key) => key in value) && hasOnlyKeys(value, [...required, ...optional]);
}

function assertEventSessionBinding(event: CanonicalEvent, session: CanonicalSessionState): void {
  if (event.hostId !== session.hostId || event.sessionId !== session.sessionId || event.provider !== session.provider
    || event.status !== session.status || session.lastEventId !== event.eventId) {
    throw new TypeError('pending Event requires its corresponding terminal Session snapshot');
  }
}

function isNewerTerminalSession(current: CanonicalSessionState, pending: CanonicalSessionState): boolean {
  if (!current.lastEventId || current.lastEventId === pending.lastEventId) return false;
  return current.updatedAt.localeCompare(pending.updatedAt) >= 0;
}
