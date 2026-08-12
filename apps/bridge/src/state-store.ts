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
import type { CanonicalEvent, CanonicalSessionState, CommandResult, HostProjection, ReplaceE2ECurrentSessionsRequestV1 } from '@ariava/protocol';
import { base64UrlDecode, e2eCurrentSessionsSemanticDigestV1 } from '@ariava/protocol';
import type {
  BridgeRuntimeHealth,
  DriverRuntimeHealth,
  EventUploadCompletionV1,
  PendingSessionHandle,
  PersistedBridgeState,
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

export const BRIDGE_RUNTIME_STATE_SCHEMA_VERSION = 3 as const;
const OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION = 2 as const;
const LEGACY_RUNTIME_STATE_SCHEMA_VERSION = 1 as const;
const RESET_INTENT_VERSION = 1 as const;
const ABSENT_HASH = 'absent';
const MAX_RECENT_EVENTS = 200;
const MAX_COMMAND_RESULTS = 200;
const EMPTY_SNAPSHOT: PersistedCurrentSessionsSnapshotState = {
  version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0,
};

function emptyState(runtimeResetEpoch = randomUUID()): PersistedBridgeState {
  return {
    schemaVersion: BRIDGE_RUNTIME_STATE_SCHEMA_VERSION, runtimeResetEpoch, host: null, sessions: {}, sessionDrivers: {},
    reconciledDrivers: {}, recentEvents: [], sessionRevisions: {}, pendingHandles: {}, commandResults: {}, seenCommands: {},
    currentSessionsSnapshot: structuredClone(EMPTY_SNAPSHOT), runtimeHealth: { status: 'healthy', drivers: [] },
  };
}

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

type RuntimeResetPhase = 'before-intent' | 'after-intent' | 'after-spool' | 'after-state' | 'after-cleanup';
export interface BridgeStateStoreOptions { deferRuntimePreflight?: boolean; runtimeCoordinator?: RuntimeCoordinator }
export interface RuntimeResetHooks { write?: SecureFileWriteHooks; remove?: SecureFileRemoveHooks }

export class BridgeStateStore {
  private storedState: PersistedBridgeState;
  private spool?: LocalEncryptedSpool;
  private runtimeReady: boolean;
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
    this.reconcileTerminalCancellations();
    this.reconcileProducerEventReservations();
    this.reconcilePendingEventJournal();
    this.resumeEventUploadCompletions();
    return recovery;
  }

  private loadCurrentOrFresh(): PersistedBridgeState {
    if (!this.filePath || !pathHasFilesystemEvidence(this.filePath)) return emptyState();
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
      const intentPath = runtimeResetIntentPathForState(this.filePath);
      if (pathHasFilesystemEvidence(intentPath)) {
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
      if (stateRecord && isCurrentStateRecord(stateRecord)) {
        const state = parseCurrentState(stateRecord, hostId);
        if (!spoolRecord) throw new Error('current Bridge runtime spool is missing');
        const spool = parseCurrentSpoolRecord(spoolRecord, hostId, state.runtimeResetEpoch);
        assertCurrentRuntimeRelationships(state, spool, hostId);
        return state;
      }
      if (!stateRecord && !spoolRecord) {
        return this.initializeFreshRuntime(hostId, keyStore, resetStep, resetWriteHooks, resetRemoveHooks);
      }
      if (isRecognizedObsoleteRuntime(stateRecord, spoolRecord, hostId)) {
        return this.beginRuntimeReset(hostId, keyStore, stateBytes, spoolBytes,
          OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION,
          resetStep, resetWriteHooks, resetRemoveHooks) as PersistedBridgeState;
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
    return this.beginRuntimeReset(hostId, keyStore, undefined, undefined,
      OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION,
      resetStep, resetWriteHooks, resetRemoveHooks) as PersistedBridgeState;
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
  setHost(host: HostProjection): void { this.state.host = sanitizePersistedHost(host); this.persist(); }
  getHost(): HostProjection | null { return this.state.host; }

  getRuntimeHealth(): BridgeRuntimeHealth {
    const health = this.state.runtimeHealth ?? { status: 'healthy' as const, drivers: [] };
    return structuredClone({
      ...health,
      drivers: [...health.drivers].sort((left, right) => left.driver.localeCompare(right.driver)),
    });
  }
  recordDriverReconciliationFailure(driver: string, seenAt: string, nextRetryAt: string): DriverRuntimeHealth {
    const nextState = structuredClone(this.state);
    const health = nextState.runtimeHealth ?? { status: 'healthy' as const, drivers: [] };
    const existing = health.drivers.find((item) => item.driver === driver);
    const degradation: DriverRuntimeHealth = existing
      ? { ...existing, count: existing.count + 1, lastSeenAt: seenAt, nextRetryAt }
      : { driver, code: 'driver_reconciliation_failed', count: 1, firstSeenAt: seenAt, lastSeenAt: seenAt, nextRetryAt };
    health.drivers = [...health.drivers.filter((item) => item.driver !== driver), degradation]
      .sort((left, right) => left.driver.localeCompare(right.driver));
    health.status = 'degraded';
    nextState.runtimeHealth = health;
    this.commit(nextState);
    return structuredClone(degradation);
  }
  recordDriverReconciliationSuccess(driver: string): { count: number } | undefined {
    const nextState = structuredClone(this.state);
    const health = nextState.runtimeHealth ?? { status: 'healthy' as const, drivers: [] };
    const recovered = health.drivers.find((item) => item.driver === driver);
    if (!recovered) return undefined;
    health.drivers = health.drivers.filter((item) => item.driver !== driver);
    health.status = health.drivers.length > 0 || health.relayPresence ? 'degraded' : 'healthy';
    nextState.runtimeHealth = health;
    this.commit(nextState);
    return { count: recovered.count };
  }
  recordRelayPresenceFailure(seenAt: string, nextRetryAt: string): void {
    const nextState = structuredClone(this.state);
    const health = nextState.runtimeHealth ?? { status: 'healthy' as const, drivers: [] };
    const existing = health.relayPresence;
    health.relayPresence = existing
      ? { ...existing, count: existing.count + 1, lastSeenAt: seenAt, nextRetryAt }
      : { code: 'relay_presence_refresh_failed', count: 1, firstSeenAt: seenAt, lastSeenAt: seenAt, nextRetryAt };
    health.status = 'degraded';
    nextState.runtimeHealth = health;
    this.commit(nextState);
  }
  recordRelayPresenceSuccess(): { count: number } | undefined {
    const nextState = structuredClone(this.state);
    const health = nextState.runtimeHealth ?? { status: 'healthy' as const, drivers: [] };
    const recovered = health.relayPresence;
    if (!recovered) return undefined;
    delete health.relayPresence;
    health.status = health.drivers.length > 0 ? 'degraded' : 'healthy';
    nextState.runtimeHealth = health;
    this.commit(nextState);
    return { count: recovered.count };
  }

  replaceDriverSessions(driverName: string, sessions: CanonicalSessionState[]): void {
    const nextState = structuredClone(this.state);
    const nextIds = new Set(sessions.map((session) => session.sessionId));
    for (const [sessionId, registeredDriver] of Object.entries(nextState.sessionDrivers)) if (registeredDriver === driverName && !nextIds.has(sessionId)) {
      delete nextState.sessionDrivers[sessionId]; delete nextState.sessions[sessionId];
    }

    for (const session of sessions) { nextState.sessions[session.sessionId] = session; nextState.sessionDrivers[session.sessionId] = driverName; }
    nextState.reconciledDrivers[driverName] = true;
    this.commit(nextState);
  }
  listSessions(): CanonicalSessionState[] { return Object.values(this.state.sessions).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)); }
  hasReconciledDriver(driverName: string): boolean { return this.state.reconciledDrivers[driverName] === true; }
  getSession(sessionId: string): CanonicalSessionState | undefined { return this.state.sessions[sessionId]; }
  getDriverNameForSession(sessionId: string): string | undefined { return this.state.sessionDrivers[sessionId]; }
  setSessionDriver(sessionId: string, driverName: string, session?: CanonicalSessionState): void {
    const nextState = structuredClone(this.state);
    const boundSession = session ?? nextState.sessions[sessionId];
    if (!boundSession || boundSession.sessionId !== sessionId || boundSession.provider !== driverName) {
      throw new TypeError('Session driver requires its canonical Session');
    }
    nextState.sessions[sessionId] = boundSession;
    nextState.sessionDrivers[sessionId] = driverName;
    this.commit(nextState);
  }
  removeSession(sessionId: string, expectedDriverName?: string): boolean {
    const driverName = this.state.sessionDrivers[sessionId];
    if (expectedDriverName !== undefined && driverName !== expectedDriverName) return false;
    const existed = sessionId in this.state.sessions || driverName !== undefined;
    if (!existed) return false;
    const nextState = structuredClone(this.state);
    delete nextState.sessions[sessionId]; delete nextState.sessionDrivers[sessionId];
    this.commit(nextState);
    return true;
  }
  removeSessionDriver(sessionId: string): void {
    if (!(sessionId in this.state.sessionDrivers)) return;
    const nextState = structuredClone(this.state);
    delete nextState.sessionDrivers[sessionId];
    this.commit(nextState);
  }
  updateSession(sessionId: string, patch: Partial<CanonicalSessionState>): CanonicalSessionState | undefined {
    const current = this.getSession(sessionId); if (!current) return undefined;
    const next = { ...current, ...patch }; this.state.sessions[sessionId] = next; this.persist(); return next;
  }

  async createCurrentSessionsPublication(hostId: string, sessions: CanonicalSessionState[], recipientSetVersion: number, observedAt: string, minimumRevision = 0): Promise<{ request: ReplaceE2ECurrentSessionsRequestV1; contentDigest: string } | undefined> {
    const contentDigest = await e2eCurrentSessionsSemanticDigestV1(hostId, sessions);
    const current = this.state.currentSessionsSnapshot;
    if (current.lastAcceptedContentDigest === contentDigest
      && current.lastAcceptedRecipientSetVersion === recipientSetVersion && current.lastAcceptedRevision >= minimumRevision) return undefined;
    const revision = Math.max(current.lastAllocatedRevision, current.lastAcceptedRevision, minimumRevision) + 1;
    const request: ReplaceE2ECurrentSessionsRequestV1 = { hostId, revision, observedAt, recipientSetVersion, sessions: [] };
    this.state.currentSessionsSnapshot = { ...current, version: 1, lastAllocatedRevision: revision };
    this.persist();
    return { request, contentDigest };
  }
  getCurrentSessionsSnapshotState(): PersistedCurrentSessionsSnapshotState { return structuredClone(this.state.currentSessionsSnapshot); }
  acceptCurrentSessionsPublication(request: ReplaceE2ECurrentSessionsRequestV1, digest: string, contentDigest: string): boolean {
    const current = this.state.currentSessionsSnapshot;
    if (request.revision < current.lastAcceptedRevision) return false;
    this.state.currentSessionsSnapshot = { version: 1, lastAllocatedRevision: Math.max(current.lastAllocatedRevision, request.revision),
      lastAcceptedRevision: Math.max(current.lastAcceptedRevision, request.revision), lastAcceptedDigest: digest,
      lastAcceptedContentDigest: contentDigest, lastAcceptedRecipientSetVersion: request.recipientSetVersion };
    this.persist(); return true;
  }
  noteCurrentSessionsSnapshotRevisionLowerBound(revision: number): void {
    const current = this.state.currentSessionsSnapshot;
    const nextAllocated = Math.max(current.lastAllocatedRevision, revision);
    if (nextAllocated === current.lastAllocatedRevision) return;
    this.state.currentSessionsSnapshot = { ...current, lastAllocatedRevision: nextAllocated };
    this.persist();
  }
  getProducerEventReservation(sessionId: string, fingerprint: string): PersistedProducerEventReservationV1 | undefined {
    const reservation = this.state.producerEventReservations?.[producerReservationKey(sessionId, fingerprint)];
    return reservation && structuredClone(reservation);
  }
  reserveProducerEvent(reservation: PersistedProducerEventReservationV1): void {
    const key = producerReservationKey(reservation.sessionId, reservation.fingerprint);
    const existing = this.state.producerEventReservations?.[key];
    if (existing) {
      if (existing.eventId !== reservation.eventId || existing.createdAt !== reservation.createdAt) {
        throw new TypeError('producer Event reservation conflict');
      }
      return;
    }
    const nextState = structuredClone(this.state);
    const reservations = { ...(nextState.producerEventReservations ?? {}), [key]: structuredClone(reservation) };
    const retained = Object.entries(reservations).slice(-200);
    nextState.producerEventReservations = Object.fromEntries(retained);
    this.commit(nextState);
  }
  getProducerEventTuple(eventId: string, fingerprint: string): { event: CanonicalEvent; session: CanonicalSessionState } | undefined {
    return this.openProducerTuple('event-reservation-v2', eventId, fingerprint)
      ?? this.openProducerTuple('event-source-v2', eventId, fingerprint);
  }
  reserveProducerEventTuple(event: CanonicalEvent, terminalSession: CanonicalSessionState, fingerprint: string): void {
    this.enqueuePendingEvent(event, terminalSession, fingerprint, 'event-reservation-v2');
  }
  getTerminalEventCancellation(sessionId: string): PersistedProducerEventReservationV1 | undefined {
    const reservation = Object.values(this.state.producerEventReservations ?? {}).find((candidate) => {
      if (candidate.sessionId !== sessionId) return false;
      return this.spool?.get(candidate.eventId)?.payloadKind === 'event-reservation-v2';
    });
    return reservation && structuredClone(reservation);
  }
  cancelTerminalEvent(input: { eventId: string; sessionId: string; fingerprint: string; removeSession?: boolean;
    nextDriverName?: string; createdAt?: string }): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const reservationKey = producerReservationKey(input.sessionId, input.fingerprint);
    const reservation = this.state.producerEventReservations?.[reservationKey];
    const source = this.spool.get(input.eventId);
    if ((!reservation || reservation.eventId !== input.eventId) && source?.payloadKind !== 'event-reservation-v2') return;
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
      payloadKind: 'terminal-cancellation-v2', createdAt: cancellation.createdAt,
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
    const intents = new Map(this.spool.list('terminal-cancellation-v2').map((item) => [item.eventId, item]));
    for (const cancellation of Object.values(this.state.terminalCancellations ?? {})) {
      const item = intents.get(cancellation.eventId);
      if (item) {
        const persisted = this.openSpoolJson(item.spoolItemId);
        if (JSON.stringify(persisted) !== JSON.stringify(cancellation)) {
          throw new TypeError('terminal cancellation recovery journal conflicts with state');
        }
      } else if (this.spool.get(cancellation.eventId)) {
        throw new Error('terminal cancellation recovery journal is incomplete');
      }
      this.finishTerminalCancellation(cancellation);
      if (this.state.terminalCancellations?.[cancellation.eventId]) {
        throw new Error('terminal cancellation recovery requires retry');
      }
      intents.delete(cancellation.eventId);
    }
    for (const item of intents.values()) this.spool.remove(item.spoolItemId);
  }

  appendRecentEvent(event: CanonicalEvent): void {
    const nextState = structuredClone(this.state);
    nextState.recentEvents = retainRecentEvents([event, ...nextState.recentEvents], nextState.pendingHandles);
    this.commit(nextState);
  }
  queuePendingEvent(event: CanonicalEvent, terminalSession: CanonicalSessionState, producerFingerprint?: string): void {
    assertEventSessionBinding(event, terminalSession);
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const existingKind = this.spool.get(event.eventId)?.payloadKind;
    if (producerFingerprint && existingKind === 'event-reservation-v2') {
      this.promoteProducerEventTuple(event, terminalSession, producerFingerprint);
    } else if (producerFingerprint && existingKind === 'event-source-v2') {
      const existing = this.openProducerTuple('event-source-v2', event.eventId, producerFingerprint);
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
    payloadKind: 'event-source-v2' | 'event-reservation-v2' = 'event-source-v2'): void {
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
    const existing = this.openProducerTuple('event-reservation-v2', event.eventId, fingerprint);
    if (!existing || JSON.stringify(existing) !== JSON.stringify({ event, session: terminalSession })) {
      throw new TypeError('pending Event retry journal conflicts with the bound tuple');
    }
    this.spool.replace([event.eventId], [{ spoolItemId: event.eventId, sessionId: event.sessionId, eventId: event.eventId,
      payloadKind: 'event-source-v2', createdAt: event.createdAt, plaintext: new TextEncoder().encode(serialized) }]);
  }
  private openProducerTuple(kind: 'event-source-v2' | 'event-reservation-v2', eventId: string, fingerprint: string):
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
    for (const item of this.spool.list('event-reservation-v2')) {
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
    for (const { event, session, producerFingerprint } of this.peekPendingUploadRecords()) {
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
    return this.spool.list('event-source-v2')
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
  getInflightEventUpload(eventId: string): unknown | undefined { return this.openSpoolJson(`inflight:event:${eventId}`); }
  persistInflightEventUpload(eventId: string, sessionId: string, upload: unknown): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    this.spool.enqueue({ spoolItemId: `inflight:event:${eventId}`, sessionId, eventId, payloadKind: 'event-upload-v2',
      createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(upload)) });
  }
  replaceInflightEventUpload(eventId: string, sessionId: string, upload: unknown): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    this.spool.replace([`inflight:event:${eventId}`], [{ spoolItemId: `inflight:event:${eventId}`, sessionId, eventId,
      payloadKind: 'event-upload-v2', createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(upload)) }]);
  }
  removeInflightEventUpload(eventId: string): void { this.spool?.remove(`inflight:event:${eventId}`); }
  listInflightSessionIds(): string[] { return this.spool?.list('session-upload-v2').map((item) => item.sessionId) ?? []; }
  getInflightSessionUpload(sessionId: string): unknown | undefined { return this.openSpoolJson(`inflight:session:${sessionId}`); }
  persistInflightSessionUpload(sessionId: string, upload: unknown): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    this.spool.enqueue({ spoolItemId: `inflight:session:${sessionId}`, sessionId, payloadKind: 'session-upload-v2',
      createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(upload)) });
  }
  replaceInflightSessionUpload(sessionId: string, upload: unknown): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    this.spool.replace([`inflight:session:${sessionId}`], [{ spoolItemId: `inflight:session:${sessionId}`, sessionId,
      payloadKind: 'session-upload-v2', createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(upload)) }]);
  }
  removeInflightSessionUpload(sessionId: string): void { this.spool?.remove(`inflight:session:${sessionId}`); }
  clearInflightSessionUploads(sessionIds?: readonly string[]): number {
    const ids = sessionIds ? new Set(sessionIds) : undefined;
    let removed = 0;
    if (!this.spool) return 0;
    const shouldRemove = (sessionId: string): boolean => !ids || ids.has(sessionId);
    for (const item of this.spool.list('session-upload-v2')) {
      if (!shouldRemove(item.sessionId)) continue;
      this.spool.remove(item.spoolItemId);
      removed += 1;
    }
    if (removed > 0) this.persist();
    return removed;
  }
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
      payloadKind: 'event-dead-letter-v2',
      createdAt: quarantinedAt,
      plaintext: new TextEncoder().encode(JSON.stringify(record)),
    }]);
    this.persist();
    return true;
  }
  getQuarantinedEventRecord(eventId: string): unknown | undefined { return this.openSpoolJson(`dead-letter:event:${eventId}`); }
  currentSessionRevision(sessionId: string): number { return this.state.sessionRevisions[sessionId] ?? 0; }
  nextSessionRevision(sessionId: string): number { return this.currentSessionRevision(sessionId) + 1; }
  commitSessionRevision(sessionId: string, revision: number): void {
    const current = this.currentSessionRevision(sessionId);
    if (revision === current) return;
    if (revision !== current + 1) throw new TypeError('session revision must advance monotonically');
    this.state.sessionRevisions[sessionId] = revision; this.persist();
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
    if (!Number.isSafeInteger(version) || version < 1 || (this.state.recipientSetVersion !== undefined && version < this.state.recipientSetVersion)) throw new TypeError('recipient set version rollback rejected');
    this.state.recipientSetVersion = version; this.persist();
  }
  queuePendingSessionHandle(handle: PendingSessionHandle): void {
    const event = this.state.recentEvents.find((candidate) => candidate.eventId === handle.handledThroughEventId);
    if (!event || event.hostId !== handle.hostId || event.sessionId !== handle.sessionId) {
      throw new TypeError('handledThroughEventId must reference a durable Event for the same Host and Session');
    }
    if (handle.handledThroughEventCreatedAt !== undefined && handle.handledThroughEventCreatedAt !== event.createdAt) {
      throw new TypeError('handledThroughEventCreatedAt does not match the durable Event');
    }
    const boundHandle = { ...handle, handledThroughEventCreatedAt: event.createdAt };
    const key = sessionHandleKey(boundHandle.hostId, boundHandle.sessionId);
    const current = this.state.pendingHandles[key];
    if (current && comparePendingHandles(boundHandle, current) < 0) {
      throw new TypeError('handledThroughEventId is older than the pending durable cursor');
    }
    const nextState = structuredClone(this.state);
    nextState.pendingHandles[key] = boundHandle;
    nextState.recentEvents = retainRecentEvents(nextState.recentEvents, nextState.pendingHandles);
    this.commit(nextState);
  }
  peekPendingSessionHandles(): PendingSessionHandle[] { return Object.values(this.state.pendingHandles); }
  removePendingSessionHandle(hostId: string, sessionId: string, handledThroughEventId?: string): void {
    const key = sessionHandleKey(hostId, sessionId); const current = this.state.pendingHandles[key]; if (!current) return;
    if (handledThroughEventId && current.handledThroughEventId !== handledThroughEventId) return;
    const nextState = structuredClone(this.state);
    delete nextState.pendingHandles[key];
    this.commit(nextState);
  }
  getCommandResult(commandId: string): CommandResult | undefined { return this.state.commandResults[commandId]; }
  hasSeenCommand(commandId: string): boolean { return commandId in this.state.seenCommands; }
  rememberCommandResult(result: CommandResult, expected: { commandId: string; hostId: string; sessionId: string }): void {
    if (result.commandId !== expected.commandId || result.hostId !== expected.hostId || result.sessionId !== expected.sessionId) {
      throw new TypeError('command result does not match its trusted command binding');
    }
    const nextState = structuredClone(this.state);
    nextState.commandResults[result.commandId] = structuredClone(result);
    nextState.seenCommands[result.commandId] = result.updatedAt;
    const retainedIds = new Set(Object.keys(nextState.commandResults).slice(-MAX_COMMAND_RESULTS));
    nextState.commandResults = Object.fromEntries(
      Object.entries(nextState.commandResults).filter(([commandId]) => retainedIds.has(commandId)),
    );
    nextState.seenCommands = Object.fromEntries(
      Object.entries(nextState.seenCommands).filter(([commandId]) => retainedIds.has(commandId)),
    );
    this.commit(nextState);
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
function producerReservationKey(sessionId: string, fingerprint: string): string { return `${sessionId}\n${fingerprint}`; }
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
  return value !== undefined && ('write' in value || 'remove' in value);
}

function isCurrentStateRecord(value: Record<string, unknown>): boolean {
  if (!hasExactOptionalKeys(value, CURRENT_STATE_REQUIRED_KEYS, CURRENT_STATE_OPTIONAL_KEYS)
    || value.schemaVersion !== BRIDGE_RUNTIME_STATE_SCHEMA_VERSION || !isRuntimeEpoch(value.runtimeResetEpoch)
    || !(value.host === null || isCurrentHost(value.host)) || !isValueMap(value.sessions, isCurrentSession)
    || !isStringMap(value.sessionDrivers) || !isTrueMap(value.reconciledDrivers)
    || !Array.isArray(value.recentEvents) || !value.recentEvents.every(isCurrentEvent)
    || !isNonNegativeIntegerMap(value.sessionRevisions) || !isValueMap(value.pendingHandles, isCurrentPendingHandle)
    || !isValueMap(value.commandResults, isCurrentCommandResult) || !isStringMap(value.seenCommands)
    || !isCurrentSnapshot(value.currentSessionsSnapshot)) return false;
  if (value.recipientSetVersion !== undefined && !isPositiveSafeInteger(value.recipientSetVersion)) return false;
  return (value.eventUploadCompletions === undefined || isValueMap(value.eventUploadCompletions, isCurrentEventCompletion))
    && (value.producerEventReservations === undefined || isValueMap(value.producerEventReservations, isCurrentProducerReservation))
    && (value.terminalCancellations === undefined || isValueMap(value.terminalCancellations, isCurrentTerminalCancellation))
    && (value.runtimeHealth === undefined || isCurrentRuntimeHealth(value.runtimeHealth));
}

function parseCurrentState(value: unknown, hostId?: string): PersistedBridgeState {
  if (!isRecord(value) || !isCurrentStateRecord(value)) throw new Error('Bridge runtime state schema is invalid');
  const state = structuredClone(value) as unknown as PersistedBridgeState;
  if (hostId !== undefined) assertCurrentStateRelationships(state, hostId);
  return state;
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
  if (value.commandResults !== undefined && !isValueMap(value.commandResults, isCurrentCommandResult)) return false;
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
  if (!state || !spool || !isObsoleteStateRecord(state, hostId) || !isSpoolRecordForSchema(
    spool, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, hostId, state.runtimeResetEpoch as string, 'current',
  )) return false;
  return hasRecognizedPriorRuntimeRelationships(state, spool);
}

function isObsoleteStateRecord(value: Record<string, unknown>, hostId: string): boolean {
  if (!hasExactOptionalKeys(value, CURRENT_STATE_REQUIRED_KEYS, CURRENT_STATE_OPTIONAL_KEYS)
    || value.schemaVersion !== OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION || !isRuntimeEpoch(value.runtimeResetEpoch)
    || !(value.host === null || isCurrentHost(value.host)) || !isValueMap(value.sessions, isCurrentSession)
    || !isStringMap(value.sessionDrivers) || !isTrueMap(value.reconciledDrivers)
    || !Array.isArray(value.recentEvents) || !value.recentEvents.every(isObsoleteEvent)
    || !isNonNegativeIntegerMap(value.sessionRevisions) || !isValueMap(value.pendingHandles, isCurrentPendingHandle)
    || !isValueMap(value.commandResults, isCurrentCommandResult) || !isStringMap(value.seenCommands)
    || !isCurrentSnapshot(value.currentSessionsSnapshot)) return false;
  if (value.recipientSetVersion !== undefined && !isPositiveSafeInteger(value.recipientSetVersion)) return false;
  if ((value.eventUploadCompletions !== undefined && !isValueMap(value.eventUploadCompletions, isCurrentEventCompletion))
    || (value.producerEventReservations !== undefined && !isValueMap(value.producerEventReservations, isCurrentProducerReservation))
    || (value.terminalCancellations !== undefined && !isValueMap(value.terminalCancellations, isCurrentTerminalCancellation))
    || (value.runtimeHealth !== undefined && !isCurrentRuntimeHealth(value.runtimeHealth))) return false;
  try {
    assertCurrentStateRelationships(value as unknown as PersistedBridgeState, hostId);
    return true;
  } catch { return false; }
}

function parseCurrentSpoolRecord(value: Record<string, unknown>, hostId: string, epoch: string): LocalSpoolFileV2 {
  if (!isSpoolRecordForSchema(value, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION, hostId, epoch, 'current')) {
    throw new Error('current Bridge runtime spool schema is invalid');
  }
  return structuredClone(value) as unknown as LocalSpoolFileV2;
}

function isSpoolRecordForSchema(
  value: Record<string, unknown>, schemaVersion: 2 | 3, hostId: string, epoch: string, kind: 'current' | 'standalone-v2',
): boolean {
  return hasExactKeys(value, ['version', 'runtimeStateSchemaVersion', 'runtimeResetEpoch', 'hostId', 'keyId', 'items'])
    && value.version === 2 && value.runtimeStateSchemaVersion === schemaVersion
    && value.runtimeResetEpoch === epoch && value.hostId === hostId && isVerifier(value.keyId)
    && Array.isArray(value.items) && value.items.every((item) => isRawSpoolItem(item, hostId, kind));
}

function isRecognizedPriorSpoolRecord(value: Record<string, unknown>, hostId: string): boolean {
  if (hasExactKeys(value, ['version', 'items']) && value.version === 1 && Array.isArray(value.items)
    && value.items.every((item) => isRawSpoolItem(item, hostId, 'v1'))) {
    return hasRecognizedPriorSpoolRelationships(value.items);
  }
  return isSpoolRecordForSchema(value, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, hostId, 'standalone', 'standalone-v2')
    && hasRecognizedPriorSpoolRelationships(value.items as unknown[]);
}

function isRawSpoolItem(value: unknown, hostId: string, kind: 'current' | 'v1' | 'standalone-v2'): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value,
    ['version', 'spoolItemId', 'hostId', 'sessionId', 'payloadKind', 'nonce', 'ciphertext', 'aadVersion', 'createdAt'],
    ['eventId'])) return false;
  if (value.version !== 1 || value.hostId !== hostId || !isNonEmptyString(value.spoolItemId)
    || !isNonEmptyString(value.sessionId) || (value.eventId !== undefined && !isNonEmptyString(value.eventId))
    || !(kind === 'v1' ? PRIOR_V1_SPOOL_KINDS.has(value.payloadKind as string) : isRecognizedLocalSpoolPayloadKind(value.payloadKind))
    || !isNonEmptyString(value.nonce) || !isNonEmptyString(value.ciphertext) || value.aadVersion !== 1
    || !isNonEmptyString(value.createdAt)) return false;
  try {
    base64UrlDecode(value.nonce, 12, 'spool nonce');
    return base64UrlDecode(value.ciphertext, undefined, 'spool ciphertext').length >= 16;
  } catch { return false; }
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
    || (from === OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION && to === BRIDGE_RUNTIME_STATE_SCHEMA_VERSION);
}

function emptyStateForSchema(schemaVersion: 2 | 3, epoch: string): Record<string, unknown> {
  return { ...emptyState(epoch), schemaVersion };
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
  if (intent.toSchemaVersion === BRIDGE_RUNTIME_STATE_SCHEMA_VERSION) {
    const state = parseCurrentState(stateTarget, intent.hostId);
    const spool = parseCurrentSpoolRecord(spoolTarget as unknown as Record<string, unknown>, intent.hostId, intent.epoch);
    assertCurrentRuntimeRelationships(state, spool, intent.hostId);
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
    const valid = intent.toSchemaVersion === BRIDGE_RUNTIME_STATE_SCHEMA_VERSION
      ? !!parsed && isCurrentStateRecord(parsed)
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
      : !!spool && isSpoolRecordForSchema(spool, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, hostId,
        (spool.runtimeResetEpoch as string), 'current');
    if (!valid) throw new Error('Bridge runtime reset spool source schema is invalid');
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
function isVerifier(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value);
}
function isRuntimeEpoch(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function isNonEmptyString(value: unknown): value is string { return typeof value === 'string' && value.length > 0; }
function isPositiveSafeInteger(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) > 0; }
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
  'openingText', 'latestActivityText', 'workingDirectory', 'hbaseSessionKey', 'harnessProvider', 'actionablePrompt',
  'lastEventId', 'snoozedUntil',
] as const;
function isCurrentSession(value: unknown): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, SESSION_REQUIRED_KEYS, SESSION_OPTIONAL_KEYS)
    || !SESSION_REQUIRED_KEYS.filter((key) => key !== 'status').every((key) => isNonEmptyString(value[key]))
    || !['idle', 'working', 'need_human'].includes(value.status as string)) return false;
  return SESSION_OPTIONAL_KEYS.every((key) => value[key] === undefined
    || (key === 'actionablePrompt' ? isCurrentActionablePrompt(value[key]) : typeof value[key] === 'string'));
}
const EVENT_REQUIRED_KEYS = [
  'eventId', 'hostId', 'sessionId', 'provider', 'type', 'status', 'agentText', 'createdAt',
] as const;
const EVENT_OPTIONAL_KEYS = [
  'humanText', 'projectName', 'contextText', 'workingDirectory', 'hbaseSessionKey', 'harnessProvider',
  'actionablePrompt', 'correlationId', 'needHuman',
] as const;
function isCurrentEvent(value: unknown): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, EVENT_REQUIRED_KEYS, EVENT_OPTIONAL_KEYS)
    || !EVENT_REQUIRED_KEYS.filter((key) => key !== 'type' && key !== 'status').every((key) => isNonEmptyString(value[key]))) return false;
  if (value.type === 'done') { if (value.status !== 'idle' || value.needHuman !== undefined) return false; }
  else if (value.type === 'need_human') { if (value.status !== 'need_human' || !isCurrentNeedHuman(value.needHuman)) return false; }
  else return false;
  return EVENT_OPTIONAL_KEYS.every((key) => value[key] === undefined || key === 'needHuman'
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
function isCurrentCommandResult(value: unknown): boolean {
  return isRecord(value) && hasExactOptionalKeys(value,
    ['commandId', 'hostId', 'sessionId', 'accepted', 'status', 'message', 'updatedAt'], ['correlationId'])
    && ['commandId', 'hostId', 'sessionId', 'message', 'updatedAt'].every((key) => isNonEmptyString(value[key]))
    && typeof value.accepted === 'boolean'
    && ['queued', 'delivered', 'executed', 'expired', 'rejected', 'failed'].includes(value.status as string)
    && (value.correlationId === undefined || isNonEmptyString(value.correlationId));
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
  for (const sessionId of Object.keys(state.sessionDrivers)) {
    if (!state.sessions[sessionId]) throw new Error('Bridge runtime Session driver binding is invalid');
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
  for (const [commandId, result] of Object.entries(state.commandResults)) {
    const session = state.sessions[result.sessionId];
    const lastEvent = session?.lastEventId ? events.get(session.lastEventId) : undefined;
    if (commandId !== result.commandId || result.hostId !== hostId
      || (session && lastEvent && lastEvent.sessionId !== result.sessionId)
      || state.seenCommands[commandId] !== result.updatedAt) {
      throw new Error('Bridge runtime command result binding is invalid');
    }
  }
  if (Object.keys(state.seenCommands).some((commandId) => !state.commandResults[commandId])) {
    throw new Error('Bridge runtime seen-command binding is invalid');
  }
  for (const [eventId, completion] of Object.entries(state.eventUploadCompletions ?? {})) {
    const currentRevision = state.sessionRevisions[completion.sessionId] ?? 0;
    const event = events.get(eventId);
    if (eventId !== completion.eventId || !sessions.has(completion.sessionId)
      || !event || event.sessionId !== completion.sessionId
      || currentRevision < completion.revision - 1 || currentRevision > completion.revision) {
      throw new Error('Bridge runtime Event completion binding is invalid');
    }
  }
  for (const [key, reservation] of Object.entries(state.producerEventReservations ?? {})) {
    const event = events.get(reservation.eventId);
    if (key !== producerReservationKey(reservation.sessionId, reservation.fingerprint) || !sessions.has(reservation.sessionId)
      || (event && event.sessionId !== reservation.sessionId)) {
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
    const eventKind = item.payloadKind !== 'session-source-v2' && item.payloadKind !== 'session-upload-v2';
    if (eventKind && !item.eventId) throw new Error('Bridge runtime spool Event binding is invalid');
    if (item.payloadKind === 'event-source-v2') {
      const event = state.recentEvents.find((candidate) => candidate.eventId === item.eventId);
      if (item.spoolItemId !== item.eventId || (event && event.sessionId !== item.sessionId)) {
        throw new Error('Bridge runtime Event source binding is invalid');
      }
    }
    if (item.payloadKind === 'event-reservation-v2') {
      const reservation = Object.values(state.producerEventReservations ?? {})
        .find((candidate) => candidate.eventId === item.eventId);
      const cancellation = state.terminalCancellations?.[item.eventId!];
      if (item.spoolItemId !== item.eventId
        || (reservation && reservation.sessionId !== item.sessionId)
        || (cancellation && cancellation.sessionId !== item.sessionId)) {
        throw new Error('Bridge runtime Event reservation binding is invalid');
      }
    }
    if (item.payloadKind === 'event-upload-v2') {
      const event = state.recentEvents.find((candidate) => candidate.eventId === item.eventId);
      if (item.spoolItemId !== `inflight:event:${item.eventId}` || (event && event.sessionId !== item.sessionId)) {
        throw new Error('Bridge runtime Event upload binding is invalid');
      }
    }
    if (item.payloadKind === 'event-dead-letter-v2') {
      const event = state.recentEvents.find((candidate) => candidate.eventId === item.eventId);
      if (item.spoolItemId !== `dead-letter:event:${item.eventId}` || (event && event.sessionId !== item.sessionId)) {
        throw new Error('Bridge runtime Event dead-letter binding is invalid');
      }
    }
    if (item.payloadKind === 'session-upload-v2' && item.spoolItemId !== `inflight:session:${item.sessionId}`) {
      throw new Error('Bridge runtime Session upload binding is invalid');
    }
    if (item.payloadKind === 'terminal-cancellation-v2') {
      const cancellation = state.terminalCancellations?.[item.eventId!];
      if (item.spoolItemId !== terminalCancellationItemId(item.eventId!)
        || !cancellation || cancellation.sessionId !== item.sessionId) {
        throw new Error('Bridge runtime terminal cancellation spool binding is invalid');
      }
    }
  }
  for (const completion of Object.values(state.eventUploadCompletions ?? {})) {
    if (!completion.inflightRemoved && !ids.has(`inflight:event:${completion.eventId}`)) {
      throw new Error('Bridge runtime Event completion upload is missing');
    }
    if (!completion.sourceRemoved && !ids.has(completion.eventId)) throw new Error('Bridge runtime Event completion source is missing');
  }
  for (const cancellation of Object.values(state.terminalCancellations ?? {})) {
    const journal = ids.has(terminalCancellationItemId(cancellation.eventId));
    const source = ids.has(cancellation.eventId);
    if (!journal && source) throw new Error('Bridge runtime terminal cancellation journal is missing');
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
    && isSpoolRecordForSchema(spool, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, hostId,
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
  if (!isRecord(value) || !hasExactOptionalKeys(value, PRIOR_SESSION_REQUIRED_KEYS, SESSION_OPTIONAL_KEYS)
    || value.hostId !== hostId || !PRIOR_SESSION_REQUIRED_KEYS.filter((key) => key !== 'status').every((key) => isNonEmptyString(value[key]))
    || !['idle', 'working', 'blocked', 'done', 'unknown'].includes(value.status as string)) return false;
  return SESSION_OPTIONAL_KEYS.every((key) => value[key] === undefined
    || (key === 'actionablePrompt' ? isCurrentActionablePrompt(value[key]) : typeof value[key] === 'string'));
}

const OBSOLETE_EVENT_REQUIRED_KEYS = [...EVENT_REQUIRED_KEYS, 'typeLabel'] as const;

function isObsoleteEvent(value: unknown): boolean {
  if (!isRecord(value) || !hasExactOptionalKeys(value, OBSOLETE_EVENT_REQUIRED_KEYS, EVENT_OPTIONAL_KEYS)
    || !OBSOLETE_EVENT_REQUIRED_KEYS.filter((key) => key !== 'type' && key !== 'status')
      .every((key) => isNonEmptyString(value[key]))) {
    return false;
  }
  if (value.type === 'done') { if (value.status !== 'idle' || value.needHuman !== undefined) return false; }
  else if (value.type === 'need_human') { if (value.status !== 'need_human' || !isCurrentNeedHuman(value.needHuman)) return false; }
  else return false;
  return EVENT_OPTIONAL_KEYS.every((key) => value[key] === undefined || key === 'needHuman'
    || (key === 'actionablePrompt' ? isCurrentActionablePrompt(value[key]) : typeof value[key] === 'string'));
}

function isRecognizedPriorEvent(value: unknown, hostId: string): boolean {
  return isRecord(value)
    && hasExactOptionalKeys(value, OBSOLETE_EVENT_REQUIRED_KEYS, EVENT_OPTIONAL_KEYS.filter((key) => key !== 'needHuman'))
    && value.hostId === hostId && OBSOLETE_EVENT_REQUIRED_KEYS.filter((key) => key !== 'type' && key !== 'status')
      .every((key) => isNonEmptyString(value[key]))
    && ['working', 'blocked', 'done', 'question_requested'].includes(value.type as string)
    && ['idle', 'working', 'blocked', 'done', 'unknown'].includes(value.status as string)
    && EVENT_OPTIONAL_KEYS.filter((key) => key !== 'needHuman').every((key) => value[key] === undefined
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
