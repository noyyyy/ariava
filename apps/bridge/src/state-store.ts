import { readFileSync } from 'node:fs';
import { pathHasFilesystemEvidence, readSecureJson, writeSecureJson } from './host-manager/secure-files';
import type { ActiveSessionSnapshot, CanonicalEvent, CanonicalSessionState, CommandResult, HostProjection, ReplaceCurrentSessionsRequest } from '@ariava/protocol';
import { contentSha256 } from '@ariava/protocol';
import type { EventUploadCompletionV1, PendingCurrentSessionsSnapshot, PendingSessionHandle, PersistedBridgeState, PersistedCurrentSessionsSnapshotState } from './types';
import { LocalEncryptedSpool, createRuntimeSpoolKeyStore, spoolPathForState, type SpoolKeyStore } from './e2e/local-spool';

const EMPTY_STATE: PersistedBridgeState = {
  host: null, sessions: {}, sessionDrivers: {}, reconciledDrivers: {}, recentEvents: [], sessionRevisions: {},
  pendingHandles: {}, commandResults: {}, seenCommands: {},
  currentSessionsSnapshot: { version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 },
};

export class BridgeStateStore {
  private state: PersistedBridgeState;
  private spool?: LocalEncryptedSpool;
  constructor(private readonly filePath: string) { this.state = this.load(); }

  initializeEncryptedSpool(hostId: string, identityPath: string, platform: NodeJS.Platform | string, keyStore?: SpoolKeyStore,
    migrationStep?: (phase: 'journaled' | 'item-encrypted' | 'item-journaled' | 'completed', eventId?: string) => void): { droppedUnreadableItems: number } {
    this.spool = new LocalEncryptedSpool(spoolPathForState(this.filePath), hostId,
      keyStore ?? createRuntimeSpoolKeyStore(identityPath, platform));
    const legacy = this.state.pendingEvents ?? [];
    if (legacy.length || this.state.spoolMigration) {
      if (!this.state.spoolMigration) {
        this.state.spoolMigration = { version: 1, remainingEventIds: legacy.map((event) => event.eventId), startedAt: new Date().toISOString() };
        this.persist();
        migrationStep?.('journaled');
      }
      for (const eventId of [...this.state.spoolMigration.remainingEventIds]) {
        const event = legacy.find((candidate) => candidate.eventId === eventId);
        if (!event) throw new Error('legacy spool migration journal is inconsistent');
        this.enqueuePendingEvent(event);
        migrationStep?.('item-encrypted', eventId);
        this.state.spoolMigration.remainingEventIds = this.state.spoolMigration.remainingEventIds.filter((id) => id !== eventId);
        this.persist();
        migrationStep?.('item-journaled', eventId);
      }
      const markers = protectedMarkers(legacy);
      delete this.state.pendingEvents; delete this.state.spoolMigration; this.persist();
      migrationStep?.('completed');
      const stateText = readFileSync(this.filePath, 'utf8');
      if (markers.some((marker) => marker && stateText.includes(marker))) throw new Error('legacy pending event migration marker remains in state');
    } else if ('pendingEvents' in this.state) { delete this.state.pendingEvents; this.persist(); }
    const recovery = this.spool.recoverUnreadable();
    this.resumeEventUploadCompletions();
    return recovery;
  }

  private load(): PersistedBridgeState {
    if (!pathHasFilesystemEvidence(this.filePath)) return structuredClone(EMPTY_STATE);
    try {
      const parsed = readSecureJson<PersistedBridgeState & { pendingReads?: Record<string, LegacyPendingSessionRead> }>(this.filePath);
      const nextState: PersistedBridgeState = {
        ...structuredClone(EMPTY_STATE), ...withoutLegacyPendingReads(parsed),
        host: sanitizePersistedHost(parsed.host ?? null), sessions: parsed.sessions ?? {},
        sessionDrivers: parsed.sessionDrivers ?? {},
        reconciledDrivers: parsed.reconciledDrivers ?? inferLegacyReconciledDrivers(parsed.sessionDrivers),
        recentEvents: parsed.recentEvents ?? [], pendingEvents: parsed.pendingEvents ?? [],
        sessionRevisions: parsed.sessionRevisions ?? {}, eventUploadCompletions: parsed.eventUploadCompletions ?? {},
        pendingHandles: parsed.pendingHandles ?? migratePendingReads(parsed), commandResults: parsed.commandResults ?? {},
        seenCommands: parsed.seenCommands ?? {}, currentSessionsSnapshot: sanitizeSnapshotState(parsed.currentSessionsSnapshot),
      };
      if ((parsed.host && hasLegacyClaimCodeFields(parsed.host)) || parsed.pendingReads || !parsed.currentSessionsSnapshot) {
        writeSecureJson(this.filePath, nextState);
      }
      return nextState;
    } catch (error) { throw new Error('Bridge state file is invalid or insecure', { cause: error }); }
  }
  private persist(): void { writeSecureJson(this.filePath, this.state); }
  setHost(host: HostProjection): void { this.state.host = sanitizePersistedHost(host); this.persist(); }
  getHost(): HostProjection | null { return this.state.host; }

  replaceDriverSessions(driverName: string, sessions: CanonicalSessionState[]): void {
    const nextIds = new Set(sessions.map((session) => session.sessionId));
    for (const [sessionId, registeredDriver] of Object.entries(this.state.sessionDrivers)) if (registeredDriver === driverName && !nextIds.has(sessionId)) {
      delete this.state.sessionDrivers[sessionId]; delete this.state.sessions[sessionId];
    }

    for (const session of sessions) { this.state.sessions[session.sessionId] = session; this.state.sessionDrivers[session.sessionId] = driverName; }
    this.state.reconciledDrivers[driverName] = true;
    this.persist();
  }
  listSessions(): CanonicalSessionState[] { return Object.values(this.state.sessions).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)); }
  hasReconciledDriver(driverName: string): boolean { return this.state.reconciledDrivers[driverName] === true; }
  getSession(sessionId: string): CanonicalSessionState | undefined { return this.state.sessions[sessionId]; }
  getDriverNameForSession(sessionId: string): string | undefined { return this.state.sessionDrivers[sessionId]; }
  setSessionDriver(sessionId: string, driverName: string): void { this.state.sessionDrivers[sessionId] = driverName; this.persist(); }
  removeSession(sessionId: string, expectedDriverName?: string): boolean {
    const driverName = this.state.sessionDrivers[sessionId];
    if (expectedDriverName !== undefined && driverName !== expectedDriverName) return false;
    const existed = sessionId in this.state.sessions || driverName !== undefined;
    delete this.state.sessions[sessionId]; delete this.state.sessionDrivers[sessionId];
    if (existed) this.persist();
    return existed;
  }
  removeSessionDriver(sessionId: string): void { delete this.state.sessionDrivers[sessionId]; this.persist(); }
  updateSession(sessionId: string, patch: Partial<CanonicalSessionState>): CanonicalSessionState | undefined {
    const current = this.getSession(sessionId); if (!current) return undefined;
    const next = { ...current, ...patch }; this.state.sessions[sessionId] = next; this.persist(); return next;
  }

  async stageCurrentSessionsSnapshot(hostId: string, sessions: ActiveSessionSnapshot[], observedAt: string, minimumRevision = 0): Promise<PendingCurrentSessionsSnapshot | undefined> {
    const contentDigest = await snapshotContentDigest(hostId, sessions);
    const current = this.state.currentSessionsSnapshot;
    if (current.pending?.contentDigest === contentDigest && current.pending.request.hostId === hostId) return structuredClone(current.pending);
    if (!current.pending && current.lastAcceptedContentDigest === contentDigest && current.lastAcceptedRevision >= minimumRevision) return undefined;
    const revision = Math.max(current.lastAllocatedRevision, current.lastAcceptedRevision, minimumRevision) + 1;
    const request: ReplaceCurrentSessionsRequest = { hostId, revision, observedAt, sessions };
    const pending: PendingCurrentSessionsSnapshot = { request, digest: await snapshotDigest(request), contentDigest };
    this.state.currentSessionsSnapshot = { ...current, version: 1, lastAllocatedRevision: revision, pending };
    this.persist();
    return structuredClone(pending);
  }
  getPendingCurrentSessionsSnapshot(): PendingCurrentSessionsSnapshot | undefined {
    const pending = this.state.currentSessionsSnapshot.pending; return pending ? structuredClone(pending) : undefined;
  }
  getCurrentSessionsSnapshotState(): PersistedCurrentSessionsSnapshotState { return structuredClone(this.state.currentSessionsSnapshot); }
  acceptCurrentSessionsSnapshot(revision: number, digest: string): boolean {
    const current = this.state.currentSessionsSnapshot; const pending = current.pending;
    if (!pending || pending.request.revision !== revision || pending.digest !== digest) return false;
    this.state.currentSessionsSnapshot = { version: 1, lastAllocatedRevision: Math.max(current.lastAllocatedRevision, revision),
      lastAcceptedRevision: Math.max(current.lastAcceptedRevision, revision), lastAcceptedDigest: digest, lastAcceptedContentDigest: pending.contentDigest };
    this.persist(); return true;
  }
  noteCurrentSessionsSnapshotRevisionLowerBound(revision: number): void {
    const current = this.state.currentSessionsSnapshot;
    const nextAllocated = Math.max(current.lastAllocatedRevision, revision); const nextAccepted = Math.max(current.lastAcceptedRevision, revision);
    if (nextAllocated === current.lastAllocatedRevision && nextAccepted === current.lastAcceptedRevision) return;
    this.state.currentSessionsSnapshot = { ...current, lastAllocatedRevision: nextAllocated, lastAcceptedRevision: nextAccepted }; this.persist();
  }
  clearPendingCurrentSessionsSnapshot(revision: number, digest: string): boolean {
    const pending = this.state.currentSessionsSnapshot.pending;
    if (!pending || pending.request.revision !== revision || pending.digest !== digest) return false;
    const { pending: _pending, ...current } = this.state.currentSessionsSnapshot; this.state.currentSessionsSnapshot = current; this.persist(); return true;
  }
  appendRecentEvent(event: CanonicalEvent): void { this.state.recentEvents = [event, ...this.state.recentEvents].slice(0, 200); this.persist(); }
  queuePendingEvent(event: CanonicalEvent): void {
    this.state.recentEvents = [event, ...this.state.recentEvents].slice(0, 200);
    if (!this.spool) { (this.state.pendingEvents ??= []).push(event); this.persist(); return; }
    this.enqueuePendingEvent(event); this.persist();
  }
  private enqueuePendingEvent(event: CanonicalEvent): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    const session = this.getSession(event.sessionId);
    const payload = new TextEncoder().encode(JSON.stringify({ event, session }));
    this.spool.enqueue({ spoolItemId: event.eventId, sessionId: event.sessionId, eventId: event.eventId,
      payloadKind: 'event-source-v1', createdAt: event.createdAt, plaintext: payload });
  }
  peekPendingEvents(): CanonicalEvent[] {
    if (!this.spool) return [...(this.state.pendingEvents ?? [])];
    return this.spool.list().map((item) => { const bytes = this.spool!.open(item); try {
      const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as { event: CanonicalEvent };
      return parsed.event;
    } finally { bytes.fill(0); } });
  }
  peekPendingUploads(): Array<{ event: CanonicalEvent; session?: CanonicalSessionState }> {
    if (!this.spool) return (this.state.pendingEvents ?? []).map((event) => ({ event, session: this.getSession(event.sessionId) }));
    return this.spool.list('event-source-v1').map((item) => { const bytes = this.spool!.open(item); try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as { event: CanonicalEvent; session?: CanonicalSessionState };
    } finally { bytes.fill(0); } });
  }
  getInflightEventUpload(eventId: string): unknown | undefined { return this.openSpoolJson(`inflight:event:${eventId}`); }
  persistInflightEventUpload(eventId: string, sessionId: string, upload: unknown): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    this.spool.enqueue({ spoolItemId: `inflight:event:${eventId}`, sessionId, eventId, payloadKind: 'event-upload-v1',
      createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(upload)) });
  }
  replaceInflightEventUpload(eventId: string, sessionId: string, upload: unknown): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    this.spool.replace([`inflight:event:${eventId}`], [{ spoolItemId: `inflight:event:${eventId}`, sessionId, eventId,
      payloadKind: 'event-upload-v1', createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(upload)) }]);
  }
  removeInflightEventUpload(eventId: string): void { this.spool?.remove(`inflight:event:${eventId}`); }
  listInflightSessionIds(): string[] { return this.spool?.list('session-upload-v1').map((item) => item.sessionId) ?? []; }
  getInflightSessionUpload(sessionId: string): unknown | undefined { return this.openSpoolJson(`inflight:session:${sessionId}`); }
  persistInflightSessionUpload(sessionId: string, upload: unknown): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    this.spool.enqueue({ spoolItemId: `inflight:session:${sessionId}`, sessionId, payloadKind: 'session-upload-v1',
      createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(upload)) });
  }
  replaceInflightSessionUpload(sessionId: string, upload: unknown): void {
    if (!this.spool) throw new Error('encrypted spool is not initialized');
    this.spool.replace([`inflight:session:${sessionId}`], [{ spoolItemId: `inflight:session:${sessionId}`, sessionId,
      payloadKind: 'session-upload-v1', createdAt: new Date().toISOString(), plaintext: new TextEncoder().encode(JSON.stringify(upload)) }]);
  }
  removeInflightSessionUpload(sessionId: string): void { this.spool?.remove(`inflight:session:${sessionId}`); }
  private openSpoolJson(itemId: string): unknown | undefined {
    const item = this.spool?.get(itemId); if (!item) return undefined; const bytes = this.spool!.open(item);
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } finally { bytes.fill(0); }
  }
  removePendingEvent(eventId: string): void {
    if (this.spool) this.spool.remove(eventId); else this.state.pendingEvents = (this.state.pendingEvents ?? []).filter((event) => event.eventId !== eventId);
    this.persist();
  }
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
      if (this.spool) this.spool.remove(eventId);
      else this.state.pendingEvents = (this.state.pendingEvents ?? []).filter((event) => event.eventId !== eventId);
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
    const key = sessionHandleKey(handle.hostId, handle.sessionId); const current = this.state.pendingHandles[key];
    if (!current || comparePendingHandles(handle, current) >= 0) { this.state.pendingHandles[key] = handle; this.persist(); }
  }
  peekPendingSessionHandles(): PendingSessionHandle[] { return Object.values(this.state.pendingHandles); }
  removePendingSessionHandle(hostId: string, sessionId: string, handledThroughEventId?: string): void {
    const key = sessionHandleKey(hostId, sessionId); const current = this.state.pendingHandles[key]; if (!current) return;
    if (handledThroughEventId && current.handledThroughEventId !== handledThroughEventId) return; delete this.state.pendingHandles[key]; this.persist();
  }
  getCommandResult(commandId: string): CommandResult | undefined { return this.state.commandResults[commandId]; }
  hasSeenCommand(commandId: string): boolean { return commandId in this.state.seenCommands; }
  rememberCommandResult(result: CommandResult): void { this.state.commandResults[result.commandId] = result; this.state.seenCommands[result.commandId] = result.updatedAt; this.persist(); }
}

function protectedMarkers(events: CanonicalEvent[]): string[] { return events.flatMap((event) => [event.assistantText, event.userMessageText, event.contextText, event.actionablePrompt?.label, ...(event.actionablePrompt?.options ?? [])]).filter((value): value is string => Boolean(value)); }
function sessionHandleKey(hostId: string, sessionId: string): string { return `${hostId}:${sessionId}`; }
function comparePendingHandles(left: PendingSessionHandle, right: PendingSessionHandle): number {
  const cursorCompare = (left.handledThroughEventCreatedAt ?? left.handledAt).localeCompare(right.handledThroughEventCreatedAt ?? right.handledAt);
  if (cursorCompare !== 0) return cursorCompare; const eventCompare = left.handledThroughEventId.localeCompare(right.handledThroughEventId);
  return eventCompare !== 0 ? eventCompare : left.updatedAt.localeCompare(right.updatedAt);
}
function withoutLegacyPendingReads(parsed: PersistedBridgeState & { pendingReads?: Record<string, LegacyPendingSessionRead> }): PersistedBridgeState { const { pendingReads: _, ...current } = parsed; return current; }
function migratePendingReads(parsed: PersistedBridgeState & { pendingReads?: Record<string, LegacyPendingSessionRead> }): Record<string, PendingSessionHandle> {
  return Object.fromEntries(Object.entries(parsed.pendingReads ?? {}).map(([key, read]) => [key, { hostId: read.hostId, sessionId: read.sessionId,
    handledThroughEventId: read.latestReadEventId, handledThroughEventCreatedAt: read.latestReadEventCreatedAt, handledAt: read.readAt,
    action: read.source === 'bridge_recovery' ? 'bridge_recovery' : 'pi_input', updatedAt: read.updatedAt }]));
}
interface LegacyPendingSessionRead { hostId: string; sessionId: string; latestReadEventId: string; latestReadEventCreatedAt?: string; readAt: string; source: 'pi_local_interaction' | 'bridge_recovery'; updatedAt: string }
function sanitizePersistedHost(host: HostProjection | null): HostProjection | null { if (!host) return null; const value = { ...host } as HostProjection & Record<string, unknown>; delete value.claimCode; delete value.claimCodeExpiresAt; delete value.ownerUserId; return value; }
function hasLegacyClaimCodeFields(host: HostProjection): boolean { return 'claimCode' in host || 'claimCodeExpiresAt' in host || 'ownerUserId' in host; }
function sameEventCompletion(left: EventUploadCompletionV1, right: EventUploadCompletionV1): boolean {
  return left.version === right.version && left.eventId === right.eventId && left.sessionId === right.sessionId
    && left.revision === right.revision && left.eventContentId === right.eventContentId
    && left.sessionContentId === right.sessionContentId;
}

async function hashSnapshot(value: unknown): Promise<string> {
  return contentSha256(JSON.stringify(value));
}

async function snapshotDigest(request: ReplaceCurrentSessionsRequest): Promise<string> {
  return hashSnapshot(request);
}

async function snapshotContentDigest(hostId: string, sessions: ActiveSessionSnapshot[]): Promise<string> {
  return hashSnapshot({ hostId, sessions });
}

function sanitizeSnapshotState(value: PersistedCurrentSessionsSnapshotState | undefined): PersistedCurrentSessionsSnapshotState {
  if (!value || value.version !== 1) return structuredClone(EMPTY_STATE.currentSessionsSnapshot);
  const lastAllocatedRevision = safeRevision(value.lastAllocatedRevision);
  const lastAcceptedRevision = safeRevision(value.lastAcceptedRevision);
  const pending = sanitizePendingSnapshot(value.pending);
  return {
    version: 1,
    lastAllocatedRevision: Math.max(lastAllocatedRevision, lastAcceptedRevision, pending?.request.revision ?? 0),
    lastAcceptedRevision,
    ...(typeof value.lastAcceptedDigest === 'string' ? { lastAcceptedDigest: value.lastAcceptedDigest } : {}),
    ...(typeof value.lastAcceptedContentDigest === 'string' ? { lastAcceptedContentDigest: value.lastAcceptedContentDigest } : {}),
    ...(pending ? { pending } : {}),
  };
}

function sanitizePendingSnapshot(value: PendingCurrentSessionsSnapshot | undefined): PendingCurrentSessionsSnapshot | undefined {
  if (!value || typeof value.digest !== 'string' || typeof value.contentDigest !== 'string') return undefined;
  const request = value.request;
  if (!request || !Number.isSafeInteger(request.revision) || request.revision <= 0 || !Array.isArray(request.sessions)) return undefined;
  return value;
}

function safeRevision(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function inferLegacyReconciledDrivers(sessionDrivers: Record<string, string> | undefined): Record<string, true> {
  const driverNames = new Set(Object.values(sessionDrivers ?? {}));
  return Object.fromEntries([...driverNames].map((driverName) => [driverName, true]));
}
