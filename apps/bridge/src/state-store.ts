import { pathHasFilesystemEvidence, readSecureJson, writeSecureJson } from './host-manager/secure-files';
import type {
  ActiveSessionSnapshot,
  CanonicalEvent,
  CanonicalSessionState,
  CommandResult,
  HostProjection,
  ReplaceCurrentSessionsRequest,
} from '@ariava/protocol';
import { contentSha256 } from '@ariava/protocol';
import type { PendingCurrentSessionsSnapshot, PendingSessionHandle, PersistedBridgeState, PersistedCurrentSessionsSnapshotState } from './types';

const EMPTY_STATE: PersistedBridgeState = {
  host: null,
  sessions: {},
  sessionDrivers: {},
  reconciledDrivers: {},
  recentEvents: [],
  pendingEvents: [],
  pendingHandles: {},
  commandResults: {},
  seenCommands: {},
  currentSessionsSnapshot: {
    version: 1,
    lastAllocatedRevision: 0,
    lastAcceptedRevision: 0,
  },
};

export class BridgeStateStore {
  private state: PersistedBridgeState;

  constructor(private readonly filePath: string) {
    this.state = this.load();
  }

  private load(): PersistedBridgeState {
    if (!pathHasFilesystemEvidence(this.filePath)) {
      return structuredClone(EMPTY_STATE);
    }

    try {
      const parsed = readSecureJson<PersistedBridgeState & { pendingReads?: Record<string, LegacyPendingSessionRead> }>(this.filePath);
      const nextState: PersistedBridgeState = {
        ...structuredClone(EMPTY_STATE),
        ...withoutLegacyPendingReads(parsed),
        host: sanitizePersistedHost(parsed.host ?? null),
        sessions: parsed.sessions ?? {},
        sessionDrivers: parsed.sessionDrivers ?? {},
        reconciledDrivers: parsed.reconciledDrivers ?? inferLegacyReconciledDrivers(parsed.sessionDrivers),
        recentEvents: parsed.recentEvents ?? [],
        pendingEvents: parsed.pendingEvents ?? [],
        pendingHandles: parsed.pendingHandles ?? migratePendingReads(parsed),
        commandResults: parsed.commandResults ?? {},
        seenCommands: parsed.seenCommands ?? {},
        currentSessionsSnapshot: sanitizeSnapshotState(parsed.currentSessionsSnapshot),
      };

      if ((parsed.host && hasLegacyClaimCodeFields(parsed.host)) || parsed.pendingReads || !parsed.currentSessionsSnapshot) {
        writeSecureJson(this.filePath, nextState);
      }

      return nextState;
    } catch (error) {
      throw new Error('Bridge state file is invalid or insecure', { cause: error });
    }
  }

  private persist(): void {
    writeSecureJson(this.filePath, this.state);
  }

  setHost(host: HostProjection): void {
    this.state.host = sanitizePersistedHost(host);
    this.persist();
  }

  getHost(): HostProjection | null {
    return this.state.host;
  }

  replaceDriverSessions(driverName: string, sessions: CanonicalSessionState[]): void {
    const nextIds = new Set(sessions.map((session) => session.sessionId));

    for (const [sessionId, registeredDriver] of Object.entries(this.state.sessionDrivers)) {
      if (registeredDriver === driverName && !nextIds.has(sessionId)) {
        delete this.state.sessionDrivers[sessionId];
        delete this.state.sessions[sessionId];
      }
    }

    for (const session of sessions) {
      this.state.sessions[session.sessionId] = session;
      this.state.sessionDrivers[session.sessionId] = driverName;
    }
    this.state.reconciledDrivers[driverName] = true;

    this.persist();
  }

  listSessions(): CanonicalSessionState[] {
    return Object.values(this.state.sessions).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  hasReconciledDriver(driverName: string): boolean {
    return this.state.reconciledDrivers[driverName] === true;
  }

  getSession(sessionId: string): CanonicalSessionState | undefined {
    return this.state.sessions[sessionId];
  }

  getDriverNameForSession(sessionId: string): string | undefined {
    return this.state.sessionDrivers[sessionId];
  }

  setSessionDriver(sessionId: string, driverName: string): void {
    this.state.sessionDrivers[sessionId] = driverName;
    this.persist();
  }

  removeSession(sessionId: string, expectedDriverName?: string): boolean {
    const driverName = this.state.sessionDrivers[sessionId];
    if (expectedDriverName !== undefined && driverName !== expectedDriverName) return false;
    const existed = sessionId in this.state.sessions || driverName !== undefined;
    delete this.state.sessions[sessionId];
    delete this.state.sessionDrivers[sessionId];
    if (existed) this.persist();
    return existed;
  }

  updateSession(sessionId: string, patch: Partial<CanonicalSessionState>): CanonicalSessionState | undefined {
    const current = this.getSession(sessionId);
    if (!current) return undefined;

    const next = { ...current, ...patch };
    this.state.sessions[sessionId] = next;
    this.persist();
    return next;
  }

  async stageCurrentSessionsSnapshot(
    hostId: string,
    sessions: ActiveSessionSnapshot[],
    observedAt: string,
    minimumRevision = 0,
  ): Promise<PendingCurrentSessionsSnapshot | undefined> {
    const contentDigest = await snapshotContentDigest(hostId, sessions);
    const current = this.state.currentSessionsSnapshot;
    if (current.pending?.contentDigest === contentDigest && current.pending.request.hostId === hostId) {
      return structuredClone(current.pending);
    }
    if (!current.pending
      && current.lastAcceptedContentDigest === contentDigest
      && current.lastAcceptedRevision >= minimumRevision) {
      return undefined;
    }
    const revision = Math.max(current.lastAllocatedRevision, current.lastAcceptedRevision, minimumRevision) + 1;
    const request: ReplaceCurrentSessionsRequest = { hostId, revision, observedAt, sessions };
    const pending: PendingCurrentSessionsSnapshot = {
      request,
      digest: await snapshotDigest(request),
      contentDigest,
    };
    this.state.currentSessionsSnapshot = { ...current, version: 1, lastAllocatedRevision: revision, pending };
    this.persist();
    return structuredClone(pending);
  }

  getPendingCurrentSessionsSnapshot(): PendingCurrentSessionsSnapshot | undefined {
    const pending = this.state.currentSessionsSnapshot.pending;
    return pending ? structuredClone(pending) : undefined;
  }

  getCurrentSessionsSnapshotState(): PersistedCurrentSessionsSnapshotState {
    return structuredClone(this.state.currentSessionsSnapshot);
  }

  acceptCurrentSessionsSnapshot(revision: number, digest: string): boolean {
    const current = this.state.currentSessionsSnapshot;
    const pending = current.pending;
    if (!pending || pending.request.revision !== revision || pending.digest !== digest) return false;
    this.state.currentSessionsSnapshot = {
      version: 1,
      lastAllocatedRevision: Math.max(current.lastAllocatedRevision, revision),
      lastAcceptedRevision: Math.max(current.lastAcceptedRevision, revision),
      lastAcceptedDigest: digest,
      lastAcceptedContentDigest: pending.contentDigest,
    };
    this.persist();
    return true;
  }

  noteCurrentSessionsSnapshotRevisionLowerBound(revision: number): void {
    const current = this.state.currentSessionsSnapshot;
    const nextAllocated = Math.max(current.lastAllocatedRevision, revision);
    const nextAccepted = Math.max(current.lastAcceptedRevision, revision);
    if (nextAllocated === current.lastAllocatedRevision && nextAccepted === current.lastAcceptedRevision) return;
    this.state.currentSessionsSnapshot = {
      ...current,
      lastAllocatedRevision: nextAllocated,
      lastAcceptedRevision: nextAccepted,
    };
    this.persist();
  }

  clearPendingCurrentSessionsSnapshot(revision: number, digest: string): boolean {
    const pending = this.state.currentSessionsSnapshot.pending;
    if (!pending || pending.request.revision !== revision || pending.digest !== digest) return false;
    const { pending: _pending, ...current } = this.state.currentSessionsSnapshot;
    this.state.currentSessionsSnapshot = current;
    this.persist();
    return true;
  }

  appendRecentEvent(event: CanonicalEvent): void {
    this.state.recentEvents = [event, ...this.state.recentEvents].slice(0, 200);
    this.persist();
  }

  queuePendingEvent(event: CanonicalEvent): void {
    this.state.pendingEvents.push(event);
    this.state.recentEvents = [event, ...this.state.recentEvents].slice(0, 200);
    this.persist();
  }

  peekPendingEvents(): CanonicalEvent[] {
    return [...this.state.pendingEvents];
  }

  removePendingEvent(eventId: string): void {
    this.state.pendingEvents = this.state.pendingEvents.filter((event) => event.eventId !== eventId);
    this.persist();
  }

  queuePendingSessionHandle(handle: PendingSessionHandle): void {
    const key = sessionHandleKey(handle.hostId, handle.sessionId);
    const current = this.state.pendingHandles[key];
    if (!current || comparePendingHandles(handle, current) >= 0) {
      this.state.pendingHandles[key] = handle;
      this.persist();
    }
  }

  peekPendingSessionHandles(): PendingSessionHandle[] {
    return Object.values(this.state.pendingHandles);
  }

  removePendingSessionHandle(hostId: string, sessionId: string, handledThroughEventId?: string): void {
    const key = sessionHandleKey(hostId, sessionId);
    const current = this.state.pendingHandles[key];
    if (!current) return;
    if (handledThroughEventId && current.handledThroughEventId !== handledThroughEventId) return;
    delete this.state.pendingHandles[key];
    this.persist();
  }

  getCommandResult(commandId: string): CommandResult | undefined {
    return this.state.commandResults[commandId];
  }

  hasSeenCommand(commandId: string): boolean {
    return commandId in this.state.seenCommands;
  }

  rememberCommandResult(result: CommandResult): void {
    this.state.commandResults[result.commandId] = result;
    this.state.seenCommands[result.commandId] = result.updatedAt;
    this.persist();
  }
}

function sessionHandleKey(hostId: string, sessionId: string): string {
  return `${hostId}:${sessionId}`;
}

function comparePendingHandles(left: PendingSessionHandle, right: PendingSessionHandle): number {
  const leftCursor = left.handledThroughEventCreatedAt ?? left.handledAt;
  const rightCursor = right.handledThroughEventCreatedAt ?? right.handledAt;
  const cursorCompare = leftCursor.localeCompare(rightCursor);
  if (cursorCompare !== 0) return cursorCompare;
  const eventCompare = left.handledThroughEventId.localeCompare(right.handledThroughEventId);
  if (eventCompare !== 0) return eventCompare;
  return left.updatedAt.localeCompare(right.updatedAt);
}

function withoutLegacyPendingReads(
  parsed: PersistedBridgeState & { pendingReads?: Record<string, LegacyPendingSessionRead> },
): PersistedBridgeState {
  const { pendingReads: _pendingReads, ...current } = parsed;
  return current;
}

function migratePendingReads(parsed: PersistedBridgeState & { pendingReads?: Record<string, LegacyPendingSessionRead> }): Record<string, PendingSessionHandle> {
  const migrated: Record<string, PendingSessionHandle> = {};
  for (const [key, read] of Object.entries(parsed.pendingReads ?? {})) {
    migrated[key] = {
      hostId: read.hostId,
      sessionId: read.sessionId,
      handledThroughEventId: read.latestReadEventId,
      handledThroughEventCreatedAt: read.latestReadEventCreatedAt,
      handledAt: read.readAt,
      action: read.source === 'bridge_recovery' ? 'bridge_recovery' : 'pi_input',
      updatedAt: read.updatedAt,
    };
  }
  return migrated;
}

interface LegacyPendingSessionRead {
  hostId: string;
  sessionId: string;
  latestReadEventId: string;
  latestReadEventCreatedAt?: string;
  readAt: string;
  source: 'pi_local_interaction' | 'bridge_recovery';
  updatedAt: string;
}

function sanitizePersistedHost(host: HostProjection | null): HostProjection | null {
  if (!host) {
    return null;
  }

  const persistedHost = { ...host } as HostProjection & Record<string, unknown>;
  delete persistedHost.claimCode;
  delete persistedHost.claimCodeExpiresAt;
  delete persistedHost.ownerUserId;
  return persistedHost;
}

function hasLegacyClaimCodeFields(host: HostProjection): boolean {
  return 'claimCode' in host || 'claimCodeExpiresAt' in host || 'ownerUserId' in host;
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
