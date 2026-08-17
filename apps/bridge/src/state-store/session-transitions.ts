import type {
  CanonicalEvent,
  CanonicalSessionState,
  PendingSessionHandle,
  PersistedBridgeState,
} from '../types';
import type { StateTransition } from './state-transitions';

/** Deterministic Session, driver binding, pending-handle, and revision calculations (spec §6.1). */

export const MAX_RECENT_EVENTS = 200;

export function sessionHandleKey(hostId: string, sessionId: string): string { return `${hostId}:${sessionId}`; }

export function comparePendingHandles(left: PendingSessionHandle, right: PendingSessionHandle): number {
  const cursorCompare = (left.handledThroughEventCreatedAt ?? left.handledAt)
    .localeCompare(right.handledThroughEventCreatedAt ?? right.handledAt);
  if (cursorCompare !== 0) return cursorCompare;
  const eventCompare = left.handledThroughEventId.localeCompare(right.handledThroughEventId);
  return eventCompare !== 0 ? eventCompare : left.updatedAt.localeCompare(right.updatedAt);
}

export function retainRecentEvents(
  events: CanonicalEvent[],
  pendingHandles: Record<string, PendingSessionHandle>,
): CanonicalEvent[] {
  const unique = events.filter((event, index) => events.findIndex((candidate) => candidate.eventId === event.eventId) === index);
  const protectedIds = new Set(Object.values(pendingHandles).map((handle) => handle.handledThroughEventId));
  const retainedProtected = unique.filter((event) => protectedIds.has(event.eventId));
  const available = Math.max(0, MAX_RECENT_EVENTS - retainedProtected.length);
  return [...retainedProtected, ...unique.filter((event) => !protectedIds.has(event.eventId)).slice(0, available)]
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

/** Clone-first full-driver Session replacement. */
export function replaceDriverSessionsTransition(
  state: PersistedBridgeState,
  driverName: string,
  sessions: CanonicalSessionState[],
): StateTransition<void> {
  const nextState = structuredClone(state);
  const nextIds = new Set(sessions.map((session) => session.sessionId));
  for (const [sessionId, registeredDriver] of Object.entries(nextState.sessionDrivers)) {
    if (registeredDriver === driverName && !nextIds.has(sessionId)) {
      delete nextState.sessionDrivers[sessionId];
      delete nextState.sessions[sessionId];
    }
  }
  for (const session of sessions) {
    nextState.sessions[session.sessionId] = session;
    nextState.sessionDrivers[session.sessionId] = driverName;
  }
  nextState.reconciledDrivers[driverName] = true;
  return { state: nextState, result: undefined };
}

/** Clone-first Session/driver binding (validation throws before any write). */
export function setSessionDriverTransition(
  state: PersistedBridgeState,
  sessionId: string,
  driverName: string,
  session?: CanonicalSessionState,
): StateTransition<void> {
  const nextState = structuredClone(state);
  const boundSession = session ?? nextState.sessions[sessionId];
  if (!boundSession || boundSession.sessionId !== sessionId
    || (boundSession.provider !== driverName && driverName !== 'agent-adapter')) {
    throw new TypeError('Session driver requires its canonical Session');
  }
  nextState.sessions[sessionId] = boundSession;
  nextState.sessionDrivers[sessionId] = driverName;
  return { state: nextState, result: undefined };
}

export function removeSessionTransition(
  state: PersistedBridgeState,
  sessionId: string,
  expectedDriverName?: string,
): StateTransition<boolean> {
  const driverName = state.sessionDrivers[sessionId];
  if (expectedDriverName !== undefined && driverName !== expectedDriverName) return { state, result: false };
  const existed = sessionId in state.sessions || driverName !== undefined;
  if (!existed) return { state, result: false };
  const nextState = structuredClone(state);
  delete nextState.sessions[sessionId];
  delete nextState.sessionDrivers[sessionId];
  delete nextState.producerEventCheckpoints?.[sessionId];
  return { state: nextState, result: true };
}

export function removeSessionDriverTransition(
  state: PersistedBridgeState,
  sessionId: string,
): StateTransition<void> {
  if (!(sessionId in state.sessionDrivers)) return { state, result: undefined };
  const nextState = structuredClone(state);
  delete nextState.sessionDrivers[sessionId];
  return { state: nextState, result: undefined };
}

/** Mutate-first Session patch (write-failure live value is mutated). */
export function updateSessionTransition(
  state: PersistedBridgeState,
  sessionId: string,
  patch: Partial<CanonicalSessionState>,
): StateTransition<CanonicalSessionState | undefined> {
  const current = state.sessions[sessionId];
  if (!current) return { state, result: undefined };
  const next = { ...current, ...patch };
  return { state: { ...state, sessions: { ...state.sessions, [sessionId]: next } }, result: next };
}

export function queuePendingSessionHandleTransition(
  state: PersistedBridgeState,
  handle: PendingSessionHandle,
): StateTransition<void> {
  const event = state.recentEvents.find((candidate) => candidate.eventId === handle.handledThroughEventId);
  if (!event || event.hostId !== handle.hostId || event.sessionId !== handle.sessionId) {
    throw new TypeError('handledThroughEventId must reference a durable Event for the same Host and Session');
  }
  if (handle.handledThroughEventCreatedAt !== undefined && handle.handledThroughEventCreatedAt !== event.createdAt) {
    throw new TypeError('handledThroughEventCreatedAt does not match the durable Event');
  }
  const boundHandle = { ...handle, handledThroughEventCreatedAt: event.createdAt };
  const key = sessionHandleKey(boundHandle.hostId, boundHandle.sessionId);
  const current = state.pendingHandles[key];
  if (current && comparePendingHandles(boundHandle, current) < 0) {
    throw new TypeError('handledThroughEventId is older than the pending durable cursor');
  }
  const nextState = structuredClone(state);
  nextState.pendingHandles[key] = boundHandle;
  nextState.recentEvents = retainRecentEvents(nextState.recentEvents, nextState.pendingHandles);
  return { state: nextState, result: undefined };
}

export function removePendingSessionHandleTransition(
  state: PersistedBridgeState,
  hostId: string,
  sessionId: string,
  handledThroughEventId?: string,
): StateTransition<void> {
  const key = sessionHandleKey(hostId, sessionId);
  const current = state.pendingHandles[key];
  if (!current) return { state, result: undefined };
  if (handledThroughEventId && current.handledThroughEventId !== handledThroughEventId) return { state, result: undefined };
  const nextState = structuredClone(state);
  delete nextState.pendingHandles[key];
  return { state: nextState, result: undefined };
}

export function readCurrentSessionRevision(state: PersistedBridgeState, sessionId: string): number {
  return state.sessionRevisions[sessionId] ?? 0;
}

export function readNextSessionRevision(state: PersistedBridgeState, sessionId: string): number {
  return readCurrentSessionRevision(state, sessionId) + 1;
}

/** Mutate-first monotonic revision commit (write-failure live value is mutated). */
export function commitSessionRevisionTransition(
  state: PersistedBridgeState,
  sessionId: string,
  revision: number,
): StateTransition<void> {
  const current = readCurrentSessionRevision(state, sessionId);
  if (revision === current) return { state, result: undefined };
  if (revision !== current + 1) throw new TypeError('session revision must advance monotonically');
  return {
    state: { ...state, sessionRevisions: { ...state.sessionRevisions, [sessionId]: revision } },
    result: undefined,
  };
}
