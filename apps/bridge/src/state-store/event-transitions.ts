import type {
  CanonicalEvent,
  CanonicalSessionState,
  EventUploadCompletionV1,
  PersistedBridgeState,
  PersistedProducerEventReservationV1,
} from '../types';
import type { StateTransition } from './state-transitions';
import { producerReservationKey } from './state-codec';
import { retainRecentEvents } from './session-transitions';

/**
 * Deterministic bounded Event-evidence calculations (spec §6.1, migration step 5).
 *
 * Scope: bounded recent/pending/quarantine evidence and comparisons only.
 * The producer/terminal/completion journal WORKFLOWS stay in the imperative
 * shell (extracted in the lifecycle/spool batch); this module never touches
 * spool I/O, clocks, or random sources.
 */

/** Exact completion compare used by the event-completion journal. */
export function sameEventCompletion(left: EventUploadCompletionV1, right: EventUploadCompletionV1): boolean {
  return left.version === right.version && left.eventId === right.eventId && left.sessionId === right.sessionId
    && left.revision === right.revision && left.eventContentId === right.eventContentId
    && left.sessionContentId === right.sessionContentId;
}

/** Clone-first bounded recent-event append (always persists, matching the baseline shell). */
export function appendRecentEventTransition(
  state: PersistedBridgeState,
  event: CanonicalEvent,
): StateTransition<void> {
  const nextState = structuredClone(state);
  nextState.recentEvents = retainRecentEvents([event, ...nextState.recentEvents], nextState.pendingHandles);
  return { state: nextState, result: undefined };
}

/** Deterministic terminal-Session freshness comparison for pending-journal replay. */
export function isNewerTerminalSession(current: CanonicalSessionState, pending: CanonicalSessionState): boolean {
  if (!current.lastEventId || current.lastEventId === pending.lastEventId) return false;
  return current.updatedAt.localeCompare(pending.updatedAt) >= 0;
}

/** Clone-first bounded producer Event reservation (duplicate = same-reference no-op, matching the baseline shell). */
export function reserveProducerEventTransition(
  state: PersistedBridgeState,
  reservation: PersistedProducerEventReservationV1,
): StateTransition<void> {
  const key = producerReservationKey(reservation.sessionId, reservation.fingerprint);
  const existing = state.producerEventReservations?.[key];
  if (existing) {
    if (existing.eventId !== reservation.eventId || existing.createdAt !== reservation.createdAt) {
      throw new TypeError('producer Event reservation conflict');
    }
    return { state, result: undefined };
  }
  const nextState = structuredClone(state);
  const reservations = { ...(nextState.producerEventReservations ?? {}), [key]: structuredClone(reservation) };
  const retained = Object.entries(reservations).slice(-200);
  nextState.producerEventReservations = Object.fromEntries(retained);
  return { state: nextState, result: undefined };
}

/** Durable dead-letter record shape for quarantined Events. */
export interface QuarantineEventRecordV1 {
  version: 1;
  eventId: string;
  sessionId: string;
  reason: string;
  quarantinedAt: string;
  source: unknown;
  inflight?: unknown;
}

/** Pure construction of the quarantined Event dead-letter record (spool replace stays in the shell). */
export function buildQuarantineRecord(
  eventId: string,
  sessionId: string,
  reason: string,
  quarantinedAt: string,
  source: unknown,
  inflight?: unknown,
): QuarantineEventRecordV1 {
  return {
    version: 1 as const,
    eventId,
    sessionId,
    reason,
    quarantinedAt,
    source,
    ...(inflight ? { inflight } : {}),
  };
}
