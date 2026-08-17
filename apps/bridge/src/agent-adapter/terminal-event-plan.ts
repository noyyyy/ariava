import type { CanonicalEvent, CanonicalSessionState } from '@ariava/protocol';
import {
  assertProducerContextMatchesSession,
  immutableCopy,
  producerEventFingerprint,
} from './registry-codec';
import type {
  AgentAdapterEventInput,
  PendingTerminal,
  RegisteredSession,
} from './registry-types';

export type TerminalEventTuple = {
  readonly event: CanonicalEvent;
  readonly session: CanonicalSessionState;
};

export type ProducerReservation = {
  readonly version: 1;
  readonly eventId: string;
  readonly sessionId: string;
  readonly fingerprint: string;
  readonly createdAt: string;
};

export type TerminalEventPlan =
  | { type: 'return-live-duplicate'; promoteNow: boolean }
  | { type: 'return-reservation-without-tuple'; eventId: string }
  | { type: 'stage-reserved-tuple'; tuple: TerminalEventTuple; promoteNow: boolean }
  | { type: 'cancel-older-and-reserve'; tuple: TerminalEventTuple; reservation: ProducerReservation; promoteNow: boolean }
  | { type: 'reserve-new-tuple'; tuple: TerminalEventTuple; reservation: ProducerReservation; promoteNow: boolean }
  | { type: 'reject'; error: Error };

export interface TerminalEventPlanInput {
  readonly session: RegisteredSession | undefined;
  readonly livePending: PendingTerminal | undefined;
  readonly persistedReservation: ProducerReservation | undefined;
  readonly persistedTuple: TerminalEventTuple | undefined;
  readonly hasPendingCommandWork: boolean;
  readonly input: AgentAdapterEventInput;
  readonly eventId: string;
}

export function planTerminalEvent(snapshot: TerminalEventPlanInput): TerminalEventPlan {
  const { session, livePending, persistedReservation, persistedTuple, hasPendingCommandWork, input, eventId } = snapshot;

  if (!session) return { type: 'reject', error: new Error(`Session ${input.sessionId} is not registered`) };
  if (input.sessionId !== session.sessionId) {
    return { type: 'reject', error: new TypeError('canonical Event sessionId does not match the request path') };
  }
  if (input.provider !== session.provider) {
    return { type: 'reject', error: new TypeError('canonical Event provider does not match the registered Session') };
  }
  try {
    assertProducerContextMatchesSession(input, session);
  } catch (error) {
    return { type: 'reject', error: error instanceof Error ? error : new TypeError('canonical Event does not match the registered Session') };
  }

  const fingerprint = producerEventFingerprint(input);
  if (livePending && producerEventFingerprint(livePending.event) === fingerprint) {
    return { type: 'return-live-duplicate', promoteNow: !hasPendingCommandWork };
  }
  if (persistedReservation) {
    if (!persistedTuple) {
      return { type: 'return-reservation-without-tuple', eventId: persistedReservation.eventId };
    }
    return { type: 'stage-reserved-tuple', tuple: persistedTuple, promoteNow: !hasPendingCommandWork };
  }

  const event = immutableCopy({ ...input, eventId, hostId: session.hostId } as CanonicalEvent);
  const terminalRegistered = { ...session, status: event.status, latestActivityText: event.agentText,
    lastEventId: eventId, semanticUpdatedAt: event.createdAt };
  const terminalSession = immutableCopy(toCanonicalSessionState(terminalRegistered));
  const tuple: TerminalEventTuple = Object.freeze({ event, session: terminalSession });
  const reservation: ProducerReservation = {
    version: 1, eventId, sessionId: session.sessionId, fingerprint, createdAt: event.createdAt,
  };
  if (livePending) {
    return { type: 'cancel-older-and-reserve', tuple, reservation, promoteNow: !hasPendingCommandWork };
  }
  return { type: 'reserve-new-tuple', tuple, reservation, promoteNow: !hasPendingCommandWork };
}

export function toCanonicalSessionState(
  session: Omit<RegisteredSession, 'driverInstanceId' | 'ownerLease' | 'lastOwnerLeaseMonotonic'>,
): CanonicalSessionState {
  return { sessionId: session.sessionId, hostId: session.hostId, provider: session.provider, projectName: session.projectName,
    nameText: session.nameText, openingText: session.openingText, latestActivityText: session.latestActivityText,
    workingDirectory: session.cwd, harnessProvider: session.harnessProvider,
    status: session.status, updatedAt: session.semanticUpdatedAt, lastEventId: session.lastEventId };
}
