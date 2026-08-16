import type {
  CanonicalEvent,
  CanonicalSessionState,
  SessionStatus,
} from '@ariava/protocol';
import type {
  PendingSessionHandle,
  PersistedProducerEventReservationV1,
} from '../types';

export type AgentAdapterEventInput = CanonicalEvent extends infer Event
  ? Event extends CanonicalEvent ? Omit<Event, 'eventId' | 'hostId'> : never
  : never;

export interface RegisteredSession {
  sessionId: string;
  provider: string;
  projectName: string;
  cwd: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
  harnessProvider?: string;
  pid?: number;
  hostId: string;
  registeredAt: string;
  lastHeartbeatAt: string;
  status: SessionStatus;
  semanticUpdatedAt: string;
  lastEventId?: string;
}

export interface RegisterSessionInput {
  sessionId: string;
  provider: string;
  projectName: string;
  cwd: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
  harnessProvider?: string;
  pid?: number;
  status?: SessionStatus;
}

export const SESSION_TTL_MS = 45_000;
export const TERMINAL_RETRY_DELAYS_MS = [100, 500, 2_000, 5_000] as const;

export type PendingTerminal = { event: CanonicalEvent; session: CanonicalSessionState };
export type RegistryMutationReason = 'register' | 'semantic' | 'handle' | 'unregister' | 'ttl';
export type RegistryMutationCallback = (reason: RegistryMutationReason) => void;
export interface RegistryRetryScheduler {
  schedule(callback: () => void, delayMs: number): unknown;
  cancel(handle: unknown): void;
}

export type RegistryStateStore = {
  getSession(sessionId: string): CanonicalSessionState | undefined;
  setSessionDriver(sessionId: string, driverName: string, session?: CanonicalSessionState): void;
  removeSession(sessionId: string, expectedDriverName?: string): boolean;
  getTerminalEventCancellation(sessionId: string): PersistedProducerEventReservationV1 | undefined;
  cancelTerminalEvent(input: {
    eventId: string;
    sessionId: string;
    fingerprint: string;
    removeSession?: boolean;
    nextDriverName?: string;
    createdAt?: string;
  }): void;
  reserveProducerEventTuple(event: CanonicalEvent, terminalSession: CanonicalSessionState, fingerprint: string): void;
  getProducerEventTuple(eventId: string, fingerprint: string): { event: CanonicalEvent; session: CanonicalSessionState } | undefined;
  reserveProducerEvent(reservation: PersistedProducerEventReservationV1): void;
  getProducerEventReservation(sessionId: string, fingerprint: string): PersistedProducerEventReservationV1 | undefined;
  queuePendingEvent(event: CanonicalEvent, terminalSession: CanonicalSessionState, producerFingerprint?: string): void;
  queuePendingSessionHandle(handle: PendingSessionHandle): void;
};
