import type {
  CanonicalEvent,
  CanonicalSessionState,
  SessionStatus,
} from '@ariava/protocol';
import type {
  PendingSessionHandle,
  PersistedProducerEventReservationV1,
  ProducerEventSourceCheckpointV1,
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
  driverInstanceId: string;
  ownerLease: string;
  /** In-process monotonic clock value of the last successful register/heartbeat renewal (never persisted). */
  lastOwnerLeaseMonotonic: number;
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
  driverInstanceId: string;
}

export const SESSION_TTL_MS = 45_000;
export const OWNER_LEASE_TTL_MS = SESSION_TTL_MS;
export const TERMINAL_RETRY_DELAYS_MS = [100, 500, 2_000, 5_000] as const;

/** Shared finite upper bounds for Agent Adapter v3 wire bodies (§3.4). */
export const AGENT_ADAPTER_LIMITS = {
  requestBodyBytes: 256 * 1024,
  identifierBytes: 256,
} as const;

/** Owner headers required on every owner route (all except register and health). */
export const AGENT_ADAPTER_OWNER_HEADERS = {
  driverInstance: 'x-ariava-driver-instance' as const,
  ownerLease: 'x-ariava-owner-lease' as const,
} as const;

const adapterTextEncoder = new TextEncoder();

export function isBoundedAgentAdapterIdentifier(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return adapterTextEncoder.encode(value).byteLength <= AGENT_ADAPTER_LIMITS.identifierBytes;
}

export type PendingTerminal = { event: CanonicalEvent; session: CanonicalSessionState };
export type RegistryMutationReason = 'register' | 'semantic' | 'handle' | 'unregister' | 'ttl';
export type RegistryMutationCallback = (reason: RegistryMutationReason) => void;
export interface RegistryRetryScheduler {
  schedule(callback: () => void, delayMs: number): unknown;
  cancel(handle: unknown): void;
}

export type RegistryStateStore = {
  getSession(sessionId: string): CanonicalSessionState | undefined;
  getDriverNameForSession(sessionId: string): string | undefined;
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
  acceptProducerEventSource(input: {
    reservation: PersistedProducerEventReservationV1;
    checkpoint: ProducerEventSourceCheckpointV1;
  }): void;
  getProducerEventReservation(sessionId: string, fingerprint: string): PersistedProducerEventReservationV1 | undefined;
  getProducerEventCheckpoint(sessionId: string): ProducerEventSourceCheckpointV1 | undefined;
  queuePendingEvent(event: CanonicalEvent, terminalSession: CanonicalSessionState, producerFingerprint?: string): void;
  queuePendingSessionHandle(handle: PendingSessionHandle): void;
  /** Durable execution-journal hook: mark a claimed/dispatched command outcome-unknown when its journal entry exists. */
  markCommandOutcomeUnknownIfPresent?(commandId: string): boolean;
};
