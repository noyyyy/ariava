import type {
  CanonicalSessionState,
  SessionStatus,
} from '@ariava/protocol';
import {
  canonicalProducerContextFingerprint,
  normalizedOwner,
  producerContextFingerprint,
  sameOwner,
  semanticFingerprint,
} from './registry-codec';
import type { RegisteredSession, RegisterSessionInput } from './registry-types';

export type PersistedTerminalCancellation = {
  readonly eventId: string;
  readonly fingerprint: string;
};

export type RegistrationEvidence = {
  readonly previousLive: RegisteredSession | undefined;
  readonly persistedSession: CanonicalSessionState | undefined;
  readonly terminalCancellation: PersistedTerminalCancellation | undefined;
};

export type RegistrationAuthorization =
  | { readonly kind: 'authorized' }
  | { readonly kind: 'collision'; readonly sessionId: string };

export function authorizeRegistration(
  evidence: Pick<RegistrationEvidence, 'previousLive' | 'persistedSession'>,
  input: RegisterSessionInput,
): RegistrationAuthorization {
  const requestedOwner = normalizedOwner(input);
  const liveOwner = evidence.previousLive ? normalizedOwner(evidence.previousLive) : undefined;
  const persistedOwner = evidence.persistedSession ? normalizedOwner(evidence.persistedSession) : undefined;
  if ((liveOwner && !sameOwner(liveOwner, requestedOwner))
    || (persistedOwner && !sameOwner(persistedOwner, requestedOwner))) {
    return { kind: 'collision', sessionId: input.sessionId };
  }
  return { kind: 'authorized' };
}

export type RegistrationPersistence =
  | { readonly kind: 'durable-cancel-terminal'; readonly nextDriverName: string; readonly persistedCancellation: PersistedTerminalCancellation }
  | { readonly kind: 'durable-set-session-driver' }
  | { readonly kind: 'no-op'; readonly nextDriverName: string; readonly persistedCancellation: undefined };

export type RegistrationTransition = {
  readonly nextSession: Omit<RegisteredSession, 'driverInstanceId' | 'ownerLease' | 'lastOwnerLeaseMonotonic'>;
  readonly semanticChanged: boolean;
  readonly contextChanged: boolean;
  readonly persistence: RegistrationPersistence;
};

export function reduceRegistration(
  evidence: RegistrationEvidence,
  input: RegisterSessionInput,
  hostId: string,
  now: string,
): RegistrationTransition {
  const previous = evidence.previousLive;
  const nextSession: Omit<RegisteredSession, 'driverInstanceId' | 'ownerLease' | 'lastOwnerLeaseMonotonic'> = {
    sessionId: input.sessionId, provider: input.provider, projectName: input.projectName, cwd: input.cwd, nameText: input.nameText,
    openingText: input.openingText, latestActivityText: input.latestActivityText,
    harnessProvider: input.harnessProvider, pid: input.pid,
    hostId, registeredAt: previous?.registeredAt ?? now, lastHeartbeatAt: now,
    status: input.status ?? 'idle', semanticUpdatedAt: previous?.semanticUpdatedAt ?? now,
    lastEventId: previous?.lastEventId,
  };
  const semanticChanged = !previous || semanticFingerprint(previous) !== semanticFingerprint(nextSession);
  if (semanticChanged && previous) nextSession.semanticUpdatedAt = now;
  const contextChanged = previous !== undefined
    && producerContextFingerprint(previous) !== producerContextFingerprint(nextSession);
  const persistedContextChanged = previous === undefined && evidence.persistedSession !== undefined
    && canonicalProducerContextFingerprint(evidence.persistedSession) !== producerContextFingerprint(nextSession);
  const terminalCancellation = evidence.terminalCancellation;
  const cancelTerminalRoute = contextChanged || (persistedContextChanged && terminalCancellation !== undefined);

  let persistence: RegistrationPersistence;
  if (!cancelTerminalRoute) {
    persistence = { kind: 'durable-set-session-driver' };
  } else if (terminalCancellation !== undefined) {
    persistence = { kind: 'durable-cancel-terminal', nextDriverName: input.provider, persistedCancellation: terminalCancellation };
  } else {
    persistence = { kind: 'no-op', nextDriverName: input.provider, persistedCancellation: undefined };
  }
  return { nextSession, semanticChanged, contextChanged, persistence };
}

export type HeartbeatInput = {
  readonly status: SessionStatus;
  readonly latestActivityText?: string | null;
  readonly metadata?: {
    readonly openingText?: string | null;
    readonly projectName?: string;
    readonly nameText?: string;
  };
};

export type HeartbeatTransition = {
  readonly nextSession: RegisteredSession;
  readonly semanticChanged: boolean;
  readonly contextChanged: boolean;
};

export function reduceHeartbeat(session: RegisteredSession, input: HeartbeatInput, now: string): HeartbeatTransition {
  const before = semanticFingerprint(session);
  const contextBefore = producerContextFingerprint(session);
  const nextSession: RegisteredSession = { ...session, lastHeartbeatAt: now, status: input.status };
  if (input.latestActivityText !== undefined) nextSession.latestActivityText = input.latestActivityText ?? undefined;
  const metadata = input.metadata ?? {};
  if (metadata.openingText !== undefined) nextSession.openingText = metadata.openingText ?? undefined;
  if (metadata.projectName !== undefined) nextSession.projectName = metadata.projectName;
  if (metadata.nameText !== undefined) nextSession.nameText = metadata.nameText;
  const contextChanged = producerContextFingerprint(nextSession) !== contextBefore;
  const semanticChanged = semanticFingerprint(nextSession) !== before;
  if (semanticChanged) nextSession.semanticUpdatedAt = now;
  return { nextSession, semanticChanged, contextChanged };
}
