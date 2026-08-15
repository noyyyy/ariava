import type { ProfileResourceSet } from '../profile';
import {
  encodeHostDomainResetJournal,
  hostDomainResourceDigest,
  parseHostDomainResetJournal,
  phaseOrder,
  type HostDomainResetJournalV1,
  type HostDomainResetPhase,
  type HostDomainResetSigningCleanupV1,
} from './host-domain-reset-journal-schema';

/**
 * Exact machine-authorized transition union. The production coordinator may
 * not construct arbitrary `Partial<Journal>` patches; every write-side
 * advancement must submit one of these discriminated transitions.
 */
export type HostDomainResetJournalTransition =
  | { kind: 'advance'; phase: 'quarantined'; at: string }                                  // quarantine-pending -> quarantined
  | { kind: 'bind-prepared'; at: string; oldHostId: string | null; oldKeyId: string | null;
      oldEncryptionKeyId: string | null; signingCleanup: HostDomainResetSigningCleanupV1 | null;
      revoke: { state: 'not-attempted'; outcome: null } | { state: 'skipped'; outcome: 'old-identity-unreadable' } }
  | { kind: 'start-revoke'; at: string }                                                   // prepared -> revoke-pending
  | { kind: 'complete-revoke'; at: string; outcome: 'revoked' | 'identity-already-revoked' } // revoke-pending -> old-identity-revoked
  | { kind: 'begin-signing-replacement'; at: string }                                      // old-identity-revoked -> signing-replacement-pending
                                                                                            //   or prepared -> signing-replacement-pending (only with recognized unreadable evidence)
  | { kind: 'complete-signing-replacement'; at: string; newHostId: string; newKeyId: string } // -> signing-identity-replaced
  | { kind: 'complete-encryption-replacement'; at: string }                                // -> encryption-identity-replaced
  | { kind: 'complete-artifact-cleanup'; at: string }                                      // -> runtime-artifacts-cleared
  | { kind: 'complete-config-save'; at: string }                                           // -> config-saved
  | { kind: 'complete-enrollment'; at: string }                                            // -> enrolled
  | { kind: 'complete-metadata-sync'; at: string }                                         // -> service-metadata-synchronized
  | { kind: 'complete-restore-intent'; at: string }                                        // -> service-restore-pending
  | { kind: 'replay' };                                                                    // same-phase byte-identical

export type HostResetJournalViolation =
  | { kind: 'unknown-transition' }
  | { kind: 'phase-rollback' }
  | { kind: 'phase-skip' }
  | { kind: 'forbidden-skip' }
  | { kind: 'same-phase-mutation' }
  | { kind: 'timestamp-rollback' }
  | { kind: 'immutable-binding-change'; field: string }
  | { kind: 'premature-binding' }
  | { kind: 'non-null-overwrite'; field: string }
  | { kind: 'digest-mismatch' }
  | { kind: 'service-snapshot-change' }
  | { kind: 'invalid-candidate'; detail?: string };

export type JournalTransitionResult =
  | { ok: true; journal: HostDomainResetJournalV1 }
  | { ok: false; reason: HostResetJournalViolation };

type NonReplayTransition = Exclude<HostDomainResetJournalTransition, { kind: 'replay' }>;
type TransitionKind = NonReplayTransition['kind'];

const TRANSITION_TARGET: Record<TransitionKind, HostDomainResetPhase> = {
  advance: 'quarantined',
  'bind-prepared': 'prepared',
  'start-revoke': 'revoke-pending',
  'complete-revoke': 'old-identity-revoked',
  'begin-signing-replacement': 'signing-replacement-pending',
  'complete-signing-replacement': 'signing-identity-replaced',
  'complete-encryption-replacement': 'encryption-identity-replaced',
  'complete-artifact-cleanup': 'runtime-artifacts-cleared',
  'complete-config-save': 'config-saved',
  'complete-enrollment': 'enrolled',
  'complete-metadata-sync': 'service-metadata-synchronized',
  'complete-restore-intent': 'service-restore-pending',
};

const TRANSITION_SOURCES: Record<TransitionKind, readonly HostDomainResetPhase[]> = {
  advance: ['quarantine-pending'],
  'bind-prepared': ['quarantined'],
  'start-revoke': ['prepared'],
  'complete-revoke': ['revoke-pending'],
  'begin-signing-replacement': ['prepared', 'old-identity-revoked'],
  'complete-signing-replacement': ['signing-replacement-pending'],
  'complete-encryption-replacement': ['signing-identity-replaced'],
  'complete-artifact-cleanup': ['encryption-identity-replaced'],
  'complete-config-save': ['runtime-artifacts-cleared'],
  'complete-enrollment': ['config-saved'],
  'complete-metadata-sync': ['enrolled'],
  'complete-restore-intent': ['service-metadata-synchronized'],
};

const TRANSITION_MUTATIONS: Record<TransitionKind, readonly string[]> = {
  advance: ['phase', 'updatedAt'],
  'bind-prepared': ['phase', 'updatedAt', 'oldHostId', 'oldKeyId', 'oldEncryptionKeyId', 'signingCleanup', 'revoke'],
  'start-revoke': ['phase', 'updatedAt', 'revoke'],
  'complete-revoke': ['phase', 'updatedAt', 'revoke'],
  'begin-signing-replacement': ['phase', 'updatedAt', 'signingReplacementAttemptedAt'],
  'complete-signing-replacement': ['phase', 'updatedAt', 'newHostId', 'newKeyId'],
  'complete-encryption-replacement': ['phase', 'updatedAt', 'encryptionIdentityReplacedAt'],
  'complete-artifact-cleanup': ['phase', 'updatedAt', 'runtimeArtifactsClearedAt'],
  'complete-config-save': ['phase', 'updatedAt', 'configSavedAt'],
  'complete-enrollment': ['phase', 'updatedAt', 'enrolledAt'],
  'complete-metadata-sync': ['phase', 'updatedAt', 'serviceMetadataSynchronizedAt'],
  'complete-restore-intent': ['phase', 'updatedAt'],
};

const IMMUTABLE_FIELDS = [
  'version', 'operationId', 'profile', 'resourceDigest', 'createdAt',
] as const;
const OLD_BINDING_FIELDS = [
  'oldHostId', 'oldKeyId', 'oldEncryptionKeyId', 'signingCleanup', 'revoke',
] as const;
const NULL_ONLY_FIELDS = [
  'oldHostId', 'oldKeyId', 'oldEncryptionKeyId', 'signingCleanup',
  'newHostId', 'newKeyId', 'signingReplacementAttemptedAt', 'encryptionIdentityReplacedAt',
  'runtimeArtifactsClearedAt', 'configSavedAt', 'enrolledAt', 'serviceMetadataSynchronizedAt',
] as const;

/**
 * Apply one machine-authorized transition to the stored current journal.
 * Returns the candidate on success or a classified violation. The candidate
 * must pass the exact decoder after applying (digest, phase evidence, and
 * timestamp invariants are re-validated by the schema).
 */
export function applyHostDomainResetJournalTransition(
  current: HostDomainResetJournalV1,
  transition: HostDomainResetJournalTransition,
  resources: ProfileResourceSet,
): JournalTransitionResult {
  if (transition.kind === 'replay') return { ok: true, journal: current };

  const target = TRANSITION_TARGET[transition.kind];
  if (Date.parse(transition.at) < Date.parse(current.updatedAt)) {
    return { ok: false, reason: { kind: 'timestamp-rollback' } };
  }
  const candidate = buildCandidate(current, transition);
  if (target === current.phase) {
    return encodeHostDomainResetJournal(candidate) === encodeHostDomainResetJournal(current)
      ? { ok: true, journal: candidate }
      : { ok: false, reason: { kind: 'same-phase-mutation' } };
  }

  const sources = TRANSITION_SOURCES[transition.kind];
  if (!sources.includes(current.phase)) {
    if (phaseOrder(current.phase) > phaseOrder(target)) {
      return { ok: false, reason: { kind: 'phase-rollback' } };
    }
    return transition.kind === 'begin-signing-replacement' && current.phase === 'prepared'
      ? { ok: false, reason: { kind: 'forbidden-skip' } }
      : { ok: false, reason: { kind: 'phase-skip' } };
  }
  if (transition.kind === 'begin-signing-replacement' && current.phase === 'prepared') {
    const revokeSkipped = current.revoke.state === 'skipped' && current.revoke.outcome === 'old-identity-unreadable';
    if (!revokeSkipped || current.signingCleanup === null) {
      return { ok: false, reason: { kind: 'forbidden-skip' } };
    }
  }

  const overwritten = nullOnlyOverwritten(current, transition);
  if (overwritten !== null) {
    return { ok: false, reason: { kind: 'non-null-overwrite', field: overwritten } };
  }
  const scope = mutatedOutOfScope(current, candidate, transition);
  if (scope !== null) {
    if (scope === 'service') return { ok: false, reason: { kind: 'service-snapshot-change' } };
    if ((OLD_BINDING_FIELDS as readonly string[]).includes(scope)) {
      return { ok: false, reason: { kind: 'premature-binding' } };
    }
    return { ok: false, reason: { kind: 'immutable-binding-change', field: scope } };
  }
  if (candidate.resourceDigest !== hostDomainResourceDigest(resources)) {
    return { ok: false, reason: { kind: 'digest-mismatch' } };
  }

  let journal: HostDomainResetJournalV1;
  try {
    journal = parseHostDomainResetJournal(candidate, resources);
  } catch {
    return { ok: false, reason: { kind: 'invalid-candidate' } };
  }
  return { ok: true, journal };
}

/**
 * Create-time guard: the initial journal must be an exact schema-valid
 * `quarantine-pending` journal with empty identity evidence, empty effect
 * timestamps, `revoke = not-attempted/null`, and `updatedAt === createdAt`.
 */
export function validateInitialJournal(
  initial: HostDomainResetJournalV1,
  resources: ProfileResourceSet,
): JournalTransitionResult {
  let parsed: HostDomainResetJournalV1;
  try {
    parsed = parseHostDomainResetJournal(initial, resources);
  } catch {
    return { ok: false, reason: { kind: 'invalid-candidate' } };
  }
  if (parsed.phase !== 'quarantine-pending') {
    return { ok: false, reason: { kind: 'invalid-candidate', detail: 'initial journal must be quarantine-pending' } };
  }
  if (parsed.oldHostId !== null || parsed.oldKeyId !== null || parsed.newHostId !== null
    || parsed.newKeyId !== null || parsed.oldEncryptionKeyId !== null || parsed.signingCleanup !== null) {
    return { ok: false, reason: { kind: 'invalid-candidate', detail: 'initial journal must not bind identity evidence' } };
  }
  if (parsed.signingReplacementAttemptedAt !== null || parsed.encryptionIdentityReplacedAt !== null
    || parsed.runtimeArtifactsClearedAt !== null || parsed.configSavedAt !== null || parsed.enrolledAt !== null
    || parsed.serviceMetadataSynchronizedAt !== null) {
    return { ok: false, reason: { kind: 'invalid-candidate', detail: 'initial journal must not carry effect timestamps' } };
  }
  if (parsed.revoke.state !== 'not-attempted' || parsed.revoke.outcome !== null) {
    return { ok: false, reason: { kind: 'invalid-candidate', detail: 'initial journal revoke must be not-attempted/null' } };
  }
  if (parsed.updatedAt !== parsed.createdAt) {
    return { ok: false, reason: { kind: 'invalid-candidate', detail: 'initial journal updatedAt must equal createdAt' } };
  }
  return { ok: true, journal: parsed };
}

function buildCandidate(current: HostDomainResetJournalV1, transition: NonReplayTransition): HostDomainResetJournalV1 {
  const at = transition.at;
  const base = { ...current, updatedAt: at };
  switch (transition.kind) {
    case 'advance':
      return { ...base, phase: 'quarantined' };
    case 'bind-prepared':
      return {
        ...base,
        phase: 'prepared',
        oldHostId: transition.oldHostId,
        oldKeyId: transition.oldKeyId,
        oldEncryptionKeyId: transition.oldEncryptionKeyId,
        signingCleanup: transition.signingCleanup,
        revoke: transition.revoke,
      };
    case 'start-revoke':
      return { ...base, phase: 'revoke-pending', revoke: { state: 'pending', outcome: null } };
    case 'complete-revoke':
      return { ...base, phase: 'old-identity-revoked', revoke: { state: 'complete', outcome: transition.outcome } };
    case 'begin-signing-replacement':
      return { ...base, phase: 'signing-replacement-pending', signingReplacementAttemptedAt: at };
    case 'complete-signing-replacement':
      return { ...base, phase: 'signing-identity-replaced', newHostId: transition.newHostId, newKeyId: transition.newKeyId };
    case 'complete-encryption-replacement':
      return { ...base, phase: 'encryption-identity-replaced', encryptionIdentityReplacedAt: at };
    case 'complete-artifact-cleanup':
      return { ...base, phase: 'runtime-artifacts-cleared', runtimeArtifactsClearedAt: at };
    case 'complete-config-save':
      return { ...base, phase: 'config-saved', configSavedAt: at };
    case 'complete-enrollment':
      return { ...base, phase: 'enrolled', enrolledAt: at };
    case 'complete-metadata-sync':
      return { ...base, phase: 'service-metadata-synchronized', serviceMetadataSynchronizedAt: at };
    case 'complete-restore-intent':
      return { ...base, phase: 'service-restore-pending' };
  }
}

function nullOnlyOverwritten(current: HostDomainResetJournalV1, transition: NonReplayTransition): string | null {
  switch (transition.kind) {
    case 'bind-prepared':
      for (const field of ['oldHostId', 'oldKeyId', 'oldEncryptionKeyId', 'signingCleanup'] as const) {
        if (current[field] !== null) return field;
      }
      return null;
    case 'complete-signing-replacement':
      if (current.newHostId !== null) return 'newHostId';
      if (current.newKeyId !== null) return 'newKeyId';
      return null;
    case 'begin-signing-replacement':
      return current.signingReplacementAttemptedAt !== null ? 'signingReplacementAttemptedAt' : null;
    case 'complete-encryption-replacement':
      return current.encryptionIdentityReplacedAt !== null ? 'encryptionIdentityReplacedAt' : null;
    case 'complete-artifact-cleanup':
      return current.runtimeArtifactsClearedAt !== null ? 'runtimeArtifactsClearedAt' : null;
    case 'complete-config-save':
      return current.configSavedAt !== null ? 'configSavedAt' : null;
    case 'complete-enrollment':
      return current.enrolledAt !== null ? 'enrolledAt' : null;
    case 'complete-metadata-sync':
      return current.serviceMetadataSynchronizedAt !== null ? 'serviceMetadataSynchronizedAt' : null;
    default:
      return null;
  }
}

function mutatedOutOfScope(
  current: HostDomainResetJournalV1,
  candidate: HostDomainResetJournalV1,
  transition: NonReplayTransition,
): string | null {
  const allowed = new Set(TRANSITION_MUTATIONS[transition.kind]);
  for (const key of [...IMMUTABLE_FIELDS, ...OLD_BINDING_FIELDS, 'service', 'newHostId', 'newKeyId',
    'signingReplacementAttemptedAt', 'encryptionIdentityReplacedAt', 'runtimeArtifactsClearedAt',
    'configSavedAt', 'enrolledAt', 'serviceMetadataSynchronizedAt'] as const) {
    if (allowed.has(key)) continue;
    if (fieldChanged(key, current, candidate)) return key;
  }
  return null;
}

function fieldChanged(
  key: string,
  current: HostDomainResetJournalV1,
  candidate: HostDomainResetJournalV1,
): boolean {
  const currentValue = (current as unknown as Record<string, unknown>)[key];
  const candidateValue = (candidate as unknown as Record<string, unknown>)[key];
  return JSON.stringify(currentValue) !== JSON.stringify(candidateValue);
}
