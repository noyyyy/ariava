import type {
  HostDomainResetJournalV1,
  HostDomainResetPhase,
  HostDomainResetSigningCleanupV1,
} from './host-domain-reset-journal-schema';
export {
  HOST_DOMAIN_RESET_BINDING_INPUTS,
  hostDomainResourceDigest,
  identityResourceDigest,
} from './host-domain-reset-journal-binding';
export type { HostDomainResetBindingInput } from './host-domain-reset-journal-binding';

/**
 * Pure Host-domain reset journal transition policy.
 *
 * This module owns phase/order/transition validation and never performs
 * filesystem effects, I/O, locking, or journal removal. The pure resource
 * binding seam is owned by `host-domain-reset-journal-binding.ts`; policy may
 * re-export it for compatibility but schema never depends on policy.
 *
 * The policy validates the exact transition union instead of arbitrary
 * `Partial<Journal>` patches: allowed edges are exactly the adjacent phase
 * edges below, the only skip is `prepared -> signing-replacement-pending`
 * authorized exclusively by already-journaled recognized-unreadable evidence,
 * and same-phase transitions accept only byte-identical replay.
 */

// ---------------------------------------------------------------------------
// Frozen v1 phase order and exact transition union
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Frozen v1 phase order and exact transition union
// ---------------------------------------------------------------------------

/** Canonical frozen v1 phase order (journal-boundary spec §3.1). */
export const HOST_DOMAIN_RESET_PHASE_ORDER: readonly HostDomainResetPhase[] = [
  'quarantine-pending',
  'quarantined',
  'prepared',
  'revoke-pending',
  'old-identity-revoked',
  'signing-replacement-pending',
  'signing-identity-replaced',
  'encryption-identity-replaced',
  'runtime-artifacts-cleared',
  'config-saved',
  'enrolled',
  'service-metadata-synchronized',
  'service-restore-pending',
];

type JournalField = keyof HostDomainResetJournalV1;

/** Journal fields (excluding phase/updatedAt) that the transition policy checks. */
const TRANSITION_FIELDS: readonly JournalField[] = [
  'service',
  'revoke',
  'oldHostId',
  'oldKeyId',
  'newHostId',
  'newKeyId',
  'oldEncryptionKeyId',
  'signingCleanup',
  'signingReplacementAttemptedAt',
  'encryptionIdentityReplacedAt',
  'runtimeArtifactsClearedAt',
  'configSavedAt',
  'enrolledAt',
  'serviceMetadataSynchronizedAt',
];

/** Fields bound immutably for the whole journal lifetime. */
const IMMUTABLE_FIELDS: readonly JournalField[] = [
  'version',
  'operationId',
  'profile',
  'resourceDigest',
  'createdAt',
  'service',
];

export type HostResetJournalViolation =
  | { kind: 'same-phase-modification'; field: JournalField }
  | { kind: 'phase-rollback'; from: HostDomainResetPhase; to: HostDomainResetPhase }
  | { kind: 'non-adjacent-transition'; from: HostDomainResetPhase; to: HostDomainResetPhase }
  | { kind: 'unreadable-skip-without-evidence'; from: HostDomainResetPhase; to: HostDomainResetPhase }
  | { kind: 'revoke-precondition-mismatch'; from: HostDomainResetPhase; to: HostDomainResetPhase }
  | { kind: 'immutable-field-changed'; field: JournalField }
  | { kind: 'field-change-not-allowed'; field: JournalField; from: HostDomainResetPhase; to: HostDomainResetPhase }
  | { kind: 'one-way-fill-violation'; field: JournalField }
  | { kind: 'timestamp-rollback' };

/**
 * Exact discriminated transition union accepted by the secure store.
 *
 * Every variant names its phase and the fields that may be written on that
 * exact edge; nothing else may change. `signing-replacement-pending` covers
 * both the `old-identity-revoked` adjacent edge and the unique recognized-
 * unreadable `prepared` skip, which the policy distinguishes by the current
 * journal's revoke evidence.
 */
export type HostDomainResetTransition =
  | { phase: 'quarantined' }
  | {
    phase: 'prepared';
    oldHostId: string | null;
    oldKeyId: string | null;
    oldEncryptionKeyId: string | null;
    signingCleanup: HostDomainResetSigningCleanupV1 | null;
    revoke: HostDomainResetJournalV1['revoke'];
  }
  | { phase: 'revoke-pending'; revoke: { state: 'pending'; outcome: null } }
  | { phase: 'old-identity-revoked'; revoke: { state: 'complete'; outcome: 'revoked' | 'identity-already-revoked' } }
  | { phase: 'signing-replacement-pending'; signingReplacementAttemptedAt: string }
  | { phase: 'signing-identity-replaced'; newHostId: string; newKeyId: string }
  | { phase: 'encryption-identity-replaced'; encryptionIdentityReplacedAt: string }
  | { phase: 'runtime-artifacts-cleared'; runtimeArtifactsClearedAt: string }
  | { phase: 'config-saved'; configSavedAt: string }
  | { phase: 'enrolled'; enrolledAt: string }
  | { phase: 'service-metadata-synchronized'; serviceMetadataSynchronizedAt: string }
  | { phase: 'service-restore-pending' };

/**
 * Applies an exact transition to the current journal, stamping `updatedAt`.
 * Pure: never performs I/O, locking, or validation (the store validates the
 * resulting candidate through `validateHostDomainResetTransition`).
 */
export function applyHostDomainResetTransition(
  current: HostDomainResetJournalV1,
  transition: HostDomainResetTransition,
  updatedAt: string,
): HostDomainResetJournalV1 {
  switch (transition.phase) {
    case 'quarantined':
      return { ...current, phase: 'quarantined', updatedAt };
    case 'prepared':
      return {
        ...current,
        phase: 'prepared',
        oldHostId: transition.oldHostId,
        oldKeyId: transition.oldKeyId,
        oldEncryptionKeyId: transition.oldEncryptionKeyId,
        signingCleanup: transition.signingCleanup,
        revoke: transition.revoke,
        updatedAt,
      };
    case 'revoke-pending':
      return { ...current, phase: 'revoke-pending', revoke: transition.revoke, updatedAt };
    case 'old-identity-revoked':
      return { ...current, phase: 'old-identity-revoked', revoke: transition.revoke, updatedAt };
    case 'signing-replacement-pending':
      return { ...current, phase: 'signing-replacement-pending', signingReplacementAttemptedAt: transition.signingReplacementAttemptedAt, updatedAt };
    case 'signing-identity-replaced':
      return { ...current, phase: 'signing-identity-replaced', newHostId: transition.newHostId, newKeyId: transition.newKeyId, updatedAt };
    case 'encryption-identity-replaced':
      return { ...current, phase: 'encryption-identity-replaced', encryptionIdentityReplacedAt: transition.encryptionIdentityReplacedAt, updatedAt };
    case 'runtime-artifacts-cleared':
      return { ...current, phase: 'runtime-artifacts-cleared', runtimeArtifactsClearedAt: transition.runtimeArtifactsClearedAt, updatedAt };
    case 'config-saved':
      return { ...current, phase: 'config-saved', configSavedAt: transition.configSavedAt, updatedAt };
    case 'enrolled':
      return { ...current, phase: 'enrolled', enrolledAt: transition.enrolledAt, updatedAt };
    case 'service-metadata-synchronized':
      return { ...current, phase: 'service-metadata-synchronized', serviceMetadataSynchronizedAt: transition.serviceMetadataSynchronizedAt, updatedAt };
    case 'service-restore-pending':
      return { ...current, phase: 'service-restore-pending', updatedAt };
  }
}

export type JournalTransitionResult =
  | { ok: true; journal: HostDomainResetJournalV1 }
  | { ok: false; reason: HostResetJournalViolation };

interface TransitionEdge {
  from: HostDomainResetPhase;
  to: HostDomainResetPhase;
  /** Fields that may differ between current and candidate on this edge. */
  writable: ReadonlySet<JournalField>;
  /** Subset of `writable` that may only change one-way null -> value. */
  fillOnly: ReadonlySet<JournalField>;
  /** Optional precondition on the current journal for this edge. */
  require?: (current: HostDomainResetJournalV1) => boolean;
  /** Violation emitted when `require` fails. */
  requireViolation: HostResetJournalViolation;
}

const NO_FIELDS: ReadonlySet<JournalField> = new Set();

function fillOnly(...fields: JournalField[]): ReadonlySet<JournalField> {
  return new Set(fields);
}

function writableWith(...fields: JournalField[]): ReadonlySet<JournalField> {
  return new Set(fields);
}

const TRANSITION_EDGES: readonly TransitionEdge[] = [
  {
    from: 'quarantine-pending',
    to: 'quarantined',
    writable: NO_FIELDS,
    fillOnly: NO_FIELDS,
    requireViolation: { kind: 'non-adjacent-transition', from: 'quarantine-pending', to: 'quarantined' },
  },
  {
    from: 'quarantined',
    to: 'prepared',
    writable: writableWith('oldHostId', 'oldKeyId', 'oldEncryptionKeyId', 'signingCleanup', 'revoke'),
    fillOnly: fillOnly('oldHostId', 'oldKeyId', 'oldEncryptionKeyId', 'signingCleanup'),
    requireViolation: { kind: 'non-adjacent-transition', from: 'quarantined', to: 'prepared' },
  },
  {
    from: 'prepared',
    to: 'revoke-pending',
    writable: writableWith('revoke'),
    fillOnly: NO_FIELDS,
    require: (current) => current.revoke.state === 'not-attempted' && current.revoke.outcome === null,
    requireViolation: { kind: 'revoke-precondition-mismatch', from: 'prepared', to: 'revoke-pending' },
  },
  {
    from: 'prepared',
    to: 'signing-replacement-pending',
    writable: writableWith('signingReplacementAttemptedAt'),
    fillOnly: fillOnly('signingReplacementAttemptedAt'),
    require: (current) => current.revoke.state === 'skipped' && current.revoke.outcome === 'old-identity-unreadable',
    requireViolation: { kind: 'unreadable-skip-without-evidence', from: 'prepared', to: 'signing-replacement-pending' },
  },
  {
    from: 'revoke-pending',
    to: 'old-identity-revoked',
    writable: writableWith('revoke'),
    fillOnly: NO_FIELDS,
    require: (current) => current.revoke.state === 'pending',
    requireViolation: { kind: 'revoke-precondition-mismatch', from: 'revoke-pending', to: 'old-identity-revoked' },
  },
  {
    from: 'old-identity-revoked',
    to: 'signing-replacement-pending',
    writable: writableWith('signingReplacementAttemptedAt'),
    fillOnly: fillOnly('signingReplacementAttemptedAt'),
    requireViolation: { kind: 'non-adjacent-transition', from: 'old-identity-revoked', to: 'signing-replacement-pending' },
  },
  {
    from: 'signing-replacement-pending',
    to: 'signing-identity-replaced',
    writable: writableWith('newHostId', 'newKeyId'),
    fillOnly: fillOnly('newHostId', 'newKeyId'),
    requireViolation: { kind: 'non-adjacent-transition', from: 'signing-replacement-pending', to: 'signing-identity-replaced' },
  },
  {
    from: 'signing-identity-replaced',
    to: 'encryption-identity-replaced',
    writable: writableWith('encryptionIdentityReplacedAt'),
    fillOnly: fillOnly('encryptionIdentityReplacedAt'),
    requireViolation: { kind: 'non-adjacent-transition', from: 'signing-identity-replaced', to: 'encryption-identity-replaced' },
  },
  {
    from: 'encryption-identity-replaced',
    to: 'runtime-artifacts-cleared',
    writable: writableWith('runtimeArtifactsClearedAt'),
    fillOnly: fillOnly('runtimeArtifactsClearedAt'),
    requireViolation: { kind: 'non-adjacent-transition', from: 'encryption-identity-replaced', to: 'runtime-artifacts-cleared' },
  },
  {
    from: 'runtime-artifacts-cleared',
    to: 'config-saved',
    writable: writableWith('configSavedAt'),
    fillOnly: fillOnly('configSavedAt'),
    requireViolation: { kind: 'non-adjacent-transition', from: 'runtime-artifacts-cleared', to: 'config-saved' },
  },
  {
    from: 'config-saved',
    to: 'enrolled',
    writable: writableWith('enrolledAt'),
    fillOnly: fillOnly('enrolledAt'),
    requireViolation: { kind: 'non-adjacent-transition', from: 'config-saved', to: 'enrolled' },
  },
  {
    from: 'enrolled',
    to: 'service-metadata-synchronized',
    writable: writableWith('serviceMetadataSynchronizedAt'),
    fillOnly: fillOnly('serviceMetadataSynchronizedAt'),
    requireViolation: { kind: 'non-adjacent-transition', from: 'enrolled', to: 'service-metadata-synchronized' },
  },
  {
    from: 'service-metadata-synchronized',
    to: 'service-restore-pending',
    writable: NO_FIELDS,
    fillOnly: NO_FIELDS,
    requireViolation: { kind: 'non-adjacent-transition', from: 'service-metadata-synchronized', to: 'service-restore-pending' },
  },
];

function sameValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function phaseIndex(phase: HostDomainResetPhase): number {
  const index = HOST_DOMAIN_RESET_PHASE_ORDER.indexOf(phase);
  if (index < 0) throw new TypeError(`Host-domain reset journal phase ${phase} is not a known v1 phase`);
  return index;
}

function findEdge(from: HostDomainResetPhase, to: HostDomainResetPhase): TransitionEdge | undefined {
  return TRANSITION_EDGES.find((edge) => edge.from === from && edge.to === to);
}

function firstDifferingField(current: HostDomainResetJournalV1, candidate: HostDomainResetJournalV1): JournalField | undefined {
  for (const field of TRANSITION_FIELDS) {
    if (!sameValue(current[field], candidate[field])) return field;
  }
  return undefined;
}

/**
 * Validates that `candidate` is reached from `current` by exactly one legal
 * transition. Both journals must already be exact-decoded/schema-valid.
 *
 * - same phase: accepts only byte-identical replay;
 * - different phase: must be an adjacent edge (or the unique recognized-
 *   unreadable skip) with only the edge's writable fields differing;
 * - `quarantined -> prepared` is the only edge that binds old identity/E2E/
 *   cleanup/revoke decision;
 * - new IDs and the six effect timestamps fill only one-way null -> value on
 *   their exact edge and are never overwritten;
 * - operation/profile/resource/service/createdAt never change and `updatedAt`
 *   never rolls back.
 */
export function validateHostDomainResetTransition(
  current: HostDomainResetJournalV1,
  candidate: HostDomainResetJournalV1,
): JournalTransitionResult {
  if (candidate.phase === current.phase) {
    if (sameValue(current, candidate)) return { ok: true, journal: candidate };
    const field = firstDifferingField(current, candidate) ?? 'updatedAt';
    return { ok: false, reason: { kind: 'same-phase-modification', field } };
  }

  if (phaseIndex(candidate.phase) < phaseIndex(current.phase)) {
    return { ok: false, reason: { kind: 'phase-rollback', from: current.phase, to: candidate.phase } };
  }

  const edge = findEdge(current.phase, candidate.phase);
  if (!edge) {
    return { ok: false, reason: { kind: 'non-adjacent-transition', from: current.phase, to: candidate.phase } };
  }

  if (edge.require && !edge.require(current)) {
    return { ok: false, reason: edge.requireViolation };
  }

  if (Date.parse(candidate.updatedAt) < Date.parse(current.updatedAt)) {
    return { ok: false, reason: { kind: 'timestamp-rollback' } };
  }

  for (const field of IMMUTABLE_FIELDS) {
    if (!sameValue(current[field], candidate[field])) {
      return { ok: false, reason: { kind: 'immutable-field-changed', field } };
    }
  }

  for (const field of TRANSITION_FIELDS) {
    if (IMMUTABLE_FIELDS.includes(field)) continue;
    if (!sameValue(current[field], candidate[field])) {
      if (!edge.writable.has(field)) {
        return { ok: false, reason: { kind: 'field-change-not-allowed', field, from: current.phase, to: candidate.phase } };
      }
      if (edge.fillOnly.has(field) && current[field] !== null) {
        return { ok: false, reason: { kind: 'one-way-fill-violation', field } };
      }
    }
  }

  return { ok: true, journal: candidate };
}

/** Human-readable message for a transition violation (used by the store). */
export function hostResetJournalViolationMessage(reason: HostResetJournalViolation): string {
  switch (reason.kind) {
    case 'same-phase-modification':
      return `Host-domain reset journal ${reason.field} cannot change without a phase transition`;
    case 'phase-rollback':
      return `Host-domain reset journal phase rollback is not allowed (from ${reason.from} to ${reason.to})`;
    case 'non-adjacent-transition':
      return `Host-domain reset journal non-adjacent phase transition is not allowed (from ${reason.from} to ${reason.to})`;
    case 'unreadable-skip-without-evidence':
      return `Host-domain reset journal unreadable skip requires journaled skipped/old-identity-unreadable revoke evidence (from ${reason.from} to ${reason.to})`;
    case 'revoke-precondition-mismatch':
      return `Host-domain reset journal revoke transition is not allowed (from ${reason.from} to ${reason.to})`;
    case 'immutable-field-changed':
      return `Host-domain reset journal ${reason.field} cannot change`;
    case 'field-change-not-allowed':
      return `Host-domain reset journal ${reason.field} cannot change on transition (from ${reason.from} to ${reason.to})`;
    case 'one-way-fill-violation':
      return `Host-domain reset journal ${reason.field} can only be filled once`;
    case 'timestamp-rollback':
      return 'Host-domain reset journal timestamp rollback is not allowed';
  }
}
