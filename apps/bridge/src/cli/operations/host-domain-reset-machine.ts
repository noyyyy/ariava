import {
  HOST_DOMAIN_RESET_PHASE_ORDER,
} from './host-domain-reset-journal-policy';
import type {
  HostDomainResetJournalV1,
  HostDomainResetRevokeOutcome,
  HostDomainResetRevokeState,
} from './host-domain-reset-journal-schema';

/**
 * Pure Host-domain reset state machine (primary spec §6–§7, journal-boundary
 * spec §3.2/§7).
 *
 * This module owns ONLY the frozen phase -> next-action vocabulary. It is
 * strictly pure: it never performs I/O, never generates keys, never inspects
 * filesystem/sentinel/Relay/service evidence, and never modifies the journal.
 * `nextHostResetAction(journal)` receives only an exact-decoded v1 journal and
 * is uniquely determined by the phase plus already-journaled fields; any
 * journal that is not a legal, exact-decoded v1 journal fails closed.
 *
 * Import boundary: this module imports ONLY type definitions from the
 * schema module and the pure phase order from the policy module (used for
 * fail-closed legality checks). It never imports the store module,
 * executor/recovery/artifact modules, or any host-manager/state-store/
 * relay/I-O module.
 */

export type HostResetAction =
  | { type: 'stop-quarantine-and-acquire-runtime' }
  | { type: 'inspect-and-bind-old-domain' }
  | { type: 'persist-revoke-intent' }
  | { type: 'revoke-old-identity' }
  | { type: 'persist-signing-replacement-intent' }
  | { type: 'replace-signing-identity' }
  | { type: 'finalize-signing-and-replace-encryption-identity' }
  | { type: 'finalize-encryption-and-clear-runtime-artifacts' }
  | { type: 'persist-config' }
  | { type: 'enroll-new-identity' }
  | { type: 'sync-service-metadata' }
  | { type: 'persist-service-restore-intent' }
  | { type: 'restore-service-and-remove-journal' };

const REVOKE_STATES: readonly HostDomainResetRevokeState[] = ['not-attempted', 'pending', 'complete', 'skipped'];
const REVOKE_OUTCOMES: readonly HostDomainResetRevokeOutcome[] = [
  null,
  'revoked',
  'identity-already-revoked',
  'old-identity-unreadable',
];

function isLegalRevokeCombination(state: HostDomainResetRevokeState, outcome: HostDomainResetRevokeOutcome): boolean {
  if (!REVOKE_STATES.includes(state) || !REVOKE_OUTCOMES.includes(outcome)) return false;
  if (state === 'not-attempted' || state === 'pending') return outcome === null;
  if (state === 'complete') return outcome === 'revoked' || outcome === 'identity-already-revoked';
  return state === 'skipped' && outcome === 'old-identity-unreadable';
}

function assertLegalJournal(journal: HostDomainResetJournalV1): void {
  if (!journal || typeof journal !== 'object'
    || !HOST_DOMAIN_RESET_PHASE_ORDER.includes(journal.phase)) throw invalidMachineJournal();
  const revoke = journal.revoke;
  if (!revoke || typeof revoke !== 'object'
    || !isLegalRevokeCombination(revoke.state, revoke.outcome)) {
    throw invalidMachineJournal();
  }
  // Phase-specific revoke consistency (schema §3.2 invariants): an illegal
  // revoke combination for the current phase fails closed even when the
  // generic combination is legal (e.g. complete/revoked at revoke-pending).
  const phase = journal.phase;
  if (phase === 'quarantine-pending' || phase === 'quarantined') {
    if (revoke.state !== 'not-attempted' || revoke.outcome !== null) throw invalidMachineJournal();
    return;
  }
  if (phase === 'revoke-pending') {
    if (revoke.state !== 'pending' || revoke.outcome !== null) throw invalidMachineJournal();
    return;
  }
  if (phase === 'old-identity-revoked') {
    if (revoke.state !== 'complete'
      || (revoke.outcome !== 'revoked' && revoke.outcome !== 'identity-already-revoked')) {
      throw invalidMachineJournal();
    }
    return;
  }
  if (phase === 'prepared') {
    // Prepared records intent selection but has not persisted revoke-pending.
    // `pending/null` is schema-invalid at this phase and must fail closed.
    if (revoke.state !== 'not-attempted' && revoke.state !== 'skipped') {
      throw invalidMachineJournal();
    }
    return;
  }
  // Later phases: the signed/E2E/artifact/config/enroll/metadata/restore
  // phases keep the definitive revoke decision already journaled.
  if (revoke.state !== 'complete' && revoke.state !== 'skipped') throw invalidMachineJournal();
}

function invalidMachineJournal(): TypeError {
  return new TypeError('Host-domain reset journal is invalid');
}

/**
 * Returns the single next action for an exact-decoded journal.
 *
 * The action is determined ONLY by `journal.phase` and already-journaled
 * fields. In particular the `prepared` phase expands into two mapping cases:
 * - readable old identity (journaled revoke `not-attempted` with
 *   `outcome: null`) selects `persist-revoke-intent`;
 * - recognized-unreadable old identity (journaled revoke
 *   `skipped` + `old-identity-unreadable`) selects
 *   `persist-signing-replacement-intent`.
 * No external evidence can reach this function, so none can change its result.
 * Any unknown phase, illegal revoke combination, or malformed journal fails
 * closed.
 */
export function nextHostResetAction(journal: HostDomainResetJournalV1): HostResetAction {
  assertLegalJournal(journal);
  switch (journal.phase) {
    case 'quarantine-pending':
      return { type: 'stop-quarantine-and-acquire-runtime' };
    case 'quarantined':
      return { type: 'inspect-and-bind-old-domain' };
    case 'prepared': {
      if (journal.revoke.state === 'skipped') {
        if (journal.revoke.outcome !== 'old-identity-unreadable') throw invalidMachineJournal();
        return { type: 'persist-signing-replacement-intent' };
      }
      if (journal.revoke.state !== 'not-attempted') {
        throw invalidMachineJournal();
      }
      if (journal.revoke.outcome !== null) throw invalidMachineJournal();
      return { type: 'persist-revoke-intent' };
    }
    case 'revoke-pending':
      return { type: 'revoke-old-identity' };
    case 'old-identity-revoked':
      return { type: 'persist-signing-replacement-intent' };
    case 'signing-replacement-pending':
      return { type: 'replace-signing-identity' };
    case 'signing-identity-replaced':
      return { type: 'finalize-signing-and-replace-encryption-identity' };
    case 'encryption-identity-replaced':
      return { type: 'finalize-encryption-and-clear-runtime-artifacts' };
    case 'runtime-artifacts-cleared':
      return { type: 'persist-config' };
    case 'config-saved':
      return { type: 'enroll-new-identity' };
    case 'enrolled':
      return { type: 'sync-service-metadata' };
    case 'service-metadata-synchronized':
      return { type: 'persist-service-restore-intent' };
    case 'service-restore-pending':
      return { type: 'restore-service-and-remove-journal' };
  }
}
