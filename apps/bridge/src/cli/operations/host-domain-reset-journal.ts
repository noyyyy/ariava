import {
  loadHostDomainResetJournal,
} from './host-domain-reset-journal-store';
import type { ProfileResourceSet } from '../profile';

// ---------------------------------------------------------------------------
// Host-domain reset journal compatibility module (journal-boundary spec §9)
//
// This module exports EXACTLY the authoritative compatibility surface. Low-level
// schema/codec internals, raw journal writes/unlinks, and lock snapshots are
// NOT public here. Consumers must go through the high-level store operations.
// ---------------------------------------------------------------------------

export {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
} from './host-domain-reset-journal-schema';
export type {
  HostDomainResetPhase,
  HostDomainResetRevokeState,
  HostDomainResetRevokeOutcome,
  HostDomainResetServiceBackend,
  HostDomainResetSigningCleanupV1,
  HostDomainResetJournalV1,
} from './host-domain-reset-journal-schema';
export {
  identityResourceDigest,
  hostDomainResourceDigest,
} from './host-domain-reset-journal-policy';
export type { HostDomainResetTransition } from './host-domain-reset-journal-policy';
export {
  loadHostDomainResetJournal,
  advanceHostDomainResetJournal,
  createHostDomainResetJournal,
  removeAfterServiceRestoreConfirmed,
} from './host-domain-reset-journal-store';
export type { RestoreConfirmation } from './host-domain-reset-journal-store';
export type { HostIdentityOperationLease } from './host-identity-operation-lock';

export function assertHostDomainResetRuntimeStartAllowed(resources: ProfileResourceSet): void {
  const journal = loadHostDomainResetJournal(resources);
  if (!journal) return;
  const remediation = resources.identityProfile === 'dev'
    ? 'bun run dev:cli -- identity reset --confirm'
    : 'ariava identity reset --confirm';
  const error = new Error(`Host-domain reset recovery required at phase ${journal.phase}; run \`${remediation}\``);
  Object.assign(error, {
    code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
    phase: journal.phase,
    operationId: journal.operationId,
    retryable: true,
    remediation,
  });
  throw error;
}
