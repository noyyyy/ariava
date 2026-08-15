/**
 * Compatibility module for the Host-domain reset journal.
 *
 * Authoritative public surface (spec §9): constants, journal types, digests,
 * the controlled store operations, and the opaque operation-lease / machine
 * transition / restore-confirmation types. Low-level decoder internals, raw
 * encoder/bytes, lock snapshots, and unsafe write/remove are NOT exposed here;
 * the unrestricted raw write/remove API and the `operationLockHeld` bypass no
 * longer exist in production.
 */
export {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
  identityResourceDigest,
  hostDomainResourceDigest,
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
  advanceHostDomainResetJournal,
  assertHostDomainResetRuntimeStartAllowed,
  createHostDomainResetJournal,
  loadHostDomainResetJournal,
  removeAfterServiceRestoreConfirmed,
} from './host-domain-reset-journal-store';
export type { RestoreConfirmation } from './host-domain-reset-journal-store';
export type {
  HostDomainResetJournalTransition,
  HostResetJournalViolation,
} from './host-domain-reset-journal-policy';
export type { HostIdentityOperationLease } from './host-identity-operation-lock';
