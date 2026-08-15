/**
 * Test-tree fixture support for the Host-domain reset journal.
 *
 * Builds schema-valid v1 journals at any frozen phase (via the pure schema
 * module) and persists them as canonical secure bytes. This helper is test
 * support only: production code must never import it, and tests must reach
 * journal I/O through the store API or through this helper.
 */
import { mkdirSync } from 'node:fs';
import type { ProfileResourceSet } from '../../src/cli/profile';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
  hostDomainResourceDigest,
  parseHostDomainResetJournal,
  type HostDomainResetJournalV1,
  type HostDomainResetPhase,
} from '../../src/cli/operations/host-domain-reset-journal-schema';
import {
  removeSecureFileIfPresent,
  writeSecureJson,
  type SecureFileRemoveHooks,
} from '../../src/host-manager/secure-files';

export const OLD_HOST = `host_${'A'.repeat(43)}`;
export const OLD_KEY = `key_${'B'.repeat(43)}`;
export const OLD_EKEY = `ekey_${'C'.repeat(43)}`;
export const NEW_HOST = `host_${'D'.repeat(43)}`;
export const NEW_KEY = `key_${'E'.repeat(43)}`;
export const TS0 = '2026-08-11T00:00:00.000Z';
export const TS1 = '2026-08-11T00:00:01.000Z';

export function unmanagedOrLaunchedService(resources: ProfileResourceSet): HostDomainResetJournalV1['service'] {
  return {
    managed: resources.identityProfile === 'default',
    installed: false,
    enabled: false,
    wasRunning: false,
    backend: resources.identityProfile === 'default' ? 'launchd' : 'none',
  };
}

/**
 * Build a schema-valid v1 journal at any frozen phase with the evidence the
 * normative phase table requires (readable revoke path). `patch` is applied
 * last and must keep the result schema-valid; it is validated at write time.
 */
export function buildJournal(
  resources: ProfileResourceSet,
  phase: HostDomainResetPhase,
  patch: Partial<HostDomainResetJournalV1> = {},
): HostDomainResetJournalV1 {
  const index = HOST_DOMAIN_RESET_PHASES.indexOf(phase);
  const atLeast = (candidate: HostDomainResetPhase) => index >= HOST_DOMAIN_RESET_PHASES.indexOf(candidate);
  const preInspection = phase === 'quarantine-pending' || phase === 'quarantined';
  const oldKnown = !preInspection;
  const revoke: HostDomainResetJournalV1['revoke'] = preInspection || phase === 'prepared'
    ? { state: 'not-attempted', outcome: null }
    : phase === 'revoke-pending'
      ? { state: 'pending', outcome: null }
      : { state: 'complete', outcome: 'revoked' };
  return {
    version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
    operationId: 'reset_0123456789abcdef',
    profile: resources.identityProfile,
    phase,
    oldHostId: oldKnown ? OLD_HOST : null,
    oldKeyId: oldKnown ? OLD_KEY : null,
    newHostId: atLeast('signing-identity-replaced') ? NEW_HOST : null,
    newKeyId: atLeast('signing-identity-replaced') ? NEW_KEY : null,
    oldEncryptionKeyId: oldKnown ? OLD_EKEY : null,
    signingCleanup: null,
    signingReplacementAttemptedAt: atLeast('signing-replacement-pending') ? TS1 : null,
    encryptionIdentityReplacedAt: atLeast('encryption-identity-replaced') ? TS1 : null,
    runtimeArtifactsClearedAt: atLeast('runtime-artifacts-cleared') ? TS1 : null,
    configSavedAt: atLeast('config-saved') ? TS1 : null,
    enrolledAt: atLeast('enrolled') ? TS1 : null,
    serviceMetadataSynchronizedAt: atLeast('service-metadata-synchronized') ? TS1 : null,
    resourceDigest: hostDomainResourceDigest(resources),
    createdAt: TS0,
    updatedAt: TS1,
    revoke,
    service: unmanagedOrLaunchedService(resources),
    ...patch,
  };
}

/**
 * Persist a journal as canonical owner-only bytes. The journal is validated
 * through the exact schema decoder first, so invalid fixtures fail closed at
 * write time (matching the store's write acceptance).
 */
export function writeJournalFixture(
  resources: ProfileResourceSet,
  journal: HostDomainResetJournalV1,
  uid?: number,
): void {
  mkdirSync(resources.root, { recursive: true, mode: 0o700 });
  const validated = parseHostDomainResetJournal(journal, resources);
  writeSecureJson(resources.hostDomainResetJournalPath, validated, uid);
}

export function removeJournalFixture(resources: ProfileResourceSet, uid?: number, hooks?: SecureFileRemoveHooks): void {
  removeSecureFileIfPresent(resources.hostDomainResetJournalPath, uid, hooks);
}
