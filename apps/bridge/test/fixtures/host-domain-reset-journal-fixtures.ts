import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { ProfileResourceSet } from '../../src/cli/profile';
import { encodeHostDomainResetJournal, type HostDomainResetJournalV1 } from '../../src/cli/operations/host-domain-reset-journal-schema';
import { removeSecureFileIfPresent, type SecureFileRemoveHooks } from '../../src/host-manager/secure-files';

/**
 * Test-tree journal fixture helpers.
 *
 * These helpers live ONLY in the test tree and are never imported by
 * production code. They replace the removed raw production exports
 * (`writeHostDomainResetJournal` / `removeHostDomainResetJournal`) so tests
 * can plant exact v1 journal bytes and clean them up idempotently. Writes go
 * through the schema encoder, so invalid fixtures fail closed exactly like the
 * production codec does.
 */

export function writeJournalFixture(resources: ProfileResourceSet, journal: HostDomainResetJournalV1): void {
  const bytes = encodeHostDomainResetJournal(journal, resources);
  mkdirSync(dirname(resources.hostDomainResetJournalPath), { recursive: true, mode: 0o700 });
  writeFileSync(resources.hostDomainResetJournalPath, bytes, { mode: 0o600 });
}

export function removeJournalFixture(resources: ProfileResourceSet, hooks: SecureFileRemoveHooks = {}): void {
  removeSecureFileIfPresent(resources.hostDomainResetJournalPath, undefined, hooks);
}
