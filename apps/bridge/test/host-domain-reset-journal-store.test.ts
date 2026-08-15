import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ProcessAwareLockDependencies } from '../src/host-manager/process-aware-lock';
import type { HostIdentity } from '../src/identity';
import type { ProfileResourceSet } from '../src/cli/profile';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
  advanceHostDomainResetJournal,
  createHostDomainResetJournal,
  hostDomainResourceDigest,
  loadHostDomainResetJournal,
  removeAfterServiceRestoreConfirmed,
  type HostDomainResetJournalV1,
} from '../src/cli/operations/host-domain-reset-journal';
import {
  restoreHostDomainServiceAndConfirm,
  type RestoreConfirmation,
} from '../src/cli/operations/host-domain-reset-journal-store';
import { withHostIdentityOperationLock, type HostIdentityOperationLease } from '../src/cli/operations/host-identity-operation-lock';
import { AriavaCliError } from '../src/host-manager/service/errors';
import { writeJournalFixture } from './fixtures/host-domain-reset-journal-fixtures';

const roots: string[] = [];

/** Deterministic process-aware lock deps so tests never depend on live ps inspection. */
function lockDependencies(): Partial<ProcessAwareLockDependencies> {
  return {
    platform: 'linux',
    uid: process.getuid!(),
    pid: process.pid,
    now: () => new Date(),
    ownerToken: () => 'a'.repeat(48),
    currentProcessStart: () => 'test-process-start',
    inspector: { inspect: () => ({ status: 'alive', processStart: 'test-process-start' }) },
  };
}

function temporaryHome(): string {
  const root = mkdtempSync(join(tmpdir(), 'ariava-host-reset-journal-store-'));
  roots.push(root);
  return root;
}

function resourcesFor(profileId: 'default' | 'dev'): ProfileResourceSet {
  const home = temporaryHome();
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  try {
    const profile = profileId === 'default' ? createDefaultProfile() : createDevProfile();
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    return profile.resources;
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousXdg;
  }
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function quarantinePendingFor(resources: ProfileResourceSet): HostDomainResetJournalV1 {
  const timestamp = '2026-08-11T00:00:00.000Z';
  return {
    version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
    operationId: 'reset_0123456789abcdef',
    profile: resources.identityProfile,
    phase: 'quarantine-pending',
    oldHostId: null,
    oldKeyId: null,
    newHostId: null,
    newKeyId: null,
    oldEncryptionKeyId: null,
    signingCleanup: null,
    signingReplacementAttemptedAt: null,
    encryptionIdentityReplacedAt: null,
    runtimeArtifactsClearedAt: null,
    configSavedAt: null,
    enrolledAt: null,
    serviceMetadataSynchronizedAt: null,
    resourceDigest: hostDomainResourceDigest(resources),
    createdAt: timestamp,
    updatedAt: timestamp,
    revoke: { state: 'not-attempted', outcome: null },
    service: resources.identityProfile === 'default'
      ? { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'systemd-user' }
      : { managed: false, installed: false, enabled: false, wasRunning: false, backend: 'none' },
  };
}

async function withLease<T>(resources: ProfileResourceSet, run: (lease: HostIdentityOperationLease) => Promise<T>): Promise<T> {
  return withHostIdentityOperationLock(resources, run, lockDependencies());
}

/** Build a journal at service-restore-pending for guarded-removal tests. */
function restorePendingFor(resources: ProfileResourceSet, patch: Partial<HostDomainResetJournalV1> = {}): HostDomainResetJournalV1 {
  const index = HOST_DOMAIN_RESET_PHASES.indexOf('service-restore-pending');
  const timestamp = '2026-08-11T00:00:00.000Z';
  return {
    version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
    operationId: 'reset_0123456789abcdef',
    profile: resources.identityProfile,
    phase: 'service-restore-pending',
    oldHostId: `host_${'A'.repeat(43)}`,
    oldKeyId: `key_${'B'.repeat(43)}`,
    newHostId: `host_${'C'.repeat(43)}`,
    newKeyId: `key_${'D'.repeat(43)}`,
    oldEncryptionKeyId: `ekey_${'E'.repeat(43)}`,
    signingCleanup: null,
    signingReplacementAttemptedAt: timestamp,
    encryptionIdentityReplacedAt: timestamp,
    runtimeArtifactsClearedAt: timestamp,
    configSavedAt: timestamp,
    enrolledAt: timestamp,
    serviceMetadataSynchronizedAt: timestamp,
    resourceDigest: hostDomainResourceDigest(resources),
    createdAt: timestamp,
    updatedAt: timestamp,
    revoke: { state: 'complete', outcome: 'revoked' },
    service: resources.identityProfile === 'default'
      ? { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'systemd-user' }
      : { managed: false, installed: false, enabled: false, wasRunning: false, backend: 'none' },
    ...patch,
  } as unknown as HostDomainResetJournalV1;
}

function replacementIdentityFor(
  resources: ProfileResourceSet,
  journal: HostDomainResetJournalV1,
  patch: Partial<HostIdentity> = {},
): HostIdentity {
  const hostId = journal.newHostId!;
  const keyId = journal.newKeyId!;
  return {
    identityVersion: 2,
    hostId,
    keyId,
    algorithm: 'Ed25519',
    publicKey: 'a'.repeat(43),
    publicKeyFingerprint: hostId.slice('host_'.length),
    createdAt: journal.updatedAt,
    privateKeyStorage: { type: 'linux-json', path: resources.identityMetadataPath },
    signer: {
      entityId: hostId,
      keyId,
      sign: async () => 'signature',
      signRequest: async () => ({ 'x-ariava-signature': 'signature' }),
    },
    ...patch,
  };
}

function confirmRestored(
  resources: ProfileResourceSet,
  journal: HostDomainResetJournalV1,
  lease: HostIdentityOperationLease,
  replacement: HostIdentity = replacementIdentityFor(resources, journal),
): RestoreConfirmation {
  return restoreHostDomainServiceAndConfirm(
    resources, journal, lease, replacement, () => false,
  ).confirmation;
}

describe('Host-domain reset journal store', () => {
  test('createHostDomainResetJournal exclusively creates a quarantine-pending journal under a live lease', async () => {
    const resources = resourcesFor('dev');
    await withLease(resources, async (lease) => {
      const created = createHostDomainResetJournal(resources, quarantinePendingFor(resources), lease);
      expect(created.phase).toBe('quarantine-pending');
      expect(loadHostDomainResetJournal(resources)).toEqual(created);
      expect(() => createHostDomainResetJournal(resources, quarantinePendingFor(resources), lease))
        .toThrow(/already exists/i);
    });
  });

  test('createHostDomainResetJournal fails closed when the lease is lost before or after the write', async () => {
    const resources = resourcesFor('dev');
    const lost = {
      assertOwned() {
        throw new AriavaCliError('ERR_HOST_RESET_LEASE_LOST', 'Host identity operation lease is no longer held.', { retryable: true });
      },
    } as unknown as HostIdentityOperationLease;
    expect(() => createHostDomainResetJournal(resources, quarantinePendingFor(resources), lost)).toThrow(/lease/i);
    expect(loadHostDomainResetJournal(resources)).toBeNull();
  });

  test('createHostDomainResetJournal rejects non-quarantine-pending initial journals', async () => {
    const resources = resourcesFor('dev');
    await withLease(resources, async (lease) => {
      const prepared = { ...quarantinePendingFor(resources), phase: 'prepared' as const };
      expect(() => createHostDomainResetJournal(resources, prepared, lease)).toThrow(/quarantine-pending/i);
      expect(loadHostDomainResetJournal(resources)).toBeNull();
    });
  });

  test('advance applies an exact transition, stamps updatedAt, and rejects stale snapshots', async () => {
    const resources = resourcesFor('dev');
    await withLease(resources, async (lease) => {
      const initial = quarantinePendingFor(resources);
      createHostDomainResetJournal(resources, initial, lease);
      const advanced = advanceHostDomainResetJournal(resources, initial, { phase: 'quarantined' }, lease);
      expect(advanced.phase).toBe('quarantined');
      expect(loadHostDomainResetJournal(resources)).toEqual(advanced);

      const stale = initial;
      expect(() => advanceHostDomainResetJournal(resources, stale, { phase: 'prepared', oldHostId: `host_${'A'.repeat(43)}`, oldKeyId: `key_${'B'.repeat(43)}`, oldEncryptionKeyId: null, signingCleanup: null, revoke: { state: 'not-attempted', outcome: null } }, lease))
        .toThrow(/changed before advancement/i);
    });
  });

  test('advance fails closed when the lease is lost before the write', async () => {
    const resources = resourcesFor('dev');
    await withLease(resources, async (lease) => {
      const initial = quarantinePendingFor(resources);
      createHostDomainResetJournal(resources, initial, lease);
      const lost = {
        assertOwned() {
          throw new AriavaCliError('ERR_HOST_RESET_LEASE_LOST', 'Host identity operation lease is no longer held.', { retryable: true });
        },
      } as unknown as HostIdentityOperationLease;
      expect(() => advanceHostDomainResetJournal(resources, initial, { phase: 'quarantined' }, lost)).toThrow(/lease/i);
      expect(loadHostDomainResetJournal(resources)).toEqual(initial);
    });
  });

  test('advance serializes competing advancements with the process-aware lock', async () => {
    const resources = resourcesFor('dev');
    await withLease(resources, async (lease) => {
      const initial = quarantinePendingFor(resources);
      createHostDomainResetJournal(resources, initial, lease);
      let nestedError: unknown;
      const advanced = advanceHostDomainResetJournal(resources, initial, { phase: 'quarantined' }, lease, {
        hooks: {
          beforePromotion() {
            try {
              advanceHostDomainResetJournal(resources, initial, { phase: 'quarantined' }, lease);
            } catch (error) {
              nestedError = error;
            }
          },
        },
      });
      expect(advanced.phase).toBe('quarantined');
      expect(nestedError).toBeInstanceOf(Error);
      expect(String(nestedError)).toMatch(/lock|advancement|another/i);
    });
  });

  test('guarded removal consumes a valid single-use confirmation', async () => {
    const resources = resourcesFor('default');
    await withLease(resources, async (lease) => {
      const journal = restorePendingFor(resources);
      writeJournalFixture(resources, journal);
      const confirmation = confirmRestored(resources, journal, lease);
      expect(() => removeAfterServiceRestoreConfirmed(resources, journal, lease, confirmation)).not.toThrow();
      expect(loadHostDomainResetJournal(resources)).toBeNull();
    });
  });

  test('guarded removal rejects a reused confirmation', async () => {
    const resources = resourcesFor('default');
    await withLease(resources, async (lease) => {
      const journal = restorePendingFor(resources);
      writeJournalFixture(resources, journal);
      const confirmation = confirmRestored(resources, journal, lease);
      removeAfterServiceRestoreConfirmed(resources, journal, lease, confirmation);
      writeJournalFixture(resources, journal);
      expect(() => removeAfterServiceRestoreConfirmed(resources, journal, lease, confirmation))
        .toThrow(/already consumed|reused/i);
    });
  });

  test('guarded removal rejects a forged confirmation', async () => {
    const resources = resourcesFor('default');
    await withLease(resources, async (lease) => {
      const journal = restorePendingFor(resources);
      writeJournalFixture(resources, journal);
      const forged = Object.freeze({}) as RestoreConfirmation;
      expect(() => removeAfterServiceRestoreConfirmed(resources, journal, lease, forged)).toThrow(/forged|unrecognized/i);
      expect(loadHostDomainResetJournal(resources)).toEqual(journal);
    });
  });

  test('guarded removal rejects a wrong phase journal', async () => {
    const resources = resourcesFor('default');
    await withLease(resources, async (lease) => {
      const prepared = {
        ...restorePendingFor(resources),
        phase: 'prepared' as const,
        newHostId: null,
        newKeyId: null,
        signingReplacementAttemptedAt: null,
        encryptionIdentityReplacedAt: null,
        runtimeArtifactsClearedAt: null,
        configSavedAt: null,
        enrolledAt: null,
        serviceMetadataSynchronizedAt: null,
        revoke: { state: 'not-attempted', outcome: null },
      } as HostDomainResetJournalV1;
      const validJournal = restorePendingFor(resources);
      writeJournalFixture(resources, validJournal);
      const confirmation = confirmRestored(resources, validJournal, lease);
      writeJournalFixture(resources, prepared);
      expect(() => removeAfterServiceRestoreConfirmed(resources, prepared, lease, confirmation))
        .toThrow(/service-restore-pending/i);
    });
  });

  test('guarded removal rejects a stale or replaced journal', async () => {
    const resources = resourcesFor('default');
    await withLease(resources, async (lease) => {
      const journal = restorePendingFor(resources);
      const replacement = restorePendingFor(resources, { operationId: 'reset_9999999999999999' });
      writeJournalFixture(resources, journal);
      const confirmation = confirmRestored(resources, journal, lease);
      writeJournalFixture(resources, replacement);
      expect(() => removeAfterServiceRestoreConfirmed(resources, journal, lease, confirmation))
        .toThrow(/changed|stale|replaced/i);
    });
  });

  test('restore confirmation cannot be spread-cloned', async () => {
    const resources = resourcesFor('default');
    await withLease(resources, async (lease) => {
      const journal = restorePendingFor(resources);
      writeJournalFixture(resources, journal);
      const confirmation = confirmRestored(resources, journal, lease);
      const clone = { ...confirmation } as RestoreConfirmation;
      expect(() => removeAfterServiceRestoreConfirmed(resources, journal, lease, clone))
        .toThrow(/forged|unrecognized/i);
      expect(() => removeAfterServiceRestoreConfirmed(resources, journal, lease, confirmation)).not.toThrow();
    });
  });

  test('restore refuses a wrong replacement identity or storage reference before invoking restore', async () => {
    const resources = resourcesFor('default');
    await withLease(resources, async (lease) => {
      const journal = restorePendingFor(resources);
      writeJournalFixture(resources, journal);
      let restoreCalls = 0;
      const restore = () => { restoreCalls += 1; return false; };
      const wrongIdentity = replacementIdentityFor(resources, journal, {
        hostId: `host_${'F'.repeat(43)}`,
        keyId: `key_${'G'.repeat(43)}`,
      });
      try {
        restoreHostDomainServiceAndConfirm(resources, journal, lease, wrongIdentity, restore);
        throw new Error('expected wrong identity rejection');
      } catch (error) {
        expect(error).toMatchObject({ code: 'ERR_HOST_RESET_REMOVE_WRONG_IDENTITY' });
      }
      const wrongReference = replacementIdentityFor(resources, journal, {
        privateKeyStorage: { type: 'linux-json', path: `${resources.identityMetadataPath}.foreign` },
      });
      try {
        restoreHostDomainServiceAndConfirm(resources, journal, lease, wrongReference, restore);
        throw new Error('expected wrong identity reference rejection');
      } catch (error) {
        expect(error).toMatchObject({ code: 'ERR_HOST_RESET_REMOVE_WRONG_IDENTITY' });
      }
      expect(restoreCalls).toBe(0);
      expect(loadHostDomainResetJournal(resources)).toEqual(journal);
    });
  });

  test('guarded removal rejects an absent or foreign lease', async () => {
    const resources = resourcesFor('default');
    await withLease(resources, async (lease) => {
      const journal = restorePendingFor(resources);
      writeJournalFixture(resources, journal);
      const confirmation = confirmRestored(resources, journal, lease);
      const foreign = {
        assertOwned() {
          throw new AriavaCliError('ERR_HOST_RESET_LEASE_LOST', 'Host identity operation lease is no longer held.', { retryable: true });
        },
      } as unknown as HostIdentityOperationLease;
      expect(() => removeAfterServiceRestoreConfirmed(resources, journal, foreign, confirmation)).toThrow(/lease/i);
      expect(loadHostDomainResetJournal(resources)).toEqual(journal);
    });
  });
});
