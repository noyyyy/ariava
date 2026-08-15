import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { HostEncryptionIdentity, HostEncryptionIdentityStore, HostIdentity, HostIdentityStore } from '../src/identity';
import { publicIdentityMetadata } from '../src/identity';
import type { HostReplacementSpoolKeyStore } from '../src/e2e/local-spool';
import type { RuntimeCoordinator } from '../src/runtime-lock';
import type { ProcessAwareLockDependencies } from '../src/host-manager/process-aware-lock';
import type { AriavaUserConfig } from '../src/host-manager/config';
import type { ProfileResourceSet } from '../src/cli/profile';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
  hostDomainResourceDigest,
  loadHostDomainResetJournal,
  type HostDomainResetJournalV1,
} from '../src/cli/operations/host-domain-reset-journal';
import { identityResourceDigest } from '../src/cli/operations/host-domain-reset-journal-policy';
import {
  hostIdentityOperationLockPath,
  withHostIdentityOperationLock,
  type HostIdentityOperationLease,
} from '../src/cli/operations/host-identity-operation-lock';
import {
  prepareRecovery,
  recoverServiceRestorePending as recoverServiceRestorePendingUnderLease,
  type HostResetRecoveryDependencies,
  type HostResetRecoveryResult,
} from '../src/cli/operations/host-domain-reset-recovery';
import { AriavaCliError } from '../src/host-manager/service/errors';
import { writeJournalFixture } from './fixtures/host-domain-reset-journal-fixtures';

/**
 * Host-domain reset recovery tests (primary spec §9, §12; journal-boundary
 * spec §8, §11).
 *
 * Exercises the recovery module DIRECTLY with injected fakes: the exact §7.2
 * call order, fresh-process lifecycle rehydration comparing only
 * managed/installed/enabled/backend (never running state), revoke
 * uncertainty, runtime ownership release before restore, idempotent
 * restoreAndConfirm, single-use confirmation, guarded-removal refusals, and
 * crash-after-restore-before-remove full redo. Store-level forged/reused/
 * wrong-op/wrong-service/wrong-identity confirmation refusals are covered by
 * `host-domain-reset-journal-store.test.ts`.
 */

const OLD_HOST = `host_${'A'.repeat(43)}`;
const OLD_KEY = `key_${'B'.repeat(43)}`;
const NEW_HOST = `host_${'D'.repeat(43)}`;
const NEW_KEY = `key_${'E'.repeat(43)}`;
const OLD_EKEY = `ekey_${'C'.repeat(43)}`;
const NEW_EKEY = `ekey_${'F'.repeat(43)}`;

const TIMESTAMP = '2026-08-11T00:00:00.000Z';

const roots: string[] = [];
const originalHome = process.env.HOME;
const originalXdg = process.env.XDG_CONFIG_HOME;

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME; else process.env.HOME = originalHome;
  if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = originalXdg;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

/** Fresh default-profile resources in an isolated HOME. */
function defaultResources(): ProfileResourceSet {
  const home = mkdtempSync(join(tmpdir(), 'ariava-reset-recovery-'));
  roots.push(home);
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  const profile = createDefaultProfile();
  mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
  return profile.resources;
}

function unmanagedService() {
  return { managed: false, installed: false, enabled: false, wasRunning: false, backend: 'none' as const };
}

function managedService() {
  return { managed: true, installed: true, enabled: true, wasRunning: true, backend: 'systemd-user' as const };
}

/** Schema-valid journal at service-restore-pending for the given resources. */
function restorePendingJournal(resources: ProfileResourceSet, patch: Partial<HostDomainResetJournalV1> = {}): HostDomainResetJournalV1 {
  return {
    version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
    operationId: 'reset_0123456789abcdef',
    profile: resources.identityProfile,
    phase: 'service-restore-pending',
    oldHostId: OLD_HOST,
    oldKeyId: OLD_KEY,
    newHostId: NEW_HOST,
    newKeyId: NEW_KEY,
    oldEncryptionKeyId: OLD_EKEY,
    signingCleanup: null,
    signingReplacementAttemptedAt: TIMESTAMP,
    encryptionIdentityReplacedAt: TIMESTAMP,
    runtimeArtifactsClearedAt: TIMESTAMP,
    configSavedAt: TIMESTAMP,
    enrolledAt: TIMESTAMP,
    serviceMetadataSynchronizedAt: TIMESTAMP,
    resourceDigest: hostDomainResourceDigest(resources),
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
    revoke: { state: 'complete', outcome: 'revoked' },
    service: resources.identityProfile === 'default' ? managedService() : unmanagedService(),
    ...patch,
  };
}

function makeIdentity(hostId: string, keyId: string, identityPath = '/tmp/fake-identity.json'): HostIdentity {
  return {
    identityVersion: 2,
    hostId,
    keyId,
    algorithm: 'Ed25519',
    publicKey: 'a'.repeat(43),
    publicKeyFingerprint: hostId.slice('host_'.length),
    createdAt: TIMESTAMP,
    privateKeyStorage: { type: 'linux-json', path: identityPath },
    signer: {
      entityId: hostId,
      keyId,
      sign: async () => 'signature',
      signRequest: async () => ({ 'x-ariava-signature': 'sig' }),
    },
  };
}

function makeEncryptionIdentity(hostId: string, encryptionKeyId: string): HostEncryptionIdentity {
  return {
    version: 1,
    hostId,
    encryptionKeyId,
    publicKey: 'b'.repeat(43),
    privateKeyPkcs8: new Uint8Array(32),
    sequence: 1,
    createdAt: TIMESTAMP,
  };
}

/** Sentinel converted by the local wrapper into a real production-issued lease. */
const OK_LEASE = Symbol('issued-operation-lease');

/** Structurally forged lease used only by explicit rejection tests. */
function lostLease(): HostIdentityOperationLease {
  return {
    assertOwned() {
      throw new AriavaCliError('ERR_HOST_RESET_LEASE_LOST', 'Host identity operation lease is no longer held.', { retryable: true });
    },
  } as unknown as HostIdentityOperationLease;
}

function testLockDependencies(): Partial<ProcessAwareLockDependencies> {
  return {
    platform: 'linux',
    uid: process.getuid?.(),
    pid: process.pid,
    now: () => new Date(),
    ownerToken: () => 'a'.repeat(48),
    currentProcessStart: () => 'recovery-test-process-start',
    inspector: { inspect: () => ({ status: 'alive', processStart: 'recovery-test-process-start' }) },
  };
}

async function recoverServiceRestorePending(
  deps: HostResetRecoveryDependencies,
  journal: HostDomainResetJournalV1,
  lease: HostIdentityOperationLease | typeof OK_LEASE,
  onLease?: (lease: HostIdentityOperationLease) => void,
 ): Promise<HostResetRecoveryResult> {
  if (lease !== OK_LEASE) return recoverServiceRestorePendingUnderLease(deps, journal, lease);
  return withHostIdentityOperationLock(deps.resources, async (issued) => {
    onLease?.(issued);
    return recoverServiceRestorePendingUnderLease(deps, journal, issued);
  }, testLockDependencies());
}

interface CallRecorder {
  calls: string[];
}

interface RecoveryFakes extends CallRecorder {
  lifecycle: HostResetRecoveryDependencies['lifecycle'];
  runtime: HostResetRecoveryDependencies['runtime'];
  config: HostResetRecoveryDependencies['config'];
  spoolKey: HostReplacementSpoolKeyStore;
  identity: HostIdentityStore;
  encryption: HostEncryptionIdentityStore;
  disposed: number;
  prepareResult?: HostDomainResetJournalV1['service'];
  identityPath: string;
}

function createFakes(options: {
  replacementActive?: boolean;
  configMatches?: boolean;
  lifecycleMismatch?: boolean;
  restoreReturn?: boolean;
  spoolKeyAssertAbsent?: boolean;
  service?: HostDomainResetJournalV1['service'];
} = {}): RecoveryFakes {
  const fakes: RecoveryFakes = {
    calls: [],
    disposed: 0,
    spoolKey: {
      removeForHostReplacement() {},
      assertAbsentForHostReplacement() {
        fakes.calls.push('spool-key-absent');
        if (options.spoolKeyAssertAbsent === false) throw new Error('spool key evidence still present');
      },
    },
    identity: {
      inspect: async () => ({ status: 'ready', storageType: 'linux-json', storageReference: { type: 'linux-json', path: fakes.identityPath }, ownerIntegrity: true, permissionIntegrity: true, metadataIntegrity: true }),
      load: async () => (options.replacementActive === false
        ? makeIdentity(OLD_HOST, OLD_KEY, fakes.identityPath)
        : makeIdentity(NEW_HOST, NEW_KEY, fakes.identityPath)),
      createFirstRun: async () => makeIdentity(NEW_HOST, NEW_KEY, fakes.identityPath),
      resetAfterExplicitConfirmation: async () => makeIdentity(NEW_HOST, NEW_KEY, fakes.identityPath),
      recoverExplicitReset: async () => null,
      completeExplicitReset() {},
      deleteAfterHostReplacement() {},
    },
    encryption: {
      load: () => (options.replacementActive === false ? makeEncryptionIdentity(OLD_HOST, OLD_EKEY) : makeEncryptionIdentity(NEW_HOST, NEW_EKEY)),
      loadOrCreate: (hostId: string) => makeEncryptionIdentity(hostId, NEW_EKEY),
      identity: (encryptionKeyId: string) => (encryptionKeyId === NEW_EKEY ? makeEncryptionIdentity(NEW_HOST, NEW_EKEY) : null),
      retainedIdentityIds: () => new Set(),
      replaceCurrent: (hostId: string) => makeEncryptionIdentity(hostId, NEW_EKEY),
      prune: () => [],
      replaceForReset: (hostId: string) => makeEncryptionIdentity(hostId, NEW_EKEY),
      recoverReset: () => null,
      completeReset() {},
      deleteAfterHostReplacement() {},
    },
    lifecycle: {
      prepare: () => {
        fakes.calls.push('prepare');
        const journalService = options.service ?? managedService();
        if (options.lifecycleMismatch) return unmanagedService();
        // Same managed/installed/enabled/backend as the journal but a
        // DIFFERENT wasRunning, proving running state is never compared to
        // the historical restore target.
        return { ...journalService, wasRunning: !journalService.wasRunning };
      },
      stopAndConfirm: () => { fakes.calls.push('stop'); },
      synchronizeMetadata: () => { fakes.calls.push('sync'); },
      restoreAndConfirm: () => {
        fakes.calls.push('restore');
        return options.restoreReturn ?? false;
      },
      validateRestored: () => false,
    },
    runtime: {
      acquire: () => {
        fakes.calls.push('acquire');
        const coordinator: RuntimeCoordinator = {
          statePath: undefined,
          spoolPath: undefined,
          assertOwned() {},
          claimStateWriter: () => () => {},
          dispose() { fakes.disposed += 1; },
        };
        fakes.runtime.held = coordinator;
        return coordinator;
      },
      held: undefined,
      release() { fakes.runtime.held = undefined; },
    },
    identityPath: '/tmp/fake-identity.json',
    config: {
      load: () => (options.configMatches === false
        ? {}
        : { identity: publicIdentityMetadata(makeIdentity(NEW_HOST, NEW_KEY, fakes.identityPath)) } as AriavaUserConfig),
      save: () => {},
    },
  };
  return fakes;
}

function dependencies(resources: ProfileResourceSet, fakes: RecoveryFakes): HostResetRecoveryDependencies {
  fakes.identityPath = resources.identityMetadataPath;
  return {
    profileId: resources.identityProfile,
    resources,
    identityStore: fakes.identity,
    encryptionStore: fakes.encryption,
    spoolKeyStore: fakes.spoolKey,
    lifecycle: fakes.lifecycle,
    runtime: fakes.runtime,
    config: fakes.config,
    hooks: { afterEffect: () => { fakes.calls.push('after-effect'); } },
  };
}

describe('prepareRecovery', () => {
  test('rehydrates a fresh lifecycle adapter and compares only managed/installed/enabled/backend', () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources);
    expect(() => prepareRecovery(dependencies(resources, fakes), journal)).not.toThrow();
    expect(fakes.calls).toContain('prepare');
  });

  test('never compares current running state to journal.service.wasRunning', () => {
    const resources = defaultResources();
    const fakes = createFakes({ restoreReturn: true });
    const journal = restorePendingJournal(resources, { service: { ...managedService(), wasRunning: false } });
    // lifecycle.prepare returns wasRunning flipped vs the journal snapshot but
    // the same managed/installed/enabled/backend: rehydration still passes.
    expect(() => prepareRecovery(dependencies(resources, fakes), journal)).not.toThrow();
  });

  test('fails closed on a managed/installed/enabled/backend mismatch before any effect', () => {
    const resources = defaultResources();
    const fakes = createFakes({ lifecycleMismatch: true });
    const journal = restorePendingJournal(resources);
    expect(() => prepareRecovery(dependencies(resources, fakes), journal)).toThrow(/service state changed/i);
    expect(fakes.calls).toEqual(['prepare']);
  });
});

describe('recoverServiceRestorePending', () => {
  test('runs the exact §7.2 call order and removes the journal under a live lease', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    const result = await recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE);

    expect(result.hostId).toBe(NEW_HOST);
    expect(result.keyId).toBe(NEW_KEY);
    expect(result.revokedOldIdentity).toBe(true);
    expect(result.links).toEqual([]);
    expect(result.watchPairingRequired).toBe(true);
    expect(result.service.processRunning).toBe(false);
    expect(result.service.status).toBe('stopped');
    // prepare -> stop -> acquire -> restore -> after-effect; dispose/release
    // happen before restore and are not ordered after it.
    const restoreIndex = fakes.calls.indexOf('restore');
    expect(fakes.calls.indexOf('prepare')).toBeLessThan(restoreIndex);
    expect(fakes.calls.indexOf('stop')).toBeLessThan(restoreIndex);
    expect(fakes.calls.indexOf('acquire')).toBeLessThan(restoreIndex);
    expect(fakes.calls.indexOf('after-effect')).toBeGreaterThan(restoreIndex);
    expect(fakes.disposed).toBeGreaterThan(0);
    // Runtime ownership is released BEFORE restore: dispose happened before
    // restoreAndConfirm returned.
    expect(fakes.disposed).toBeGreaterThan(0);
    expect(loadHostDomainResetJournal(resources)).toBeNull();
  });

  test('runtime ownership is released before restore (dispose precedes restoreAndConfirm)', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    // The fake dispose() records via fakes.disposed; the runtime release path
    // clears held. Assert held is cleared before restore runs.
    let heldDuringRestore: unknown = 'unset';
    const originalRestore = fakes.lifecycle.restoreAndConfirm;
    fakes.lifecycle.restoreAndConfirm = (snapshot, reference) => {
      heldDuringRestore = fakes.runtime.held;
      return originalRestore(snapshot, reference);
    };

    await recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE);
    expect(heldDuringRestore).toBeUndefined();
    expect(fakes.disposed).toBeGreaterThan(0);
  });

  test('legal false restore return still issues a confirmation and removes the journal', async () => {
    const resources = defaultResources();
    const fakes = createFakes({ restoreReturn: false });
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    const result = await recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE);
    expect(result.service.processRunning).toBe(false);
    expect(result.service.status).toBe('stopped');
    expect(loadHostDomainResetJournal(resources)).toBeNull();
  });

  test('true restore return yields running status for a managed service', async () => {
    const resources = defaultResources();
    const fakes = createFakes({ restoreReturn: true });
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    const result = await recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE);
    expect(result.service.processRunning).toBe(true);
    expect(result.service.status).toBe('running');
  });

  test('restoreAndConfirm is called even when lifecycle evidence suggests the service is already started', async () => {
    const resources = defaultResources();
    const fakes = createFakes({ restoreReturn: true });
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);
    // prepare returns wasRunning=true (already started) yet restoreAndConfirm
    // must still be invoked idempotently.
    expect(fakes.calls).not.toContain('restore');
    await recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE);
    expect(fakes.calls).toContain('restore');
  });

  test('fresh-process lifecycle rehydration: two invocations with different adapters both rehydrate', async () => {
    const resources = defaultResources();
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    const firstFakes = createFakes();
    const first = await recoverServiceRestorePending(dependencies(resources, firstFakes), journal, OK_LEASE);
    expect(first.hostId).toBe(NEW_HOST);

    // Re-plant the journal as a fresh process would see it after a crash
    // before removal, with a NEW lifecycle adapter instance.
    writeJournalFixture(resources, journal);
    const secondFakes = createFakes();
    const second = await recoverServiceRestorePending(dependencies(resources, secondFakes), journal, OK_LEASE);
    expect(second.hostId).toBe(NEW_HOST);
    expect(secondFakes.calls).toContain('prepare');
    expect(secondFakes.calls).toContain('restore');
    expect(loadHostDomainResetJournal(resources)).toBeNull();
  });

  test('revoke uncertainty: skipped/old-identity-unreadable journal follows the same restore sequence', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources, {
      revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
      signingCleanup: {
        kind: 'linux-json',
        resourceDigest: identityResourceDigest(resources.identityMetadataPath),
        profile: resources.identityProfile,
        previousAccount: null,
        previousPendingAccount: null,
        interruptedCreationAccount: null,
      },
    });
    writeJournalFixture(resources, journal);

    const result = await recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE);
    expect(result.revokedOldIdentity).toBe(false);
    expect(result.warning).toMatch(/ERR_IDENTITY_INVALID/i);
    expect(fakes.calls).toContain('restore');
    expect(loadHostDomainResetJournal(resources)).toBeNull();
  });

  test('sentinel-finalizer ordering: replacement verification precedes restore', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);
    // identity load() happens during requireReplacement (verification), before
    // restore. Record it through a wrapped store.
    const loads: string[] = [];
    const originalLoad = fakes.identity.load.bind(fakes.identity);
    fakes.identity.load = async () => { loads.push('identity-load'); return originalLoad(); };

    await recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE);
    const loadIndex = fakes.calls.indexOf('acquire');
    const restoreIndex = fakes.calls.indexOf('restore');
    expect(loads.length).toBeGreaterThan(0);
    expect(loadIndex).toBeLessThan(restoreIndex);
  });

  test('snapshot mismatch fails closed before any restore effect', async () => {
    const resources = defaultResources();
    const fakes = createFakes({ lifecycleMismatch: true });
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
    expect(fakes.calls).toEqual(['prepare']);
    expect(loadHostDomainResetJournal(resources)).not.toBeNull();
  });

  test('config identity mismatch fails closed', async () => {
    const resources = defaultResources();
    const fakes = createFakes({ configMatches: false });
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
    expect(fakes.calls).not.toContain('restore');
    expect(loadHostDomainResetJournal(resources)).not.toBeNull();
  });

  test('replacement signing evidence mismatch fails closed', async () => {
    const resources = defaultResources();
    const fakes = createFakes({ replacementActive: false });
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
    expect(fakes.calls).not.toContain('restore');
  });

  test('runtime acquisition failure fails closed with ERR_HOST_RESET_RUNTIME_ACTIVE semantics', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    fakes.runtime.acquire = () => { throw new Error('runtime active'); };
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RUNTIME_ACTIVE' });
    expect(fakes.calls).not.toContain('restore');
  });

  test('reintroduced link keyring evidence fails closed before restore', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);
    mkdirSync(join(resources.linkKeyringPath, '..'), { recursive: true, mode: 0o700 });
    writeFileSync(resources.linkKeyringPath, 'reintroduced', { mode: 0o600 });

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
    expect(fakes.calls).not.toContain('restore');
  });

  test('incomplete state/spool pair fails closed', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);
    mkdirSync(join(resources.statePath, '..'), { recursive: true, mode: 0o700 });
    writeFileSync(resources.statePath, 'state', { mode: 0o600 });

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
    expect(fakes.calls).not.toContain('restore');
  });

  test('invalid runtime artifact evidence fails closed', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);
    mkdirSync(join(resources.statePath, '..'), { recursive: true, mode: 0o700 });
    writeFileSync(resources.statePath, 'not-json', { mode: 0o600 });
    const spoolPath = `${resources.statePath}.spool.json`;
    mkdirSync(join(spoolPath, '..'), { recursive: true, mode: 0o700 });
    writeFileSync(spoolPath, 'not-json', { mode: 0o600 });

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
    expect(fakes.calls).not.toContain('restore');
  });

  test('wrong-phase journal fails closed before any effect', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources, { phase: 'enrolled' });

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
    expect(fakes.calls).toEqual([]);
  });

  test('guarded removal rejects a stale or replaced journal', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources);
    // Plant a DIFFERENT journal on disk than the one passed to recovery:
    // guarded removal re-loads and must fail closed on the mismatch.
    writeJournalFixture(resources, restorePendingJournal(resources, {
      operationId: 'reset_0fedcba987654321',
      updatedAt: '2026-08-12T00:00:00.000Z',
      serviceMetadataSynchronizedAt: '2026-08-12T00:00:00.000Z',
    }));

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_REMOVE_STALE_JOURNAL' });
    expect(loadHostDomainResetJournal(resources)).not.toBeNull();
  });

  test('guarded removal rejects a structurally forged lease before restore', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    await expect(recoverServiceRestorePending(dependencies(resources, fakes), journal, lostLease()))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_LEASE_LOST' });
    expect(fakes.calls).not.toContain('restore');
    expect(loadHostDomainResetJournal(resources)).not.toBeNull();
  });

  test('crash after restore before removal: next invocation fully redoes and obtains a fresh confirmation', async () => {
    const resources = defaultResources();
    const journal = restorePendingJournal(resources);

    // First process: restoreAndConfirm succeeds, then the real operation-lock
    // record is replaced before the store's post-restore ownership check.
    writeJournalFixture(resources, journal);
    const firstFakes = createFakes();
    const originalRestore = firstFakes.lifecycle.restoreAndConfirm;
    firstFakes.lifecycle.restoreAndConfirm = (snapshot, identityReference) => {
      const restored = originalRestore(snapshot, identityReference);
      writeFileSync(hostIdentityOperationLockPath(resources), `${JSON.stringify({
        schemaVersion: 1,
        pid: process.pid,
        processStart: 'foreign-process-start',
        createdAt: new Date().toISOString(),
        ownerToken: 'f'.repeat(48),
      })}\n`, { mode: 0o600 });
      return restored;
    };
    await expect(recoverServiceRestorePending(dependencies(resources, firstFakes), journal, OK_LEASE))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_LEASE_LOST' });
    expect(firstFakes.calls).toContain('restore');
    expect(loadHostDomainResetJournal(resources)).not.toBeNull();

    // Second process: a NEW lifecycle adapter instance fully redoes
    // prepare/stop/validate/restore and obtains a new confirmation.
    rmSync(hostIdentityOperationLockPath(resources), { force: true });
    const secondFakes = createFakes();
    const second = await recoverServiceRestorePending(dependencies(resources, secondFakes), journal, OK_LEASE);
    expect(second.hostId).toBe(NEW_HOST);
    expect(secondFakes.calls).toEqual(['prepare', 'stop', 'acquire', 'spool-key-absent', 'restore', 'after-effect']);
    expect(loadHostDomainResetJournal(resources)).toBeNull();
  });

  test('unmanaged dev-profile service yields unmanaged status', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-reset-recovery-dev-'));
    roots.push(home);
    process.env.HOME = home;
    process.env.XDG_CONFIG_HOME = join(home, 'xdg');
    const profile = createDevProfile();
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    const resources = profile.resources;
    const fakes = createFakes({ service: unmanagedService() });
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    const result = await recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE);
    expect(result.service.managed).toBe(false);
    expect(result.service.status).toBe('unmanaged');
    expect(loadHostDomainResetJournal(resources)).toBeNull();
  });

  test('unmanaged profile lifecycle snapshot is accepted by rehydration', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-reset-recovery-dev2-'));
    roots.push(home);
    process.env.HOME = home;
    process.env.XDG_CONFIG_HOME = join(home, 'xdg');
    const profile = createDevProfile();
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    const resources = profile.resources;
    const fakes = createFakes({ service: unmanagedService() });
    const journal = restorePendingJournal(resources);
    // dev-profile journal uses the unmanaged service snapshot; the fake
    // lifecycle returns the same managed/installed/enabled/backend fields
    // with a flipped wasRunning, proving running state is never compared.
    expect(() => prepareRecovery(dependencies(resources, fakes), journal)).not.toThrow();
  });

  test('unused validateRestored is never proof for removal', async () => {
    const resources = defaultResources();
    const fakes = createFakes();
    fakes.lifecycle.validateRestored = () => true;
    const journal = restorePendingJournal(resources);
    writeJournalFixture(resources, journal);

    // Even though validateRestored claims the service is restored, the module
    // must still run the full sequence and require a confirmation for removal.
    const result = await recoverServiceRestorePending(dependencies(resources, fakes), journal, OK_LEASE);
    expect(result.hostId).toBe(NEW_HOST);
    expect(fakes.calls).toContain('restore');
    expect(loadHostDomainResetJournal(resources)).toBeNull();
  });
});
