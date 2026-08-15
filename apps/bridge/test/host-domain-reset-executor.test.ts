import { afterEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { base64UrlEncode } from '@ariava/protocol';
import type { HostPlatform } from '@ariava/protocol';
import type {
  HostEncryptionIdentity,
  HostEncryptionIdentityStore,
  HostIdentity,
  HostIdentityStore,
} from '../src/identity';
import { HostIdentityError } from '../src/identity/errors';
import { RESET_ONLY_IDENTITY_EVIDENCE_SOURCE } from '../src/identity/reset-only-evidence-source';
import type { HostReplacementSpoolKeyStore } from '../src/e2e/local-spool';
import type { RuntimeCoordinator } from '../src/runtime-lock';
import type { AriavaUserConfig } from '../src/host-manager/config';
import type { ProfileResourceSet } from '../src/cli/profile';
import { createDevProfile } from '../src/cli/profiles/dev';
import {
  executeHostResetAction,
  recoveryRequired,
  type HostResetExecutorDependencies,
  type HostResetExecutorResult,
} from '../src/cli/operations/host-domain-reset-executor';
import {
  nextHostResetAction,
  type HostResetAction,
} from '../src/cli/operations/host-domain-reset-machine';
import type {
  HostDomainResetJournalV1,
  HostDomainResetSigningCleanupV1,
} from '../src/cli/operations/host-domain-reset-journal-schema';
import { HOST_DOMAIN_RESET_PHASES } from '../src/cli/operations/host-domain-reset-journal-schema';

/**
 * Host-domain reset executor tests (primary spec §7.2 matrix, §8, §12).
 *
 * Exercises the executor module DIRECTLY with injected fakes: precondition
 * failures keep the current phase (relay revoke failure, signing finalizer
 * failure blocking the X25519 effect, X25519 finalizer failure blocking
 * artifact cleanup), idempotent recovery, the prepared readable vs
 * recognized-unreadable binding, and effect-before-phase ordering per row.
 */

const OLD_HOST = `host_${'A'.repeat(43)}`;
const OLD_KEY = `key_${'B'.repeat(43)}`;
const NEW_HOST = `host_${'D'.repeat(43)}`;
const NEW_KEY = `key_${'E'.repeat(43)}`;
const OLD_EKEY = `ekey_${'C'.repeat(43)}`;
const NEW_EKEY = `ekey_${'F'.repeat(43)}`;

const NOW = new Date('2026-08-13T00:00:00.000Z');

const roots: string[] = [];
const originalHome = process.env.HOME;
const originalXdg = process.env.XDG_CONFIG_HOME;

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME; else process.env.HOME = originalHome;
  if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = originalXdg;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

/** Fresh dev profile with an isolated HOME; returns its fixed resources. */
function devResources(): ProfileResourceSet {
  const home = mkdtempSync(join(tmpdir(), 'ariava-reset-executor-'));
  roots.push(home);
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  const profile = createDevProfile();
  mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
  mkdirSync(dirname(profile.resources.statePath), { recursive: true, mode: 0o700 });
  mkdirSync(dirname(profile.resources.encryptedSpoolPath), { recursive: true, mode: 0o700 });
  mkdirSync(dirname(profile.resources.linkKeyringPath), { recursive: true, mode: 0o700 });
  mkdirSync(dirname(profile.resources.runtimeResetIntentPath), { recursive: true, mode: 0o700 });
  return profile.resources;
}

function serviceSnapshot(managed = false) {
  return managed
    ? { managed: true, installed: true, enabled: true, wasRunning: true, backend: 'launchd' as const }
    : { managed: false, installed: false, enabled: false, wasRunning: false, backend: 'none' as const };
}

/** Schema-valid journal at `phase` with the evidence its phase requires. */
function journalAtPhase(
  phase: HostDomainResetJournalV1['phase'],
  patch: Partial<HostDomainResetJournalV1> = {},
  resources: ProfileResourceSet,
): HostDomainResetJournalV1 {
  const index = HOST_DOMAIN_RESET_PHASES.indexOf(phase);
  const atLeast = (candidate: HostDomainResetJournalV1['phase']) => index >= HOST_DOMAIN_RESET_PHASES.indexOf(candidate);
  const timestamp = '2026-08-13T00:00:00.000Z';
  const base: HostDomainResetJournalV1 = {
    version: 1,
    operationId: 'reset_executor_0123456789abcdef',
    profile: resources.identityProfile,
    phase,
    oldHostId: OLD_HOST,
    oldKeyId: OLD_KEY,
    newHostId: null,
    newKeyId: null,
    oldEncryptionKeyId: OLD_EKEY,
    signingCleanup: null,
    signingReplacementAttemptedAt: null,
    encryptionIdentityReplacedAt: null,
    runtimeArtifactsClearedAt: null,
    configSavedAt: null,
    enrolledAt: null,
    serviceMetadataSynchronizedAt: null,
    resourceDigest: 'a'.repeat(64),
    createdAt: '2026-08-12T00:00:00.000Z',
    updatedAt: timestamp,
    revoke: { state: 'not-attempted', outcome: null },
    service: serviceSnapshot(resources.identityProfile === 'default'),
  };
  const journal: HostDomainResetJournalV1 = {
    ...base,
    ...(phase === 'quarantine-pending' || phase === 'quarantined'
      ? { oldHostId: null, oldKeyId: null, oldEncryptionKeyId: null }
      : {}),
    ...(atLeast('revoke-pending') ? { revoke: { state: 'pending' as const, outcome: null } } : {}),
    ...(atLeast('old-identity-revoked')
      ? { revoke: { state: 'complete' as const, outcome: 'revoked' as const } }
      : {}),
    ...(atLeast('signing-replacement-pending') ? { signingReplacementAttemptedAt: timestamp } : {}),
    ...(atLeast('signing-identity-replaced')
      ? { newHostId: NEW_HOST, newKeyId: NEW_KEY }
      : {}),
    ...(atLeast('encryption-identity-replaced') ? { encryptionIdentityReplacedAt: timestamp } : {}),
    ...(atLeast('runtime-artifacts-cleared') ? { runtimeArtifactsClearedAt: timestamp } : {}),
    ...(atLeast('config-saved') ? { configSavedAt: timestamp } : {}),
    ...(atLeast('enrolled') ? { enrolledAt: timestamp } : {}),
    ...(atLeast('service-metadata-synchronized') ? { serviceMetadataSynchronizedAt: timestamp } : {}),
    ...patch,
  };
  return journal;
}

function makeIdentity(hostId: string, keyId: string): HostIdentity {
  return {
    identityVersion: 2,
    hostId,
    keyId,
    algorithm: 'Ed25519',
    publicKey: 'a'.repeat(43),
    publicKeyFingerprint: hostId.slice('host_'.length),
    createdAt: NOW.toISOString(),
    privateKeyStorage: { type: 'linux-json', path: '/tmp/fake-identity.json' },
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
    createdAt: NOW.toISOString(),
  };
}

/** Canonicalizes a path like `canonicalRuntimePath` (resolve + deepest realpath ancestor). */
function canonicalTestPath(path: string): string {
  let candidate = resolve(path);
  const missing: string[] = [];
  for (;;) {
    try {
      return resolve(realpathSync.native(candidate), ...missing.reverse());
    } catch {
      missing.push(dirname(candidate).length < candidate.length ? candidate.slice(dirname(candidate).length + 1) : candidate);
      const parent = dirname(candidate);
      if (parent === candidate) throw new Error(`cannot canonicalize ${path}`);
      candidate = parent;
    }
  }
}

/** Fabricates schema-valid v1 Linux legacy identity evidence at the profile path. Returns the evidence hostId. */
function writeLinuxLegacyEvidence(resources: ProfileResourceSet): string {
  const publicKey = new Uint8Array(32);
  const fingerprint = base64UrlEncode(new Uint8Array(createHash('sha256').update(publicKey).digest()));
  const evidence = {
    version: 1,
    entityType: 'host',
    hostId: `host_${fingerprint}`,
    keyId: `key_${fingerprint}`,
    algorithm: 'Ed25519',
    publicKey: base64UrlEncode(publicKey),
    publicKeyFingerprint: fingerprint,
    createdAt: NOW.toISOString(),
  };
  writeFileSync(resources.identityMetadataPath, JSON.stringify(evidence), { mode: 0o600 });
  return evidence.hostId;
}

interface FakeStores {
  identity: HostIdentityStore & Record<string, unknown>;
  encryption: HostEncryptionIdentityStore & Record<string, unknown>;
  spoolKey: HostReplacementSpoolKeyStore;
  identityReadable: boolean;
  revokeFailures: number;
  signingFinalizeFailures: number;
  encryptionFinalizeFailures: number;
  completeExplicitResetCalls: string[];
  completeResetCalls: string[];
  encryptReplaceCalls: Array<{ hostId: string; operationId?: string }>;
  /** When set, identity load()/recoverExplicitReset() return the replacement. */
  replacementActive: boolean;
  /** Host the encryption store currently returns from load(); null = absent. */
  encryptionHost: string | null;
}

function createFakeStores(options: {
  readable?: boolean;
  legacyEvidence?: 'unreadable';
  encryptionHost?: string | null;
  recoveryCandidate?: boolean;
} = {}): FakeStores {
  const state: FakeStores = {
    identity: {} as HostIdentityStore,
    encryption: {} as HostEncryptionIdentityStore,
    spoolKey: {
      removeForHostReplacement() {},
      assertAbsentForHostReplacement() {},
    },
    identityReadable: options.readable ?? true,
    revokeFailures: 0,
    signingFinalizeFailures: 0,
    encryptionFinalizeFailures: 0,
    completeExplicitResetCalls: [],
    completeResetCalls: [],
    encryptReplaceCalls: [],
    replacementActive: false,
    encryptionHost: options.encryptionHost === undefined ? OLD_HOST : options.encryptionHost,
  };


  state.identity = {
    inspect: async () => ({ status: 'ready', storageType: 'linux-json', storageReference: { type: 'linux-json', path: '/tmp/id.json' }, ownerIntegrity: true, permissionIntegrity: true, metadataIntegrity: true }),
    load: async () => {
      if (!state.identityReadable) {
        throw new HostIdentityError('ERR_IDENTITY_INVALID', 'corrupt identity evidence');
      }
      return state.replacementActive ? makeIdentity(NEW_HOST, NEW_KEY) : makeIdentity(OLD_HOST, OLD_KEY);
    },
    createFirstRun: async () => makeIdentity(NEW_HOST, NEW_KEY),
    resetAfterExplicitConfirmation: async () => makeIdentity(NEW_HOST, NEW_KEY),
    recoverExplicitReset: async () => (state.replacementActive ? makeIdentity(NEW_HOST, NEW_KEY) : null),
    completeExplicitReset: (operationId) => {
      state.completeExplicitResetCalls.push(operationId);
      if (state.signingFinalizeFailures > 0) {
        state.signingFinalizeFailures -= 1;
        throw new Error('signing finalizer failed');
      }
    },
    deleteAfterHostReplacement() {},
  };
  if (options.legacyEvidence === 'unreadable') {
    (state.identity as Record<string, unknown>)[RESET_ONLY_IDENTITY_EVIDENCE_SOURCE] = () => ({
      kind: 'linux-json' as const,
      identityPath: '/tmp/fake-identity.json',
    });
  }

  state.encryption = {
    load: () => (state.encryptionHost === null ? null : makeEncryptionIdentity(state.encryptionHost, state.encryptionHost === OLD_HOST ? OLD_EKEY : NEW_EKEY)),
    loadOrCreate: (hostId: string) => makeEncryptionIdentity(hostId, NEW_EKEY),
    identity: (encryptionKeyId: string) => (encryptionKeyId === OLD_EKEY ? makeEncryptionIdentity(OLD_HOST, OLD_EKEY) : null),
    retainedIdentityIds: () => new Set(),
    replaceCurrent: (hostId: string) => makeEncryptionIdentity(hostId, NEW_EKEY),
    prune: () => [],
    replaceForReset: (hostId: string, operationId?: string) => {
      state.encryptReplaceCalls.push({ hostId, operationId });
      state.encryptionHost = hostId;
      return makeEncryptionIdentity(hostId, NEW_EKEY);
    },
    recoverReset: (hostId: string) => (
      options.recoveryCandidate ? makeEncryptionIdentity(hostId, NEW_EKEY) : null
    ),
    completeReset: (operationId) => {
      state.completeResetCalls.push(operationId);
      if (state.encryptionFinalizeFailures > 0) {
        state.encryptionFinalizeFailures -= 1;
        throw new Error('encryption finalizer failed');
      }
    },
    deleteAfterHostReplacement() {},
  };
  return state;
}

function createDependencies(
  stores: FakeStores,
  overrides: Partial<HostResetExecutorDependencies> = {},
  options: { replacementActive?: boolean; encryptionHost?: string | null } = {},
): HostResetExecutorDependencies {
  const resources = devResources();
  stores.replacementActive = options.replacementActive ?? false;
  if (options.encryptionHost !== undefined) stores.encryptionHost = options.encryptionHost;
  const lifecycle = {
    prepare: () => serviceSnapshot(resources.identityProfile === 'default'),
    stopAndConfirm() {},
    synchronizeMetadata() {},
    restoreAndConfirm: () => false,
    validateRestored: () => false,
  };
  let heldCoordinator: RuntimeCoordinator | undefined;
  const runtime: HostResetExecutorDependencies['runtime'] = {
    acquire: () => {
      const coordinator: RuntimeCoordinator = {
        statePath: canonicalTestPath(resources.statePath),
        spoolPath: canonicalTestPath(resources.encryptedSpoolPath),
        assertOwned() {},
        claimStateWriter: () => () => {},
        dispose() {},
      };
      heldCoordinator = coordinator;
      return coordinator;
    },
    get held() { return heldCoordinator; },
    set held(value) { heldCoordinator = value; },
    release() { heldCoordinator = undefined; },
  };
  let savedConfig: AriavaUserConfig = {};
  const config: HostResetExecutorDependencies['config'] = {
    load: () => savedConfig,
    save: (next) => { savedConfig = next; },
  };
  const replacementMetadata = {
    identityVersion: 2,
    hostId: NEW_HOST,
    keyId: NEW_KEY,
    algorithm: 'Ed25519',
    publicKey: 'a'.repeat(43),
    publicKeyFingerprint: NEW_HOST.slice('host_'.length),
    createdAt: NOW.toISOString(),
    privateKeyStorage: { type: 'linux-json' as const, path: '/tmp/fake-identity.json' },
  };
  return {
    profileId: resources.identityProfile,
    resources,
    identityStore: stores.identity,
    encryptionStore: stores.encryption,
    spoolKeyStore: stores.spoolKey,
    lifecycle,
    runtime,
    config,
    baseConfig: {},
    relayBaseUrl: 'https://relay.invalid',
    hostName: 'reset-test-host',
    platform: 'darwin' as HostPlatform,
    bridgeVersion: 'test',
    revoke: async () => {
      if (stores.revokeFailures > 0) {
        stores.revokeFailures -= 1;
        throw new Error('relay unreachable');
      }
      return 'revoked';
    },
    replace: async () => makeIdentity(NEW_HOST, NEW_KEY),
    enroll: async () => {},
    hooks: undefined,
    now: () => NOW,
    ...overrides,
    config: overrides.config ?? {
      load: () => ({ identity: replacementMetadata } as AriavaUserConfig),
      save: (next) => { savedConfig = next; },
    },
  };
}

function expectTransition(result: HostResetExecutorResult, phase: string) {
  expect(result.kind).toBe('transition');
  if (result.kind !== 'transition') throw new Error('expected transition');
  expect(result.transition.phase).toBe(phase);
}

function phaseIndex(phase: HostDomainResetJournalV1['phase']): number {
  return HOST_DOMAIN_RESET_PHASES.indexOf(phase);
}

function nextPhaseOf(action: HostResetAction['type']): HostDomainResetJournalV1['phase'] {
  switch (action) {
    case 'stop-quarantine-and-acquire-runtime': return 'quarantined';
    case 'inspect-and-bind-old-domain': return 'prepared';
    case 'persist-revoke-intent': return 'revoke-pending';
    case 'revoke-old-identity': return 'old-identity-revoked';
    case 'persist-signing-replacement-intent': return 'signing-replacement-pending';
    case 'replace-signing-identity': return 'signing-identity-replaced';
    case 'finalize-signing-and-replace-encryption-identity': return 'encryption-identity-replaced';
    case 'finalize-encryption-and-clear-runtime-artifacts': return 'runtime-artifacts-cleared';
    case 'persist-config': return 'config-saved';
    case 'enroll-new-identity': return 'enrolled';
    case 'sync-service-metadata': return 'service-metadata-synchronized';
    case 'persist-service-restore-intent': return 'service-restore-pending';
    case 'restore-service-and-remove-journal': return 'service-restore-pending';
  }
}

describe('executor dispatch covers every machine action', () => {
  const actions: Array<[HostResetAction['type'], HostDomainResetJournalV1['phase']]> = [
    ['stop-quarantine-and-acquire-runtime', 'quarantine-pending'],
    ['inspect-and-bind-old-domain', 'quarantined'],
    ['persist-revoke-intent', 'prepared'],
    ['revoke-old-identity', 'revoke-pending'],
    ['persist-signing-replacement-intent', 'old-identity-revoked'],
    ['replace-signing-identity', 'signing-replacement-pending'],
    ['finalize-signing-and-replace-encryption-identity', 'signing-identity-replaced'],
    ['finalize-encryption-and-clear-runtime-artifacts', 'encryption-identity-replaced'],
    ['persist-config', 'runtime-artifacts-cleared'],
    ['enroll-new-identity', 'config-saved'],
    ['sync-service-metadata', 'enrolled'],
    ['persist-service-restore-intent', 'service-metadata-synchronized'],
    ['restore-service-and-remove-journal', 'service-restore-pending'],
  ];

  for (const [action, phase] of actions) {
    test(`dispatches ${action} from ${phase}`, async () => {
      const resources = devResources();
      const replaced = phaseIndex(phase) >= phaseIndex('signing-identity-replaced');
      const stores = createFakeStores();
      const deps = createDependencies(stores, {}, {
        replacementActive: replaced,
        encryptionHost: phaseIndex(phase) >= phaseIndex('encryption-identity-replaced') ? NEW_HOST : OLD_HOST,
      });
      if (action === 'finalize-encryption-and-clear-runtime-artifacts') {
        deps.runtime.held = deps.runtime.acquire();
      }
      const journal = journalAtPhase(phase, {}, resources);
      const result = await executeHostResetAction({ type: action }, journal, deps);
      if (action === 'restore-service-and-remove-journal') {
        expect(result.kind).toBe('restore');
        if (result.kind === 'restore') {
          expect(result.outcome.recoveryOwned).toBe(true);
          expect(result.outcome.journal.phase).toBe('service-restore-pending');
        }
        return;
      }
      expectTransition(result, nextPhaseOf(action));
    });
  }
});

describe('stop-quarantine-and-acquire-runtime', () => {
  test('rehydrates lifecycle, stops the service, acquires runtime, and commits quarantined', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    const stopped: string[] = [];
    const deps = createDependencies(stores, {
      lifecycle: {
        prepare: () => serviceSnapshot(false),
        stopAndConfirm: (snapshot) => { stopped.push(snapshot.backend); },
        synchronizeMetadata() {},
        restoreAndConfirm: () => false,
        validateRestored: () => false,
      },
    });
    const journal = journalAtPhase('quarantine-pending', {}, resources);
    const result = await executeHostResetAction({ type: 'stop-quarantine-and-acquire-runtime' }, journal, deps);
    expectTransition(result, 'quarantined');
    expect(stopped).toEqual(['none']);
    expect(deps.runtime.held).toBeDefined();
  });

  test('fails closed when the service snapshot changed during recovery', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    const deps = createDependencies(stores, {
      lifecycle: {
        prepare: () => serviceSnapshot(true),
        stopAndConfirm() {},
        synchronizeMetadata() {},
        restoreAndConfirm: () => false,
        validateRestored: () => false,
      },
    });
    const journal = journalAtPhase('quarantine-pending', {}, resources);
    await expect(executeHostResetAction({ type: 'stop-quarantine-and-acquire-runtime' }, journal, deps))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { retryable: true } });
    expect(deps.runtime.held).toBeUndefined();
  });
});

describe('inspect-and-bind-old-domain', () => {
  test('binds a readable old identity to prepared with not-attempted revoke', async () => {
    const resources = devResources();
    const stores = createFakeStores({ readable: true });
    const journal = journalAtPhase('quarantined', {}, resources);
    const result = await executeHostResetAction({ type: 'inspect-and-bind-old-domain' }, journal, createDependencies(stores));
    expect(result.kind).toBe('transition');
    if (result.kind !== 'transition') return;
    expect(result.transition.phase).toBe('prepared');
    if (result.transition.phase !== 'prepared') return;
    expect(result.transition.oldHostId).toBe(OLD_HOST);
    expect(result.transition.oldKeyId).toBe(OLD_KEY);
    expect(result.transition.oldEncryptionKeyId).toBe(OLD_EKEY);
    expect(result.transition.revoke).toEqual({ state: 'not-attempted', outcome: null });
    expect(result.transition.signingCleanup).toBeNull();
  });

  test('binds recognized-unreadable legacy evidence to prepared with the skip decision', async () => {
    const resources = devResources();
    const legacyHostId = writeLinuxLegacyEvidence(resources);
    const stores = createFakeStores({ readable: false });
    (stores.identity as Record<string, unknown>)[RESET_ONLY_IDENTITY_EVIDENCE_SOURCE] = () => ({
      kind: 'linux-json' as const,
      identityPath: resources.identityMetadataPath,
    });
    const journal = journalAtPhase('quarantined', {}, resources);
    const result = await executeHostResetAction({ type: 'inspect-and-bind-old-domain' }, journal, createDependencies(stores));
    expect(result.kind).toBe('transition');
    if (result.kind !== 'transition') return;
    expect(result.transition.phase).toBe('prepared');
    if (result.transition.phase !== 'prepared') return;
    expect(result.transition.oldHostId).toBe(legacyHostId);
    expect(result.transition.revoke).toEqual({ state: 'skipped', outcome: 'old-identity-unreadable' });
    const cleanup = result.transition.signingCleanup as HostDomainResetSigningCleanupV1 | null;
    expect(cleanup?.kind).toBe('linux-json');
    expect(cleanup?.profile).toBe('dev');
  });

  test('unknown unreadable evidence blocks without producing a transition', async () => {
    const resources = devResources();
    const stores = createFakeStores({ readable: false });
    const journal = journalAtPhase('quarantined', {}, resources);
    await expect(executeHostResetAction({ type: 'inspect-and-bind-old-domain' }, journal, createDependencies(stores)))
      .rejects.toThrow('does not support reset-only evidence inspection');
  });
});

describe('revoke-old-identity', () => {
  test('conclusive relay response advances to old-identity-revoked', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    const journal = journalAtPhase('revoke-pending', {}, resources);
    const result = await executeHostResetAction({ type: 'revoke-old-identity' }, journal, createDependencies(stores));
    expect(result.kind).toBe('transition');
    if (result.kind !== 'transition') return;
    expect(result.transition.phase).toBe('old-identity-revoked');
    if (result.transition.phase !== 'old-identity-revoked') return;
    expect(result.transition.revoke).toEqual({ state: 'complete', outcome: 'revoked' });
  });

  test('network/5xx/malformed relay response keeps the current phase', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    stores.revokeFailures = 1;
    const journal = journalAtPhase('revoke-pending', {}, resources);
    await expect(executeHostResetAction({ type: 'revoke-old-identity' }, journal, createDependencies(stores)))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { retryable: true } });
  });
});

describe('replace-signing-identity', () => {
  test('commits signing-identity-replaced with the new IDs', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    const journal = journalAtPhase('signing-replacement-pending', {}, resources);
    const result = await executeHostResetAction({ type: 'replace-signing-identity' }, journal, createDependencies(stores));
    expectTransition(result, 'signing-identity-replaced');
  });

  test('idempotently recovers an already-replaced signing identity without re-replacing', async () => {
    const resources = devResources();
    let replaceCalls = 0;
    const stores = createFakeStores();
    const journal = journalAtPhase('signing-replacement-pending', {
      newHostId: NEW_HOST, newKeyId: NEW_KEY,
    }, resources);
    const result = await executeHostResetAction({ type: 'replace-signing-identity' }, journal, createDependencies(stores, {
      replace: async () => { replaceCalls += 1; return makeIdentity(NEW_HOST, NEW_KEY); },
    }, { replacementActive: true }));
    expectTransition(result, 'signing-identity-replaced');
    expect(replaceCalls).toBe(0);
  });
});

describe('finalize-signing-and-replace-encryption-identity', () => {
  test('finalizes the signing sentinel before any X25519 effect', async () => {
    const resources = devResources();
    const stores = createFakeStores({ encryptionHost: OLD_HOST });
    const journal = journalAtPhase('signing-identity-replaced', {}, resources);
    const result = await executeHostResetAction(
      { type: 'finalize-signing-and-replace-encryption-identity' },
      journal,
      createDependencies(stores, {}, { replacementActive: true, encryptionHost: OLD_HOST }),
    );
    expectTransition(result, 'encryption-identity-replaced');
    expect(stores.completeExplicitResetCalls).toEqual([journal.operationId]);
    expect(stores.encryptReplaceCalls.length).toBe(1);
    expect(stores.encryptReplaceCalls[0]).toMatchObject({ hostId: NEW_HOST });
  });

  test('signing finalizer failure blocks the X25519 effect and keeps the phase', async () => {
    const resources = devResources();
    const stores = createFakeStores({ encryptionHost: OLD_HOST });
    stores.signingFinalizeFailures = 1;
    const journal = journalAtPhase('signing-identity-replaced', {}, resources);
    await expect(executeHostResetAction(
      { type: 'finalize-signing-and-replace-encryption-identity' },
      journal,
      createDependencies(stores, {}, { replacementActive: true, encryptionHost: OLD_HOST }),
    )).rejects.toThrow('signing finalizer failed');
    expect(stores.encryptReplaceCalls.length).toBe(0);
    expect(stores.completeResetCalls.length).toBe(0);
  });
});

describe('finalize-encryption-and-clear-runtime-artifacts', () => {
  test('finalizes the X25519 sentinel before clearing artifacts', async () => {
    const resources = devResources();
    const stores = createFakeStores({ encryptionHost: NEW_HOST });
    let cleared = 0;
    const deps = createDependencies(stores, {
      spoolKeyStore: { ...stores.spoolKey, removeForHostReplacement: () => { cleared += 1; } },
    }, { replacementActive: true, encryptionHost: NEW_HOST });
    deps.runtime.held = deps.runtime.acquire();
    const journal = journalAtPhase('encryption-identity-replaced', {}, resources);
    const result = await executeHostResetAction({ type: 'finalize-encryption-and-clear-runtime-artifacts' }, journal, deps);
    expectTransition(result, 'runtime-artifacts-cleared');
    expect(stores.completeResetCalls).toEqual([journal.operationId]);
    expect(cleared).toBe(1);
  });

  test('X25519 finalizer failure blocks artifact cleanup and keeps the phase', async () => {
    const resources = devResources();
    const stores = createFakeStores({ encryptionHost: NEW_HOST });
    stores.encryptionFinalizeFailures = 1;
    let cleared = 0;
    const deps = createDependencies(stores, {
      spoolKeyStore: { ...stores.spoolKey, removeForHostReplacement: () => { cleared += 1; } },
    }, { replacementActive: true, encryptionHost: NEW_HOST });
    deps.runtime.held = deps.runtime.acquire();
    const journal = journalAtPhase('encryption-identity-replaced', {}, resources);
    await expect(executeHostResetAction({ type: 'finalize-encryption-and-clear-runtime-artifacts' }, journal, deps))
      .rejects.toThrow('encryption finalizer failed');
    expect(cleared).toBe(0);
  });

  test('fails closed when runtime ownership is not held', async () => {
    const resources = devResources();
    const stores = createFakeStores({ encryptionHost: NEW_HOST });
    const journal = journalAtPhase('encryption-identity-replaced', {}, resources);
    await expect(executeHostResetAction(
      { type: 'finalize-encryption-and-clear-runtime-artifacts' },
      journal,
      createDependencies(stores, {}, { replacementActive: true, encryptionHost: NEW_HOST }),
    )).rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
  });
});

describe('persist-config and enroll-new-identity', () => {
  test('persist-config saves the replacement identity into config', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    const saved: AriavaUserConfig[] = [];
    const journal = journalAtPhase('runtime-artifacts-cleared', {}, resources);
    const result = await executeHostResetAction({ type: 'persist-config' }, journal, createDependencies(stores, {
      config: { load: () => ({}), save: (next) => { saved.push(next); } },
      baseConfig: { hostName: 'base-host' },
    }, { replacementActive: true }));
    expectTransition(result, 'config-saved');
    expect(saved.length).toBe(1);
    expect(saved[0].identity).toMatchObject({ hostId: NEW_HOST, keyId: NEW_KEY });
    expect(saved[0].hostName).toBe('base-host');
  });

  test('enroll-new-identity rejects a config not bound to the replacement', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    const journal = journalAtPhase('config-saved', {}, resources);
    await expect(executeHostResetAction({ type: 'enroll-new-identity' }, journal, createDependencies(stores, {
      config: { load: () => ({ identity: { hostId: OLD_HOST, keyId: OLD_KEY } }), save: () => {} },
    }, { replacementActive: true }))).rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
  });

  test('enroll-new-identity enrolls the zero-link replacement identity', async () => {
    const resources = devResources();
    const stores = createFakeStores({ encryptionHost: NEW_HOST });
    const enrolled: string[] = [];
    const journal = journalAtPhase('config-saved', {}, resources);
    const result = await executeHostResetAction({ type: 'enroll-new-identity' }, journal, createDependencies(stores, {
      enroll: async (identity) => { enrolled.push(identity.hostId); },
    }, { replacementActive: true, encryptionHost: NEW_HOST }));
    expectTransition(result, 'enrolled');
    expect(enrolled).toEqual([NEW_HOST]);
  });
});

describe('sync-service-metadata and persist-service-restore-intent', () => {
  test('sync-service-metadata synchronizes the service definition', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    let synced = 0;
    const journal = journalAtPhase('enrolled', {}, resources);
    const result = await executeHostResetAction({ type: 'sync-service-metadata' }, journal, createDependencies(stores, {
      lifecycle: {
        prepare: () => serviceSnapshot(false),
        stopAndConfirm() {},
        synchronizeMetadata: () => { synced += 1; },
        restoreAndConfirm: () => false,
        validateRestored: () => false,
      },
    }, { replacementActive: true }));
    expectTransition(result, 'service-metadata-synchronized');
    expect(synced).toBe(1);
  });

  test('persist-service-restore-intent commits service-restore-pending without removing the journal', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    const journal = journalAtPhase('service-metadata-synchronized', {}, resources);
    const result = await executeHostResetAction({ type: 'persist-service-restore-intent' }, journal, createDependencies(stores, {}, { replacementActive: true }));
    expectTransition(result, 'service-restore-pending');
  });
});

describe('restore-service-and-remove-journal slot', () => {
  test('returns the restore outcome descriptor owned by the recovery module', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    const journal = journalAtPhase('service-restore-pending', {}, resources);
    const result = await executeHostResetAction({ type: 'restore-service-and-remove-journal' }, journal, createDependencies(stores));
    expect(result.kind).toBe('restore');
    if (result.kind === 'restore') expect(result.outcome.journal.phase).toBe('service-restore-pending');
  });

  test('fails closed on a wrong-phase journal', async () => {
    const resources = devResources();
    const stores = createFakeStores();
    const journal = journalAtPhase('enrolled', {}, resources);
    await expect(executeHostResetAction({ type: 'restore-service-and-remove-journal' }, journal, createDependencies(stores)))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED' });
  });
});

describe('machine + executor coherence', () => {
  test('nextHostResetAction selects an action whose executor succeeds for every phase', async () => {
    const resources = devResources();
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      const journal = journalAtPhase(phase, {}, resources);
      const replaced = phaseIndex(phase) >= phaseIndex('signing-identity-replaced');
      const stores = createFakeStores();
      const deps = createDependencies(stores, {}, {
        replacementActive: replaced,
        encryptionHost: phaseIndex(phase) >= phaseIndex('encryption-identity-replaced') ? NEW_HOST : OLD_HOST,
      });
      if (phase === 'encryption-identity-replaced' || phase === 'runtime-artifacts-cleared') {
        deps.runtime.held = deps.runtime.acquire();
      }
      const action = nextHostResetAction(journal);
      const result = await executeHostResetAction(action, journal, deps);
      expect(result.kind === 'transition' || result.kind === 'restore', `phase ${phase}`).toBe(true);
    }
  });

  test('recoveryRequired preserves retryable semantics', () => {
    const error = recoveryRequired('phase kept');
    expect(error).toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { retryable: true } });
  });
});
