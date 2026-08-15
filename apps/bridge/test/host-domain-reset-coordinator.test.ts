import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createProfileCliContext, loadResolvedProfileConfig } from '../src/cli/context';
import { formatHumanCliFailure, normalizeCliFailure } from '../src/cli/failure';
import { initializeProfile } from '../src/cli/operations/initialize';
import { resetHostDomain, type HostDomainResetHooks } from '../src/cli/operations/host-domain-reset';
import { HOST_DOMAIN_RESET_PHASES, loadHostDomainResetJournal } from '../src/cli/operations/host-domain-reset-journal';
import { createDevProfile } from '../src/cli/profiles/dev';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { acquireRuntimeCoordinator } from '../src/runtime-lock';
import { BridgeStateStore } from '../src/state-store';
import type { AriavaUserConfig } from '../src/host-manager/config';
import { SecureFileError } from '../src/host-manager/secure-files';
import { AriavaCliError } from '../src/host-manager/service/errors';
import { acquireOnboardingLock } from '../src/host-manager/onboarding/lock';
import {
  hostIdentityOperationLockPath,
  withHostIdentityOperationLock,
} from '../src/cli/operations/host-identity-operation-lock';
import type { HostIdentityOperationLease } from '../src/cli/operations/host-identity-operation-lock';
import { RESET_ONLY_IDENTITY_EVIDENCE_SOURCE } from '../src/identity/reset-only-evidence-source';
import { HostIdentityError } from '../src/identity/errors';
import { enrollCurrentIdentity } from '../src/identity/manager';

const roots: string[] = [];
const originalHome = process.env.HOME;
const originalXdg = process.env.XDG_CONFIG_HOME;
const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalHome === undefined) delete process.env.HOME; else process.env.HOME = originalHome;
  if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = originalXdg;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const deterministicHostIdentityOperationLock = {
  run: withHostIdentityOperationLock,
};

function fixture(useProductionLock = false) {
  const home = mkdtempSync(join(tmpdir(), 'ariava-reset-coordinator-'));
  roots.push(home);
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  const profile = createDevProfile();
  mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
  let config: AriavaUserConfig = {};
  const context = createProfileCliContext({
    profile,
    platform: 'linux',
    hostName: () => 'reset-test-host',
    generateSecret: () => 'a'.repeat(64),
    config: {
      load: () => structuredClone(config),
      save: (next) => { config = structuredClone(next); },
    },
    ...(useProductionLock ? {} : { hostIdentityOperationLock: deterministicHostIdentityOperationLock }),
  });
  let signingReplacements = 0;
  let encryptionReplacements = 0;
  const originalEncryptionCreate = context.encryptionIdentity.create;
  context.encryptionIdentity.create = (resources, platform) => {
    const store = originalEncryptionCreate(resources, platform);
    const replace = store.replaceForReset.bind(store);
    store.replaceForReset = (hostId, operationId) => {
      encryptionReplacements += 1;
      return replace(hostId, operationId);
    };
    return store;
  };
  const dependencies = (hooks?: HostDomainResetHooks) => ({
    bridgeVersion: 'test',
    revoke: async () => 'revoked' as const,
    replace: async (store: ReturnType<typeof context.identity.create>, operationId: string) => {
      signingReplacements += 1;
      return store.resetAfterExplicitConfirmation(operationId);
    },
    enroll: async () => {},
    hooks,
  });
  return {
    mutateConfig: (mutate: (current: AriavaUserConfig) => AriavaUserConfig) => { config = mutate(structuredClone(config)); },
    context,
    profile,
    dependencies,
    counts: () => ({ signingReplacements, encryptionReplacements }),
  };
}

function crashOnceAtPhase(phase: string): HostDomainResetHooks {
  let armed = true;
  return {
    afterPhase(current) {
      if (armed && current === phase) {
        armed = false;
        throw new Error(`crash after phase ${phase}`);
      }
    },
  };
}

function crashOnceAfterEffect(effect: Parameters<NonNullable<HostDomainResetHooks['afterEffect']>>[0]): HostDomainResetHooks {
  let armed = true;
  return {
    afterEffect(current) {
      if (armed && current === effect) {
        armed = false;
        throw new Error(`crash after effect ${effect}`);
      }
    },
  };
}

  test('reset routes through the profile lock boundary', async () => {
    const value = fixture();
    const resetLocks: string[] = [];
    value.context.hostIdentityOperationLock = {
      async run(resources, operation) {
        resetLocks.push(resources.hostDomainResetJournalPath);
        return withHostIdentityOperationLock(resources, operation);
      },
    };
    await initializeProfile(value.context);
    await resetHostDomain(value.context, value.dependencies());
    expect(resetLocks).toEqual([value.profile.resources.hostDomainResetJournalPath]);
  });

describe('Host-domain reset coordinator recovery', () => {
  test('managed service quarantine failure leaves identity and Relay untouched', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const identityBefore = readFileSync(value.profile.resources.identityMetadataPath);
    let identityStoreCreations = 0;
    let revokeCalls = 0;
    const originalIdentityCreate = value.context.identity.create;
    value.context.identity.create = (...args) => {
      identityStoreCreations += 1;
      return originalIdentityCreate(...args);
    };
    value.context.hostDomainResetLifecycle.stopAndConfirm = () => {
      throw new AriavaCliError('ERR_SERVICE_COMMAND', 'service quarantine failed');
    };

    await expect(resetHostDomain(value.context, {
      ...value.dependencies(),
      revoke: async () => { revokeCalls += 1; return 'revoked'; },
    })).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase: 'quarantine-pending' },
    });
    expect(identityStoreCreations).toBe(0);
    expect(revokeCalls).toBe(0);
    expect(readFileSync(value.profile.resources.identityMetadataPath)).toEqual(identityBefore);
    expect(loadHostDomainResetJournal(value.profile.resources)).toMatchObject({ phase: 'quarantine-pending' });
  });

  test('persists running service intent before stop when initial runtime acquisition fails', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-reset-prepared-before-stop-')); roots.push(home);
    process.env.HOME = home; process.env.XDG_CONFIG_HOME = join(home, 'xdg');
    const profile = createDefaultProfile(); mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    let config: AriavaUserConfig = {};
    let currentRunning = true;
    let acquisitionAttempts = 0;
    const calls: string[] = [];
    const context = createProfileCliContext({
      profile, platform: 'linux', hostName: () => 'managed-host', generateSecret: () => 'a'.repeat(64),
      config: { load: () => structuredClone(config), save: (next) => { config = structuredClone(next); } },
      hostIdentityOperationLock: deterministicHostIdentityOperationLock,
      runtimeCoordinator: {
        acquire(resources) {
          acquisitionAttempts += 1;
          if (acquisitionAttempts === 1) throw new Error('runtime acquisition failed');
          return acquireRuntimeCoordinator(resources.statePath, resources.encryptedSpoolPath);
        },
      },
      hostDomainResetLifecycle: {
        prepare: () => ({ managed: true, installed: true, enabled: true, wasRunning: currentRunning, backend: 'systemd-user' }),
        stopAndConfirm: () => { calls.push('stop'); currentRunning = false; },
        synchronizeMetadata: () => { calls.push('sync'); },
        restoreAndConfirm: (snapshot) => { calls.push('restore'); currentRunning = snapshot.wasRunning; return currentRunning; },
        validateRestored: () => currentRunning,
      },
    });
    await initializeProfile(context);
    const identityBefore = readFileSync(profile.resources.identityMetadataPath);
    const originalIdentityCreate = context.identity.create;
    let identityStoreCreations = 0;
    let revokeCalls = 0;
    context.identity.create = (...args) => {
      identityStoreCreations += 1;
      return originalIdentityCreate(...args);
    };
    const dependencies = {
      bridgeVersion: 'test',
      revoke: async () => { revokeCalls += 1; return 'revoked' as const; },
      replace: async (store: ReturnType<typeof context.identity.create>, operationId: string) => store.resetAfterExplicitConfirmation(operationId),
      enroll: async () => {},
    };

    await expect(resetHostDomain(context, dependencies)).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      data: { phase: 'quarantine-pending', retryable: true },
    });
    expect(loadHostDomainResetJournal(profile.resources)).toMatchObject({
      phase: 'quarantine-pending',
      service: { installed: true, wasRunning: true },
    });
    expect(currentRunning).toBe(false);
    expect(identityStoreCreations).toBe(0);
    expect(revokeCalls).toBe(0);
    expect(readFileSync(profile.resources.identityMetadataPath)).toEqual(identityBefore);

    const result = await resetHostDomain(context, dependencies);
    expect(result.service.processRunning).toBe(true);
    expect(calls).toEqual(['stop', 'stop', 'sync', 'restore']);
    expect(existsSync(profile.resources.hostDomainResetJournalPath)).toBe(false);
  });
  test('service-restore-pending retry restarts a previously running stopped service', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-reset-retry-restore-')); roots.push(home);
    process.env.HOME = home; process.env.XDG_CONFIG_HOME = join(home, 'xdg');
    const profile = createDefaultProfile(); mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    let config: AriavaUserConfig = {};
    let currentRunning = true;
    let restoreAttempts = 0;
    const calls: string[] = [];
    const snapshot = { managed: true, installed: true, enabled: true, wasRunning: true, backend: 'systemd-user' as const };
    const context = createProfileCliContext({
      profile, platform: 'linux', hostName: () => 'managed-host', generateSecret: () => 'a'.repeat(64),
      config: { load: () => structuredClone(config), save: (next) => { config = structuredClone(next); } },
      hostIdentityOperationLock: deterministicHostIdentityOperationLock,
      hostDomainResetLifecycle: {
        prepare: () => snapshot,
        stopAndConfirm: () => { calls.push('stop'); currentRunning = false; },
        synchronizeMetadata: () => { calls.push('sync'); },
        restoreAndConfirm: () => {
          calls.push('restore');
          restoreAttempts += 1;
          if (restoreAttempts === 1) throw new Error('start confirmation failed');
          currentRunning = true;
          return true;
        },
        validateRestored: () => { calls.push('validate'); return currentRunning; },
      },
    });
    await initializeProfile(context);
    const dependencies = {
      bridgeVersion: 'test', revoke: async () => 'revoked' as const,
      replace: async (store: ReturnType<typeof context.identity.create>, operationId: string) => store.resetAfterExplicitConfirmation(operationId),
      enroll: async () => {},
    };

    await expect(resetHostDomain(context, dependencies)).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      data: { phase: 'service-restore-pending', retryable: true },
    });
    expect(currentRunning).toBe(false);
    calls.length = 0;

    const result = await resetHostDomain(context, dependencies);
    expect(result.service.processRunning).toBe(true);
    expect(calls).toEqual(['stop', 'restore']);
    expect(existsSync(profile.resources.hostDomainResetJournalPath)).toBe(false);
  });


  test.each([
    { installed: false, enabled: false, wasRunning: false },
    { installed: true, enabled: false, wasRunning: false },
    { installed: true, enabled: true, wasRunning: false },
    { installed: true, enabled: false, wasRunning: true },
    { installed: true, enabled: true, wasRunning: true },
  ])('managed service state converges through reset ($installed/$enabled/$wasRunning)', async (service) => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-reset-managed-')); roots.push(home);
    process.env.HOME = home; process.env.XDG_CONFIG_HOME = join(home, 'xdg');
    const profile = createDefaultProfile(); mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    let config: AriavaUserConfig = {};
    const calls: string[] = [];
    let currentRunning = service.wasRunning;
    const context = createProfileCliContext({
      profile, platform: 'linux', hostName: () => 'managed-host', generateSecret: () => 'a'.repeat(64),
      config: { load: () => structuredClone(config), save: (next) => { config = structuredClone(next); } },
      hostIdentityOperationLock: deterministicHostIdentityOperationLock,
      hostDomainResetLifecycle: {
        prepare: () => ({ managed: true, ...service, backend: 'systemd-user' }),
        stopAndConfirm: () => { calls.push('stop'); currentRunning = false; },
        synchronizeMetadata: () => { calls.push('sync'); },
        restoreAndConfirm: () => { calls.push('restore'); currentRunning = service.wasRunning; return currentRunning; },
        validateRestored: () => currentRunning,
      },
    });
    await initializeProfile(context);
    const result = await resetHostDomain(context, {
      bridgeVersion: 'test', revoke: async () => 'revoked',
      replace: async (store, operationId: string) => store.resetAfterExplicitConfirmation(operationId), enroll: async () => {},
    });
    expect(result.service).toEqual({ managed: true, ...service, backend: 'systemd-user', processRunning: service.wasRunning, status: service.wasRunning ? 'running' : 'stopped' });
    expect(calls).toEqual(['stop', 'sync', 'restore']);
    expect(existsSync(profile.resources.hostDomainResetJournalPath)).toBe(false);
  });

  test('default profile recovery uses the production remediation command', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-reset-production-envelope-'));
    roots.push(home);
    process.env.HOME = home;
    process.env.XDG_CONFIG_HOME = join(home, 'xdg');
    const profile = createDefaultProfile();
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    let config: AriavaUserConfig = {};
    const context = createProfileCliContext({
      profile, platform: 'linux', hostName: () => 'production-host', generateSecret: () => 'a'.repeat(64),
      config: { load: () => structuredClone(config), save: (next) => { config = structuredClone(next); } },
      hostIdentityOperationLock: deterministicHostIdentityOperationLock,
    });
    await initializeProfile(context);
    const dependencies = {
      bridgeVersion: 'test', revoke: async () => 'revoked' as const,
      replace: async (store: ReturnType<typeof context.identity.create>, operationId: string) => store.resetAfterExplicitConfirmation(operationId),
      enroll: async () => {}, hooks: crashOnceAtPhase('prepared'),
    };
    await expect(resetHostDomain(context, dependencies)).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      data: {
        phase: 'prepared', retryable: true,
        remediation: { command: 'ariava identity reset --confirm' },
      },
    });
  });



  test('service-restore-pending recovery uses the idempotent restore path without stop or sync', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const calls: string[] = [];
    value.context.hostDomainResetLifecycle = {
      prepare: () => ({ managed: false, installed: false, enabled: false, wasRunning: false, backend: 'none' }),
      stopAndConfirm: () => { calls.push('stop'); },
      synchronizeMetadata: () => { calls.push('sync'); },
      restoreAndConfirm: () => { calls.push('restore'); return false; },
      validateRestored: () => { calls.push('validate'); return false; },
    };
    await expect(resetHostDomain(value.context, value.dependencies(crashOnceAtPhase('service-restore-pending')))).rejects.toThrow();
    calls.length = 0;
    const result = await resetHostDomain(value.context, value.dependencies());
    expect(result.service.processRunning).toBe(false);
    expect(calls).toEqual(['stop', 'restore']);
  });

  test('locked initial signing identity fails before journal or Host-domain effects', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const originalCreate = value.context.identity.create;
    let revokeCalls = 0;
    value.context.identity.create = (resources, platform) => {
      const store = originalCreate(resources, platform);
      store.load = async () => {
        const { HostIdentityError } = await import('../src/identity/errors');
        throw new HostIdentityError('ERR_IDENTITY_KEYCHAIN_LOCKED', 'Keychain temporarily locked');
      };
      return store;
    };

    await expect(resetHostDomain(value.context, {
      ...value.dependencies(),
      revoke: async () => { revokeCalls += 1; return 'revoked'; },
    })).rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase: 'quarantined' } });
    expect(revokeCalls).toBe(0);
    expect(value.counts()).toEqual({ signingReplacements: 0, encryptionReplacements: 0 });
    expect(loadHostDomainResetJournal(value.profile.resources)).toMatchObject({ phase: 'quarantined' });
  });

  test('initial X25519 load failure releases unmanaged runtime ownership for same-process retry', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const originalCreate = value.context.encryptionIdentity.create;
    let failInitialLoad = true;
    value.context.encryptionIdentity.create = (resources, platform) => {
      const store = originalCreate(resources, platform);
      const load = store.load.bind(store);
      store.load = () => {
        if (failInitialLoad) {
          failInitialLoad = false;
          throw new Error('transient X25519 read failure');
        }
        return load();
      };
      return store;
    };

    await expect(resetHostDomain(value.context, value.dependencies())).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase: 'quarantined' },
    });
    expect(loadHostDomainResetJournal(value.profile.resources)).toMatchObject({ phase: 'quarantined' });
    expect(value.counts()).toEqual({ signingReplacements: 0, encryptionReplacements: 0 });

    const result = await resetHostDomain(value.context, value.dependencies());
    expect(result.hostId).toStartWith('host_');
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
  });

  test('locked replacement retry retains journal without creating a third identity', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const originalCreate = value.context.identity.create;
    let replacementWritten = false;
    let lockReplacementReads = false;
    value.context.identity.create = (resources, platform) => {
      const store = originalCreate(resources, platform);
      const load = store.load.bind(store);
      store.load = async () => {
        if (replacementWritten && lockReplacementReads) {
          const { HostIdentityError } = await import('../src/identity/errors');
          throw new HostIdentityError('ERR_IDENTITY_KEYCHAIN_LOCKED', 'Keychain temporarily locked');
        }
        return load();
      };
      return store;
    };
    const dependencies = value.dependencies({
      afterEffect(effect) {
        if (effect === 'signing-replaced') {
          lockReplacementReads = true;
          throw new Error('crash before replacement IDs are journaled');
        }
      },
    });
    const originalReplace = dependencies.replace;
    dependencies.replace = async (store) => {
      const replacement = await originalReplace(store);
      replacementWritten = true;
      return replacement;
    };

    await expect(resetHostDomain(value.context, dependencies)).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      data: { phase: 'signing-replacement-pending' },
    });
    const journal = loadHostDomainResetJournal(value.profile.resources)!;
    expect(journal.newHostId).toBeNull();
    expect(value.counts().signingReplacements).toBe(1);

    await expect(resetHostDomain(value.context, value.dependencies())).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      data: { phase: 'signing-replacement-pending' },
    });
    expect(loadHostDomainResetJournal(value.profile.resources)).toEqual(journal);
    expect(value.counts().signingReplacements).toBe(1);
  });


  test('does not adopt an unreadable old signing identity that later becomes readable', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const originalCreate = value.context.identity.create;
    const oldIdentity = await originalCreate(value.profile.resources, 'linux').load();
    const oldRecord = JSON.parse(readFileSync(value.profile.resources.identityMetadataPath, 'utf8'));
    oldRecord.createdAt = '2099-12-31T23:59:59.999Z';
    writeFileSync(value.profile.resources.identityMetadataPath, JSON.stringify(oldRecord), { mode: 0o600 });
    const futureDatedOldIdentity = await originalCreate(value.profile.resources, 'linux').load();
    let identityReadable = false;
    value.context.identity.create = (resources, platform) => {
      const store = originalCreate(resources, platform);
      const load = store.load.bind(store);
      store.load = async () => {
        if (!identityReadable) {
          identityReadable = true;
          const { HostIdentityError } = await import('../src/identity/errors');
          throw new HostIdentityError('ERR_IDENTITY_INVALID', 'corrupt identity evidence');
        }
        return load();
      };
      return store;
    };
    const spoolCleanupHostIds: Array<string | undefined> = [];
    const originalSpoolCreate = value.context.hostReplacementSpoolKey.create;
    value.context.hostReplacementSpoolKey.create = (resources, platform) => {
      const store = originalSpoolCreate(resources, platform);
      store.removeForHostReplacement = (expectedOldHostId) => { spoolCleanupHostIds.push(expectedOldHostId); };
      return store;
    };

    await expect(resetHostDomain(
      value.context, value.dependencies(crashOnceAtPhase('signing-replacement-pending')),
    )).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      data: { phase: 'signing-replacement-pending', retryable: true },
    });

    const result = await resetHostDomain(value.context, value.dependencies());
    expect(result.hostId).not.toBe(oldIdentity!.hostId);
    expect(result.hostId).not.toBe(futureDatedOldIdentity!.hostId);
    expect(result.warning).toContain('ERR_IDENTITY_INVALID');
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
    expect(spoolCleanupHostIds).toEqual([undefined]);
  });

  test('unknown unreadable signing evidence blocks before journal, Relay, or replacement', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const originalCreate = value.context.identity.create;
    let revokeCalls = 0;
    value.context.identity.create = (resources, platform) => {
      const store = originalCreate(resources, platform);
      store.load = async () => {
        const { HostIdentityError } = await import('../src/identity/errors');
        throw new HostIdentityError('ERR_IDENTITY_INVALID', 'corrupt identity evidence');
      };
      (store as any)[RESET_ONLY_IDENTITY_EVIDENCE_SOURCE] = () => ({ kind: 'unknown' });
      return store;
    };
    await expect(resetHostDomain(value.context, {
      ...value.dependencies(), revoke: async () => { revokeCalls += 1; return 'revoked'; },
    })).rejects.toMatchObject({ code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase: 'quarantined' } });
    expect(revokeCalls).toBe(0);
    expect(loadHostDomainResetJournal(value.profile.resources)).toMatchObject({ phase: 'quarantined' });
    expect(value.counts()).toEqual({ signingReplacements: 0, encryptionReplacements: 0 });
  });

  test('recognized pending identity evidence skips Relay and completes full replacement', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const path = value.profile.resources.identityMetadataPath;
    const current = JSON.parse(readFileSync(path, 'utf8'));
    current.pendingRotation = {
      operationId: 'op_legacy_pending', issuedAt: new Date().toISOString(), identity: { ...current },
    };
    writeFileSync(path, JSON.stringify(current), { mode: 0o600 });
    let revokeCalls = 0;
    const result = await resetHostDomain(value.context, {
      ...value.dependencies(), revoke: async () => { revokeCalls += 1; return 'revoked'; },
    });
    expect(revokeCalls).toBe(0);
    expect(result.revokedOldIdentity).toBe(false);
    expect(result.warning).toContain('ERR_IDENTITY_INVALID');
    expect(result.hostId).not.toBe(current.hostId);
    expect(result.links).toEqual([]);
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
    expect(existsSync(value.profile.resources.hostDomainResetJournalPath)).toBe(false);
  });

  test('recognized pending identity resumes after crash at prepared with exact journal binding', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const path = value.profile.resources.identityMetadataPath;
    const current = JSON.parse(readFileSync(path, 'utf8'));
    current.pendingRotation = {
      operationId: 'op_legacy_pending_crash', issuedAt: new Date().toISOString(), identity: { ...current },
    };
    writeFileSync(path, JSON.stringify(current), { mode: 0o600 });
    let revokeCalls = 0;
    const dependencies = {
      ...value.dependencies(crashOnceAtPhase('prepared')),
      revoke: async () => { revokeCalls += 1; return 'revoked' as const; },
    };
    await expect(resetHostDomain(value.context, dependencies)).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase: 'prepared' },
    });
    expect(loadHostDomainResetJournal(value.profile.resources)).toMatchObject({
      phase: 'prepared', revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
      signingCleanup: {
        kind: 'linux-json', profile: 'dev', previousAccount: null, previousPendingAccount: null,
        interruptedCreationAccount: null,
      },
    });
    const result = await resetHostDomain(value.context, { ...value.dependencies(), revoke: dependencies.revoke });
    expect(result.hostId).not.toBe(current.hostId);
    expect(revokeCalls).toBe(0);
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
    expect(existsSync(value.profile.resources.hostDomainResetJournalPath)).toBe(false);
  });

  test('crash after durable quarantine occurs before identity inspection or Relay revoke', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const identityBefore = readFileSync(value.profile.resources.identityMetadataPath);
    const originalIdentityCreate = value.context.identity.create;
    let identityStoreCreations = 0;
    let revokeCalls = 0;
    value.context.identity.create = (...args) => {
      identityStoreCreations += 1;
      return originalIdentityCreate(...args);
    };
    const dependencies = {
      ...value.dependencies(crashOnceAtPhase('quarantined')),
      revoke: async () => { revokeCalls += 1; return 'revoked' as const; },
    };

    await expect(resetHostDomain(value.context, dependencies)).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase: 'quarantined' },
    });
    expect(identityStoreCreations).toBe(0);
    expect(revokeCalls).toBe(0);
    expect(readFileSync(value.profile.resources.identityMetadataPath)).toEqual(identityBefore);
    expect(loadHostDomainResetJournal(value.profile.resources)).toMatchObject({ phase: 'quarantined' });

    const result = await resetHostDomain(value.context, { ...value.dependencies(), revoke: dependencies.revoke });
    expect(result.hostId).not.toBe(JSON.parse(identityBefore.toString()).hostId);
    expect(revokeCalls).toBe(1);
  });

  test.each([
    { name: 'top-level extra', mutate: (response: any) => ({ ...response, extra: true }) },
    { name: 'Host extra', mutate: (response: any) => ({ host: { ...response.host, extra: true } }) },
    { name: 'mismatched Host', mutate: (response: any) => ({ host: { ...response.host, hostId: `host_${'Z'.repeat(43)}` } }) },
    { name: 'revoked status', mutate: (response: any) => ({ host: { ...response.host, status: 'revoked' } }) },
    { name: 'nonzero links field', mutate: (response: any) => ({ ...response, links: [{ linkId: 'unexpected' }] }) },
  ])('invalid enrollment response ($name) does not advance reset beyond config-saved', async ({ mutate }) => {
    const value = fixture();
    await initializeProfile(value.context);
    const oldIdentity = await value.context.identity.create(value.profile.resources, 'linux').load();
    let enrolledHostId: string | undefined;
    globalThis.fetch = (async (_input, init) => {
      const body = JSON.parse(new TextDecoder().decode(init?.body as Uint8Array)) as { hostId: string };
      enrolledHostId = body.hostId;
      const response = { host: {
        hostId: body.hostId, hostName: 'reset-test-host (Dev)', platform: 'linux', bridgeVersion: 'test',
        registeredAt: '2026-08-12T00:00:00.000Z', lastSeenAt: '2026-08-12T00:00:01.000Z',
        bridgeStatus: 'online', status: 'active',
      } };
      return Response.json(mutate(response));
    }) as typeof fetch;

    await expect(resetHostDomain(value.context, {
      ...value.dependencies(), enroll: enrollCurrentIdentity,
    })).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase: 'config-saved', retryable: true },
    });
    const journal = loadHostDomainResetJournal(value.profile.resources);
    expect(journal).toMatchObject({
      phase: 'config-saved', newHostId: enrolledHostId, enrolledAt: null,
    });
    expect(enrolledHostId).not.toBe(oldIdentity!.hostId);
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
  });

  test('live dev runtime fails before journal, Relay, signing, E2E, or config effects', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const { resources } = loadResolvedProfileConfig(value.context);
    const owner = acquireRuntimeCoordinator(resources.statePath, resources.encryptedSpoolPath);
    await expect(resetHostDomain(value.context, value.dependencies())).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase: 'quarantine-pending', retryable: true },
    });
    expect(loadHostDomainResetJournal(resources)).toMatchObject({ phase: 'quarantine-pending' });
    expect(value.counts()).toEqual({ signingReplacements: 0, encryptionReplacements: 0 });
    owner.dispose();
  });

  test.each(HOST_DOMAIN_RESET_PHASES)('retry converges after crash at phase %s', async (phase) => {
    const value = fixture();
    await initializeProfile(value.context);
    await expect(resetHostDomain(value.context, value.dependencies(crashOnceAtPhase(phase)))).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase, retryable: true },
    });
    const result = await resetHostDomain(value.context, value.dependencies());
    expect(result.watchPairingRequired).toBe(true);
    expect(result.links).toEqual([]);
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
    expect(existsSync(value.profile.resources.hostDomainResetJournalPath)).toBe(false);
  });

  test.each([
    'signing-replaced',
    'encryption-replaced',
    'artifacts-cleared',
    'config-saved',
    'enrolled',
    'service-metadata-synchronized',
    'service-restored',
  ] as const)('retry converges after lost continuation at %s', async (effect) => {
    const value = fixture();
    await initializeProfile(value.context);
    await expect(resetHostDomain(value.context, value.dependencies(crashOnceAfterEffect(effect)))).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { retryable: true },
    });
    const result = await resetHostDomain(value.context, value.dependencies());
    expect(result.hostId).toStartWith('host_');
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
    expect(existsSync(value.profile.resources.hostDomainResetJournalPath)).toBe(false);
  });


  test.each([
    'linkKeyringPath', 'statePath', 'encryptedSpoolPath', 'runtimeResetIntentPath',
  ] as const)('reintroduced %s at final recovery fails closed without removing journal', async (resourceName) => {
    const value = fixture();
    await initializeProfile(value.context);
    await expect(resetHostDomain(value.context, value.dependencies(crashOnceAtPhase('service-restore-pending')))).rejects.toThrow();
    const journal = loadHostDomainResetJournal(value.profile.resources)!;
    writeFileSync(value.profile.resources[resourceName], '{}', { mode: 0o600 });
    await expect(resetHostDomain(value.context, value.dependencies())).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { retryable: true },
    });
    expect(loadHostDomainResetJournal(value.profile.resources)).toEqual(journal);
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
  });

  test('mutated config identity at final recovery fails closed with stable replacement IDs', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    await expect(resetHostDomain(value.context, value.dependencies(crashOnceAtPhase('service-restore-pending')))).rejects.toThrow();
    const journal = loadHostDomainResetJournal(value.profile.resources)!;
    value.mutateConfig((config) => ({ ...config, identity: { ...config.identity!, keyId: `key_${'Z'.repeat(43)}` } }));
    await expect(resetHostDomain(value.context, value.dependencies())).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { retryable: true },
    });
    expect(loadHostDomainResetJournal(value.profile.resources)).toMatchObject({ newHostId: journal.newHostId, newKeyId: journal.newKeyId });
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
  });

  test('missing E2E evidence at final recovery fails closed without a third identity', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    await expect(resetHostDomain(value.context, value.dependencies(crashOnceAtPhase('service-restore-pending')))).rejects.toThrow();
    const journal = loadHostDomainResetJournal(value.profile.resources)!;
    rmSync(value.profile.resources.encryptionIdentityPath);
    await expect(resetHostDomain(value.context, value.dependencies())).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { retryable: true },
    });
    expect(loadHostDomainResetJournal(value.profile.resources)).toMatchObject({ newHostId: journal.newHostId, newKeyId: journal.newKeyId });
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
  });


  test('running managed service retry accepts replacement runtime artifacts without a second lifecycle', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-reset-restored-runtime-')); roots.push(home);
    process.env.HOME = home; process.env.XDG_CONFIG_HOME = join(home, 'xdg');
    const profile = createDefaultProfile(); mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    let config: AriavaUserConfig = {};
    const calls: string[] = [];
    let currentRunning = true;
    const context = createProfileCliContext({
      profile, platform: 'linux', hostName: () => 'managed-host', generateSecret: () => 'a'.repeat(64),
      config: { load: () => structuredClone(config), save: (next) => { config = structuredClone(next); } },
      hostIdentityOperationLock: deterministicHostIdentityOperationLock,
      hostDomainResetLifecycle: {
        prepare: () => ({ managed: true, installed: true, enabled: true, wasRunning: true, backend: 'systemd-user' }),
        stopAndConfirm: () => { calls.push('stop'); currentRunning = false; },
        synchronizeMetadata: () => { calls.push('sync'); },
        restoreAndConfirm: () => {
          calls.push('restore');
          const runtime = new BridgeStateStore(profile.resources.statePath, undefined, { deferRuntimePreflight: true });
          runtime.initializeEncryptedSpool(config.identity!.hostId, profile.resources.identityMetadataPath, 'linux');
          runtime.dispose();
          currentRunning = true;
          return true;
        },
        validateRestored: () => { calls.push('validate'); return currentRunning; },
      },
    });
    await initializeProfile(context);
    const dependencies = {
      bridgeVersion: 'test', revoke: async () => 'revoked' as const,
      replace: async (store: ReturnType<typeof context.identity.create>, operationId: string) => store.resetAfterExplicitConfirmation(operationId),
      enroll: async () => {}, hooks: crashOnceAfterEffect('service-restored'),
    };
    await expect(resetHostDomain(context, dependencies)).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', data: { phase: 'service-restore-pending', retryable: true },
    });
    expect(calls).toEqual(['stop', 'sync', 'restore']);
    const journal = loadHostDomainResetJournal(profile.resources)!;
    const validState = readFileSync(profile.resources.statePath, 'utf8');
    const validSpool = readFileSync(profile.resources.encryptedSpoolPath, 'utf8');
    calls.length = 0;
    for (const hostId of [
      journal.oldHostId!,
      `host_${'Z'.repeat(43)}`,
    ] as const) {
      const spool = JSON.parse(validSpool);
      spool.hostId = hostId;
      writeFileSync(profile.resources.encryptedSpoolPath, `${JSON.stringify(spool, null, 2)}\n`, { mode: 0o600 });
      await expect(resetHostDomain(context, { ...dependencies, hooks: undefined })).rejects.toMatchObject({
        code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      });
      expect(loadHostDomainResetJournal(profile.resources)).toEqual(journal);
      expect(calls).toEqual(['stop']);
      calls.length = 0;
      writeFileSync(profile.resources.encryptedSpoolPath, validSpool, { mode: 0o600 });
    }
    writeFileSync(profile.resources.statePath, '{}\n', { mode: 0o600 });
    await expect(resetHostDomain(context, { ...dependencies, hooks: undefined })).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
    });
    expect(loadHostDomainResetJournal(profile.resources)).toEqual(journal);
    expect(calls).toEqual(['stop']);
    calls.length = 0;
    writeFileSync(profile.resources.statePath, validState, { mode: 0o600 });
    const result = await resetHostDomain(context, { ...dependencies, hooks: undefined });
    expect(result.hostId).toBe(journal.newHostId!);
    expect(calls).toEqual(['stop', 'restore']);
    expect(existsSync(profile.resources.hostDomainResetJournalPath)).toBe(false);
  });



  test('present malformed journal evidence retains original validation error semantics', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    writeFileSync(value.profile.resources.hostDomainResetJournalPath, '{"unsafe":"evidence"}\n', { mode: 0o600 });
    await expect(resetHostDomain(value.context, value.dependencies())).rejects.toEqual(
      new TypeError('Host-domain reset journal is invalid'),
    );
  });

  test('rejects prepared future evidence before Relay revoke or service recovery effects', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    await expect(resetHostDomain(value.context, value.dependencies(crashOnceAtPhase('prepared')))).rejects.toThrow();
    const journal = loadHostDomainResetJournal(value.profile.resources)!;
    writeFileSync(value.profile.resources.hostDomainResetJournalPath, JSON.stringify({
      ...journal,
      newHostId: `host_${'C'.repeat(43)}`,
      newKeyId: `key_${'D'.repeat(43)}`,
      configSavedAt: journal.createdAt,
    }), { mode: 0o600 });
    let revokeCalls = 0;
    let stopCalls = 0;
    let restoreCalls = 0;
    value.context.hostDomainResetLifecycle.stopAndConfirm = () => { stopCalls += 1; };
    value.context.hostDomainResetLifecycle.restoreAndConfirm = () => { restoreCalls += 1; return false; };

    await expect(resetHostDomain(value.context, {
      ...value.dependencies(),
      revoke: async () => { revokeCalls += 1; return 'revoked'; },
    })).rejects.toThrow(/journal is invalid/i);
    expect({ revokeCalls, stopCalls, restoreCalls }).toEqual({ revokeCalls: 0, stopCalls: 0, restoreCalls: 0 });
    expect(value.counts()).toEqual({ signingReplacements: 0, encryptionReplacements: 0 });
  });

  test('journal advancement validation failure is normalized without rewriting evidence', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    let corruptedBytes = '';
    await expect(resetHostDomain(value.context, value.dependencies({
      afterPhase(phase) {
        if (phase !== 'revoke-pending') return;
        corruptedBytes = '{"corrupted":"during-advance"}\n';
        writeFileSync(value.profile.resources.hostDomainResetJournalPath, corruptedBytes, { mode: 0o600 });
      },
    }))).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      data: { phase: 'revoke-pending', retryable: true },
    });
    expect(readFileSync(value.profile.resources.hostDomainResetJournalPath, 'utf8')).toBe(corruptedBytes);
    expect(value.counts()).toEqual({ signingReplacements: 0, encryptionReplacements: 0 });
  });


  test.each([
    ['ERR_SERVICE_METADATA', 'metadata drift'],
    ['ERR_SERVICE_COMMAND', 'service command failed'],
  ] as const)('pending reset normalizes %s without exposing the service cause', async (code, message) => {
    const value = fixture();
    await initializeProfile(value.context);
    await expect(resetHostDomain(value.context, value.dependencies(crashOnceAtPhase('prepared')))).rejects.toThrow();
    const journal = loadHostDomainResetJournal(value.profile.resources)!;
    value.context.hostDomainResetLifecycle.stopAndConfirm = () => { throw new AriavaCliError(code, message, { path: '/secret/path' }); };
    try {
      await resetHostDomain(value.context, value.dependencies());
      throw new Error('expected recovery failure');
    } catch (error) {
      expect(error).toMatchObject({
        code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
        data: {
          phase: journal.phase, operationId: journal.operationId, retryable: true,
          remediation: { command: 'bun run dev:cli -- identity reset --confirm' },
        },
      });
      expect(JSON.stringify(error)).not.toContain('/secret/path');
      expect((error as Error & { cause?: unknown }).cause).toBeInstanceOf(AriavaCliError);
    }
  });


  test.each([
    ['existing recoveryRequired()', () => new AriavaCliError('ERR_HOST_RESET_RECOVERY_REQUIRED', 'raw recovery /secret/path', { raw: 'service output token=secret' })],
    ['journal write SecureFileError', () => new SecureFileError('Secure atomic write failed: /secret/journal', new Error('token=secret'))],
    ['journal advance SecureFileError', () => new SecureFileError('Secure advancement failed: /secret/journal', new Error('raw service output'))],
    ['journal remove SecureFileError', () => new SecureFileError('Secure removal failed: /secret/journal', new Error('token=secret'))],
    ['ERR_SERVICE_INSTALL', () => new AriavaCliError('ERR_SERVICE_INSTALL', 'install failed /secret/unit', { stderr: 'raw service output token=secret' })],
    ['ERR_SERVICE_METADATA', () => new AriavaCliError('ERR_SERVICE_METADATA', 'metadata failed /secret/unit', { path: '/secret/unit' })],
    ['ERR_SERVICE_COMMAND', () => new AriavaCliError('ERR_SERVICE_COMMAND', 'command failed /secret/unit', { stderr: 'raw service output' })],
    ['TypeError', () => new TypeError('invalid /secret/path token=secret')],
    ['generic Error', () => new Error('boom /secret/path raw service output token=secret')],
  ] as const)('valid journal normalizes %s to a redacted complete recovery envelope', async (_label, createCause) => {
    const value = fixture();
    await initializeProfile(value.context);
    await expect(resetHostDomain(value.context, value.dependencies(crashOnceAtPhase('prepared')))).rejects.toThrow();
    const journal = loadHostDomainResetJournal(value.profile.resources)!;
    const cause = createCause();
    value.context.hostDomainResetLifecycle.stopAndConfirm = () => { throw cause; };
    try {
      await resetHostDomain(value.context, value.dependencies());
      throw new Error('expected recovery failure');
    } catch (error) {
      const failure = normalizeCliFailure(error);
      expect(failure).toEqual({
        ok: false, code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
        message: `Host reset recovery requires attention at phase ${journal.phase}.`,
        data: {
          phase: journal.phase, operationId: journal.operationId, retryable: true,
          remediation: {
            message: 'Retry the profile-specific Host reset recovery command: bun run dev:cli -- identity reset --confirm',
            command: 'bun run dev:cli -- identity reset --confirm',
          },
        },
      });
      expect(formatHumanCliFailure(failure)).toBe(
        `ariava: Host reset recovery requires attention at phase ${journal.phase}.\n`
        + 'Retry the profile-specific Host reset recovery command: bun run dev:cli -- identity reset --confirm\n'
        + 'Next: bun run dev:cli -- identity reset --confirm\n',
      );
      const serialized = JSON.stringify(error);
      for (const sensitive of ['/secret', 'token=secret', 'raw service output', 'install failed', 'metadata failed', 'command failed', 'boom']) {
        expect(serialized).not.toContain(sensitive);
      }
      expect((error as Error & { cause?: unknown }).cause).toBe(cause);
      expect(Object.keys(error as object)).not.toContain('cause');
    }
  });



  test('profile operation lock recovers only provably stale ownership and fails closed for live ownership', async () => {
    const value = fixture(true);
    await initializeProfile(value.context);
    const lockPath = hostIdentityOperationLockPath(value.profile.resources);
    const live = acquireOnboardingLock(lockPath);
    await expect(resetHostDomain(value.context, value.dependencies())).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_IN_PROGRESS', data: { retryable: true },
    });
    live.release();

    writeFileSync(lockPath, `${JSON.stringify({
      schemaVersion: 1, pid: 2_147_483_647, processStart: 'definitely-absent',
      createdAt: '2000-01-01T00:00:00.000Z', ownerToken: 'a'.repeat(48),
    })}\n`, { mode: 0o600 });
    await resetHostDomain(value.context, value.dependencies());
    expect(existsSync(lockPath)).toBe(false);
  });


});
