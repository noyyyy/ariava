import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ProcessAwareLockDependencies } from '../src/host-manager/process-aware-lock';
import type { ProfileResourceSet } from '../src/cli/profile';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import {
  assertHostIdentityOperationLeaseOwned,
  hostIdentityOperationLockPath,
  withHostIdentityOperationLock,
  type HostIdentityOperationLease,
} from '../src/cli/operations/host-identity-operation-lock';
import { AriavaCliError } from '../src/host-manager/service/errors';

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
  const root = mkdtempSync(join(tmpdir(), 'ariava-host-reset-operation-lock-'));
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

describe('Host identity operation lease', () => {
  test('withHostIdentityOperationLock passes an opaque owned lease into the callback', async () => {
    const resources = resourcesFor('dev');
    let received: HostIdentityOperationLease | undefined;
    await withHostIdentityOperationLock(resources, async (lease) => {
      received = lease;
      expect(typeof lease.assertOwned).toBe('function');
    }, lockDependencies());
    expect(received).toBeDefined();
  });

  test('assertOwned succeeds while the wrapper is running and fails closed after release', async () => {
    const resources = resourcesFor('dev');
    let captured: HostIdentityOperationLease | undefined;
    await withHostIdentityOperationLock(resources, async (lease) => {
      captured = lease;
      expect(() => lease.assertOwned()).not.toThrow();
    }, lockDependencies());
    expect(() => captured!.assertOwned()).toThrow(AriavaCliError);
    expect(() => captured!.assertOwned()).toThrow(/lease/i);
  });

  test('structurally forged leases fail closed at the authorization boundary', () => {
    const resources = resourcesFor('dev');
    const forged = { assertOwned() {} } as unknown as HostIdentityOperationLease;
    expect(() => assertHostIdentityOperationLeaseOwned(forged, resources)).toThrow(/lease/i);
  });

  test('an issued lease is bound to every selected-profile resource field', async () => {
    const resources = resourcesFor('default');
    const counterpart = resourcesFor('dev');
    const sameLockPathAliases: ProfileResourceSet[] = [
      { ...resources, statePath: `${resources.statePath}.foreign` },
      { ...resources, identityProfile: 'dev' },
      { ...resources, identityEvidenceAccount: 'ariava-dev-host-identity' },
      { ...resources, agentAdapterPort: resources.agentAdapterPort + 1 },
    ];
    await withHostIdentityOperationLock(resources, async (lease) => {
      expect(() => assertHostIdentityOperationLeaseOwned(lease, resources)).not.toThrow();
      expect(() => assertHostIdentityOperationLeaseOwned(lease, counterpart)).toThrow(/lease/i);
      for (const alias of sameLockPathAliases) {
        expect(hostIdentityOperationLockPath(alias)).toBe(hostIdentityOperationLockPath(resources));
        expect(() => assertHostIdentityOperationLeaseOwned(lease, alias)).toThrow(/lease/i);
      }
    }, lockDependencies());
  });

  test('assertOwned fails closed when the on-disk lock record is replaced by a foreign owner', async () => {
    const resources = resourcesFor('dev');
    const lockPath = hostIdentityOperationLockPath(resources);
    await withHostIdentityOperationLock(resources, async (lease) => {
      writeFileSync(lockPath, JSON.stringify({
        schemaVersion: 1, pid: 4242, processStart: 'foreign-start',
        createdAt: '2026-08-11T00:00:00.000Z', ownerToken: 'f'.repeat(48),
      }), { mode: 0o600 });
      expect(() => lease.assertOwned()).toThrow(/lease/i);
    }, lockDependencies());
  });

  test('wrapper releases the lease on callback throw and allows a subsequent acquisition', async () => {
    const resources = resourcesFor('dev');
    await expect(withHostIdentityOperationLock(resources, async () => {
      throw new Error('boom');
    }, lockDependencies())).rejects.toThrow('boom');
    await expect(withHostIdentityOperationLock(resources, async () => 'ok', lockDependencies())).resolves.toBe('ok');
  });

  test('second concurrent acquisition fails closed while the first lease is held', async () => {
    const resources = resourcesFor('dev');
    let releaseFirst!: () => void;
    const first = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const running = withHostIdentityOperationLock(resources, async () => {
      await first;
      return 'done';
    }, lockDependencies());
    await expect(withHostIdentityOperationLock(resources, async () => 'second', lockDependencies()))
      .rejects.toMatchObject({ code: 'ERR_HOST_RESET_IN_PROGRESS' });
    releaseFirst();
    await expect(running).resolves.toBe('done');
  });
});
