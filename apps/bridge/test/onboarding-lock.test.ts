import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  acquireOnboardingLock,
  createProcessInspector,
  ephemeralBootstrapLockPath,
  normalizeMacProcessStart,
  parseLinuxProcessStart,
  withOnboardingLock,
  type LockDependencies,
  type OnboardingLockRecord,
  type ProcessInspection,
} from '../src/host-manager/onboarding';

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function memoryLock(options: {
  now?: Date;
  existing?: OnboardingLockRecord;
  inspection?: ProcessInspection;
  replaceBeforeRelease?: boolean;
} = {}) {
  const files = new Map<string, OnboardingLockRecord>();
  const path = '/runtime/onboarding.lock';
  if (options.existing) files.set(path, structuredClone(options.existing));
  const removed: string[] = [];
  const deps: Partial<LockDependencies> = {
    platform: 'linux',
    uid: 501,
    pid: 222,
    now: () => options.now ?? new Date('2026-07-20T12:00:00.000Z'),
    ownerToken: () => 'b'.repeat(48),
    currentProcessStart: () => 'current-start',
    inspector: { inspect: () => options.inspection ?? { status: 'alive', processStart: 'old-start' } },
    exists: (target) => files.has(target),
    read: (target) => {
      const value = files.get(target);
      if (!value) throw new Error('ENOENT');
      return structuredClone(value);
    },
    create: (target, record) => {
      if (files.has(target)) throw new Error('EEXIST');
      files.set(target, structuredClone(record));
    },
    remove: (target) => {
      removed.push(target);
      files.delete(target);
    },
    assertSecure: () => {},
  };
  return { path, files, removed, deps };
}

function oldRecord(overrides: Partial<OnboardingLockRecord> = {}): OnboardingLockRecord {
  return {
    schemaVersion: 1,
    pid: 111,
    processStart: 'old-start',
    createdAt: '2026-07-20T11:00:00.000Z',
    ownerToken: 'a'.repeat(48),
    ...overrides,
  };
}

describe('onboarding locks', () => {
  test('uses an ephemeral uid/version lock outside the product config tree', () => {
    const path = ephemeralBootstrapLockPath('0.1.6-next/unsafe', 501);
    expect(path).toContain('ariava-501/onboard-0.1.6-next_unsafe.lock');
    expect(path).not.toContain('/.config/ariava/');
  });

  test('allows one owner and rejects a simultaneous contender', () => {
    const fixture = memoryLock();
    const first = acquireOnboardingLock(fixture.path, fixture.deps);
    expect(() => acquireOnboardingLock(fixture.path, fixture.deps)).toThrow();
    first.release();
    expect(fixture.files.has(fixture.path)).toBe(false);
  });

  test('does not recover live, young-dead, or unprovable locks', () => {
    for (const fixture of [
      memoryLock({ existing: oldRecord(), inspection: { status: 'alive', processStart: 'old-start' } }),
      memoryLock({ existing: oldRecord({ createdAt: '2026-07-20T11:59:00.000Z' }), inspection: { status: 'absent' } }),
      memoryLock({ existing: oldRecord(), inspection: { status: 'unprovable' } }),
    ]) {
      expect(() => acquireOnboardingLock(fixture.path, fixture.deps)).toThrow();
      expect(fixture.files.get(fixture.path)).toEqual(fixture.files.get(fixture.path));
    }
  });

  test('recovers only old proven-dead or PID-reused locks', () => {
    for (const inspection of [
      { status: 'absent' as const },
      { status: 'alive' as const, processStart: 'new-start' },
    ]) {
      const fixture = memoryLock({ existing: oldRecord(), inspection });
      const lock = acquireOnboardingLock(fixture.path, fixture.deps);
      expect(lock.record.ownerToken).toBe('b'.repeat(48));
      expect(fixture.removed).toEqual([fixture.path]);
      lock.release();
    }
  });

  test('release removes only the still-owned token and finally releases on failure', async () => {
    const replaced = memoryLock();
    const lock = acquireOnboardingLock(replaced.path, replaced.deps);
    replaced.files.set(replaced.path, oldRecord({ ownerToken: 'c'.repeat(48) }));
    lock.release();
    expect(replaced.files.get(replaced.path)?.ownerToken).toBe('c'.repeat(48));

    const finalFixture = memoryLock();
    await expect(withOnboardingLock(finalFixture.path, async () => {
      throw new Error('SIGINT');
    }, finalFixture.deps)).rejects.toThrow('SIGINT');
    expect(finalFixture.files.has(finalFixture.path)).toBe(false);
  });

  test('fails closed for malformed secure records', () => {
    for (const record of [
      oldRecord({ createdAt: 'not-a-time' }),
      oldRecord({ ownerToken: 'short' }),
      oldRecord({ pid: 0 }),
    ]) {
      const fixture = memoryLock({ existing: record, inspection: { status: 'absent' } });
      expect(() => acquireOnboardingLock(fixture.path, fixture.deps)).toThrow();
      expect(fixture.removed).toEqual([]);
    }
  });

  test('real secure-file boundary rejects symlinks and wrong modes', () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-onboarding-lock-'));
    roots.push(root);
    chmodSync(root, 0o700);
    const lockPath = join(root, 'onboarding.lock');
    writeFileSync(lockPath, JSON.stringify(oldRecord()), { mode: 0o644 });
    expect(() => acquireOnboardingLock(lockPath)).toThrow();

    rmSync(lockPath);
    const target = join(root, 'target.json');
    writeFileSync(target, JSON.stringify(oldRecord()), { mode: 0o600 });
    symlinkSync(target, lockPath);
    expect(lstatSync(lockPath).isSymbolicLink()).toBe(true);
    expect(() => acquireOnboardingLock(lockPath)).toThrow();
  });

  test('parses Linux and macOS process-start evidence and fails closed when macOS is unprovable', () => {
    const stat = `123 (name with ) paren) S ${Array.from({ length: 19 }, (_, index) => index === 18 ? '98765' : '0').join(' ')}`;
    expect(parseLinuxProcessStart(stat)).toBe('98765');
    expect(parseLinuxProcessStart('malformed')).toBeUndefined();

    const macStart = 'Sun Jul 20 10:11:12 2026';
    expect(normalizeMacProcessStart(`  ${macStart}\n`)).toBe(macStart);
    expect(normalizeMacProcessStart('unknown')).toBeUndefined();

    const calls: string[] = [];
    const inspector = createProcessInspector('darwin', {
      run(command, args) {
        calls.push(`${command} ${args.join(' ')}`);
        return { status: 2, stdout: '', stderr: 'denied' };
      },
    }, () => undefined);
    expect(inspector.inspect(111)).toEqual({ status: 'unprovable' });
    expect(calls).toEqual(['ps -p 111 -o lstart=']);
  });
});
