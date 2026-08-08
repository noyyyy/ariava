import { afterEach, describe, expect, test } from 'bun:test';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  acquireRuntimeLock,
  runtimeLockPathForState,
  runtimeTakeoverMutexPathForState,
  type RuntimeLockDependencies,
  type RuntimeLockRecord,
} from '../src/runtime-lock';

const roots: string[] = [];
const claimantFixture = join(import.meta.dir, 'fixtures/runtime-lock-claimant.ts');
const staleRecord: RuntimeLockRecord = {
  schemaVersion: 1,
  pid: 100,
  processStart: 'old-start',
  createdAt: '2026-08-07T00:00:00.000Z',
  ownerToken: 'c'.repeat(48),
};

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(name: string): { root: string; statePath: string; lockPath: string; mutexPath: string } {
  const root = mkdtempSync(join(tmpdir(), `ariava-runtime-lock-${name}-`));
  chmodSync(root, 0o700);
  roots.push(root);
  const statePath = join(root, 'state.json');
  return {
    root,
    statePath,
    lockPath: runtimeLockPathForState(statePath),
    mutexPath: runtimeTakeoverMutexPathForState(statePath),
  };
}

function writeRecord(path: string, record: RuntimeLockRecord = staleRecord, mode = 0o600): void {
  writeFileSync(path, `${JSON.stringify(record, null, 2)}\n`, { mode });
}

function dependencies(
  pid: number,
  processStart: string,
  inspect: RuntimeLockDependencies['inspector']['inspect'],
  token = 'a'.repeat(48),
): RuntimeLockDependencies {
  return {
    uid: process.getuid!(),
    pid,
    now: () => new Date('2026-08-08T00:00:00.000Z'),
    ownerToken: () => token,
    currentProcessStart: () => processStart,
    inspector: { inspect },
  };
}

function waitFor(path: string, timeoutMs = 5_000): Promise<void> {
  const startedAt = Date.now();
  return new Promise((resolve, reject) => {
    const poll = (): void => {
      if (existsSync(path)) return resolve();
      if (Date.now() - startedAt >= timeoutMs) return reject(new Error(`timed out waiting for ${path}`));
      setTimeout(poll, 5);
    };
    poll();
  });
}

function runClaimant(
  root: string,
  statePath: string,
  name: string,
  mode: string,
  gatePath = '',
): ReturnType<typeof Bun.spawn> {
  return Bun.spawn([process.execPath, claimantFixture, root, statePath, name, mode, gatePath], {
    cwd: process.cwd(),
    stdout: 'pipe',
    stderr: 'pipe',
  });
}

function removeClaimantLiveness(root: string): void {
  for (const name of readdirSync(root).filter((entry) => entry.startsWith('alive-'))) {
    unlinkSync(join(root, name));
  }
}

describe('secure runtime lock', () => {
  test('serializes two stale reclaimers so only one wins and the loser observes its live lock', async () => {
    const { root, statePath, lockPath } = fixture('race');
    writeRecord(lockPath);
    const gatePath = join(root, 'gate');
    const first = runClaimant(root, statePath, 'first', 'ordered-race', gatePath);
    const second = runClaimant(root, statePath, 'second', 'ordered-race', gatePath);
    await Promise.all([waitFor(join(root, 'ready-first')), waitFor(join(root, 'ready-second'))]);
    writeFileSync(gatePath, '', { mode: 0o600 });
    await waitFor(join(root, 'winner-first'));
    await waitFor(join(root, 'loser-second'));
    expect(readFileSync(join(root, 'loser-second'), 'utf8')).toMatch(/runtime lock/i);
    expect(JSON.parse(readFileSync(lockPath, 'utf8')).ownerToken).toBe('a'.repeat(48));
    expect(existsSync(join(root, 'winner-second'))).toBe(false);
    writeFileSync(join(root, 'release-first'), '', { mode: 0o600 });
    expect(await first.exited).toBe(0);
    expect(await second.exited).toBe(2);
    expect(existsSync(lockPath)).toBe(false);
  });

  test.each([
    ['mutex creation', 'crash-mutex', 81],
    ['stale main validation', 'crash-validation', 82],
    ['stale main removal', 'crash-removal', 83],
    ['new main creation and fsync', 'crash-creation', 84],
    ['mutex cleanup', 'crash-cleanup', 85],
  ])('recovers deterministically after claimant crash at %s', async (_boundary, mode, exitCode) => {
    const { root, statePath, lockPath } = fixture(mode);
    writeRecord(lockPath);
    const claimant = runClaimant(root, statePath, 'crashed', mode);
    expect(await claimant.exited).toBe(exitCode);
    removeClaimantLiveness(root);

    const replacement = acquireRuntimeLock(
      statePath,
      dependencies(200, 'replacement-start', () => ({ status: 'absent' }), 'e'.repeat(48)),
    );
    replacement.assertOwned();
    expect(JSON.parse(readFileSync(lockPath, 'utf8')).ownerToken).toBe('e'.repeat(48));
    replacement.release();
    expect(existsSync(lockPath)).toBe(false);
  });

  test('refuses a live owner and allows PID reuse only when process-start identity mismatches', () => {
    const live = fixture('live');
    writeRecord(live.lockPath);
    expect(() => acquireRuntimeLock(
      live.statePath,
      dependencies(200, 'new-start', () => ({ status: 'alive', processStart: staleRecord.processStart })),
    )).toThrow(/runtime lock/i);
    expect(JSON.parse(readFileSync(live.lockPath, 'utf8'))).toEqual(staleRecord);

    const reused = fixture('pid-reuse');
    writeRecord(reused.lockPath);
    const lock = acquireRuntimeLock(
      reused.statePath,
      dependencies(200, 'new-start', () => ({ status: 'alive', processStart: 'reused-start' })),
    );
    lock.release();
  });

  test.each(['invalid token', 'permissive mode', 'symlink', 'foreign owner'])(
    'fails closed for insecure main-lock evidence: %s',
    (failure) => {
      const { root, statePath, lockPath } = fixture(`main-${failure.replaceAll(' ', '-')}`);
      const record = failure === 'invalid token' ? { ...staleRecord, ownerToken: 'not-a-token' } : staleRecord;
      if (failure === 'symlink') {
        const target = join(root, 'main-target');
        writeRecord(target, record);
        symlinkSync(target, lockPath);
      } else {
        writeRecord(lockPath, record, failure === 'permissive mode' ? 0o644 : 0o600);
      }
      const uid = failure === 'foreign owner' ? process.getuid!() + 1 : process.getuid!();
      expect(() => acquireRuntimeLock(statePath, { ...dependencies(200, 'new-start', () => ({ status: 'absent' })), uid }))
        .toThrow(/runtime lock/i);
      expect(existsSync(lockPath)).toBe(true);
    },
  );

  test.each(['invalid token', 'permissive mode', 'symlink', 'foreign owner'])(
    'fails closed for insecure takeover-mutex evidence: %s',
    (failure) => {
      const { root, statePath, lockPath, mutexPath } = fixture(`mutex-${failure.replaceAll(' ', '-')}`);
      writeRecord(lockPath);
      const record = failure === 'invalid token' ? { ...staleRecord, ownerToken: 'not-a-token' } : staleRecord;
      if (failure === 'symlink') {
        const target = join(root, 'mutex-target');
        writeRecord(target, record);
        symlinkSync(target, mutexPath);
      } else {
        writeRecord(mutexPath, record, failure === 'permissive mode' ? 0o644 : 0o600);
      }
      const uid = failure === 'foreign owner' ? process.getuid!() + 1 : process.getuid!();
      expect(() => acquireRuntimeLock(statePath, { ...dependencies(200, 'new-start', () => ({ status: 'absent' })), uid }))
        .toThrow(/runtime lock/i);
      expect(JSON.parse(readFileSync(lockPath, 'utf8'))).toEqual(staleRecord);
    },
  );

  test.each([
    ['live', { status: 'alive', processStart: staleRecord.processStart } as const],
    ['ambiguous', { status: 'unprovable' } as const],
  ])('refuses %s takeover-mutex ownership', (_name, inspection) => {
    const { statePath, lockPath, mutexPath } = fixture(`mutex-${_name}`);
    writeRecord(lockPath);
    writeRecord(mutexPath);
    expect(() => acquireRuntimeLock(statePath, dependencies(200, 'new-start', () => inspection)))
      .toThrow(/runtime lock/i);
    expect(JSON.parse(readFileSync(lockPath, 'utf8'))).toEqual(staleRecord);
  });

  test('clean release removes only the exact owned main lock and mutex generation', () => {
    const { statePath, lockPath, mutexPath } = fixture('release');
    const lock = acquireRuntimeLock(
      statePath,
      dependencies(200, 'owner-start', (pid) => pid === 200
        ? { status: 'alive', processStart: 'owner-start' }
        : { status: 'absent' }),
    );
    expect(lstatSync(lockPath).mode & 0o777).toBe(0o600);
    lock.release();
    lock.release();
    expect(existsSync(lockPath)).toBe(false);
    expect(existsSync(mutexPath)).toBe(false);
  });

  test('release refuses exact-content replacement with a different inode', () => {
    const { statePath, lockPath } = fixture('release-replacement');
    const lock = acquireRuntimeLock(
      statePath,
      dependencies(200, 'owner-start', (pid) => pid === 200
        ? { status: 'alive', processStart: 'owner-start' }
        : { status: 'absent' }),
    );
    const replacement = join(lockPath, '..', 'replacement-lock');
    writeRecord(replacement, lock.record);
    unlinkSync(lockPath);
    writeFileSync(lockPath, readFileSync(replacement), { mode: 0o600 });
    expect(() => lock.release()).toThrow(/runtime lock/i);
    expect(existsSync(lockPath)).toBe(true);
  });
});
