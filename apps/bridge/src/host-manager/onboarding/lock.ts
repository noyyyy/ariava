import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { AriavaCliError } from '../service/errors';
import {
  assertSecureFile,
  pathHasFilesystemEvidence,
  readSecureJson,
  removeSecureFile,
  writeSecureJsonExclusive,
} from '../secure-files';
import type { CommandRunner } from '../service/types';
import { SpawnSyncCommandRunner } from '../service/command-runner';

export const ONBOARDING_LOCK_SCHEMA_VERSION = 1;
export const DEFAULT_STALE_LOCK_AGE_MS = 5 * 60_000;

export interface OnboardingLockRecord {
  schemaVersion: 1;
  pid: number;
  processStart: string;
  createdAt: string;
  ownerToken: string;
}

export type ProcessInspection =
  | { status: 'alive'; processStart: string }
  | { status: 'absent' }
  | { status: 'unprovable' };

export interface ProcessInspector {
  inspect(pid: number): ProcessInspection;
}

export interface LockDependencies {
  platform: NodeJS.Platform;
  uid: number;
  pid: number;
  now(): Date;
  ownerToken(): string;
  currentProcessStart(): string;
  inspector: ProcessInspector;
  exists(path: string): boolean;
  read(path: string, uid: number): OnboardingLockRecord;
  create(path: string, record: OnboardingLockRecord, uid: number): void;
  remove(path: string, uid: number): void;
  assertSecure(path: string, uid: number): void;
}

export interface OwnedOnboardingLock {
  path: string;
  record: OnboardingLockRecord;
  release(): void;
}

export function ephemeralBootstrapLockPath(version: string, uid = process.getuid?.()): string {
  if (uid === undefined) throw new Error('Current uid is unavailable');
  const safeVersion = version.replace(/[^A-Za-z0-9._-]/g, '_');
  const runtimeRoot = process.env.XDG_RUNTIME_DIR?.trim();
  const ownerRuntime = runtimeRoot ? resolve(runtimeRoot) : join(resolve(tmpdir()), `ariava-${uid}`);
  return join(ownerRuntime, `onboard-${safeVersion}.lock`);
}

export function acquireOnboardingLock(
  path: string,
  dependencies: Partial<LockDependencies> = {},
  staleAgeMs = DEFAULT_STALE_LOCK_AGE_MS,
): OwnedOnboardingLock {
  const deps = resolveLockDependencies(dependencies);
  const record: OnboardingLockRecord = {
    schemaVersion: ONBOARDING_LOCK_SCHEMA_VERSION,
    pid: deps.pid,
    processStart: deps.currentProcessStart(),
    createdAt: deps.now().toISOString(),
    ownerToken: deps.ownerToken(),
  };

  try {
    deps.create(path, record, deps.uid);
  } catch (error) {
    if (!deps.exists(path)) throw error;
    const existing = readValidatedRecord(path, deps);
    if (!canRecover(existing, deps, staleAgeMs)) throw lockedError();
    // Revalidate the same secure record immediately before removing it.
    const rechecked = readValidatedRecord(path, deps);
    if (JSON.stringify(rechecked) !== JSON.stringify(existing)) throw lockedError();
    deps.remove(path, deps.uid);
    try {
      deps.create(path, record, deps.uid);
    } catch {
      throw lockedError();
    }
  }

  let released = false;
  return {
    path,
    record,
    release() {
      if (released) return;
      const current = readValidatedRecord(path, deps);
      if (current.ownerToken !== record.ownerToken) return;
      deps.remove(path, deps.uid);
      released = true;
    },
  };
}

export async function withOnboardingLock<T>(path: string, run: () => Promise<T>, deps: Partial<LockDependencies> = {}): Promise<T> {
  const lock = acquireOnboardingLock(path, deps);
  try {
    return await run();
  } finally {
    lock.release();
  }
}

export function createProcessInspector(platform: NodeJS.Platform, runner: CommandRunner, readText: (path: string) => string | undefined): ProcessInspector {
  return {
    inspect(pid: number): ProcessInspection {
      if (platform === 'linux') {
        const stat = readText(`/proc/${pid}/stat`);
        if (stat === undefined) return { status: 'absent' };
        const start = parseLinuxProcessStart(stat);
        return start ? { status: 'alive', processStart: start } : { status: 'unprovable' };
      }
      if (platform === 'darwin') {
        const result = runner.run('ps', ['-p', String(pid), '-o', 'lstart=']);
        if (result.status === 1 && !result.stdout.trim()) return { status: 'absent' };
        if (result.status !== 0) return { status: 'unprovable' };
        const normalized = normalizeMacProcessStart(result.stdout);
        return normalized ? { status: 'alive', processStart: normalized } : { status: 'unprovable' };
      }
      return { status: 'unprovable' };
    },
  };
}

export function parseLinuxProcessStart(stat: string): string | undefined {
  const close = stat.lastIndexOf(')');
  if (close < 0) return undefined;
  const fields = stat.slice(close + 1).trim().split(/\s+/);
  const start = fields[19]; // field 22 overall; fields after comm begin at field 3.
  return start && /^\d+$/.test(start) ? start : undefined;
}

export function normalizeMacProcessStart(value: string): string | undefined {
  const normalized = value.trim().replace(/\s+/g, ' ');
  return /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:[1-9]|[12]\d|3[01]) \d{2}:\d{2}:\d{2} \d{4}$/.test(normalized)
    ? normalized
    : undefined;
}

function canRecover(record: OnboardingLockRecord, deps: LockDependencies, staleAgeMs: number): boolean {
  const created = Date.parse(record.createdAt);
  if (!Number.isFinite(created) || deps.now().getTime() - created < staleAgeMs) return false;
  const inspection = deps.inspector.inspect(record.pid);
  if (inspection.status === 'absent') return true;
  if (inspection.status === 'alive') return inspection.processStart !== record.processStart;
  // Especially on macOS, age or PID evidence alone is never enough.
  return false;
}

function readValidatedRecord(path: string, deps: LockDependencies): OnboardingLockRecord {
  try {
    deps.assertSecure(path, deps.uid);
    const record = deps.read(path, deps.uid);
    if (record.schemaVersion !== 1 || !Number.isSafeInteger(record.pid) || record.pid <= 0
      || typeof record.processStart !== 'string' || !record.processStart
      || typeof record.createdAt !== 'string' || !Number.isFinite(Date.parse(record.createdAt))
      || typeof record.ownerToken !== 'string' || !/^[0-9a-f]{32,}$/.test(record.ownerToken)) {
      throw new Error('invalid lock record');
    }
    return record;
  } catch {
    throw lockedError();
  }
}

function resolveLockDependencies(overrides: Partial<LockDependencies>): LockDependencies {
  const required: (keyof LockDependencies)[] = [
    'platform', 'uid', 'pid', 'now', 'ownerToken', 'currentProcessStart', 'inspector',
    'exists', 'read', 'create', 'remove', 'assertSecure',
  ];
  if (required.every((key) => overrides[key] !== undefined)) return overrides as LockDependencies;
  return { ...defaultLockDependencies(), ...overrides };
}

function defaultLockDependencies(): LockDependencies {
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error('Current uid is unavailable');
  const inspector = createProcessInspector(process.platform, new SpawnSyncCommandRunner(), (path) => {
    try {
      return readFileSync(path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      return '';
    }
  });
  const current = inspector.inspect(process.pid);
  if (current.status !== 'alive') throw new Error('Current process start identity is unavailable');
  return {
    platform: process.platform,
    uid,
    pid: process.pid,
    now: () => new Date(),
    ownerToken: () => randomBytes(24).toString('hex'),
    currentProcessStart: () => current.processStart,
    inspector,
    exists: pathHasFilesystemEvidence,
    read: readSecureJson,
    create: writeSecureJsonExclusive,
    remove: removeSecureFile,
    assertSecure: assertSecureFile,
  };
}

function lockedError(): AriavaCliError {
  return new AriavaCliError('ERR_ONBOARDING_LOCKED', 'Another Ariava onboarding process owns the secure lock.', {
    step: 'preflight',
    retryable: true,
    remediation: { message: 'Wait for the other onboarding process to finish, then retry.' },
  });
}
