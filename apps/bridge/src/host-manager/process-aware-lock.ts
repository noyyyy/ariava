import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  assertSecureFile,
  pathHasFilesystemEvidence,
  readSecureJson,
  removeSecureFile,
  writeSecureJsonExclusive,
} from './secure-files';

export const PROCESS_AWARE_LOCK_SCHEMA_VERSION = 1;
export const DEFAULT_STALE_LOCK_AGE_MS = 5 * 60_000;

export interface ProcessAwareLockRecord {
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

export interface ProcessAwareLockDependencies {
  platform: NodeJS.Platform;
  uid: number;
  pid: number;
  now(): Date;
  ownerToken(): string;
  currentProcessStart(): string;
  inspector: ProcessInspector;
  exists(path: string): boolean;
  read(path: string, uid: number): ProcessAwareLockRecord;
  create(path: string, record: ProcessAwareLockRecord, uid: number): void;
  remove(path: string, uid: number): void;
  assertSecure(path: string, uid: number): void;
}

export interface OwnedProcessAwareLock {
  path: string;
  record: ProcessAwareLockRecord;
  release(): void;
}

interface ProcessCommandRunOptions {
  env?: NodeJS.ProcessEnv;
}

interface ProcessCommandRunner {
  run(
    command: string,
    args: string[],
    options?: ProcessCommandRunOptions,
  ): { status: number | null; stdout: string };
}

export function acquireProcessAwareLock(
  path: string,
  lockedError: () => Error,
  dependencies: Partial<ProcessAwareLockDependencies> = {},
  staleAgeMs = DEFAULT_STALE_LOCK_AGE_MS,
): OwnedProcessAwareLock {
  const deps = resolveLockDependencies(dependencies);
  const record: ProcessAwareLockRecord = {
    schemaVersion: PROCESS_AWARE_LOCK_SCHEMA_VERSION,
    pid: deps.pid,
    processStart: deps.currentProcessStart(),
    createdAt: deps.now().toISOString(),
    ownerToken: deps.ownerToken(),
  };

  try {
    deps.create(path, record, deps.uid);
  } catch (error) {
    if (!deps.exists(path)) throw error;
    const existing = readValidatedRecord(path, deps, lockedError);
    if (!canRecover(existing, deps, staleAgeMs)) throw lockedError();
    const rechecked = readValidatedRecord(path, deps, lockedError);
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
      const current = readValidatedRecord(path, deps, lockedError);
      if (current.ownerToken !== record.ownerToken) return;
      deps.remove(path, deps.uid);
      released = true;
    },
  };
}

export function createProcessInspector(
  platform: NodeJS.Platform,
  runner: ProcessCommandRunner,
  readText: (path: string) => string | undefined,
): ProcessInspector {
  return {
    inspect(pid: number): ProcessInspection {
      if (platform === 'linux') {
        const stat = readText(`/proc/${pid}/stat`);
        if (stat === undefined) return { status: 'absent' };
        const start = parseLinuxProcessStart(stat);
        return start ? { status: 'alive', processStart: start } : { status: 'unprovable' };
      }
      if (platform === 'darwin') {
        const result = runner.run('ps', ['-p', String(pid), '-o', 'lstart='], {
          env: { ...process.env, LC_ALL: 'C' },
        });
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
  const start = fields[19];
  return start && /^\d+$/.test(start) ? start : undefined;
}

export function normalizeMacProcessStart(value: string): string | undefined {
  const normalized = value.trim().replace(/\s+/g, ' ');
  return /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:[1-9]|[12]\d|3[01]) \d{2}:\d{2}:\d{2} \d{4}$/.test(normalized)
    ? normalized
    : undefined;
}

function canRecover(record: ProcessAwareLockRecord, deps: ProcessAwareLockDependencies, staleAgeMs: number): boolean {
  const created = Date.parse(record.createdAt);
  if (!Number.isFinite(created) || deps.now().getTime() - created < staleAgeMs) return false;
  const inspection = deps.inspector.inspect(record.pid);
  if (inspection.status === 'absent') return true;
  if (inspection.status === 'alive') return inspection.processStart !== record.processStart;
  return false;
}

function readValidatedRecord(
  path: string,
  deps: ProcessAwareLockDependencies,
  lockedError: () => Error,
): ProcessAwareLockRecord {
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

function resolveLockDependencies(overrides: Partial<ProcessAwareLockDependencies>): ProcessAwareLockDependencies {
  const required: (keyof ProcessAwareLockDependencies)[] = [
    'platform', 'uid', 'pid', 'now', 'ownerToken', 'currentProcessStart', 'inspector',
    'exists', 'read', 'create', 'remove', 'assertSecure',
  ];
  if (required.every((key) => overrides[key] !== undefined)) return overrides as ProcessAwareLockDependencies;
  return { ...defaultLockDependencies(), ...overrides };
}

function defaultLockDependencies(): ProcessAwareLockDependencies {
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error('Current uid is unavailable');
  const inspector = createProcessInspector(process.platform, {
    run(command, args, options) {
      const result = spawnSync(command, args, {
        encoding: 'utf8',
        shell: false,
        env: options?.env,
      });
      return { status: result.status, stdout: result.stdout ?? '' };
    },
  }, (path) => {
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
