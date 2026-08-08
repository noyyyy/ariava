import { randomBytes } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import {
  assertSecureFile,
  pathHasFilesystemEvidence,
  readSecureFile,
  removeSecureFile,
  writeSecureJsonExclusive,
} from './host-manager/secure-files';

type ProcessInspection = { status: 'alive'; processStart: string } | { status: 'absent' } | { status: 'unprovable' };
interface ProcessInspector { inspect(pid: number): ProcessInspection }

export const RUNTIME_LOCK_SCHEMA_VERSION = 1 as const;
export const RUNTIME_COORDINATOR_ACTIVE_ERROR = 'Another Ariava Bridge state coordinator owns the runtime lock for this path';

export interface RuntimeLockRecord {
  schemaVersion: 1;
  pid: number;
  processStart: string;
  createdAt: string;
  ownerToken: string;
}

export interface RuntimeLockHooks {
  beforeTakeoverMutexAcquire?(): void;
  afterTakeoverMutexAcquired?(path: string): void;
  afterStaleMainLockValidated?(path: string): void;
  afterMainLockRemoved?(path: string): void;
  afterMainLockCreated?(path: string): void;
  beforeTakeoverMutexCleanup?(): void;
}

export interface RuntimeLockDependencies {
  uid: number;
  pid: number;
  now(): Date;
  ownerToken(): string;
  currentProcessStart(): string;
  inspector: ProcessInspector;
  hooks?: RuntimeLockHooks;
}

export interface OwnedRuntimeLock {
  path: string;
  record: RuntimeLockRecord;
  assertOwned(): void;
  release(): void;
}

interface LockSnapshot {
  bytes: Buffer;
  device: number;
  inode: number;
  record: RuntimeLockRecord;
}

interface TakeoverMutex {
  owned: LockSnapshot;
  staleAncestors: Array<{ path: string; snapshot: LockSnapshot }>;
}

export interface RuntimeCoordinator {
  readonly statePath?: string;
  readonly spoolPath?: string;
  assertOwned(): void;
  claimStateWriter(): () => void;
  dispose(): void;
}

const PROCESS_RUNTIME_COORDINATORS = new Map<string, RuntimeCoordinator>();

export function runtimeLockPathForState(statePath: string): string {
  return `${statePath}.runtime.lock`;
}

export function runtimeTakeoverMutexPathForState(statePath: string): string {
  return `${runtimeLockPathForState(statePath)}.takeover`;
}

export function acquireRuntimeLock(
  statePath: string,
  overrides: Partial<RuntimeLockDependencies> = {},
): OwnedRuntimeLock {
  const path = runtimeLockPathForState(statePath);
  const mutexPath = runtimeTakeoverMutexPathForState(statePath);
  const dependencies = resolveDependencies(overrides);
  const record = createLockRecord(dependencies);

  if (!pathHasFilesystemEvidence(mutexPath)) {
    try {
      writeSecureJsonExclusive(path, record, dependencies.uid);
      return ownedRuntimeLock(path, mutexPath, readSnapshot(path, dependencies.uid), dependencies);
    } catch (error) {
      if (!pathHasFilesystemEvidence(path) && !pathHasFilesystemEvidence(mutexPath)) throw error;
    }
  }

  dependencies.hooks?.beforeTakeoverMutexAcquire?.();
  const mutex = acquireTakeoverMutex(mutexPath, dependencies);
  let created: LockSnapshot | undefined;
  try {
    dependencies.hooks?.afterTakeoverMutexAcquired?.(mutexPathForOwned(mutexPath, mutex));
    if (pathHasFilesystemEvidence(path)) {
      const staleMain = readSnapshot(path, dependencies.uid);
      if (!isDemonstrablyDead(staleMain.record, dependencies.inspector)) throw lockedError();
      dependencies.hooks?.afterStaleMainLockValidated?.(path);
      assertSnapshot(path, staleMain, dependencies.uid);
      assertSnapshot(mutexPathForOwned(mutexPath, mutex), mutex.owned, dependencies.uid);
      removeSecureFile(path, dependencies.uid);
      dependencies.hooks?.afterMainLockRemoved?.(path);
    }
    assertSnapshot(mutexPathForOwned(mutexPath, mutex), mutex.owned, dependencies.uid);
    writeSecureJsonExclusive(path, record, dependencies.uid);
    dependencies.hooks?.afterMainLockCreated?.(path);
    assertSnapshot(mutexPathForOwned(mutexPath, mutex), mutex.owned, dependencies.uid);
    created = readSnapshot(path, dependencies.uid);
    if (!sameOwner(created.record, record)) throw lockedError();
  } catch (error) {
    throw error instanceof Error && error.message === lockedError().message ? error : lockedError();
  } finally {
    dependencies.hooks?.beforeTakeoverMutexCleanup?.();
    cleanupTakeoverMutex(mutexPath, mutex, dependencies.uid);
  }

  if (!created) throw lockedError();
  return ownedRuntimeLock(path, mutexPath, created, dependencies);
}

export function acquireRuntimeCoordinator(statePath?: string, spoolPath?: string): RuntimeCoordinator {
  if (!statePath) return memoryRuntimeCoordinator();
  const canonicalStatePath = canonicalRuntimePath(statePath);
  const canonicalSpoolPath = canonicalRuntimePath(spoolPath ?? `${statePath}.spool.json`);
  const key = `${canonicalStatePath}\0${canonicalSpoolPath}`;
  if (PROCESS_RUNTIME_COORDINATORS.has(key)) throw coordinatorError();

  const lock = acquireRuntimeLock(statePath);
  let disposed = false;
  let stateWriterClaimed = false;
  const coordinator: RuntimeCoordinator = {
    statePath: canonicalStatePath,
    spoolPath: canonicalSpoolPath,
    assertOwned() {
      if (disposed) throw coordinatorError();
      lock.assertOwned();
    },
    claimStateWriter() {
      if (disposed || stateWriterClaimed) throw coordinatorError();
      stateWriterClaimed = true;
      let released = false;
      return () => {
        if (released || disposed) return;
        released = true;
        stateWriterClaimed = false;
      };
    },
    dispose() {
      if (disposed) return;
      lock.release();
      if (PROCESS_RUNTIME_COORDINATORS.get(key) !== coordinator) throw coordinatorError();
      PROCESS_RUNTIME_COORDINATORS.delete(key);
      stateWriterClaimed = false;
      disposed = true;
    },
  };
  PROCESS_RUNTIME_COORDINATORS.set(key, coordinator);
  return coordinator;
}

export function assertRuntimeWriterAllowed(coordinator: RuntimeCoordinator): void {
  coordinator.assertOwned();
}

export function assertRuntimeCoordinatorPaths(
  coordinator: RuntimeCoordinator, statePath?: string, spoolPath?: string,
 ): void {
  if (!statePath) {
    if (coordinator.statePath !== undefined || coordinator.spoolPath !== undefined) throw coordinatorError();
    return;
  }
  if (coordinator.statePath === undefined || coordinator.spoolPath === undefined
    || coordinator.statePath !== canonicalRuntimePath(statePath)
    || coordinator.spoolPath !== canonicalRuntimePath(spoolPath ?? `${statePath}.spool.json`)) {
    throw coordinatorError();
  }
}

function memoryRuntimeCoordinator(): RuntimeCoordinator {
  let disposed = false;
  let stateWriterClaimed = false;
  return {
    assertOwned() { if (disposed) throw coordinatorError(); },
    claimStateWriter() {
      if (disposed || stateWriterClaimed) throw coordinatorError();
      stateWriterClaimed = true;
      let released = false;
      return () => {
        if (released || disposed) return;
        released = true;
        stateWriterClaimed = false;
      };
    },
    dispose() { disposed = true; stateWriterClaimed = false; },
  };
}

function canonicalRuntimePath(path: string): string {
  let candidate = resolve(path);
  const missing: string[] = [];
  for (;;) {
    try {
      const canonicalAncestor = realpathSync.native(candidate);
      return resolve(canonicalAncestor, ...missing.reverse());
    } catch (error) {
      const parent = dirname(candidate);
      if (parent === candidate) throw error;
      missing.push(basename(candidate));
      candidate = parent;
    }
  }
}

function ownedRuntimeLock(
  path: string, mutexPath: string, owned: LockSnapshot, dependencies: RuntimeLockDependencies,
): OwnedRuntimeLock {
  const record = owned.record;
  let released = false;
  const assertOwned = (): void => {
    if (released) throw lockedError();
    assertSnapshot(path, owned, dependencies.uid);
  };
  return {
    path,
    record,
    assertOwned,
    release() {
      if (released) return;
      const mutex = acquireTakeoverMutex(mutexPath, dependencies);
      try {
        assertOwned();
        assertSnapshot(mutexPathForOwned(mutexPath, mutex), mutex.owned, dependencies.uid);
        removeSecureFile(path, dependencies.uid);
        released = true;
      } finally {
        cleanupTakeoverMutex(mutexPath, mutex, dependencies.uid);
      }
    },
  };
}

function acquireTakeoverMutex(basePath: string, dependencies: RuntimeLockDependencies): TakeoverMutex {
  const staleAncestors: Array<{ path: string; snapshot: LockSnapshot }> = [];
  let path = basePath;
  for (;;) {
    const record = createLockRecord(dependencies);
    try {
      writeSecureJsonExclusive(path, record, dependencies.uid);
      return { owned: readSnapshot(path, dependencies.uid), staleAncestors };
    } catch {
      if (!pathHasFilesystemEvidence(path)) throw lockedError();
      const existing = readSnapshot(path, dependencies.uid);
      if (!isDemonstrablyDead(existing.record, dependencies.inspector)) throw lockedError();
      assertSnapshot(path, existing, dependencies.uid);
      staleAncestors.push({ path, snapshot: existing });
      path = takeoverSuccessorPath(basePath, staleAncestors.length);
    }
  }
}

function cleanupTakeoverMutex(basePath: string, mutex: TakeoverMutex, uid: number): void {
  // Recovered stale ancestors are immutable serialization sentinels. Removing them would permit
  // a new base-path claimant to overlap the current successor generation (an ABA window).
  removeSnapshotIfCurrent(mutexPathForOwned(basePath, mutex), mutex.owned, uid);
}

function mutexPathForOwned(basePath: string, mutex: TakeoverMutex): string {
  return takeoverSuccessorPath(basePath, mutex.staleAncestors.length);
}

function takeoverSuccessorPath(basePath: string, generation: number): string {
  return generation === 0 ? basePath : `${basePath}.${generation}`;
}

function removeSnapshotIfCurrent(path: string, snapshot: LockSnapshot, uid: number): void {
  try {
    assertSnapshot(path, snapshot, uid);
    removeSecureFile(path, uid);
  } catch {
    // Cleanup never removes evidence that is no longer the exact mutex generation we owned or recovered.
  }
}

function readSnapshot(path: string, uid: number): LockSnapshot {
  try {
    assertSecureFile(path, uid);
    const before = lstatSync(path);
    const bytes = readSecureFile(path, uid);
    const after = lstatSync(path);
    if (before.dev !== after.dev || before.ino !== after.ino || before.isSymbolicLink() || !before.isFile()) {
      throw new Error('runtime lock changed while reading');
    }
    return { bytes, device: after.dev, inode: after.ino, record: parseRecord(bytes) };
  } catch {
    throw lockedError();
  }
}

function assertSnapshot(path: string, expected: LockSnapshot, uid: number): void {
  const current = readSnapshot(path, uid);
  if (current.device !== expected.device || current.inode !== expected.inode
    || !current.bytes.equals(expected.bytes) || current.record.ownerToken !== expected.record.ownerToken) {
    throw lockedError();
  }
}

function parseRecord(bytes: Buffer): RuntimeLockRecord {
  const value = JSON.parse(bytes.toString('utf8')) as RuntimeLockRecord;
  if (value.schemaVersion !== 1 || !Number.isSafeInteger(value.pid) || value.pid <= 0
    || typeof value.processStart !== 'string' || !value.processStart
    || typeof value.createdAt !== 'string' || !Number.isFinite(Date.parse(value.createdAt))
    || typeof value.ownerToken !== 'string' || !/^[0-9a-f]{48}$/u.test(value.ownerToken)) {
    throw new Error('invalid runtime lock');
  }
  return value;
}

function createLockRecord(dependencies: RuntimeLockDependencies): RuntimeLockRecord {
  return {
    schemaVersion: RUNTIME_LOCK_SCHEMA_VERSION,
    pid: dependencies.pid,
    processStart: dependencies.currentProcessStart(),
    createdAt: dependencies.now().toISOString(),
    ownerToken: dependencies.ownerToken(),
  };
}

function sameOwner(left: RuntimeLockRecord, right: RuntimeLockRecord): boolean {
  return left.ownerToken === right.ownerToken && left.pid === right.pid && left.processStart === right.processStart;
}

function isDemonstrablyDead(record: RuntimeLockRecord, inspector: ProcessInspector): boolean {
  const inspection = inspector.inspect(record.pid);
  return inspection.status === 'absent'
    || (inspection.status === 'alive' && inspection.processStart !== record.processStart);
}

function resolveDependencies(overrides: Partial<RuntimeLockDependencies>): RuntimeLockDependencies {
  const required: (keyof RuntimeLockDependencies)[] = [
    'uid', 'pid', 'now', 'ownerToken', 'currentProcessStart', 'inspector',
  ];
  return required.every((key) => overrides[key] !== undefined)
    ? overrides as RuntimeLockDependencies
    : { ...defaultDependencies(), ...overrides };
}

function defaultDependencies(): RuntimeLockDependencies {
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error('Current uid is unavailable');
  const inspector = createRuntimeProcessInspector();
  const current = inspector.inspect(process.pid);
  if (current.status !== 'alive') throw new Error('Current process start identity is unavailable');
  return {
    uid,
    pid: process.pid,
    now: () => new Date(),
    ownerToken: () => randomBytes(24).toString('hex'),
    currentProcessStart: () => current.processStart,
    inspector,
  };
}

function createRuntimeProcessInspector(): ProcessInspector {
  return {
    inspect(pid: number): ProcessInspection {
      if (process.platform === 'linux') {
        let stat: string;
        try { stat = readFileSync(`/proc/${pid}/stat`, 'utf8'); }
        catch (error) { return (error as NodeJS.ErrnoException).code === 'ENOENT' ? { status: 'absent' } : { status: 'unprovable' }; }
        const close = stat.lastIndexOf(')');
        const start = close < 0 ? undefined : stat.slice(close + 1).trim().split(/\s+/)[19];
        return start && /^\d+$/u.test(start) ? { status: 'alive', processStart: start } : { status: 'unprovable' };
      }
      if (process.platform === 'darwin') {
        const childProcess = process.getBuiltinModule('node:child_process') as typeof import('node:child_process');
        const result = childProcess.spawnSync('ps', ['-p', String(pid), '-o', 'lstart='], { encoding: 'utf8', shell: false });
        if (result.status === 1 && !result.stdout.trim()) return { status: 'absent' };
        if (result.status !== 0) return { status: 'unprovable' };
        const normalized = result.stdout.trim().replace(/\s+/g, ' ');
        return /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:[1-9]|[12]\d|3[01]) \d{2}:\d{2}:\d{2} \d{4}$/u.test(normalized)
          ? { status: 'alive', processStart: normalized } : { status: 'unprovable' };
      }
      return { status: 'unprovable' };
    },
  };
}

function lockedError(): Error {
  return new Error('Another Ariava Bridge runtime owns the secure runtime lock');
}
function coordinatorError(): Error {
  return new Error(RUNTIME_COORDINATOR_ACTIVE_ERROR);
}
