import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { AriavaCliError } from '../service/errors';
import {
  acquireProcessAwareLock,
  createProcessInspector,
  normalizeMacProcessStart,
  parseLinuxProcessStart,
  DEFAULT_STALE_LOCK_AGE_MS,
  PROCESS_AWARE_LOCK_SCHEMA_VERSION,
  type OwnedProcessAwareLock,
  type ProcessAwareLockDependencies,
  type ProcessAwareLockRecord,
  type ProcessInspection,
  type ProcessInspector,
} from '../process-aware-lock';

export {
  createProcessInspector,
  normalizeMacProcessStart,
  parseLinuxProcessStart,
  DEFAULT_STALE_LOCK_AGE_MS,
};
export const ONBOARDING_LOCK_SCHEMA_VERSION = PROCESS_AWARE_LOCK_SCHEMA_VERSION;
export type OnboardingLockRecord = ProcessAwareLockRecord;
export type LockDependencies = ProcessAwareLockDependencies;
export type OwnedOnboardingLock = OwnedProcessAwareLock;
export type { ProcessInspection, ProcessInspector };

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
  return acquireProcessAwareLock(path, lockedError, dependencies, staleAgeMs);
}

export async function withOnboardingLock<T>(
  path: string,
  run: () => Promise<T>,
  dependencies: Partial<LockDependencies> = {},
): Promise<T> {
  const lock = acquireOnboardingLock(path, dependencies);
  try {
    return await run();
  } finally {
    lock.release();
  }
}

function lockedError(): AriavaCliError {
  return new AriavaCliError('ERR_ONBOARDING_LOCKED', 'Another Ariava onboarding process owns the secure lock.', {
    step: 'preflight',
    retryable: true,
    remediation: { message: 'Wait for the other onboarding process to finish, then retry.' },
  });
}
