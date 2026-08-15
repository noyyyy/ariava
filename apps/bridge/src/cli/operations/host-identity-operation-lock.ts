import { resolve } from 'node:path';
import { AriavaCliError } from '../../host-manager/service/errors';
import {
  acquireProcessAwareLock,
  type ProcessAwareLockDependencies,
} from '../../host-manager/process-aware-lock';
import { readSecureJson } from '../../host-manager/secure-files';
import type { ProfileResourceSet } from '../profile';

/**
 * Opaque ownership proof for the Host identity operation lock. Only
 * `withHostIdentityOperationLock` constructs leases; callers receive one in
 * the callback and can only ask `assertOwned()`. The lease stays live from
 * before the journal is loaded/created until guarded removal completes, and
 * it cannot be forged with a boolean flag or an empty `assertOwned()`.
 */
export interface HostIdentityOperationLease {
  assertOwned(): void;
}

interface HostIdentityOperationLeasePayload {
  canonicalLockPath: string;
  assertOwned(): void;
}

const LEASE_PAYLOADS = new WeakMap<object, HostIdentityOperationLeasePayload>();

export function hostIdentityOperationLockPath(resources: ProfileResourceSet): string {
  return `${resources.hostDomainResetJournalPath}.operation.lock`;
}

export async function withHostIdentityOperationLock<T>(
  resources: ProfileResourceSet,
  run: (lease: HostIdentityOperationLease) => Promise<T>,
  dependencies: Partial<ProcessAwareLockDependencies> = {},
): Promise<T> {
  const canonicalLockPath = canonicalHostIdentityOperationLockPath(resources);
  const lock = acquireProcessAwareLock(
    canonicalLockPath,
    hostIdentityTransitionLockedError,
    dependencies,
  );
  const lease: HostIdentityOperationLease = {
    assertOwned() {
      assertHostIdentityOperationLeaseOwned(lease, canonicalLockPath);
    },
  };
  LEASE_PAYLOADS.set(lease, {
    canonicalLockPath,
    assertOwned() {
      const current = readSecureJson<{ ownerToken?: unknown }>(lock.path, dependencies.uid);
      if (current.ownerToken !== lock.record.ownerToken) {
        throw new TypeError('Host identity operation lock changed or is unsafe');
      }
    },
  });
  try {
    return await run(lease);
  } finally {
    lock.release();
  }
}

export function assertHostIdentityOperationLeaseOwned(
  lease: HostIdentityOperationLease,
  expectedResourcesOrCanonicalLockPath: ProfileResourceSet | string,
): void {
  if ((typeof lease !== 'object' && typeof lease !== 'function') || lease === null) {
    throw invalidHostIdentityOperationLease();
  }
  const payload = LEASE_PAYLOADS.get(lease);
  if (!payload) throw invalidHostIdentityOperationLease();
  const expectedCanonicalLockPath = typeof expectedResourcesOrCanonicalLockPath === 'string'
    ? resolve(expectedResourcesOrCanonicalLockPath)
    : canonicalHostIdentityOperationLockPath(expectedResourcesOrCanonicalLockPath);
  if (payload.canonicalLockPath !== expectedCanonicalLockPath) {
    throw invalidHostIdentityOperationLease();
  }
  payload.assertOwned();
}

function canonicalHostIdentityOperationLockPath(resources: ProfileResourceSet): string {
  return resolve(hostIdentityOperationLockPath(resources));
}

function hostIdentityTransitionLockedError(): AriavaCliError {
  return new AriavaCliError(
    'ERR_HOST_RESET_IN_PROGRESS',
    'Another Host identity transition is already in progress for this profile.',
    {
      retryable: true,
      remediation: { message: 'Wait for the active Host identity reset to finish, then retry.' },
    },
  );
}

function invalidHostIdentityOperationLease(): TypeError {
  return new TypeError('Host identity operation lease is invalid or unsafe');
}
