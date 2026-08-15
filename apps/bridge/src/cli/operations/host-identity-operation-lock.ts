import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { readSecureJson } from '../../host-manager/secure-files';
import { AriavaCliError } from '../../host-manager/service/errors';
import {
  acquireProcessAwareLock,
  type OwnedProcessAwareLock,
  type ProcessAwareLockDependencies,
} from '../../host-manager/process-aware-lock';
import type { ProfileResourceSet } from '../profile';

export function hostIdentityOperationLockPath(resources: ProfileResourceSet): string {
  return `${resources.hostDomainResetJournalPath}.operation.lock`;
}

const HOST_IDENTITY_OPERATION_LEASE_TYPE: unique symbol = Symbol('HostIdentityOperationLease');

export interface HostIdentityOperationLease {
  readonly [HOST_IDENTITY_OPERATION_LEASE_TYPE]: true;
  assertOwned(): void;
}

interface IssuedLease {
  canonicalLockPath: string;
  resourceDigest: string;
  owned: OwnedProcessAwareLock;
  uid: number | undefined;
  active: boolean;
}

const ISSUED_LEASES = new WeakMap<object, IssuedLease>();

function createHostIdentityOperationLease(
  resources: ProfileResourceSet,
  owned: OwnedProcessAwareLock,
  uid: number | undefined,
): HostIdentityOperationLease {
  const lease: HostIdentityOperationLease = Object.freeze({
    [HOST_IDENTITY_OPERATION_LEASE_TYPE]: true,
    assertOwned() {
      assertHostIdentityOperationLeaseOwned(lease, resources);
    },
  });
  ISSUED_LEASES.set(lease, {
    canonicalLockPath: canonicalOperationLockPath(resources),
    resourceDigest: profileResourceFingerprint(resources),
    owned,
    uid,
    active: true,
  });
  return lease;
}

export function assertHostIdentityOperationLeaseOwned(
  lease: HostIdentityOperationLease,
  resources: ProfileResourceSet,
): void {
  if ((typeof lease !== 'object' && typeof lease !== 'function') || lease === null) {
    throw hostIdentityLeaseLostError();
  }
  const issued = ISSUED_LEASES.get(lease);
  if (!issued?.active
    || issued.canonicalLockPath !== canonicalOperationLockPath(resources)
    || issued.resourceDigest !== profileResourceFingerprint(resources)) {
    throw hostIdentityLeaseLostError();
  }
  let current: { ownerToken?: unknown };
  try {
    current = readSecureJson<{ ownerToken?: unknown }>(issued.owned.path, issued.uid);
  } catch {
    throw hostIdentityLeaseLostError();
  }
  if (current.ownerToken !== issued.owned.record.ownerToken) throw hostIdentityLeaseLostError();
}

export async function withHostIdentityOperationLock<T>(
  resources: ProfileResourceSet,
  run: (lease: HostIdentityOperationLease) => Promise<T>,
  dependencies: Partial<ProcessAwareLockDependencies> = {},
): Promise<T> {
  const lock = acquireProcessAwareLock(
    hostIdentityOperationLockPath(resources),
    hostIdentityTransitionLockedError,
    dependencies,
  );
  const lease = createHostIdentityOperationLease(
    resources,
    lock,
    dependencies.uid ?? process.getuid?.(),
  );
  try {
    return await run(lease);
  } finally {
    const issued = ISSUED_LEASES.get(lease);
    if (issued) issued.active = false;
    lock.release();
  }
}

function profileResourceFingerprint(resources: ProfileResourceSet): string {
  const canonicalEntries = Object.entries(resources)
    .sort(([left], [right]) => left.localeCompare(right));
  return createHash('sha256').update(JSON.stringify(canonicalEntries)).digest('hex');
}

function canonicalOperationLockPath(resources: ProfileResourceSet): string {
  return resolve(hostIdentityOperationLockPath(resources));
}

function hostIdentityLeaseLostError(): AriavaCliError {
  return new AriavaCliError(
    'ERR_HOST_RESET_LEASE_LOST',
    'Host identity operation lease is no longer held.',
    { retryable: true, remediation: { message: 'Retry the Host reset command to resume recovery.' } },
  );
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
