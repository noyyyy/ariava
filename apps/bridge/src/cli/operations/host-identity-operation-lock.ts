import { AriavaCliError } from '../../host-manager/service/errors';
import {
  acquireProcessAwareLock,
  type ProcessAwareLockDependencies,
} from '../../host-manager/process-aware-lock';
import type { ProfileResourceSet } from '../profile';

export function hostIdentityOperationLockPath(resources: ProfileResourceSet): string {
  return `${resources.hostDomainResetJournalPath}.operation.lock`;
}

export async function withHostIdentityOperationLock<T>(
  resources: ProfileResourceSet,
  run: () => Promise<T>,
  dependencies: Partial<ProcessAwareLockDependencies> = {},
): Promise<T> {
  const lock = acquireProcessAwareLock(
    hostIdentityOperationLockPath(resources),
    hostIdentityTransitionLockedError,
    dependencies,
  );
  try {
    return await run();
  } finally {
    lock.release();
  }
}

function hostIdentityTransitionLockedError(): AriavaCliError {
  return new AriavaCliError(
    'ERR_HOST_RESET_IN_PROGRESS',
    'Another Host identity transition is already in progress for this profile.',
    {
      retryable: true,
      remediation: { message: 'Wait for the active Host reset or key rotation to finish, then retry.' },
    },
  );
}
