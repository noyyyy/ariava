import type { HostIdentity } from '../../identity';
import { AriavaCliError } from '../../host-manager/service/errors';
import {
  acquireProcessAwareLock,
  type ProcessAwareLockDependencies,
} from '../../host-manager/process-aware-lock';
import {
  pathHasFilesystemEvidence,
  readSecureJson,
  removeSecureFileIfPresent,
  writeSecureJson,
  writeSecureJsonExclusive,
  type SecureFileRemoveHooks,
  type SecureFileWriteHooks,
} from '../../host-manager/secure-files';
import type { ProfileResourceSet } from '../profile';
import {
  encodeHostDomainResetJournal,
  parseHostDomainResetJournal,
  type HostDomainResetJournalV1,
} from './host-domain-reset-journal-schema';
import {
  applyHostDomainResetTransition,
  hostResetJournalViolationMessage,
  validateHostDomainResetTransition,
  type HostDomainResetTransition,
} from './host-domain-reset-journal-policy';
import {
  assertHostIdentityOperationLeaseOwned,
  type HostIdentityOperationLease,
} from './host-identity-operation-lock';

export interface HostDomainResetJournalStoreOptions {
  uid?: number;
  hooks?: SecureFileWriteHooks;
  lockDependencies?: Partial<ProcessAwareLockDependencies>;
  now?: () => Date;
}

export function loadHostDomainResetJournal(
  resources: ProfileResourceSet,
  uid?: number,
): HostDomainResetJournalV1 | null {
  const path = resources.hostDomainResetJournalPath;
  if (!pathHasFilesystemEvidence(path)) return null;
  let value: unknown;
  try {
    value = readSecureJson<unknown>(path, uid);
  } catch (error) {
    throw new TypeError('Host-domain reset journal could not be read securely', { cause: error });
  }
  return parseHostDomainResetJournal(value, resources);
}

export function createHostDomainResetJournal(
  resources: ProfileResourceSet,
  initial: HostDomainResetJournalV1,
  operationLease: HostIdentityOperationLease,
  options: HostDomainResetJournalStoreOptions = {},
): HostDomainResetJournalV1 {
  if (initial.phase !== 'quarantine-pending') {
    throw new TypeError('Host-domain reset journal must be created in quarantine-pending');
  }
  const validated = parseHostDomainResetJournal(initial, resources);
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  writeSecureJsonExclusive(resources.hostDomainResetJournalPath, validated, options.uid, {
    ...options.hooks,
    beforePromotion() {
      options.hooks?.beforePromotion?.();
      assertHostIdentityOperationLeaseOwned(operationLease, resources);
    },
  });
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  return validated;
}

export function advanceHostDomainResetJournal(
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
  transition: HostDomainResetTransition,
  operationLease: HostIdentityOperationLease,
  options: HostDomainResetJournalStoreOptions = {},
): HostDomainResetJournalV1 {
  const lock = acquireJournalAdvancementLock(resources, options.uid, options.lockDependencies);
  try {
    const stored = loadHostDomainResetJournal(resources, options.uid);
    if (!stored || JSON.stringify(stored) !== JSON.stringify(current)) {
      throw new TypeError('Host-domain reset journal changed before advancement');
    }
    const updatedAt = (options.now ?? (() => new Date()))().toISOString();
    const candidate = parseHostDomainResetJournal(
      applyHostDomainResetTransition(stored, transition, updatedAt),
      resources,
    );
    const validation = validateHostDomainResetTransition(stored, candidate);
    if (!validation.ok) throw new TypeError(hostResetJournalViolationMessage(validation.reason));
    assertHostIdentityOperationLeaseOwned(operationLease, resources);
    writeSecureJson(resources.hostDomainResetJournalPath, validation.journal, options.uid, {
      ...options.hooks,
      beforePromotion() {
        options.hooks?.beforePromotion?.();
        lock.assertOwned();
        assertHostIdentityOperationLeaseOwned(operationLease, resources);
      },
    });
    return validation.journal;
  } finally {
    lock.release();
  }
}

interface RestoreConfirmationPayload {
  operationId: string;
  journalDigest: string;
  service: HostDomainResetJournalV1['service'];
  replacementHostId: string;
  replacementKeyId: string;
  identityReference: HostIdentity['privateKeyStorage'];
  restoreReturn: boolean;
}

declare const RESTORE_CONFIRMATION_TYPE: unique symbol;

export interface RestoreConfirmation {
  readonly [RESTORE_CONFIRMATION_TYPE]: true;
}

const CONFIRMATIONS = new WeakMap<object, RestoreConfirmationPayload>();

/**
 * Recovery-only restore seam. The caller must already have completed fresh
 * rehydration, re-quarantine, replacement-domain validation, and runtime
 * ownership release. This operation independently binds the replacement
 * identity/reference, invokes restore, and only then issues an in-process
 * single-use confirmation.
 */
export function restoreHostDomainServiceAndConfirm(
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
  operationLease: HostIdentityOperationLease,
  replacement: HostIdentity,
  restoreAndConfirm: (
    snapshot: HostDomainResetJournalV1['service'],
    identityReference: HostIdentity['privateKeyStorage'],
  ) => boolean,
  options: Pick<HostDomainResetJournalStoreOptions, 'uid'> = {},
): { processRunning: boolean; confirmation: RestoreConfirmation } {
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  if (current.phase !== 'service-restore-pending') {
    throw new TypeError('Host-domain reset service restoration requires service-restore-pending');
  }
  const stored = loadHostDomainResetJournal(resources, options.uid);
  if (!stored || JSON.stringify(stored) !== JSON.stringify(current)) {
    throw new AriavaCliError(
      'ERR_HOST_RESET_REMOVE_STALE_JOURNAL',
      'Host-domain reset journal changed before service restoration.',
      { retryable: true, remediation: { message: 'Re-run the Host reset recovery sequence from the current journal.' } },
    );
  }
  assertReplacementIdentity(resources, current, replacement);
  const identityReference = structuredClone(replacement.privateKeyStorage);
  const processRunning = restoreAndConfirm(current.service, identityReference);
  if (typeof processRunning !== 'boolean') throw invalidConfirmation();
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  const confirmation = Object.freeze({}) as RestoreConfirmation;
  CONFIRMATIONS.set(confirmation, {
    operationId: current.operationId,
    journalDigest: encodeHostDomainResetJournal(current, resources),
    service: structuredClone(current.service),
    replacementHostId: replacement.hostId,
    replacementKeyId: replacement.keyId,
    identityReference,
    restoreReturn: processRunning,
  });
  return { processRunning, confirmation };
}

export function removeAfterServiceRestoreConfirmed(
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
  operationLease: HostIdentityOperationLease,
  confirmation: RestoreConfirmation,
  options: { uid?: number; hooks?: SecureFileRemoveHooks } = {},
): void {
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  if (current.phase !== 'service-restore-pending') {
    throw new AriavaCliError(
      'ERR_HOST_RESET_REMOVE_WRONG_PHASE',
      `Host-domain reset journal is at phase ${current.phase}; guarded removal requires service-restore-pending.`,
      { retryable: false },
    );
  }
  const stored = loadHostDomainResetJournal(resources, options.uid);
  if (!stored || JSON.stringify(stored) !== JSON.stringify(current)) {
    throw new AriavaCliError(
      'ERR_HOST_RESET_REMOVE_STALE_JOURNAL',
      'Host-domain reset journal changed before guarded removal.',
      { retryable: true, remediation: { message: 'Re-run the Host reset recovery sequence from the current journal.' } },
    );
  }
  consumeRestoreConfirmation(confirmation, stored, resources);
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  removeSecureFileIfPresent(resources.hostDomainResetJournalPath, options.uid, {
    ...options.hooks,
    beforeUnlink(path) {
      options.hooks?.beforeUnlink?.(path);
      assertHostIdentityOperationLeaseOwned(operationLease, resources);
    },
  });
}

function consumeRestoreConfirmation(
  confirmation: RestoreConfirmation,
  stored: HostDomainResetJournalV1,
  resources: ProfileResourceSet,
): RestoreConfirmationPayload {
  if ((typeof confirmation !== 'object' && typeof confirmation !== 'function') || confirmation === null) {
    throw forgedConfirmation();
  }
  const payload = CONFIRMATIONS.get(confirmation);
  if (!payload) throw forgedConfirmation();
  if (payload.operationId !== stored.operationId) throw removalBindingError('ERR_HOST_RESET_REMOVE_WRONG_OPERATION');
  if (payload.journalDigest !== encodeHostDomainResetJournal(stored, resources)) {
    throw removalBindingError('ERR_HOST_RESET_REMOVE_STALE_JOURNAL');
  }
  if (JSON.stringify(payload.service) !== JSON.stringify(stored.service)) {
    throw removalBindingError('ERR_HOST_RESET_REMOVE_WRONG_SERVICE');
  }
  if (payload.replacementHostId !== stored.newHostId || payload.replacementKeyId !== stored.newKeyId
    || !isExactIdentityReference(resources, stored.newHostId, payload.identityReference)
    || typeof payload.restoreReturn !== 'boolean') {
    throw removalBindingError('ERR_HOST_RESET_REMOVE_WRONG_IDENTITY');
  }
  CONFIRMATIONS.delete(confirmation);
  return payload;
}

function assertReplacementIdentity(
  resources: ProfileResourceSet,
  journal: HostDomainResetJournalV1,
  replacement: HostIdentity,
): void {
  if (replacement.hostId !== journal.newHostId || replacement.keyId !== journal.newKeyId
    || !isExactIdentityReference(resources, replacement.hostId, replacement.privateKeyStorage)) {
    throw removalBindingError('ERR_HOST_RESET_REMOVE_WRONG_IDENTITY');
  }
}

function isExactIdentityReference(
  resources: ProfileResourceSet,
  hostId: string | null,
  reference: HostIdentity['privateKeyStorage'],
): boolean {
  if (reference.type === 'linux-json') return reference.path === resources.identityMetadataPath;
  return hostId !== null
    && reference.service === 'io.noyx.ariava.host-identity'
    && reference.account === hostId;
}

function forgedConfirmation(): AriavaCliError {
  return new AriavaCliError(
    'ERR_HOST_RESET_CONFIRMATION_FORGED',
    'Host restore confirmation is forged, reused, or unrecognized.',
    { retryable: false, remediation: { message: 'Re-run the Host reset recovery to obtain a fresh confirmation.' } },
  );
}

function removalBindingError(code:
  | 'ERR_HOST_RESET_REMOVE_WRONG_OPERATION'
  | 'ERR_HOST_RESET_REMOVE_STALE_JOURNAL'
  | 'ERR_HOST_RESET_REMOVE_WRONG_SERVICE'
  | 'ERR_HOST_RESET_REMOVE_WRONG_IDENTITY'
): AriavaCliError {
  return new AriavaCliError(code, 'Host restore confirmation does not match the current reset journal.', { retryable: false });
}

function invalidConfirmation(): TypeError {
  return new TypeError('Host-domain reset journal restore confirmation is invalid');
}

interface JournalAdvancementLock {
  assertOwned(): void;
  release(): void;
}

function acquireJournalAdvancementLock(
  resources: ProfileResourceSet,
  uid?: number,
  dependencies: Partial<ProcessAwareLockDependencies> = {},
): JournalAdvancementLock {
  const owned = acquireProcessAwareLock(
    `${resources.hostDomainResetJournalPath}.advance.lock`,
    journalAdvancementLockedError,
    { ...(uid === undefined ? {} : { uid }), ...dependencies },
  );
  return {
    assertOwned() {
      const current = readSecureJson<{ ownerToken?: unknown }>(owned.path, uid);
      if (current.ownerToken !== owned.record.ownerToken) {
        throw new TypeError('Host-domain reset journal advancement lock changed or is unsafe');
      }
    },
    release: () => owned.release(),
  };
}

function journalAdvancementLockedError(): AriavaCliError {
  return new AriavaCliError('ERR_ONBOARDING_LOCKED', 'Another Ariava onboarding process owns the secure lock.', {
    step: 'preflight',
    retryable: true,
    remediation: { message: 'Wait for the other onboarding process to finish, then retry.' },
  });
}
