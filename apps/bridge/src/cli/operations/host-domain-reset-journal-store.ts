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
import type { HostPrivateKeyStorage } from '../../identity/types';
import type { ProfileResourceSet } from '../profile';
import {
  assertHostIdentityOperationLeaseOwned,
  type HostIdentityOperationLease,
} from './host-identity-operation-lock';
import {
  canonicalJournalDigest,
  encodeHostDomainResetJournal,
  parseHostDomainResetJournal,
  type HostDomainResetJournalV1,
} from './host-domain-reset-journal-schema';
import {
  applyHostDomainResetJournalTransition,
  validateInitialJournal,
  type HostDomainResetJournalTransition,
  type HostResetJournalViolation,
} from './host-domain-reset-journal-policy';

export interface HostDomainResetJournalStoreOptions {
  uid?: number;
  writeHooks?: SecureFileWriteHooks;
  removeHooks?: SecureFileRemoveHooks;
  lockDependencies?: Partial<ProcessAwareLockDependencies>;
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

/**
 * Exclusive create of a `quarantine-pending` journal. Always acquires the
 * process-aware advancement lock, requires the journal to be absent, and
 * verifies the caller's Host identity operation lease before and after the
 * atomic exclusive write.
 */
export function createHostDomainResetJournal(
  resources: ProfileResourceSet,
  initial: HostDomainResetJournalV1,
  operationLease: HostIdentityOperationLease,
  options: HostDomainResetJournalStoreOptions = {},
): HostDomainResetJournalV1 {
  const lock = acquireJournalAdvancementLock(resources, options.uid, options.lockDependencies);
  try {
    const existing = loadHostDomainResetJournal(resources, options.uid);
    if (existing !== null) throw new TypeError('Host-domain reset journal already exists');
    const validated = validateInitialJournal(initial, resources);
    if (!validated.ok) throw transitionViolationError(validated.reason);
    assertHostIdentityOperationLeaseOwned(operationLease, resources);
    writeSecureJsonExclusive(resources.hostDomainResetJournalPath, validated.journal, options.uid, {
      ...options.writeHooks,
      beforePromotion() {
        options.writeHooks?.beforePromotion?.();
        assertHostIdentityOperationLeaseOwned(operationLease, resources);
        lock.assertOwned();
      },
    });
    assertHostIdentityOperationLeaseOwned(operationLease, resources);
    return validated.journal;
  } finally {
    lock.release();
  }
}

/**
 * Advance through exactly one machine-authorized transition. Always acquires
 * the process-aware advancement lock, requires the stored journal to exactly
 * match the caller's snapshot, and verifies the caller's Host identity
 * operation lease before the atomic write and again at promotion time.
 */
export function advanceHostDomainResetJournal(
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
  transition: HostDomainResetJournalTransition,
  operationLease: HostIdentityOperationLease,
  options: HostDomainResetJournalStoreOptions = {},
): HostDomainResetJournalV1 {
  const lock = acquireJournalAdvancementLock(resources, options.uid, options.lockDependencies);
  try {
    const stored = loadHostDomainResetJournal(resources, options.uid);
    if (!stored || encodeHostDomainResetJournal(stored) !== encodeHostDomainResetJournal(current)) {
      throw new TypeError('Host-domain reset journal changed before advancement');
    }
    const result = applyHostDomainResetJournalTransition(stored, transition, resources);
    if (!result.ok) throw transitionViolationError(result.reason);
    assertHostIdentityOperationLeaseOwned(operationLease, resources);
    writeSecureJson(resources.hostDomainResetJournalPath, result.journal, options.uid, {
      ...options.writeHooks,
      beforePromotion() {
        options.writeHooks?.beforePromotion?.();
        assertHostIdentityOperationLeaseOwned(operationLease, resources);
        lock.assertOwned();
      },
    });
    return result.journal;
  } finally {
    lock.release();
  }
}

export function restoreHostDomainServiceAndConfirm(
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
  operationLease: HostIdentityOperationLease,
  identityReference: HostPrivateKeyStorage,
  restoreAndConfirm: (
    snapshot: HostDomainResetJournalV1['service'],
    identityReference: HostPrivateKeyStorage,
  ) => boolean,
  options: Pick<HostDomainResetJournalStoreOptions, 'uid'> = {},
): { processRunning: boolean; confirmation: RestoreConfirmation } {
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  if (current.phase !== 'service-restore-pending') {
    throw new TypeError('Host-domain reset service restoration requires service-restore-pending');
  }
  const stored = loadHostDomainResetJournal(resources, options.uid);
  if (!stored || encodeHostDomainResetJournal(stored) !== encodeHostDomainResetJournal(current)) {
    throw new TypeError('Host-domain reset journal changed before service restoration');
  }
  assertReplacementIdentityReference(resources, current, identityReference);
  const processRunning = restoreAndConfirm(current.service, identityReference);
  if (typeof processRunning !== 'boolean') throw invalidConfirmation();
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  const confirmation = Object.freeze({}) as RestoreConfirmation;
  CONFIRMATION_PAYLOADS.set(confirmation, {
    operationId: current.operationId,
    journalDigest: canonicalJournalDigest(current),
    service: structuredClone(current.service),
    identityReference: structuredClone(identityReference),
    restoreReturn: processRunning,
  });
  return { processRunning, confirmation };
}

/**
 * Guarded removal requires the exact in-process confirmation produced by
 * `restoreHostDomainServiceAndConfirm` and an authentic live operation lease.
 */
export function removeAfterServiceRestoreConfirmed(
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
  operationLease: HostIdentityOperationLease,
  confirmation: RestoreConfirmation,
  options: HostDomainResetJournalStoreOptions = {},
): void {
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  if (current.phase !== 'service-restore-pending') {
    throw new TypeError('Host-domain reset journal removal requires service-restore-pending');
  }
  verifyRestoreConfirmation(confirmation, resources, current);
  const stored = loadHostDomainResetJournal(resources, options.uid);
  if (!stored || encodeHostDomainResetJournal(stored) !== encodeHostDomainResetJournal(current)) {
    throw new TypeError('Host-domain reset journal changed before removal');
  }
  consumeRestoreConfirmation(confirmation, resources, current);
  assertHostIdentityOperationLeaseOwned(operationLease, resources);
  removeSecureFileIfPresent(resources.hostDomainResetJournalPath, options.uid, {
    ...options.removeHooks,
    beforeUnlink(path) {
      options.removeHooks?.beforeUnlink?.(path);
      assertHostIdentityOperationLeaseOwned(operationLease, resources);
    },
  });
}

export function assertHostDomainResetRuntimeStartAllowed(resources: ProfileResourceSet): void {
  const journal = loadHostDomainResetJournal(resources);
  if (!journal || journal.phase === 'service-restore-pending') return;
  const remediation = resources.identityProfile === 'dev'
    ? 'bun run dev:cli -- identity reset --confirm'
    : 'ariava identity reset --confirm';
  const error = new Error(`Host-domain reset recovery required at phase ${journal.phase}; run \`${remediation}\``);
  Object.assign(error, {
    code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
    phase: journal.phase,
    operationId: journal.operationId,
    retryable: true,
    remediation,
  });
  throw error;
}

interface RestoreConfirmationPayload {
  operationId: string;
  journalDigest: string;
  service: HostDomainResetJournalV1['service'];
  identityReference: HostPrivateKeyStorage;
  restoreReturn: boolean;
}

declare const RESTORE_CONFIRMATION_TYPE: unique symbol;

export interface RestoreConfirmation {
  readonly [RESTORE_CONFIRMATION_TYPE]: true;
}

const CONFIRMATION_PAYLOADS = new WeakMap<RestoreConfirmation, RestoreConfirmationPayload>();

function verifyRestoreConfirmation(
  confirmation: RestoreConfirmation,
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
): RestoreConfirmationPayload {
  if ((typeof confirmation !== 'object' && typeof confirmation !== 'function') || confirmation === null) {
    throw invalidConfirmation();
  }
  const payload = CONFIRMATION_PAYLOADS.get(confirmation);
  if (payload === undefined) throw invalidConfirmation();
  if (payload.operationId !== current.operationId) throw invalidConfirmation();
  if (payload.journalDigest !== canonicalJournalDigest(current)) throw invalidConfirmation();
  if (JSON.stringify(payload.service) !== JSON.stringify(current.service)) throw invalidConfirmation();
  assertReplacementIdentityReference(resources, current, payload.identityReference);
  if (typeof payload.restoreReturn !== 'boolean') throw invalidConfirmation();
  return payload;
}

function consumeRestoreConfirmation(
  confirmation: RestoreConfirmation,
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
): RestoreConfirmationPayload {
  const payload = verifyRestoreConfirmation(confirmation, resources, current);
  CONFIRMATION_PAYLOADS.delete(confirmation);
  return payload;
}

function assertReplacementIdentityReference(
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
  identityReference: HostPrivateKeyStorage,
): void {
  const valid = identityReference.type === 'linux-json'
    ? identityReference.path === resources.identityMetadataPath
    : identityReference.service === 'io.noyx.ariava.host-identity'
      && current.newHostId !== null
      && identityReference.account === current.newHostId;
  if (!valid) throw invalidConfirmation();
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

function transitionViolationError(reason: HostResetJournalViolation): TypeError {
  return new TypeError(`Host-domain reset journal transition is invalid: ${reason.kind}`);
}

function invalidConfirmation(): TypeError {
  return new TypeError('Host-domain reset journal restore confirmation is invalid');
}
