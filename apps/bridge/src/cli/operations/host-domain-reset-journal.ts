import { createHash } from 'node:crypto';
import { AriavaCliError } from '../../host-manager/service/errors';
import {
  acquireProcessAwareLock,
  type ProcessAwareLockDependencies as LockDependencies,
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
import type { AriavaProfileId, ProfileResourceSet } from '../profile';

export const HOST_DOMAIN_RESET_JOURNAL_VERSION = 1 as const;

export const HOST_DOMAIN_RESET_PHASES = [
  'prepared',
  'revoke-pending',
  'old-identity-revoked',
  'signing-replacement-pending',
  'signing-identity-replaced',
  'encryption-identity-replaced',
  'runtime-artifacts-cleared',
  'config-saved',
  'enrolled',
  'service-metadata-synchronized',
  'service-restore-pending',
] as const;

export type HostDomainResetPhase = typeof HOST_DOMAIN_RESET_PHASES[number];
export type HostDomainResetRevokeState = 'not-attempted' | 'pending' | 'complete' | 'skipped';
export type HostDomainResetRevokeOutcome = 'revoked' | 'identity-already-revoked' | 'old-identity-unreadable' | null;
export type HostDomainResetServiceBackend = 'launchd' | 'systemd-user' | 'none';

export interface HostDomainResetJournalV1 {
  version: 1;
  operationId: string;
  profile: AriavaProfileId;
  phase: HostDomainResetPhase;
  oldHostId: string | null;
  oldKeyId: string | null;
  newHostId: string | null;
  newKeyId: string | null;
  oldEncryptionKeyId: string | null;
  signingReplacementAttemptedAt: string | null;
  encryptionIdentityReplacedAt: string | null;
  runtimeArtifactsClearedAt: string | null;
  configSavedAt: string | null;
  enrolledAt: string | null;
  serviceMetadataSynchronizedAt: string | null;
  resourceDigest: string;
  createdAt: string;
  updatedAt: string;
  revoke: {
    state: HostDomainResetRevokeState;
    outcome: HostDomainResetRevokeOutcome;
  };
  service: {
    managed: boolean;
    installed: boolean;
    enabled: boolean;
    wasRunning: boolean;
    backend: HostDomainResetServiceBackend;
  };
}

export interface HostDomainResetJournalWriteOptions {
  uid?: number;
  hooks?: SecureFileWriteHooks;
  lockDependencies?: Partial<LockDependencies>;
  operationLockHeld?: boolean;
}

const JOURNAL_KEYS = [
  'version', 'operationId', 'profile', 'phase', 'oldHostId', 'oldKeyId', 'newHostId', 'newKeyId',
  'oldEncryptionKeyId', 'signingReplacementAttemptedAt', 'encryptionIdentityReplacedAt',
  'runtimeArtifactsClearedAt', 'configSavedAt', 'enrolledAt', 'serviceMetadataSynchronizedAt',
  'resourceDigest', 'createdAt', 'updatedAt', 'revoke', 'service',
] as const;
const REVOKE_KEYS = ['state', 'outcome'] as const;
const SERVICE_KEYS = ['managed', 'installed', 'enabled', 'wasRunning', 'backend'] as const;
const PHASE_INDEX = new Map(HOST_DOMAIN_RESET_PHASES.map((phase, index) => [phase, index]));

export function hostDomainResourceDigest(resources: ProfileResourceSet): string {
  const paths = hostDomainResourcePaths(resources);
  const canonical = JSON.stringify(Object.fromEntries(Object.entries(paths).sort(([left], [right]) => left.localeCompare(right))));
  return createHash('sha256').update(canonical).digest('hex');
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

export function writeHostDomainResetJournal(
  resources: ProfileResourceSet,
  journal: HostDomainResetJournalV1,
  options: HostDomainResetJournalWriteOptions = {},
): void {
  const validated = parseHostDomainResetJournal(journal, resources);
  writeSecureJsonExclusive(
    resources.hostDomainResetJournalPath,
    validated,
    options.uid,
    options.hooks,
  );
}

export function advanceHostDomainResetJournal(
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
  patch: Partial<Omit<HostDomainResetJournalV1, 'version' | 'operationId' | 'profile' | 'resourceDigest' | 'createdAt'>>,
  options: HostDomainResetJournalWriteOptions = {},
): HostDomainResetJournalV1 {
  const lock = options.operationLockHeld
    ? { assertOwned() {}, release() {} }
    : acquireJournalAdvancementLock(resources, current, options.uid, options.lockDependencies);
  try {
    const stored = loadHostDomainResetJournal(resources, options.uid);
    if (!stored || JSON.stringify(stored) !== JSON.stringify(current)) {
      throw new TypeError('Host-domain reset journal changed before advancement');
    }
    const candidate = parseHostDomainResetJournal({ ...current, ...patch }, resources);
    const currentPhase = PHASE_INDEX.get(current.phase);
    const candidatePhase = PHASE_INDEX.get(candidate.phase);
    if (currentPhase === undefined || candidatePhase === undefined || candidatePhase < currentPhase) {
      throw new TypeError('Host-domain reset journal phase rollback is not allowed');
    }
    if (Date.parse(candidate.updatedAt) < Date.parse(current.updatedAt)) {
      throw new TypeError('Host-domain reset journal timestamp rollback is not allowed');
    }
    assertStableBinding(current, candidate);
    lock.assertOwned();
    writeSecureJson(resources.hostDomainResetJournalPath, candidate, options.uid, {
      ...options.hooks,
      beforePromotion() {
        options.hooks?.beforePromotion?.();
        lock.assertOwned();
      },
    });
    return candidate;
  } finally {
    lock.release();
  }
}

export function removeHostDomainResetJournal(
  resources: ProfileResourceSet,
  uid?: number,
  hooks: SecureFileRemoveHooks = {},
): void {
  removeSecureFileIfPresent(resources.hostDomainResetJournalPath, uid, hooks);
}

interface JournalAdvancementLock {
  assertOwned(): void;
  release(): void;
}

function acquireJournalAdvancementLock(
  resources: ProfileResourceSet,
  _current: HostDomainResetJournalV1,
  uid?: number,
  dependencies: Partial<LockDependencies> = {},
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


function parseHostDomainResetJournal(value: unknown, resources: ProfileResourceSet): HostDomainResetJournalV1 {
  if (!isRecord(value) || !hasExactKeys(value, JOURNAL_KEYS)) throw invalidJournal();
  if (value.version !== HOST_DOMAIN_RESET_JOURNAL_VERSION
    || !isOperationId(value.operationId)
    || value.profile !== resources.identityProfile
    || !isPhase(value.phase)
    || !isNullablePublicId(value.oldHostId, 'host_')
    || !isNullablePublicId(value.oldKeyId, 'key_')
    || !isNullablePublicId(value.newHostId, 'host_')
    || !isNullablePublicId(value.newKeyId, 'key_')
    || !isNullableEncryptionKeyId(value.oldEncryptionKeyId)
    || !isDigest(value.resourceDigest)
    || value.resourceDigest !== hostDomainResourceDigest(resources)
    || !isCanonicalTimestamp(value.createdAt)
    || !isCanonicalTimestamp(value.updatedAt)
    || Date.parse(value.updatedAt) < Date.parse(value.createdAt)
    || !isRevoke(value.revoke)
    || !isService(value.service)
    || (resources.identityProfile === 'dev' && !isUnmanagedService(value.service))
    || (value.oldHostId === null) !== (value.oldKeyId === null)
    || (value.newHostId === null) !== (value.newKeyId === null)
    || !isNullableJournalTimestamp(value.signingReplacementAttemptedAt, value.createdAt, value.updatedAt)
    || !isNullableJournalTimestamp(value.encryptionIdentityReplacedAt, value.createdAt, value.updatedAt)
    || !isNullableJournalTimestamp(value.runtimeArtifactsClearedAt, value.createdAt, value.updatedAt)
    || !isNullableJournalTimestamp(value.configSavedAt, value.createdAt, value.updatedAt)
    || !isNullableJournalTimestamp(value.enrolledAt, value.createdAt, value.updatedAt)
    || !isNullableJournalTimestamp(value.serviceMetadataSynchronizedAt, value.createdAt, value.updatedAt)) {
    throw invalidJournal();
  }
  const journal = value as unknown as HostDomainResetJournalV1;
  if (!hasValidPhaseInvariants(journal)) throw invalidJournal();
  return structuredClone(value) as unknown as HostDomainResetJournalV1;
}

function assertStableBinding(current: HostDomainResetJournalV1, candidate: HostDomainResetJournalV1): void {
  for (const key of [
    'version', 'operationId', 'profile', 'resourceDigest', 'createdAt', 'oldHostId', 'oldKeyId', 'oldEncryptionKeyId',
  ] as const) {
    if (candidate[key] !== current[key]) throw new TypeError(`Host-domain reset journal ${key} cannot change`);
  }
  if (current.newHostId !== null && candidate.newHostId !== current.newHostId) {
    throw new TypeError('Host-domain reset journal newHostId cannot change');
  }
  if (current.newKeyId !== null && candidate.newKeyId !== current.newKeyId) {
    throw new TypeError('Host-domain reset journal newKeyId cannot change');
  }
  for (const field of [
    'signingReplacementAttemptedAt', 'encryptionIdentityReplacedAt', 'runtimeArtifactsClearedAt',
    'configSavedAt', 'enrolledAt', 'serviceMetadataSynchronizedAt',
  ] as const) {
    if (current[field] !== null && candidate[field] !== current[field]) {
      throw new TypeError(`Host-domain reset journal ${field} cannot change`);
    }
  }
  if (JSON.stringify(candidate.service) !== JSON.stringify(current.service)) {
    throw new TypeError('Host-domain reset journal service snapshot cannot change');
  }
}

function hostDomainResourcePaths(resources: ProfileResourceSet): Record<string, string> {
  return {
    root: resources.root,
    configPath: resources.configPath,
    identityMetadataPath: resources.identityMetadataPath,
    encryptionIdentityPath: resources.encryptionIdentityPath,
    linkKeyringPath: resources.linkKeyringPath,
    statePath: resources.statePath,
    agentAdapterConfigPath: resources.agentAdapterConfigPath,
    piExtensionLogPath: resources.piExtensionLogPath,
    installMetadataPath: resources.installMetadataPath,
    encryptedSpoolPath: resources.encryptedSpoolPath,
    runtimeResetIntentPath: resources.runtimeResetIntentPath,
    runtimeLockPath: resources.runtimeLockPath,
    runtimeTakeoverMutexPath: resources.runtimeTakeoverMutexPath,
    macosSpoolEvidencePath: resources.macosSpoolEvidencePath,
    linuxSpoolKeyPath: resources.linuxSpoolKeyPath,
    hostDomainResetJournalPath: resources.hostDomainResetJournalPath,
  };
}

function isRevoke(value: unknown): boolean {
  if (!isRecord(value) || !hasExactKeys(value, REVOKE_KEYS)) return false;
  const states: readonly unknown[] = ['not-attempted', 'pending', 'complete', 'skipped'];
  const outcomes: readonly unknown[] = [null, 'revoked', 'identity-already-revoked', 'old-identity-unreadable'];
  if (!states.includes(value.state) || !outcomes.includes(value.outcome)) return false;
  if (value.state === 'not-attempted' || value.state === 'pending') return value.outcome === null;
  if (value.state === 'complete') return value.outcome === 'revoked' || value.outcome === 'identity-already-revoked';
  return value.state === 'skipped' && value.outcome === 'old-identity-unreadable';
}

function isService(value: unknown): boolean {
  if (!isRecord(value) || !hasExactKeys(value, SERVICE_KEYS)) return false;
  if (typeof value.managed !== 'boolean' || typeof value.installed !== 'boolean'
    || typeof value.enabled !== 'boolean' || typeof value.wasRunning !== 'boolean'
    || !['launchd', 'systemd-user', 'none'].includes(String(value.backend))) return false;
  if (!value.managed) return value.backend === 'none' && !value.installed && !value.enabled && !value.wasRunning;
  if (value.backend === 'none') return false;
  if (!value.installed && (value.enabled || value.wasRunning)) return false;
  return true;
}

function isUnmanagedService(value: Record<string, unknown>): boolean {
  return value.managed === false && value.installed === false && value.enabled === false
    && value.wasRunning === false && value.backend === 'none';
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function isPhase(value: unknown): value is HostDomainResetPhase {
  return typeof value === 'string' && PHASE_INDEX.has(value as HostDomainResetPhase);
}

function isOperationId(value: unknown): boolean {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/u.test(value);
}

function isNullablePublicId(value: unknown, prefix: 'host_' | 'key_'): boolean {
  return value === null || (typeof value === 'string' && value.startsWith(prefix)
    && /^[A-Za-z0-9_-]{43}$/u.test(value.slice(prefix.length)));
}

function isDigest(value: unknown): boolean {
  return typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);
}

function isNullableEncryptionKeyId(value: unknown): boolean {
  return value === null || (typeof value === 'string' && /^ekey_[A-Za-z0-9_-]{43}$/u.test(value));
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function isNullableJournalTimestamp(value: unknown, createdAt: unknown, updatedAt: unknown): boolean {
  return value === null || (isCanonicalTimestamp(value) && isCanonicalTimestamp(createdAt)
    && isCanonicalTimestamp(updatedAt) && Date.parse(value) >= Date.parse(createdAt)
    && Date.parse(value) <= Date.parse(updatedAt));
}

function hasValidPhaseInvariants(journal: HostDomainResetJournalV1): boolean {
  const phaseIndex = PHASE_INDEX.get(journal.phase)!;
  const atLeast = (phase: HostDomainResetPhase) => phaseIndex >= PHASE_INDEX.get(phase)!;
  const exactEvidence = (phase: HostDomainResetPhase, present: boolean) => atLeast(phase) === present;
  const oldKnown = journal.oldHostId !== null;
  if (oldKnown && journal.newHostId === journal.oldHostId) return false;
  if ((journal.phase === 'revoke-pending' || journal.phase === 'old-identity-revoked') && !oldKnown) return false;

  const expectedRevokeState: HostDomainResetRevokeState = !oldKnown
    ? 'skipped'
    : journal.phase === 'prepared'
      ? 'not-attempted'
      : journal.phase === 'revoke-pending'
        ? 'pending'
        : 'complete';
  if (journal.revoke.state !== expectedRevokeState) return false;

  if (!exactEvidence('signing-replacement-pending', journal.signingReplacementAttemptedAt !== null)) return false;
  if (!exactEvidence('signing-identity-replaced', journal.newHostId !== null && journal.newKeyId !== null)) return false;
  if (!exactEvidence('encryption-identity-replaced', journal.encryptionIdentityReplacedAt !== null)) return false;
  if (!exactEvidence('runtime-artifacts-cleared', journal.runtimeArtifactsClearedAt !== null)) return false;
  if (!exactEvidence('config-saved', journal.configSavedAt !== null)) return false;
  if (!exactEvidence('enrolled', journal.enrolledAt !== null)) return false;
  if (!exactEvidence('service-metadata-synchronized', journal.serviceMetadataSynchronizedAt !== null)) return false;
  return true;
}


function invalidJournal(): TypeError {
  return new TypeError('Host-domain reset journal is invalid');
}

export function assertHostDomainResetRuntimeStartAllowed(resources: ProfileResourceSet): void {
  const journal = loadHostDomainResetJournal(resources);
  if (!journal || journal.phase === 'service-restore-pending') return;
  const remediation = resources.identityProfile === 'dev'
    ? 'bun run dev:cli -- host reset --confirm'
    : 'ariava host reset --confirm';
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
