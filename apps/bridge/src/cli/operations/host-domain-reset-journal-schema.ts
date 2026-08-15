import { createHash } from 'node:crypto';
import type { AriavaProfileId, ProfileResourceSet } from '../profile';

export const HOST_DOMAIN_RESET_JOURNAL_VERSION = 1 as const;

export const HOST_DOMAIN_RESET_PHASES = [
  'quarantine-pending',
  'quarantined',
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

export interface HostDomainResetSigningCleanupV1 {
  kind: 'linux-json' | 'macos-keychain';
  resourceDigest: string;
  profile: AriavaProfileId;
  previousAccount: string | null;
  previousPendingAccount: string | null;
  interruptedCreationAccount: string | null;
}

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
  signingCleanup: HostDomainResetSigningCleanupV1 | null;
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

const JOURNAL_KEYS = [
  'version', 'operationId', 'profile', 'phase', 'oldHostId', 'oldKeyId', 'newHostId', 'newKeyId',
  'oldEncryptionKeyId', 'signingCleanup', 'signingReplacementAttemptedAt', 'encryptionIdentityReplacedAt',
  'runtimeArtifactsClearedAt', 'configSavedAt', 'enrolledAt', 'serviceMetadataSynchronizedAt',
  'resourceDigest', 'createdAt', 'updatedAt', 'revoke', 'service',
] as const;
const SIGNING_CLEANUP_KEYS = [
  'kind', 'resourceDigest', 'profile', 'previousAccount', 'previousPendingAccount', 'interruptedCreationAccount',
] as const;
const REVOKE_KEYS = ['state', 'outcome'] as const;
const SERVICE_KEYS = ['managed', 'installed', 'enabled', 'wasRunning', 'backend'] as const;
const PHASE_INDEX = new Map(HOST_DOMAIN_RESET_PHASES.map((phase, index) => [phase, index]));

export function identityResourceDigest(path: string): string {
  return createHash('sha256').update(path).digest('hex');
}

export function hostDomainResourceDigest(resources: ProfileResourceSet): string {
  const paths = hostDomainResourcePaths(resources);
  const canonical = JSON.stringify(Object.fromEntries(Object.entries(paths).sort(([left], [right]) => left.localeCompare(right))));
  return createHash('sha256').update(canonical).digest('hex');
}

export function hostDomainResourcePaths(resources: ProfileResourceSet): Record<string, string> {
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

/**
 * Position of a phase in the frozen v1 order. Used by the policy module to
 * classify rollback/skip/adjacency. Phases are validated before this is
 * reached, so an unknown phase here is a programming error.
 */
export function phaseOrder(phase: HostDomainResetPhase): number {
  const index = PHASE_INDEX.get(phase);
  if (index === undefined) throw invalidJournal();
  return index;
}

/**
 * Exact decoder. Unknown/missing/malformed fields fail closed, the resource
 * digest and profile must match the resolved resources, the dev profile must
 * carry an unmanaged service snapshot, and every phase must satisfy its
 * required/forbidden evidence invariants. No filesystem effects.
 */
export function parseHostDomainResetJournal(value: unknown, resources: ProfileResourceSet): HostDomainResetJournalV1 {
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
    || !isSigningCleanup(value.signingCleanup, resources)
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

/**
 * Canonical deterministic encoding: top-level and nested keys in exact
 * interface order, matching the bytes a freshly constructed coordinator
 * journal produces, so persisted v1 bytes stay byte-identical for the same
 * logical journal.
 */
export function encodeHostDomainResetJournal(journal: HostDomainResetJournalV1): string {
  return JSON.stringify(canonicalJournalRecord(journal));
}

export function canonicalJournalDigest(journal: HostDomainResetJournalV1): string {
  return createHash('sha256').update(encodeHostDomainResetJournal(journal)).digest('hex');
}

function canonicalJournalRecord(journal: HostDomainResetJournalV1): Record<string, unknown> {
  return {
    version: journal.version,
    operationId: journal.operationId,
    profile: journal.profile,
    phase: journal.phase,
    oldHostId: journal.oldHostId,
    oldKeyId: journal.oldKeyId,
    newHostId: journal.newHostId,
    newKeyId: journal.newKeyId,
    oldEncryptionKeyId: journal.oldEncryptionKeyId,
    signingCleanup: journal.signingCleanup === null
      ? null
      : {
        kind: journal.signingCleanup.kind,
        resourceDigest: journal.signingCleanup.resourceDigest,
        profile: journal.signingCleanup.profile,
        previousAccount: journal.signingCleanup.previousAccount,
        previousPendingAccount: journal.signingCleanup.previousPendingAccount,
        interruptedCreationAccount: journal.signingCleanup.interruptedCreationAccount,
      },
    signingReplacementAttemptedAt: journal.signingReplacementAttemptedAt,
    encryptionIdentityReplacedAt: journal.encryptionIdentityReplacedAt,
    runtimeArtifactsClearedAt: journal.runtimeArtifactsClearedAt,
    configSavedAt: journal.configSavedAt,
    enrolledAt: journal.enrolledAt,
    serviceMetadataSynchronizedAt: journal.serviceMetadataSynchronizedAt,
    resourceDigest: journal.resourceDigest,
    createdAt: journal.createdAt,
    updatedAt: journal.updatedAt,
    revoke: {
      state: journal.revoke.state,
      outcome: journal.revoke.outcome,
    },
    service: {
      managed: journal.service.managed,
      installed: journal.service.installed,
      enabled: journal.service.enabled,
      wasRunning: journal.service.wasRunning,
      backend: journal.service.backend,
    },
  };
}

function isSigningCleanup(value: unknown, resources: ProfileResourceSet): value is HostDomainResetSigningCleanupV1 | null {
  if (value === null) return true;
  if (!isRecord(value) || !hasExactKeys(value, SIGNING_CLEANUP_KEYS)
    || !['linux-json', 'macos-keychain'].includes(String(value.kind))
    || value.resourceDigest !== identityResourceDigest(resources.identityMetadataPath)
    || value.profile !== resources.identityProfile) return false;
  if (value.kind === 'linux-json') {
    return value.previousAccount === null && value.previousPendingAccount === null
      && value.interruptedCreationAccount === null;
  }
  const previous = typeof value.previousAccount === 'string' && /^host_[A-Za-z0-9_-]{43}$/u.test(value.previousAccount)
    ? value.previousAccount : null;
  if (value.previousAccount !== null && previous === null) return false;
  if (value.previousPendingAccount !== null && value.previousPendingAccount !== `${previous}.pending`) return false;
  if (value.interruptedCreationAccount !== null
    && (typeof value.interruptedCreationAccount !== 'string'
      || !/^host_[A-Za-z0-9_-]{43}$/u.test(value.interruptedCreationAccount)
      || (previous !== null && value.interruptedCreationAccount !== previous))) return false;
  return true;
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
  const revokeSkipped = journal.revoke.state === 'skipped' && journal.revoke.outcome === 'old-identity-unreadable';

  const preInspection = journal.phase === 'quarantine-pending' || journal.phase === 'quarantined';
  const expectedRevokeState: HostDomainResetRevokeState = preInspection
    ? 'not-attempted'
    : revokeSkipped
      ? 'skipped'
      : !oldKnown
        ? 'skipped'
        : journal.phase === 'prepared'
          ? 'not-attempted'
          : journal.phase === 'revoke-pending'
            ? 'pending'
            : 'complete';
  if (journal.revoke.state !== expectedRevokeState) return false;
  if (preInspection) {
    if (oldKnown || journal.oldEncryptionKeyId !== null || journal.revoke.outcome !== null || journal.signingCleanup !== null) return false;
  } else if (!oldKnown && !revokeSkipped) return false;
  if (revokeSkipped && journal.signingCleanup === null) return false;

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
