import {
  hostDomainResourceDigest,
  identityResourceDigest,
  type HostDomainResetProfileId,
  type HostDomainResetResourceSet,
} from './host-domain-reset-journal-binding';

export {
  hostDomainResourceDigest,
  identityResourceDigest,
} from './host-domain-reset-journal-binding';
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
  profile: HostDomainResetProfileId;
  previousAccount: string | null;
  previousPendingAccount: string | null;
  interruptedCreationAccount: string | null;
}

export interface HostDomainResetJournalV1 {
  version: 1;
  operationId: string;
  profile: HostDomainResetProfileId;
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
export const PHASE_INDEX = new Map(HOST_DOMAIN_RESET_PHASES.map((phase, index) => [phase, index]));


export function parseHostDomainResetJournal(value: unknown, resources: HostDomainResetResourceSet): HostDomainResetJournalV1 {
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

export function encodeHostDomainResetJournal(
  journal: HostDomainResetJournalV1,
  resources: HostDomainResetResourceSet,
): string {
  const validated = parseHostDomainResetJournal(journal, resources);
  return `${JSON.stringify(validated, null, 2)}\n`;
}

function isSigningCleanup(value: unknown, resources: HostDomainResetResourceSet): value is HostDomainResetSigningCleanupV1 | null {
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
