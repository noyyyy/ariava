import type { HostPlatform } from '@ariava/protocol';
import type {
  HostEncryptionIdentity,
  HostEncryptionIdentityStore,
  HostIdentity,
  HostIdentityStore,
} from '../../identity';
import { publicIdentityMetadata } from '../../identity';
import { HostIdentityError } from '../../identity/errors';
import { RESET_ONLY_IDENTITY_EVIDENCE_SOURCE } from '../../identity/reset-only-evidence-source';
import type { HostReplacementSpoolKeyStore } from '../../e2e/local-spool';
import type { RuntimeCoordinator } from '../../runtime-lock';
import { AriavaCliError } from '../../host-manager/service/errors';
import type { AriavaUserConfig } from '../../host-manager/config';
import type { AriavaProfileId, ProfileResourceSet } from '../profile';
import {
  clearHostDomainArtifacts,
  assertArtifactCleanupBoundary,
} from './host-domain-reset-artifacts';
import { inspectResetOnlyLegacyIdentityEvidence } from './identity-reset-legacy-evidence';
import { identityResourceDigest } from './host-domain-reset-journal-binding';
import type { HostDomainResetTransition } from './host-domain-reset-journal-policy';
import type {
  HostDomainResetJournalV1,
  HostDomainResetSigningCleanupV1,
} from './host-domain-reset-journal-schema';
import type { HostResetAction } from './host-domain-reset-machine';

/**
 * Narrow Host-domain reset effect executors (primary spec §8, §7.2 matrix).
 *
 * One executor per machine action. Executors perform ONLY the effects of the
 * single matrix row for their action, validate that row's preconditions, and
 * return the exact `HostDomainResetTransition` the coordinator will commit
 * through the secure store. They never own the journal loop, the Host
 * identity operation lease, or raw journal removal, and they never advance
 * the journal themselves.
 *
 * Import boundary: this module imports schema/policy/machine types, the
 * artifact plan module, identity/encryption store and service/relay
 * dependency types, and the reset-only legacy evidence decoder. It never
 * imports the journal store module, `cli/context.ts`, `node:fs`,
 * `secure-files`, or the coordinator module.
 */

// ---------------------------------------------------------------------------
// Dependency ports
// ---------------------------------------------------------------------------

/** Structural subset of `HostDomainResetLifecycleAdapter` (no coordinator import). */
export interface HostResetLifecyclePort {
  prepare(resources: unknown): HostDomainResetJournalV1['service'];
  stopAndConfirm(snapshot: HostDomainResetJournalV1['service']): void;
  synchronizeMetadata(
    snapshot: HostDomainResetJournalV1['service'],
    identityReference: HostIdentity['privateKeyStorage'],
  ): void;
  restoreAndConfirm(
    snapshot: HostDomainResetJournalV1['service'],
    identityReference: HostIdentity['privateKeyStorage'],
  ): boolean;
  validateRestored(
    snapshot: HostDomainResetJournalV1['service'],
    identityReference: HostIdentity['privateKeyStorage'],
  ): boolean;
}

/** Runtime exclusivity port: acquired at quarantine, released before restore. */
export interface HostResetRuntimePort {
  acquire(): RuntimeCoordinator;
  /** Currently held coordinator, or undefined before quarantine acquisition. */
  held: RuntimeCoordinator | undefined;
  release(): void;
}

/** Config port for idempotent identity-config persistence. */
export interface HostResetConfigPort {
  load(path: string): AriavaUserConfig;
  save(config: AriavaUserConfig, path: string): void;
}

export type HostResetEffectName =
  | 'signing-replaced'
  | 'encryption-replaced'
  | 'artifacts-cleared'
  | 'config-saved'
  | 'enrolled'
  | 'service-metadata-synchronized'
  | 'service-restored';

export interface HostResetHooks {
  afterEffect?(effect: HostResetEffectName): void;
}

/**
 * Full narrow dependency bundle assembled by the coordinator. Each per-action
 * executor consumes only the slice it needs (declared via per-executor
 * dependency types below); nothing here is the loop, the operation lease, or
 * the journal store.
 */
export interface HostResetExecutorDependencies {
  profileId: AriavaProfileId;
  resources: ProfileResourceSet;
  identityStore: HostIdentityStore;
  encryptionStore: HostEncryptionIdentityStore;
  spoolKeyStore: HostReplacementSpoolKeyStore;
  lifecycle: HostResetLifecyclePort;
  runtime: HostResetRuntimePort;
  config: HostResetConfigPort;
  baseConfig: AriavaUserConfig;
  relayBaseUrl: string;
  hostName: string;
  platform: HostPlatform;
  bridgeVersion: string;
  revoke(identity: HostIdentity): Promise<'revoked' | 'identity-already-revoked'>;
  replace(store: HostIdentityStore, operationId: string): Promise<HostIdentity>;
  enroll(
    identity: HostIdentity,
    metadata: { hostName: string; platform: HostPlatform; bridgeVersion: string },
    encryptionIdentity: HostEncryptionIdentity,
  ): Promise<void>;
  access?(kind: 'filesystemWrites', path: string): void;
  hooks?: HostResetHooks;
  now?(): Date;
}

// ---------------------------------------------------------------------------
// Shared error helpers (kept here so Task Group J imports them from this
// module; the coordinator's private copies are removed in Task J).
// ---------------------------------------------------------------------------

export function recoveryRequired(message: string, cause?: unknown): AriavaCliError {
  return new AriavaCliError('ERR_HOST_RESET_RECOVERY_REQUIRED', message, {
    retryable: true,
    remediation: { message: 'Retry the same Host reset command to resume recovery.' },
    ...(cause === undefined ? {} : { cause }),
  });
}

export function activeRuntimeError(profileId: AriavaProfileId, _error: unknown): AriavaCliError {
  return new AriavaCliError(
    'ERR_HOST_RESET_RUNTIME_ACTIVE',
    `${profileId === 'dev' ? 'Stop the foreground dev Bridge and retry. ' : ''}Host reset runtime is active`,
    { retryable: true, remediation: { message: 'Stop the active Bridge runtime, then retry Host reset.' } },
  );
}

export function isDefiniteResetRequiredIdentityError(error: unknown): boolean {
  return error instanceof HostIdentityError && [
    'ERR_IDENTITY_INVALID',
    'ERR_IDENTITY_MISSING',
    'ERR_IDENTITY_RESET_REQUIRED',
  ].includes(error.code);
}

/** Frozen v1 phase order (single source: policy module phase order). */
export function phaseBefore(
  left: HostDomainResetJournalV1['phase'],
  right: HostDomainResetJournalV1['phase'],
): boolean {
  const order: readonly HostDomainResetJournalV1['phase'][] = [
    'quarantine-pending', 'quarantined', 'prepared', 'revoke-pending', 'old-identity-revoked',
    'signing-replacement-pending', 'signing-identity-replaced', 'encryption-identity-replaced',
    'runtime-artifacts-cleared', 'config-saved', 'enrolled', 'service-metadata-synchronized',
    'service-restore-pending',
  ];
  return order.indexOf(left) < order.indexOf(right);
}

// ---------------------------------------------------------------------------
// Executor result
// ---------------------------------------------------------------------------

/**
 * Restore-sequence outcome descriptor consumed by the coordinator's routing
 * contract. The executor validates the restore precondition (journal at
 * `service-restore-pending`) and hands the journal to the coordinator, which
 * routes this outcome into `recoverServiceRestorePending` in
 * `host-domain-reset-recovery.ts` together with the still-owned Host
 * operation lease. The recovery module owns the full rehydrate / re-quarantine
 * / replacement verification / runtime ownership release / `restoreAndConfirm`
 * / single-use confirmation / guarded-removal sequence. Executors never own
 * the operation lease or raw journal removal, so this action is deliberately
 * a thin routing seam rather than the restore implementation.
 */

export type HostResetRestoreOutcome = {
  journal: HostDomainResetJournalV1;
  recoveryOwned: true;
};

export type HostResetExecutorResult =
  | { kind: 'transition'; transition: HostDomainResetTransition }
  | { kind: 'restore'; outcome: HostResetRestoreOutcome };

// ---------------------------------------------------------------------------
// Identity store helpers (moved from the coordinator; Task J removes the
// coordinator's private copies).
// ---------------------------------------------------------------------------

export async function loadExpectedOldIdentity(
  store: HostIdentityStore,
  journal: HostDomainResetJournalV1,
): Promise<HostIdentity | null> {
  if (!journal.oldHostId || journal.revoke.outcome === 'old-identity-unreadable') return null;
  const current = await store.load();
  if (!current || current.hostId !== journal.oldHostId || current.keyId !== journal.oldKeyId) {
    if (journal.phase === 'prepared' || journal.phase === 'revoke-pending') {
      throw recoveryRequired('Old Host signing identity evidence changed before Relay revoke completed');
    }
  }
  return current;
}

export async function requireReplacement(
  store: HostIdentityStore,
  journal: HostDomainResetJournalV1,
): Promise<HostIdentity> {
  if (!journal.newHostId || !journal.newKeyId) throw recoveryRequired('Replacement Host identity is not journaled');
  const current = await store.load();
  if (!current || current.hostId !== journal.newHostId || current.keyId !== journal.newKeyId) {
    throw recoveryRequired('Replacement Host signing identity evidence is invalid');
  }
  return current;
}

export async function adoptOrReplaceSigningIdentity(
  store: HostIdentityStore,
  journal: HostDomainResetJournalV1,
  replace: HostResetExecutorDependencies['replace'],
): Promise<HostIdentity> {
  let provenCandidate: HostIdentity | null | undefined;
  try {
    provenCandidate = await store.recoverExplicitReset?.(journal.operationId);
  } catch (error) {
    if (!isDefiniteResetRequiredIdentityError(error)) throw error;
    provenCandidate = null;
  }
  let current: HostIdentity | null;
  try {
    current = await store.load();
  } catch (error) {
    if (!isDefiniteResetRequiredIdentityError(error)) throw error;
    if (provenCandidate) return provenCandidate;
    prepareExactSigningCleanup(store, journal);
    return replace(store, journal.operationId);
  }
  if (journal.newHostId !== null) {
    if (current?.hostId !== journal.newHostId || current.keyId !== journal.newKeyId) {
      throw recoveryRequired('Replacement Host signing identity evidence is invalid');
    }
    return current;
  }
  if (current && current.hostId !== journal.oldHostId) {
    if (!provenCandidate || current.hostId !== provenCandidate.hostId || current.keyId !== provenCandidate.keyId) {
      throw recoveryRequired('Foreign Host signing identity evidence appeared before replacement');
    }
    return provenCandidate;
  }
  if (journal.phase !== 'signing-replacement-pending') {
    throw recoveryRequired('Replacement Host signing identity evidence is missing');
  }
  prepareExactSigningCleanup(store, journal);
  return provenCandidate ?? replace(store, journal.operationId);
}

export function prepareExactSigningCleanup(
  store: HostIdentityStore,
  journal: HostDomainResetJournalV1,
): void {
  if (journal.phase !== 'signing-replacement-pending') return;
  if (!journal.signingCleanup) return;
  const evidence = inspectResetOnlyLegacyIdentityEvidence(store);
  const expected = journal.signingCleanup;
  if (!expected || evidence.classification !== 'old-identity-unreadable'
    || evidence.oldHostId !== journal.oldHostId || evidence.oldKeyId !== journal.oldKeyId
    || evidence.source.kind !== expected.kind
    || identityResourceDigest(evidence.source.resourcePath) !== expected.resourceDigest
    || ('profile' in evidence.source && evidence.source.profile !== expected.profile)
    || JSON.stringify(evidence.cleanup ?? {
      previousAccount: null, previousPendingAccount: null, interruptedCreationAccount: null,
    }) !== JSON.stringify({
      previousAccount: expected.previousAccount,
      previousPendingAccount: expected.previousPendingAccount,
      interruptedCreationAccount: expected.interruptedCreationAccount,
    })) {
    throw recoveryRequired('Old Host signing identity cleanup evidence changed before replacement');
  }
}

// ---------------------------------------------------------------------------
// Per-action executors (§7.2 matrix rows)
// ---------------------------------------------------------------------------

type StopQuarantineDeps = Pick<
  HostResetExecutorDependencies,
  'profileId' | 'resources' | 'lifecycle' | 'runtime'
>;

async function executeStopQuarantineAndAcquireRuntime(
  journal: HostDomainResetJournalV1,
  deps: StopQuarantineDeps,
): Promise<HostResetExecutorResult> {
  const current = deps.lifecycle.prepare(deps.resources);
  if (current.managed !== journal.service.managed
    || current.installed !== journal.service.installed
    || current.enabled !== journal.service.enabled
    || current.backend !== journal.service.backend) {
    throw recoveryRequired('Host reset service state changed during recovery');
  }
  deps.lifecycle.stopAndConfirm(journal.service);
  try {
    deps.runtime.held = deps.runtime.acquire();
  } catch (error) {
    throw activeRuntimeError(deps.profileId, error);
  }
  return { kind: 'transition', transition: { phase: 'quarantined' } };
}

type InspectAndBindDeps = Pick<
  HostResetExecutorDependencies,
  'profileId' | 'identityStore' | 'encryptionStore' | 'now'
>;

async function executeInspectAndBindOldDomain(
  journal: HostDomainResetJournalV1,
  deps: InspectAndBindDeps,
): Promise<HostResetExecutorResult> {
  if (journal.phase !== 'quarantined') {
    throw recoveryRequired(`Host reset identity inspection requires the quarantined phase, got ${journal.phase}`);
  }
  let oldIdentity: HostIdentity | null = null;
  let legacyEvidence: ReturnType<typeof inspectResetOnlyLegacyIdentityEvidence> | undefined;
  try {
    oldIdentity = await deps.identityStore.load();
  } catch (error) {
    if (!isDefiniteResetRequiredIdentityError(error)) throw error;
    legacyEvidence = inspectResetOnlyLegacyIdentityEvidence(deps.identityStore);
    if (legacyEvidence.classification !== 'old-identity-unreadable') throw error;
  }
  if (oldIdentity && RESET_ONLY_IDENTITY_EVIDENCE_SOURCE in deps.identityStore) {
    const decoded = inspectResetOnlyLegacyIdentityEvidence(deps.identityStore);
    if (decoded.source.kind === 'macos-keychain') legacyEvidence = decoded;
  }
  const oldEncryptionIdentity = deps.encryptionStore.load();
  const signingCleanup: HostDomainResetSigningCleanupV1 | null = legacyEvidence
    ? {
      kind: legacyEvidence.source.kind,
      resourceDigest: identityResourceDigest(legacyEvidence.source.resourcePath),
      profile: deps.profileId,
      previousAccount: legacyEvidence.cleanup?.previousAccount ?? null,
      previousPendingAccount: legacyEvidence.cleanup?.previousPendingAccount ?? null,
      interruptedCreationAccount: legacyEvidence.cleanup?.interruptedCreationAccount ?? null,
    }
    : null;
  return {
    kind: 'transition',
    transition: {
      phase: 'prepared',
      oldHostId: oldIdentity?.hostId ?? legacyEvidence?.oldHostId ?? null,
      oldKeyId: oldIdentity?.keyId ?? legacyEvidence?.oldKeyId ?? null,
      oldEncryptionKeyId: oldEncryptionIdentity?.encryptionKeyId ?? null,
      signingCleanup,
      revoke: oldIdentity
        ? { state: 'not-attempted', outcome: null }
        : { state: 'skipped', outcome: 'old-identity-unreadable' },
    },
  };
}

async function executePersistRevokeIntent(
  journal: HostDomainResetJournalV1,
): Promise<HostResetExecutorResult> {
  // Journaled not-attempted/null revoke evidence is the ONLY authority to
  // write revoke-pending/pending (matrix row for `prepared` readable).
  if (journal.revoke.state !== 'not-attempted' || journal.revoke.outcome !== null) {
    throw recoveryRequired('Host reset revoke intent is not authorized by the journaled revoke evidence');
  }
  return {
    kind: 'transition',
    transition: { phase: 'revoke-pending', revoke: { state: 'pending', outcome: null } },
  };
}

type RevokeOldIdentityDeps = Pick<HostResetExecutorDependencies, 'identityStore' | 'revoke'>;

async function executeRevokeOldIdentity(
  journal: HostDomainResetJournalV1,
  deps: RevokeOldIdentityDeps,
): Promise<HostResetExecutorResult> {
  const oldIdentity = await loadExpectedOldIdentity(deps.identityStore, journal);
  if (!oldIdentity) throw recoveryRequired('Old Host identity is unavailable while Relay revoke is pending');
  let outcome: 'revoked' | 'identity-already-revoked';
  try {
    outcome = await deps.revoke(oldIdentity);
  } catch (error) {
    // Network/5xx/malformed keeps the current phase: never advance without a
    // conclusive Relay response.
    throw recoveryRequired('Relay revoke could not be completed; retry to resume recovery', error);
  }
  return {
    kind: 'transition',
    transition: { phase: 'old-identity-revoked', revoke: { state: 'complete', outcome } },
  };
}

type PersistSigningIntentDeps = Pick<HostResetExecutorDependencies, 'now'>;

async function executePersistSigningReplacementIntent(
  deps: PersistSigningIntentDeps,
): Promise<HostResetExecutorResult> {
  const timestamp = (deps.now?.() ?? new Date()).toISOString();
  return {
    kind: 'transition',
    transition: { phase: 'signing-replacement-pending', signingReplacementAttemptedAt: timestamp },
  };
}

type ReplaceSigningIdentityDeps = Pick<
  HostResetExecutorDependencies,
  'identityStore' | 'replace' | 'hooks'
>;

async function executeReplaceSigningIdentity(
  journal: HostDomainResetJournalV1,
  deps: ReplaceSigningIdentityDeps,
): Promise<HostResetExecutorResult> {
  const replacement = await adoptOrReplaceSigningIdentity(deps.identityStore, journal, deps.replace);
  if (journal.oldHostId && deps.identityStore.deleteAfterHostReplacement
    && !deps.identityStore.completeExplicitReset) {
    deps.identityStore.deleteAfterHostReplacement(journal.oldHostId);
  }
  deps.hooks?.afterEffect?.('signing-replaced');
  return {
    kind: 'transition',
    transition: { phase: 'signing-identity-replaced', newHostId: replacement.hostId, newKeyId: replacement.keyId },
  };
}

type FinalizeSigningDeps = Pick<
  HostResetExecutorDependencies,
  'identityStore' | 'encryptionStore' | 'hooks' | 'now'
>;

async function executeFinalizeSigningAndReplaceEncryptionIdentity(
  journal: HostDomainResetJournalV1,
  deps: FinalizeSigningDeps,
): Promise<HostResetExecutorResult> {
  const replacement = await requireReplacement(deps.identityStore, journal);
  // Operation-bound signing finalizer must succeed before ANY X25519 effect.
  deps.identityStore.completeExplicitReset?.(journal.operationId);

  const encryptionStore = deps.encryptionStore;
  let encryptionIdentity = encryptionStore.recoverReset?.(replacement.hostId, journal.operationId)
    ?? encryptionStore.load();
  if (encryptionIdentity && encryptionIdentity.hostId !== replacement.hostId) {
    if (!phaseBefore(journal.phase, 'encryption-identity-replaced')) {
      throw recoveryRequired('Replacement Host encryption identity evidence is invalid');
    }
    encryptionIdentity = null;
  }
  if (!encryptionIdentity) {
    if (!phaseBefore(journal.phase, 'encryption-identity-replaced')) {
      throw recoveryRequired('Replacement Host encryption identity evidence is missing');
    }
    encryptionIdentity = encryptionStore.recoverReset?.(replacement.hostId, journal.operationId)
      ?? encryptionStore.replaceForReset(replacement.hostId, journal.operationId);
  }
  if (journal.oldEncryptionKeyId && encryptionStore.deleteAfterHostReplacement
    && !encryptionStore.completeReset) {
    encryptionStore.deleteAfterHostReplacement(journal.oldEncryptionKeyId);
  }
  deps.hooks?.afterEffect?.('encryption-replaced');
  return {
    kind: 'transition',
    transition: {
      phase: 'encryption-identity-replaced',
      encryptionIdentityReplacedAt: (deps.now?.() ?? new Date()).toISOString(),
    },
  };
}

type FinalizeEncryptionDeps = Pick<
  HostResetExecutorDependencies,
  'resources' | 'identityStore' | 'encryptionStore' | 'spoolKeyStore' | 'runtime' | 'hooks' | 'now'
>;

async function executeFinalizeEncryptionAndClearRuntimeArtifacts(
  journal: HostDomainResetJournalV1,
  deps: FinalizeEncryptionDeps,
): Promise<HostResetExecutorResult> {
  const replacement = await requireReplacement(deps.identityStore, journal);
  const encryptionIdentity = deps.encryptionStore.load();
  if (!encryptionIdentity || encryptionIdentity.hostId !== replacement.hostId) {
    throw recoveryRequired('Replacement Host encryption identity evidence is invalid');
  }
  // Operation-bound X25519 finalizer must succeed before any artifact cleanup.
  deps.encryptionStore.completeReset?.(journal.operationId);

  const coordinator = deps.runtime.held;
  if (!coordinator) {
    throw recoveryRequired('Runtime ownership was not held when clearing Host reset artifacts');
  }
  assertArtifactCleanupBoundary();
  const expectedOldSpoolHostId = journal.revoke.outcome === 'old-identity-unreadable'
    ? undefined
    : journal.oldHostId ?? undefined;
  clearHostDomainArtifacts(deps.resources, coordinator, deps.spoolKeyStore, expectedOldSpoolHostId);
  deps.hooks?.afterEffect?.('artifacts-cleared');
  return {
    kind: 'transition',
    transition: {
      phase: 'runtime-artifacts-cleared',
      runtimeArtifactsClearedAt: (deps.now?.() ?? new Date()).toISOString(),
    },
  };
}

type PersistConfigDeps = Pick<
  HostResetExecutorDependencies,
  'resources' | 'identityStore' | 'config' | 'baseConfig' | 'access' | 'hooks' | 'now'
>;

async function executePersistConfig(
  journal: HostDomainResetJournalV1,
  deps: PersistConfigDeps,
): Promise<HostResetExecutorResult> {
  const replacement = await requireReplacement(deps.identityStore, journal);
  const expectedConfig = { ...deps.baseConfig, identity: publicIdentityMetadata(replacement) };
  const configPath = deps.resources.configPath;
  const currentConfig = deps.config.load(configPath);
  if (JSON.stringify(currentConfig.identity) !== JSON.stringify(expectedConfig.identity)) {
    deps.access?.('filesystemWrites', configPath);
    deps.config.save(expectedConfig, configPath);
  }
  deps.hooks?.afterEffect?.('config-saved');
  return {
    kind: 'transition',
    transition: { phase: 'config-saved', configSavedAt: (deps.now?.() ?? new Date()).toISOString() },
  };
}

type EnrollNewIdentityDeps = Pick<
  HostResetExecutorDependencies,
  'resources' | 'identityStore' | 'encryptionStore' | 'config' | 'relayBaseUrl' | 'hostName' | 'platform' | 'bridgeVersion' | 'enroll' | 'hooks' | 'now'
>;

async function executeEnrollNewIdentity(
  journal: HostDomainResetJournalV1,
  deps: EnrollNewIdentityDeps,
): Promise<HostResetExecutorResult> {
  const replacement = await requireReplacement(deps.identityStore, journal);
  const currentConfig = deps.config.load(deps.resources.configPath);
  if (JSON.stringify(currentConfig.identity) !== JSON.stringify(publicIdentityMetadata(replacement))) {
    throw recoveryRequired('Replacement Host config identity evidence is invalid');
  }
  const encryptionIdentity = deps.encryptionStore.load();
  if (!encryptionIdentity || encryptionIdentity.hostId !== replacement.hostId) {
    throw recoveryRequired('Replacement Host encryption identity evidence is invalid');
  }
  await deps.enroll(replacement, {
    hostName: deps.hostName,
    platform: deps.platform,
    bridgeVersion: deps.bridgeVersion,
  }, encryptionIdentity);
  deps.hooks?.afterEffect?.('enrolled');
  return {
    kind: 'transition',
    transition: { phase: 'enrolled', enrolledAt: (deps.now?.() ?? new Date()).toISOString() },
  };
}

type SyncMetadataDeps = Pick<
  HostResetExecutorDependencies,
  'identityStore' | 'lifecycle' | 'hooks' | 'now'
>;

async function executeSyncServiceMetadata(
  journal: HostDomainResetJournalV1,
  deps: SyncMetadataDeps,
): Promise<HostResetExecutorResult> {
  const replacement = await requireReplacement(deps.identityStore, journal);
  deps.lifecycle.synchronizeMetadata(journal.service, publicIdentityMetadata(replacement).privateKeyStorage);
  deps.hooks?.afterEffect?.('service-metadata-synchronized');
  return {
    kind: 'transition',
    transition: {
      phase: 'service-metadata-synchronized',
      serviceMetadataSynchronizedAt: (deps.now?.() ?? new Date()).toISOString(),
    },
  };
}

type PersistRestoreIntentDeps = Pick<HostResetExecutorDependencies, 'identityStore'>;

async function executePersistServiceRestoreIntent(
  journal: HostDomainResetJournalV1,
  deps: PersistRestoreIntentDeps,
): Promise<HostResetExecutorResult> {
  // Replacement and service metadata must be valid before the final commit
  // intent is persisted. The journal itself is NOT removed here.
  await requireReplacement(deps.identityStore, journal);
  return { kind: 'transition', transition: { phase: 'service-restore-pending' } };
}

async function executeRestoreServiceAndRemoveJournal(
  journal: HostDomainResetJournalV1,
): Promise<HostResetExecutorResult> {
  if (journal.phase !== 'service-restore-pending') {
    throw recoveryRequired(`Restore requires a service-restore-pending journal, got ${journal.phase}`);
  }
  // Routing seam (coordinator-routed): validate the restore precondition and
  // return the outcome the coordinator routes into the recovery module with
  // the still-owned operation lease. The recovery module performs rehydrate,
  // re-quarantine, replacement verification, runtime ownership release,
  // idempotent restoreAndConfirm, single-use confirmation, and guarded
  // removal; it receives the lease as a parameter.
  return { kind: 'restore', outcome: { journal, recoveryOwned: true } };
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/**
 * Runs the executor for one machine action against the current journal.
 * The executor returns the exact transition (or restore outcome) it commits;
 * the coordinator's loop is the only caller and commits via the secure store.
 */
export async function executeHostResetAction(
  action: HostResetAction,
  journal: HostDomainResetJournalV1,
  dependencies: HostResetExecutorDependencies,
): Promise<HostResetExecutorResult> {
  switch (action.type) {
    case 'stop-quarantine-and-acquire-runtime':
      return executeStopQuarantineAndAcquireRuntime(journal, dependencies);
    case 'inspect-and-bind-old-domain':
      return executeInspectAndBindOldDomain(journal, dependencies);
    case 'persist-revoke-intent':
      return executePersistRevokeIntent(journal);
    case 'revoke-old-identity':
      return executeRevokeOldIdentity(journal, dependencies);
    case 'persist-signing-replacement-intent':
      return executePersistSigningReplacementIntent(dependencies);
    case 'replace-signing-identity':
      return executeReplaceSigningIdentity(journal, dependencies);
    case 'finalize-signing-and-replace-encryption-identity':
      return executeFinalizeSigningAndReplaceEncryptionIdentity(journal, dependencies);
    case 'finalize-encryption-and-clear-runtime-artifacts':
      return executeFinalizeEncryptionAndClearRuntimeArtifacts(journal, dependencies);
    case 'persist-config':
      return executePersistConfig(journal, dependencies);
    case 'enroll-new-identity':
      return executeEnrollNewIdentity(journal, dependencies);
    case 'sync-service-metadata':
      return executeSyncServiceMetadata(journal, dependencies);
    case 'persist-service-restore-intent':
      return executePersistServiceRestoreIntent(journal, dependencies);
    case 'restore-service-and-remove-journal':
      return executeRestoreServiceAndRemoveJournal(journal);
  }
}
