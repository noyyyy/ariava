import { randomUUID } from 'node:crypto';
import type { HostPlatform } from '@ariava/protocol';
import { probeHostPlatform } from '../../host-platform';
import {
  publicIdentityMetadata,
  type HostEncryptionIdentity,
  type HostIdentity,
} from '../../identity';
import { HostIdentityError } from '../../identity/errors';
import { RESET_ONLY_IDENTITY_EVIDENCE_SOURCE } from '../../identity/reset-only-evidence-source';
import { inspectResetOnlyLegacyIdentityEvidence } from './identity-reset-legacy-evidence';
import { buildProfileInitializedConfig } from './initialize';
import { clearHostDomainArtifacts } from './host-domain-artifacts';
import { pathHasFilesystemEvidence } from '../../host-manager/secure-files';
import { AriavaCliError } from '../../host-manager/service/errors';
import { assertCurrentRuntimeArtifacts } from '../../state-store';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  advanceHostDomainResetJournal,
  createHostDomainResetJournal,
  hostDomainResourceDigest,
  identityResourceDigest,
  loadHostDomainResetJournal,
  removeAfterServiceRestoreConfirmed,
  type HostDomainResetJournalTransition,
  type HostDomainResetJournalV1,
  type HostDomainResetServiceBackend,
} from './host-domain-reset-journal';
import { restoreHostDomainServiceAndConfirm } from './host-domain-reset-journal-store';
import type { HostIdentityOperationLease } from './host-identity-operation-lock';
import type { AriavaProfileCliContext } from '../context';

export interface HostDomainResetPrimitive {
  bridgeVersion: string;
  revoke(identity: HostIdentity, relayBaseUrl: string): Promise<'revoked' | 'identity-already-revoked'>;
  replace(store: ReturnType<AriavaProfileCliContext['identity']['create']>, operationId: string): Promise<HostIdentity>;
  enroll(relayBaseUrl: string, identity: HostIdentity, metadata: {
    hostName: string; platform: HostPlatform; bridgeVersion: string;
  }, encryptionIdentity: HostEncryptionIdentity): Promise<void>;
  hooks?: HostDomainResetHooks;
}

export interface HostDomainResetHooks {
  afterPhase?(phase: HostDomainResetJournalV1['phase']): void;
  afterEffect?(effect: 'signing-replaced' | 'encryption-replaced' | 'artifacts-cleared' | 'config-saved' | 'enrolled' | 'service-metadata-synchronized' | 'service-restored'): void;
}

export interface HostDomainResetResult {
  hostId: string;
  keyId: string;
  revokedOldIdentity: boolean;
  links: [];
  watchPairingRequired: true;
  service: HostDomainResetJournalV1['service'] & { processRunning: boolean; status: 'unmanaged' | 'stopped' | 'running' };
  warning?: string;
}

export async function resetHostDomain(
  context: AriavaProfileCliContext,
  dependencies: HostDomainResetPrimitive,
): Promise<HostDomainResetResult> {
  context.validation.descriptor();
  const loaded = await import('../context').then(({ loadResolvedProfileConfig }) => loadResolvedProfileConfig(context));
  let recoveryJournal: HostDomainResetJournalV1 | null = null;
  return context.hostIdentityOperationLock.run(loaded.resources, async (lease) => {
    try {
      return await resetHostDomainUnlocked(context, dependencies, lease, (journal) => { recoveryJournal = journal; });
    } catch (error) {
      throw normalizeResetRecoveryError(context, recoveryJournal, error);
    }
  });
}

async function resetHostDomainUnlocked(
  context: AriavaProfileCliContext,
  dependencies: HostDomainResetPrimitive,
  lease: HostIdentityOperationLease,
  recordRecoveryJournal: (journal: HostDomainResetJournalV1) => void,
): Promise<HostDomainResetResult> {
  context.validation.descriptor();
  const loaded = await import('../context').then(({ loadResolvedProfileConfig }) => loadResolvedProfileConfig(context));
  const baseConfig = buildProfileInitializedConfig(context, loaded.fileConfig);
  const resolved = { ...loaded.resolved, ...baseConfig };
  const resources = context.validation.resolved(resolved);
  let journal = loadHostDomainResetJournal(resources);
  if (journal) recordRecoveryJournal(journal);
  let coordinator: ReturnType<AriavaProfileCliContext['runtimeCoordinator']['acquire']> | undefined;

  const now = (): string => new Date().toISOString();
  const advance = (transition: HostDomainResetJournalTransition) => {
    journal = advanceHostDomainResetJournal(resources, journal!, transition, lease);
    recordRecoveryJournal(journal);
    dependencies.hooks?.afterPhase?.(journal.phase);
    return journal;
  };

  let service: HostDomainResetJournalV1['service'];
  if (!journal) {
    service = context.hostDomainResetLifecycle.prepare(resources);
  } else {
    assertServiceSnapshot(context, resources, journal);
    service = journal.service;
  }

  if (!journal) {
    const timestamp = new Date().toISOString();
    journal = {
      version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
      operationId: `reset_${randomUUID().replaceAll('-', '')}`,
      profile: context.profile.id,
      phase: 'quarantine-pending',
      oldHostId: null,
      oldKeyId: null,
      newHostId: null,
      newKeyId: null,
      oldEncryptionKeyId: null,
      signingCleanup: null,
      signingReplacementAttemptedAt: null,
      encryptionIdentityReplacedAt: null,
      runtimeArtifactsClearedAt: null,
      configSavedAt: null,
      enrolledAt: null,
      serviceMetadataSynchronizedAt: null,
      resourceDigest: hostDomainResourceDigest(resources),
      createdAt: timestamp,
      updatedAt: timestamp,
      revoke: { state: 'not-attempted', outcome: null },
      service,
    };
    createHostDomainResetJournal(resources, journal, lease);
    recordRecoveryJournal(journal);
  }

  context.hostDomainResetLifecycle.stopAndConfirm(service);
  if (journal.phase === 'quarantine-pending') dependencies.hooks?.afterPhase?.(journal.phase);
  try {
    coordinator = context.runtimeCoordinator.acquire(resources);
  } catch (error) {
    throw activeRuntimeError(context, error);
  }
  let replacement: HostIdentity;
  try {
    if (journal.phase === 'quarantine-pending') advance({ kind: 'advance', phase: 'quarantined', at: now() });
    const store = context.identity.create(resources, context.platform);
    if (journal.phase === 'quarantined') {
      journal = await prepareIdentityInspectionJournal(
        context, resources, store, journal, lease, dependencies, recordRecoveryJournal,
      );
    }

    if (journal.phase === 'service-restore-pending') {
      const recoveredReplacement = await requireReplacement(store, journal);
      const encryptionIdentity = context.encryptionIdentity.create(resources, context.platform).load();
      if (!encryptionIdentity || encryptionIdentity.hostId !== recoveredReplacement.hostId) {
        throw recoveryRequired('Replacement Host encryption identity evidence is invalid');
      }
      const currentConfig = context.config.load(context.profile.resources.configPath);
      if (JSON.stringify(currentConfig.identity) !== JSON.stringify(publicIdentityMetadata(recoveredReplacement))) {
        throw recoveryRequired('Replacement Host config identity evidence is invalid');
      }
      if (pathHasFilesystemEvidence(resources.linkKeyringPath) || pathHasFilesystemEvidence(resources.runtimeResetIntentPath)) {
        throw recoveryRequired('Old or incomplete Host-bound runtime artifacts were reintroduced during reset recovery');
      }
      const stateExists = pathHasFilesystemEvidence(resources.statePath);
      const spoolExists = pathHasFilesystemEvidence(resources.encryptedSpoolPath);
      if (stateExists !== spoolExists) throw recoveryRequired('Replacement Host runtime artifact pair is incomplete');
      if (stateExists) {
        try { assertCurrentRuntimeArtifacts(resources.statePath, recoveredReplacement.hostId); }
        catch (error) { throw recoveryRequired('Replacement Host runtime artifact evidence is invalid', error); }
      } else {
        context.hostReplacementSpoolKey.create(resources, context.platform).assertAbsentForHostReplacement();
      }
      coordinator.dispose();
      coordinator = undefined;
      const identityReference = publicIdentityMetadata(recoveredReplacement).privateKeyStorage;
      const { processRunning, confirmation } = restoreHostDomainServiceAndConfirm(
        resources,
        journal,
        lease,
        identityReference,
        (snapshot, reference) => context.hostDomainResetLifecycle.restoreAndConfirm(snapshot, reference),
      );
      removeAfterServiceRestoreConfirmed(resources, journal, lease, confirmation);
      return resetResult(journal, recoveredReplacement, processRunning);
    }
    const oldIdentity = await loadExpectedOldIdentity(store, journal);
    if (journal.phase === 'prepared') {
      if (oldIdentity) advance({ kind: 'start-revoke', at: now() });
      else advance({ kind: 'begin-signing-replacement', at: now() });
    }
    if (journal.phase === 'revoke-pending') {
      if (!oldIdentity) throw recoveryRequired('Old Host identity is unavailable while Relay revoke is pending');
      const outcome = await dependencies.revoke(oldIdentity, resolved.relayBaseUrl);
      advance({ kind: 'complete-revoke', at: now(), outcome });
    }
    if (journal.phase === 'old-identity-revoked') {
      advance({ kind: 'begin-signing-replacement', at: now() });
    }

    replacement = await adoptOrReplaceSigningIdentity(store, journal, dependencies);
    if (journal.oldHostId && store.deleteAfterHostReplacement && !store.completeExplicitReset) {
      store.deleteAfterHostReplacement(journal.oldHostId);
    }
    if (journal.phase === 'signing-replacement-pending') {
      dependencies.hooks?.afterEffect?.('signing-replaced');
      advance({
        kind: 'complete-signing-replacement',
        at: now(),
        newHostId: replacement.hostId,
        newKeyId: replacement.keyId,
      });
    }
    replacement = await requireReplacement(store, journal);
    store.completeExplicitReset?.(journal.operationId);

    const encryptionStore = context.encryptionIdentity.create(resources, context.platform);
    let encryptionIdentity = encryptionStore.recoverReset?.(replacement.hostId, journal.operationId) ?? encryptionStore.load();
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
    if (journal.oldEncryptionKeyId && encryptionStore.deleteAfterHostReplacement && !encryptionStore.completeReset) {
      encryptionStore.deleteAfterHostReplacement(journal.oldEncryptionKeyId);
    }
    dependencies.hooks?.afterEffect?.('encryption-replaced');
    if (phaseBefore(journal.phase, 'encryption-identity-replaced')) {
      advance({ kind: 'complete-encryption-replacement', at: now() });
    }
    encryptionStore.completeReset?.(journal.operationId);

    const expectedOldSpoolHostId = journal.revoke.outcome === 'old-identity-unreadable'
      ? undefined
      : journal.oldHostId ?? undefined;
    clearHostDomainArtifacts(
      resources, coordinator!, context.hostReplacementSpoolKey.create(resources, context.platform), expectedOldSpoolHostId,
    );
    dependencies.hooks?.afterEffect?.('artifacts-cleared');
    if (phaseBefore(journal.phase, 'runtime-artifacts-cleared')) {
      advance({ kind: 'complete-artifact-cleanup', at: now() });
    }

    const expectedConfig = { ...baseConfig, identity: publicIdentityMetadata(replacement) };
    const currentConfig = context.config.load(context.profile.resources.configPath);
    if (JSON.stringify(currentConfig.identity) !== JSON.stringify(expectedConfig.identity)) {
      context.access?.('filesystemWrites', context.profile.resources.configPath);
      context.config.save(expectedConfig, context.profile.resources.configPath);
    }
    dependencies.hooks?.afterEffect?.('config-saved');
    if (phaseBefore(journal.phase, 'config-saved')) {
      advance({ kind: 'complete-config-save', at: now() });
    }

    await dependencies.enroll(resolved.relayBaseUrl, replacement, {
      hostName: resolved.hostName,
      platform: probeHostPlatform(context.platform),
      bridgeVersion: dependencies.bridgeVersion,
    }, encryptionIdentity);
    dependencies.hooks?.afterEffect?.('enrolled');
    if (phaseBefore(journal.phase, 'enrolled')) {
      advance({ kind: 'complete-enrollment', at: now() });
    }

    context.hostDomainResetLifecycle.synchronizeMetadata(
      journal.service, publicIdentityMetadata(replacement).privateKeyStorage,
    );
    dependencies.hooks?.afterEffect?.('service-metadata-synchronized');
    if (phaseBefore(journal.phase, 'service-metadata-synchronized')) {
      advance({ kind: 'complete-metadata-sync', at: now() });
    }
    if (phaseBefore(journal.phase, 'service-restore-pending')) advance({ kind: 'complete-restore-intent', at: now() });
  } finally {
    coordinator?.dispose();
  }

  const identityReference = publicIdentityMetadata(replacement!).privateKeyStorage;
  const { processRunning, confirmation } = restoreHostDomainServiceAndConfirm(
    resources,
    journal,
    lease,
    identityReference,
    (snapshot, reference) => context.hostDomainResetLifecycle.restoreAndConfirm(snapshot, reference),
  );
  dependencies.hooks?.afterEffect?.('service-restored');
  removeAfterServiceRestoreConfirmed(resources, journal, lease, confirmation);
  return resetResult(journal, replacement!, processRunning);
}

function activeRuntimeError(context: AriavaProfileCliContext, _error: unknown): AriavaCliError {
  return new AriavaCliError(
    'ERR_HOST_RESET_RUNTIME_ACTIVE',
    `${context.profile.id === 'dev' ? 'Stop the foreground dev Bridge and retry. ' : ''}Host reset runtime is active`,
    { retryable: true, remediation: { message: 'Stop the active Bridge runtime, then retry Host reset.' } },
  );
}

function recoveryRequired(message: string, _cause?: unknown): AriavaCliError {
  return new AriavaCliError('ERR_HOST_RESET_RECOVERY_REQUIRED', message, {
    retryable: true, remediation: { message: 'Retry the same Host reset command to resume recovery.' },
  });
}

function normalizeResetRecoveryError(
  context: AriavaProfileCliContext, journal: HostDomainResetJournalV1 | null, error: unknown,
): unknown {
  if (!journal) return error;
  const command = context.profile.id === 'dev'
    ? 'bun run dev:cli -- identity reset --confirm'
    : 'ariava identity reset --confirm';
  const normalized = new AriavaCliError(
    'ERR_HOST_RESET_RECOVERY_REQUIRED',
    `Host reset recovery requires attention at phase ${journal.phase}.`,
    {
      phase: journal.phase, operationId: journal.operationId, retryable: true,
      remediation: { message: `Retry the profile-specific Host reset recovery command: ${command}`, command },
    },
  );
  Object.defineProperty(normalized, 'cause', { value: error, enumerable: false });
  return normalized;
}

async function loadExpectedOldIdentity(
  store: ReturnType<AriavaProfileCliContext['identity']['create']>,
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

async function adoptOrReplaceSigningIdentity(
  store: ReturnType<AriavaProfileCliContext['identity']['create']>,
  journal: HostDomainResetJournalV1,
  dependencies: HostDomainResetPrimitive,
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
    return dependencies.replace(store, journal.operationId);
  }
  if (journal.newHostId !== null) {
    if (current?.hostId !== journal.newHostId || current.keyId !== journal.newKeyId) {
      throw recoveryRequired('Replacement Host signing identity evidence is invalid');
    }
    return current;
  }
  if (current && current.hostId !== journal.oldHostId) {
    if (!provenCandidate || current.hostId !== provenCandidate.hostId || current.keyId !== provenCandidate.keyId) {
      return dependencies.replace(store, journal.operationId);
    }
    return provenCandidate;
  }
  if (journal.phase !== 'signing-replacement-pending') {
    throw recoveryRequired('Replacement Host signing identity evidence is missing');
  }
  prepareExactSigningCleanup(store, journal);
  return provenCandidate ?? dependencies.replace(store, journal.operationId);
}

async function requireReplacement(
  store: ReturnType<AriavaProfileCliContext['identity']['create']>,
  journal: HostDomainResetJournalV1,
): Promise<HostIdentity> {
  if (!journal.newHostId || !journal.newKeyId) throw recoveryRequired('Replacement Host identity is not journaled');
  const current = await store.load();
  if (!current || current.hostId !== journal.newHostId || current.keyId !== journal.newKeyId) {
    throw recoveryRequired('Replacement Host signing identity evidence is invalid');
  }
  return current;
}

async function prepareIdentityInspectionJournal(
  context: AriavaProfileCliContext,
  resources: Parameters<typeof hostDomainResourceDigest>[0],
  store: ReturnType<AriavaProfileCliContext['identity']['create']>,
  journal: HostDomainResetJournalV1,
  lease: HostIdentityOperationLease,
  dependencies: HostDomainResetPrimitive,
  recordRecoveryJournal: (journal: HostDomainResetJournalV1) => void,
): Promise<HostDomainResetJournalV1> {
  if (journal.phase !== 'quarantined') return journal;
  let oldIdentity: HostIdentity | null = null;
  let legacyEvidence: ReturnType<typeof inspectResetOnlyLegacyIdentityEvidence> | undefined;
  try {
    oldIdentity = await store.load();
  } catch (error) {
    if (!isDefiniteResetRequiredIdentityError(error)) throw error;
    legacyEvidence = inspectResetOnlyLegacyIdentityEvidence(store);
    if (legacyEvidence.classification !== 'old-identity-unreadable') throw error;
  }
  if (oldIdentity && RESET_ONLY_IDENTITY_EVIDENCE_SOURCE in store) {
    const decoded = inspectResetOnlyLegacyIdentityEvidence(store);
    if (decoded.source.kind === 'macos-keychain') legacyEvidence = decoded;
  }
  const oldEncryptionIdentity = context.encryptionIdentity.create(resources, context.platform).load();
  const prepared = advanceHostDomainResetJournal(resources, journal, {
    kind: 'bind-prepared',
    at: new Date().toISOString(),
    oldHostId: oldIdentity?.hostId ?? legacyEvidence?.oldHostId ?? null,
    oldKeyId: oldIdentity?.keyId ?? legacyEvidence?.oldKeyId ?? null,
    oldEncryptionKeyId: oldEncryptionIdentity?.encryptionKeyId ?? null,
    signingCleanup: legacyEvidence ? {
      kind: legacyEvidence.source.kind,
      resourceDigest: identityResourceDigest(legacyEvidence.source.resourcePath),
      profile: context.profile.id,
      previousAccount: legacyEvidence.cleanup?.previousAccount ?? null,
      previousPendingAccount: legacyEvidence.cleanup?.previousPendingAccount ?? null,
      interruptedCreationAccount: legacyEvidence.cleanup?.interruptedCreationAccount ?? null,
    } : null,
    revoke: oldIdentity ? { state: 'not-attempted', outcome: null } : { state: 'skipped', outcome: 'old-identity-unreadable' },
  }, lease);
  recordRecoveryJournal(prepared);
  dependencies.hooks?.afterPhase?.(prepared.phase);
  return prepared;
}

function prepareExactSigningCleanup(
  store: ReturnType<AriavaProfileCliContext['identity']['create']>,
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

function isDefiniteResetRequiredIdentityError(error: unknown): boolean {
  return error instanceof HostIdentityError && [
    'ERR_IDENTITY_INVALID',
    'ERR_IDENTITY_MISSING',
    'ERR_IDENTITY_RESET_REQUIRED',
  ].includes(error.code);
}


function assertServiceSnapshot(
  context: AriavaProfileCliContext,
  resources: unknown,
  journal: HostDomainResetJournalV1,
): void {
  const current = context.hostDomainResetLifecycle.prepare(resources);
  if (current.managed !== journal.service.managed
    || current.installed !== journal.service.installed
    || current.enabled !== journal.service.enabled
    || current.backend !== journal.service.backend) {
    throw recoveryRequired('Host reset service state changed during recovery');
  }
}

function resetResult(
  journal: HostDomainResetJournalV1, replacement: HostIdentity, processRunning: boolean,
): HostDomainResetResult {
  return {
    hostId: replacement.hostId,
    keyId: replacement.keyId,
    revokedOldIdentity: journal.revoke.outcome === 'revoked' || journal.revoke.outcome === 'identity-already-revoked',
    links: [],
    watchPairingRequired: true,
    ...(journal.revoke.outcome === 'old-identity-unreadable'
      ? { warning: 'Old Host identity could not be loaded or revoked: ERR_IDENTITY_INVALID' }
      : {}),
    service: {
      ...journal.service, processRunning,
      status: journal.service.managed ? (processRunning ? 'running' : 'stopped') : 'unmanaged',
    },
  };
}

function phaseBefore(left: HostDomainResetJournalV1['phase'], right: HostDomainResetJournalV1['phase']): boolean {
  const phases: HostDomainResetJournalV1['phase'][] = [
    'quarantine-pending', 'quarantined', 'prepared', 'revoke-pending', 'old-identity-revoked',
    'signing-replacement-pending', 'signing-identity-replaced', 'encryption-identity-replaced',
    'runtime-artifacts-cleared', 'config-saved', 'enrolled', 'service-metadata-synchronized',
    'service-restore-pending',
  ];
  return phases.indexOf(left) < phases.indexOf(right);
}

export interface HostDomainResetLifecycleAdapter {
  prepare(resources: unknown): HostDomainResetJournalV1['service'];
  stopAndConfirm(snapshot: HostDomainResetJournalV1['service']): void;
  synchronizeMetadata(snapshot: HostDomainResetJournalV1['service'], identityReference: HostIdentity['privateKeyStorage']): void;
  restoreAndConfirm(snapshot: HostDomainResetJournalV1['service'], identityReference: HostIdentity['privateKeyStorage']): boolean;
  validateRestored(snapshot: HostDomainResetJournalV1['service'], identityReference: HostIdentity['privateKeyStorage']): boolean;
}

export function unmanagedHostDomainResetLifecycle(): HostDomainResetLifecycleAdapter {
  const snapshot = { managed: false, installed: false, enabled: false, wasRunning: false, backend: 'none' as HostDomainResetServiceBackend };
  return {
    prepare: () => snapshot,
    stopAndConfirm() {},
    synchronizeMetadata() {},
    restoreAndConfirm: () => false,
    validateRestored: () => false,
  };
}
