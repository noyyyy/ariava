import { randomUUID } from 'node:crypto';
import type { HostPlatform } from '@ariava/protocol';
import { probeHostPlatform } from '../../host-platform';
import {
  publicIdentityMetadata,
  type HostEncryptionIdentity,
  type HostIdentity,
} from '../../identity';
import { HostIdentityError } from '../../identity/errors';
import { buildProfileInitializedConfig } from './initialize';
import { clearHostDomainArtifacts } from './host-domain-artifacts';
import { pathHasFilesystemEvidence } from '../../host-manager/secure-files';
import { AriavaCliError } from '../../host-manager/service/errors';
import { assertCurrentRuntimeArtifacts } from '../../state-store';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  advanceHostDomainResetJournal,
  hostDomainResourceDigest,
  loadHostDomainResetJournal,
  removeHostDomainResetJournal,
  writeHostDomainResetJournal,
  type HostDomainResetJournalV1,
  type HostDomainResetServiceBackend,
} from './host-domain-reset-journal';
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
  return context.hostIdentityOperationLock.run(loaded.resources, async () => {
    try {
      return await resetHostDomainUnlocked(context, dependencies, (journal) => { recoveryJournal = journal; });
    } catch (error) {
      throw normalizeResetRecoveryError(context, recoveryJournal, error);
    }
  });
}

async function resetHostDomainUnlocked(
  context: AriavaProfileCliContext,
  dependencies: HostDomainResetPrimitive,
  recordRecoveryJournal: (journal: HostDomainResetJournalV1) => void,
): Promise<HostDomainResetResult> {
  context.validation.descriptor();
  const loaded = await import('../context').then(({ loadResolvedProfileConfig }) => loadResolvedProfileConfig(context));
  const baseConfig = buildProfileInitializedConfig(context, loaded.fileConfig);
  const resolved = { ...loaded.resolved, ...baseConfig };
  const resources = context.validation.resolved(resolved);
  const store = context.identity.create(resources, context.platform);
  let journal = loadHostDomainResetJournal(resources);
  if (journal) recordRecoveryJournal(journal);
  let coordinator: ReturnType<AriavaProfileCliContext['runtimeCoordinator']['acquire']> | undefined;

  if (!journal) {
    let oldIdentity: HostIdentity | null = null;
    try {
      oldIdentity = await store.load();
    } catch (error) {
      if (!isDefiniteResetRequiredIdentityError(error)) throw error;
    }
    const service = context.hostDomainResetLifecycle.prepare(resources);
    if (!service.managed) {
      try { coordinator = context.runtimeCoordinator.acquire(resources); }
      catch (error) { throw activeRuntimeError(context, error); }
    }
    try {
      const oldEncryptionIdentity = context.encryptionIdentity.create(resources, context.platform).load();
      const timestamp = new Date().toISOString();
      journal = {
        version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
        operationId: `reset_${randomUUID().replaceAll('-', '')}`,
        profile: context.profile.id,
        phase: 'prepared',
        oldHostId: oldIdentity?.hostId ?? null,
        oldKeyId: oldIdentity?.keyId ?? null,
        newHostId: null,
        newKeyId: null,
        oldEncryptionKeyId: oldEncryptionIdentity?.encryptionKeyId ?? null,
        signingReplacementAttemptedAt: null,
        encryptionIdentityReplacedAt: null,
        runtimeArtifactsClearedAt: null,
        configSavedAt: null,
        enrolledAt: null,
        serviceMetadataSynchronizedAt: null,
        resourceDigest: hostDomainResourceDigest(resources),
        createdAt: timestamp,
        updatedAt: timestamp,
        revoke: oldIdentity ? { state: 'not-attempted', outcome: null } : { state: 'skipped', outcome: 'old-identity-unreadable' },
        service,
      };
      writeHostDomainResetJournal(resources, journal);
      recordRecoveryJournal(journal);
      dependencies.hooks?.afterPhase?.(journal.phase);
    } catch (error) {
      coordinator?.dispose();
      throw error;
    }
    context.hostDomainResetLifecycle.stopAndConfirm(service);
    if (!coordinator) {
      try { coordinator = context.runtimeCoordinator.acquire(resources); }
      catch (error) { throw activeRuntimeError(context, error); }
    }
  } else if (journal.phase === 'service-restore-pending') {
    assertServiceSnapshot(context, resources, journal);
    const replacement = await requireReplacement(store, journal);
    const encryptionIdentity = context.encryptionIdentity.create(resources, context.platform).load();
    if (!encryptionIdentity || encryptionIdentity.hostId !== replacement.hostId) {
      throw recoveryRequired('Replacement Host encryption identity evidence is invalid');
    }
    const currentConfig = context.config.load(context.profile.resources.configPath);
    if (JSON.stringify(currentConfig.identity) !== JSON.stringify(publicIdentityMetadata(replacement))) {
      throw recoveryRequired('Replacement Host config identity evidence is invalid');
    }
    if (pathHasFilesystemEvidence(resources.linkKeyringPath) || pathHasFilesystemEvidence(resources.runtimeResetIntentPath)) {
      throw recoveryRequired('Old or incomplete Host-bound runtime artifacts were reintroduced during reset recovery');
    }
    const stateExists = pathHasFilesystemEvidence(resources.statePath);
    const spoolExists = pathHasFilesystemEvidence(resources.encryptedSpoolPath);
    if (stateExists !== spoolExists) throw recoveryRequired('Replacement Host runtime artifact pair is incomplete');
    if (stateExists) {
      try { assertCurrentRuntimeArtifacts(resources.statePath, replacement.hostId); }
      catch (error) { throw recoveryRequired('Replacement Host runtime artifact evidence is invalid', error); }
    } else {
      context.hostReplacementSpoolKey.create(resources, context.platform).assertAbsentForHostReplacement();
    }
    const processRunning = context.hostDomainResetLifecycle.restoreAndConfirm(
      journal.service, publicIdentityMetadata(replacement).privateKeyStorage,
    );
    removeHostDomainResetJournal(resources);
    return resetResult(journal, replacement, processRunning);
  } else {
    assertServiceSnapshot(context, resources, journal);
    context.hostDomainResetLifecycle.stopAndConfirm(journal.service);
    try { coordinator = context.runtimeCoordinator.acquire(resources); }
    catch (error) { throw activeRuntimeError(context, error); }
  }

  const advance = (patch: Parameters<typeof advanceHostDomainResetJournal>[2]) => {
    journal = advanceHostDomainResetJournal(
      resources,
      journal!,
      { ...patch, updatedAt: new Date().toISOString() },
      { operationLockHeld: true },
    );
    recordRecoveryJournal(journal);
    dependencies.hooks?.afterPhase?.(journal.phase);
    return journal;
  };

  let replacement: HostIdentity;
  try {
    const oldIdentity = await loadExpectedOldIdentity(store, journal);
    if (journal.phase === 'prepared') {
      if (oldIdentity) advance({ phase: 'revoke-pending', revoke: { state: 'pending', outcome: null } });
      else advance({
        phase: 'signing-replacement-pending',
        signingReplacementAttemptedAt: new Date().toISOString(),
      });
    }
    if (journal.phase === 'revoke-pending') {
      if (!oldIdentity) throw recoveryRequired('Old Host identity is unavailable while Relay revoke is pending');
      const outcome = await dependencies.revoke(oldIdentity, resolved.relayBaseUrl);
      advance({ phase: 'old-identity-revoked', revoke: { state: 'complete', outcome } });
    }
    if (journal.phase === 'old-identity-revoked') {
      advance({
        phase: 'signing-replacement-pending',
        signingReplacementAttemptedAt: new Date().toISOString(),
      });
    }

    replacement = await adoptOrReplaceSigningIdentity(store, journal, dependencies);
    if (journal.oldHostId && store.deleteAfterHostReplacement && !store.completeExplicitReset) {
      store.deleteAfterHostReplacement(journal.oldHostId);
    }
    if (journal.phase === 'signing-replacement-pending') {
      dependencies.hooks?.afterEffect?.('signing-replaced');
      advance({ phase: 'signing-identity-replaced', newHostId: replacement.hostId, newKeyId: replacement.keyId });
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
      advance({ phase: 'encryption-identity-replaced', encryptionIdentityReplacedAt: new Date().toISOString() });
    }
    encryptionStore.completeReset?.(journal.operationId);

    clearHostDomainArtifacts(
      resources, coordinator!, context.hostReplacementSpoolKey.create(resources, context.platform), journal.oldHostId ?? undefined,
    );
    dependencies.hooks?.afterEffect?.('artifacts-cleared');
    if (phaseBefore(journal.phase, 'runtime-artifacts-cleared')) {
      advance({ phase: 'runtime-artifacts-cleared', runtimeArtifactsClearedAt: new Date().toISOString() });
    }

    const expectedConfig = { ...baseConfig, identity: publicIdentityMetadata(replacement) };
    const currentConfig = context.config.load(context.profile.resources.configPath);
    if (JSON.stringify(currentConfig.identity) !== JSON.stringify(expectedConfig.identity)) {
      context.access?.('filesystemWrites', context.profile.resources.configPath);
      context.config.save(expectedConfig, context.profile.resources.configPath);
    }
    dependencies.hooks?.afterEffect?.('config-saved');
    if (phaseBefore(journal.phase, 'config-saved')) {
      advance({ phase: 'config-saved', configSavedAt: new Date().toISOString() });
    }

    await dependencies.enroll(resolved.relayBaseUrl, replacement, {
      hostName: resolved.hostName,
      platform: probeHostPlatform(context.platform),
      bridgeVersion: dependencies.bridgeVersion,
    }, encryptionIdentity);
    dependencies.hooks?.afterEffect?.('enrolled');
    if (phaseBefore(journal.phase, 'enrolled')) {
      advance({ phase: 'enrolled', enrolledAt: new Date().toISOString() });
    }

    context.hostDomainResetLifecycle.synchronizeMetadata(
      journal.service, publicIdentityMetadata(replacement).privateKeyStorage,
    );
    dependencies.hooks?.afterEffect?.('service-metadata-synchronized');
    if (phaseBefore(journal.phase, 'service-metadata-synchronized')) {
      advance({
        phase: 'service-metadata-synchronized',
        serviceMetadataSynchronizedAt: new Date().toISOString(),
      });
    }
    if (phaseBefore(journal.phase, 'service-restore-pending')) advance({ phase: 'service-restore-pending' });
  } finally {
    coordinator!.dispose();
  }

  const identityReference = publicIdentityMetadata(replacement!).privateKeyStorage;
  const processRunning = context.hostDomainResetLifecycle.restoreAndConfirm(journal.service, identityReference);
  dependencies.hooks?.afterEffect?.('service-restored');
  removeHostDomainResetJournal(resources);
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
    ? 'bun run dev:cli -- host reset --confirm'
    : 'ariava host reset --confirm';
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
  if (!journal.oldHostId) return null;
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
  const provenCandidate = await store.recoverExplicitReset?.(journal.operationId);
  let current: HostIdentity | null;
  try {
    current = await store.load();
  } catch (error) {
    if (!isDefiniteResetRequiredIdentityError(error)) throw error;
    if (provenCandidate) return provenCandidate;
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
    'prepared', 'revoke-pending', 'old-identity-revoked', 'signing-replacement-pending',
    'signing-identity-replaced', 'encryption-identity-replaced', 'runtime-artifacts-cleared',
    'config-saved', 'enrolled', 'service-metadata-synchronized', 'service-restore-pending',
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
