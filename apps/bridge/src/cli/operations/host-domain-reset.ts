import { randomUUID } from 'node:crypto';
import type { HostPlatform } from '@ariava/protocol';
import { probeHostPlatform } from '../../host-platform';
import type {
  HostEncryptionIdentity,
  HostEncryptionIdentityStore,
  HostIdentity,
  HostIdentityStore,
} from '../../identity';
import type { HostReplacementSpoolKeyStore } from '../../e2e/local-spool';
import type { RuntimeCoordinator } from '../../runtime-lock';
import { AriavaCliError } from '../../host-manager/service/errors';
import { buildProfileInitializedConfig } from './initialize';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  advanceHostDomainResetJournal,
  createHostDomainResetJournal,
  hostDomainResourceDigest,
  loadHostDomainResetJournal,
  type HostDomainResetJournalV1,
  type HostDomainResetServiceBackend,
  type HostDomainResetTransition,
} from './host-domain-reset-journal';
import { nextHostResetAction } from './host-domain-reset-machine';
import {
  activeRuntimeError,
  executeHostResetAction,
  type HostResetExecutorDependencies,
  type HostResetRuntimePort,
} from './host-domain-reset-executor';
import {
  prepareRecovery,
  recoverServiceRestorePending,
} from './host-domain-reset-recovery';
import type { HostIdentityOperationLease } from './host-identity-operation-lock';
import type { ProfileResourceSet } from '../profile';
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
  return context.hostIdentityOperationLock.run(loaded.resources, async (operationLease) => {
    try {
      return await resetHostDomainUnlocked(context, dependencies, operationLease, (journal) => { recoveryJournal = journal; });
    } catch (error) {
      throw normalizeResetRecoveryError(context, recoveryJournal, error);
    }
  });
}

/**
 * Thin coordinator (primary spec §6–§8, §11 step 8).
 *
 * The coordinator owns ONLY: descriptor validation, profile resource
 * resolution, the Host identity operation lease (obtained by the public
 * entry), the fresh-reset bootstrap (§7.1), the machine-driven loop
 * (nextHostResetAction -> exact executor -> secure store advance), and the
 * restore routing seam into the recovery module. It never parses raw JSON,
 * compares phases itself, computes resource digests itself, or owns effect
 * stores beyond constructing the narrow dependency bundle the executors
 * consume. The journal is the only durable phase/transition authority.
 */
async function resetHostDomainUnlocked(
  context: AriavaProfileCliContext,
  dependencies: HostDomainResetPrimitive,
  operationLease: HostIdentityOperationLease,
  recordRecoveryJournal: (journal: HostDomainResetJournalV1) => void,
): Promise<HostDomainResetResult> {
  context.validation.descriptor();
  const loaded = await import('../context').then(({ loadResolvedProfileConfig }) => loadResolvedProfileConfig(context));
  const baseConfig = buildProfileInitializedConfig(context, loaded.fileConfig);
  const resolved = { ...loaded.resolved, ...baseConfig };
  const resources = context.validation.resolved(resolved);

  let journal = loadHostDomainResetJournal(resources);
  if (journal) recordRecoveryJournal(journal);

  // Runtime exclusivity port: acquired at quarantine (fresh bootstrap or the
  // stop-quarantine executor on resume), disposed in the coordinator's finally,
  // and released by the recovery module before restore. Never a removal proof.
  let heldCoordinator: RuntimeCoordinator | undefined;
  const runtime: HostResetRuntimePort = {
    acquire: () => context.runtimeCoordinator.acquire(resources),
    get held() { return heldCoordinator; },
    set held(value) { heldCoordinator = value; },
    release() {
      heldCoordinator?.dispose();
      heldCoordinator = undefined;
    },
  };

  // Stores are created lazily on first executor access: no identity/E2E/
  // spool-key store exists before the quarantine advance (nothing
  // identity/Relay/destructive happens before `quarantined`).
  let identityStore: HostIdentityStore | undefined;
  let encryptionStore: HostEncryptionIdentityStore | undefined;
  let spoolKeyStore: HostReplacementSpoolKeyStore | undefined;

  const executorDeps: HostResetExecutorDependencies = {
    profileId: context.profile.id,
    resources,
    get identityStore() { return identityStore ??= context.identity.create(resources, context.platform); },
    get encryptionStore() { return encryptionStore ??= context.encryptionIdentity.create(resources, context.platform); },
    get spoolKeyStore() { return spoolKeyStore ??= context.hostReplacementSpoolKey.create(resources, context.platform); },
    lifecycle: context.hostDomainResetLifecycle,
    runtime,
    config: context.config,
    baseConfig,
    relayBaseUrl: resolved.relayBaseUrl,
    hostName: resolved.hostName,
    platform: probeHostPlatform(context.platform),
    bridgeVersion: dependencies.bridgeVersion,
    revoke: (identity) => dependencies.revoke(identity, resolved.relayBaseUrl),
    replace: dependencies.replace,
    enroll: (identity, metadata, encryptionIdentity) =>
      dependencies.enroll(resolved.relayBaseUrl, identity, metadata, encryptionIdentity),
    access: context.access,
    hooks: dependencies.hooks
      ? { afterEffect: dependencies.hooks.afterEffect }
      : undefined,
  };

  const advance = (transition: HostDomainResetTransition): HostDomainResetJournalV1 => {
    journal = advanceHostDomainResetJournal(resources, journal!, transition, operationLease);
    recordRecoveryJournal(journal);
    dependencies.hooks?.afterPhase?.(journal.phase);
    return journal;
  };

  const acquireRuntimeOwnership = (): void => {
    try {
      runtime.held = runtime.acquire();
    } catch (error) {
      throw activeRuntimeError(context.profile.id, error);
    }
  };

  try {
    if (!journal) {
      // §7.1 fresh bootstrap: prepare -> create quarantine-pending journal
      // (durable snapshot + digest binding) -> stopAndConfirm -> acquire runtime
      // exclusivity -> machine-issued transition to quarantined. Nothing
      // identity/Relay/destructive happens before `quarantined`.
      const service = context.hostDomainResetLifecycle.prepare(resources);
      journal = createHostDomainResetJournal(
        resources,
        buildInitialJournal(context, resources, service),
        operationLease,
      );
      recordRecoveryJournal(journal);
      context.hostDomainResetLifecycle.stopAndConfirm(service);
      dependencies.hooks?.afterPhase?.(journal.phase);
      acquireRuntimeOwnership();
      advance({ phase: 'quarantined' });
    } else {
      // Every resumed invocation (any phase) rehydrates the FRESH lifecycle
      // adapter and compares only managed/installed/enabled/backend before any
      // action selection or effect.
      prepareRecovery(executorDeps, journal);
      // Mid-flight resumes (prepared .. service-metadata-synchronized)
      // re-quarantine exactly like the monolithic entry: stopAndConfirm the
      // immutable snapshot, then re-acquire runtime exclusivity so the
      // artifact-clear executor finds ownership held. quarantine-pending is
      // handled by the stop-quarantine executor; service-restore-pending by
      // the recovery module.
      if (journal.phase !== 'quarantine-pending' && journal.phase !== 'service-restore-pending') {
        context.hostDomainResetLifecycle.stopAndConfirm(journal.service);
        acquireRuntimeOwnership();
      }
    }

    while (true) {
      const action = nextHostResetAction(journal);
      if (action.type === 'restore-service-and-remove-journal') {
        return await recoverServiceRestorePending(executorDeps, journal, operationLease);
      }
      const result = await executeHostResetAction(action, journal, executorDeps);
      if (result.kind === 'restore') {
        return await recoverServiceRestorePending(executorDeps, journal, operationLease);
      }
      advance(result.transition);
    }
  } finally {
    runtime.release();
  }
}

function buildInitialJournal(
  context: AriavaProfileCliContext,
  resources: ProfileResourceSet,
  service: HostDomainResetJournalV1['service'],
): HostDomainResetJournalV1 {
  const timestamp = new Date().toISOString();
  return {
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
