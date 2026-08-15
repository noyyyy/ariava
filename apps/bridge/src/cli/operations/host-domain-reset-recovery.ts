import { publicIdentityMetadata, type HostEncryptionIdentityStore, type HostIdentity, type HostIdentityStore } from '../../identity';
import type { HostReplacementSpoolKeyStore } from '../../e2e/local-spool';
import type { RuntimeCoordinator } from '../../runtime-lock';
import { pathHasFilesystemEvidence } from '../../host-manager/secure-files';
import { assertCurrentRuntimeArtifacts } from '../../state-store';
import type { AriavaProfileId, ProfileResourceSet } from '../profile';
import {
  activeRuntimeError,
  recoveryRequired,
  requireReplacement,
  type HostResetConfigPort,
  type HostResetHooks,
  type HostResetLifecyclePort,
  type HostResetRuntimePort,
} from './host-domain-reset-executor';
import {
  removeAfterServiceRestoreConfirmed,
  restoreHostDomainServiceAndConfirm,
} from './host-domain-reset-journal-store';
import type { HostIdentityOperationLease } from './host-identity-operation-lock';
import type { HostDomainResetJournalV1 } from './host-domain-reset-journal-schema';

/**
 * Host-domain reset recovery and service restoration (primary spec §9,
 * journal-boundary spec §8).
 *
 * This module owns the service-restore / recovery proof:
 *   - `prepareRecovery` rehydrates the FRESH lifecycle adapter and compares
 *     ONLY `managed`/`installed`/`enabled`/`backend` against the immutable
 *     journal service snapshot (never current running state against
 *     `journal.service.wasRunning`);
 *   - `recoverServiceRestorePending` runs the full `service-restore-pending`
 *     sequence: fresh rehydration, re-quarantine, replacement domain
 *     verification, runtime ownership release, idempotent `restoreAndConfirm`,
 *     opaque single-use confirmation, and guarded journal removal.
 *
 * The Host identity operation lease is received as an explicit parameter and
 * is never acquired or fabricated here. The journal advancement lock and the
 * guarded-removal refusals are enforced by the secure store. `validateRestored`
 * is never proof. A crash after a successful `restoreAndConfirm` but before
 * removal leaves the journal intact; the next invocation fully redoes the
 * sequence and obtains a fresh confirmation.
 *
 * Import boundary: this module imports the executor module (shared ports and
 * helpers), the public store surface (`restoreHostDomainServiceAndConfirm`,
 * `removeAfterServiceRestoreConfirmed`), schema types, identity/state-store/
 * secure-files evidence helpers, and the opaque lease type. It never imports
 * `cli/context.ts`, the coordinator module, raw store internals, or the
 * machine module.
 */

// ---------------------------------------------------------------------------
// Narrow dependency ports
// ---------------------------------------------------------------------------

/**
 * The narrow dependency bundle the recovery module consumes. Structurally a
 * subset of the executor dependency bundle, so the coordinator can pass its
 * full bundle here. `lifecycle` must be a FRESH-process adapter instance per
 * invocation: the caller constructs a new context/lifecycle adapter and never
 * reuses an old manager/install-record closure.
 */
export interface HostResetRecoveryDependencies {
  profileId: AriavaProfileId;
  resources: ProfileResourceSet;
  identityStore: HostIdentityStore;
  encryptionStore: HostEncryptionIdentityStore;
  spoolKeyStore: HostReplacementSpoolKeyStore;
  lifecycle: HostResetLifecyclePort;
  runtime: HostResetRuntimePort;
  config: HostResetConfigPort;
  hooks?: HostResetHooks;
}

/**
 * Final Host-domain reset result descriptor returned by the recovery module.
 * Structurally identical to the coordinator's public result so Task Group J's
 * coordinator can return it without conversion.
 */
export interface HostResetRecoveryResult {
  hostId: string;
  keyId: string;
  revokedOldIdentity: boolean;
  links: [];
  watchPairingRequired: true;
  service: HostDomainResetJournalV1['service'] & {
    processRunning: boolean;
    status: 'unmanaged' | 'stopped' | 'running';
  };
  warning?: string;
}

// ---------------------------------------------------------------------------
// Fresh lifecycle rehydration (primary spec §9)
// ---------------------------------------------------------------------------

/**
 * Fresh-process lifecycle rehydration guard, called for EVERY journal-bearing
 * invocation regardless of phase, before any action or effect.
 *
 * Rebuilds the manager/install-record closure via the fresh lifecycle
 * adapter's `prepare(resources)` and compares ONLY `managed`, `installed`,
 * `enabled`, `backend` against the immutable `journal.service` snapshot.
 * Current `processRunning`/`wasRunning` is NEVER compared to the historical
 * `journal.service.wasRunning` restore target. Any mismatch fails closed with
 * `ERR_HOST_RESET_RECOVERY_REQUIRED`.
 */
export function prepareRecovery(
  deps: HostResetRecoveryDependencies,
  journal: HostDomainResetJournalV1,
): void {
  const current = deps.lifecycle.prepare(deps.resources);
  if (current.managed !== journal.service.managed
    || current.installed !== journal.service.installed
    || current.enabled !== journal.service.enabled
    || current.backend !== journal.service.backend) {
    throw recoveryRequired('Host reset service state changed during recovery');
  }
}

// ---------------------------------------------------------------------------
// Service-restore-pending recovery sequence (primary spec §9)
// ---------------------------------------------------------------------------

/**
 * Runs the complete `service-restore-pending` sequence and performs guarded
 * journal removal. Receives the Host identity operation lease as an explicit
 * parameter; never acquires or fabricates it.
 *
 * Order (normative): fresh `prepare(resources)` -> re-`stopAndConfirm` ->
 * runtime exclusivity -> replacement signing/E2E/config/runtime evidence
 * verification -> RELEASE runtime ownership -> idempotent `restoreAndConfirm`
 * (even if filesystem/process evidence suggests prior start) -> single-use
 * confirmation -> guarded removal while the lease is still owned.
 */
export async function recoverServiceRestorePending(
  deps: HostResetRecoveryDependencies,
  journal: HostDomainResetJournalV1,
  operationLease: HostIdentityOperationLease,
): Promise<HostResetRecoveryResult> {
  if (journal.phase !== 'service-restore-pending') {
    throw recoveryRequired(`Restore requires a service-restore-pending journal, got ${journal.phase}`);
  }

  // (a) Fresh lifecycle rehydration: rebuild the closure and compare ONLY the
  // four immutable service fields. Fail closed before any action/effect.
  prepareRecovery(deps, journal);

  // (b) Idempotent re-stop using the immutable journal service snapshot.
  // This is unconditional, including same-process continuation: the final
  // restore action always re-quarantines before replacement verification.
  deps.lifecycle.stopAndConfirm(journal.service);

  // (c) Runtime exclusivity: obtain or confirm ownership. An active runtime
  // fails closed with ERR_HOST_RESET_RUNTIME_ACTIVE semantics.
  let coordinator: RuntimeCoordinator | undefined = deps.runtime.held;
  if (!coordinator) {
    try {
      coordinator = deps.runtime.acquire();
      deps.runtime.held = coordinator;
    } catch (error) {
      throw activeRuntimeError(deps.profileId, error);
    }
  }

  try {
    // (d) Replacement domain verification.
    const replacement = await requireReplacement(deps.identityStore, journal);

    const encryptionIdentity = deps.encryptionStore.load();
    if (!encryptionIdentity || encryptionIdentity.hostId !== replacement.hostId) {
      throw recoveryRequired('Replacement Host encryption identity evidence is invalid');
    }

    const currentConfig = deps.config.load(deps.resources.configPath);
    if (JSON.stringify(currentConfig.identity) !== JSON.stringify(publicIdentityMetadata(replacement))) {
      throw recoveryRequired('Replacement Host config identity evidence is invalid');
    }

    if (pathHasFilesystemEvidence(deps.resources.linkKeyringPath)
      || pathHasFilesystemEvidence(deps.resources.runtimeResetIntentPath)) {
      throw recoveryRequired('Old or incomplete Host-bound runtime artifacts were reintroduced during reset recovery');
    }

    const stateExists = pathHasFilesystemEvidence(deps.resources.statePath);
    const spoolExists = pathHasFilesystemEvidence(deps.resources.encryptedSpoolPath);
    if (stateExists !== spoolExists) throw recoveryRequired('Replacement Host runtime artifact pair is incomplete');
    if (stateExists) {
      try {
        assertCurrentRuntimeArtifacts(deps.resources.statePath, replacement.hostId);
      } catch (error) {
        throw recoveryRequired('Replacement Host runtime artifact evidence is invalid', error);
      }
    } else {
      deps.spoolKeyStore.assertAbsentForHostReplacement();
    }

    // (e) Release runtime ownership BEFORE restore. Runtime ownership is never
    // proof for guarded removal.
    coordinator.dispose();
    deps.runtime.release();
    coordinator = undefined;

    // (f/g) The store-owned recovery seam independently binds the verified
    // replacement identity/reference, invokes restoreAndConfirm, and issues
    // the in-process single-use confirmation only after a successful boolean
    // return. Ordinary callers cannot mint confirmations.
    const { processRunning, confirmation } = restoreHostDomainServiceAndConfirm(
      deps.resources,
      journal,
      operationLease,
      replacement,
      (snapshot, identityReference) => deps.lifecycle.restoreAndConfirm(snapshot, identityReference),
    );
    deps.hooks?.afterEffect?.('service-restored');

    // (h) Guarded removal consumes the exact confirmation while the operation
    // lease remains live and resource-bound.
    removeAfterServiceRestoreConfirmed(deps.resources, journal, operationLease, confirmation);

    // (i) Final result descriptor.
    return buildRecoveryResult(journal, replacement, processRunning);
  } finally {
    coordinator?.dispose();
    deps.runtime.release();
  }
}

function buildRecoveryResult(
  journal: HostDomainResetJournalV1,
  replacement: HostIdentity,
  processRunning: boolean,
): HostResetRecoveryResult {
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
