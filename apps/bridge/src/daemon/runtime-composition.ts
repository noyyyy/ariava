import { dirname, resolve } from 'node:path';
import { AGENT_ADAPTER_PROTOCOL_VERSION } from '@ariava/protocol';
import { AgentAdapterClient } from '../agent-adapter/client';
import type { AgentAdapterDiscoveryFile } from '../agent-adapter/config';
import { AgentAdapterRegistry } from '../agent-adapter/registry';
import { AgentAdapterServer } from '../agent-adapter/server';
import { createDefaultProfile } from '../cli/profiles/default';
import { createDevProfile } from '../cli/profiles/dev';
import { assertHostDomainResetRuntimeStartAllowed } from '../cli/operations/host-domain-reset-journal';
import { CommandRouter } from '../command-router';
import { PaiDriver } from '../drivers/pi';
import { LocalLinkKeyring } from '../e2e/link-keyring';
import { assertNodeCryptoSelfTest } from '../e2e/node-crypto-self-test';
import { DEFAULT_ENCRYPTED_UPLOAD_CRYPTO, createEncryptedUploadActions, type EncryptedEventFailure, type EncryptedUploadActions } from '../e2e/upload-actions';
import { resolvePersistedAriavaConfig } from '../host-manager/config';
import { resolveAriavaDevProfilePaths } from '../host-manager/dev-profile';
import { pathHasFilesystemEvidence } from '../host-manager/secure-files';
import { createHostEncryptionBinding, createRuntimeHostEncryptionIdentityStore, type HostEncryptionIdentity, type HostEncryptionIdentityStore, type HostIdentity } from '../identity';
import { RelayClient } from '../relay-client';
import { assertProductionNodeRuntime } from '../runtime/node-runtime';
import { acquireRuntimeCoordinator, type RuntimeCoordinator } from '../runtime-lock';
import { BridgeStateStore } from '../state-store';
import type { AgentDriver, BridgeConfig } from '../types';

/**
 * Constructor-shell runtime composition (spec §6.1, plan Task 5).
 *
 * `createBridgeDaemonShell(...)` is the synchronous acquisition phase the
 * `BridgeDaemon` constructor delegates to. It performs exactly the baseline
 * constructor acquisitions, in the baseline order:
 *
 *   1. reset guard / platform-profile path precheck
 *   2. runtime coordinator claim
 *   3. deferred state store construction (`deferRuntimePreflight: true`,
 *      coordinator supplied so the store never owns it)
 *   4. registry, adapter client, unstarted adapter server, drivers, and router
 *      construction
 *
 * and preserves the baseline reverse rollback on any construction failure:
 * dispose the constructed state store first, then dispose the claimed
 * coordinator exactly once, then rethrow. Injected dependencies (drivers,
 * registry clock) are borrowed and are never disposed here or by the daemon.
 *
 * This phase does NOT read the current identity, preflight the encrypted
 * spool, create the Relay client, bind upload actions, or start the server.
 * This module implements those operations as explicit async activation helpers;
 * `BridgeDaemon` invokes them and remains the single lifecycle owner.
 */

/** Whether a shell resource is daemon-owned (disposed/stopped by the daemon) or borrowed (never disposed). */
export type BridgeDaemonResourceOwnership = 'owned' | 'borrowed';

/**
 * Explicit ownership metadata for every resource in the shell bundle.
 * Literal types make the contract static: fields other than `drivers` can only
 * ever be `'owned'`, so a regression that stops owning a resource is a compile
 * error, not a runtime surprise.
 */
export interface BridgeDaemonShellOwnership {
  /** Claimed by this shell; the daemon (or constructor rollback) disposes it exactly once. */
  readonly runtimeCoordinator: 'owned';
  /** Constructed deferred with the coordinator; the daemon disposes it exactly once. */
  readonly stateStore: 'owned';
  /**
   * Constructed here; the daemon disposes it in `stop()`. Characterized
   * partial-failure caveat: when startup validation fails, the daemon disposes
   * state store/coordinator and a later `stop()` returns early, so this
   * registry dispose never runs in that path.
   */
  readonly adapterRegistry: 'owned';
  /** Constructed here; the daemon owns its lifetime (no disposal surface). */
  readonly adapterClient: 'owned';
  /**
   * Constructed here (unstarted); the daemon stops it in `stop()`. After a
   * startup-validation failure `stop()` returns early with the server still
   * unstarted and its stop count at zero (characterized partial-failure
   * cleanup, spec §6.2); on every path where `stop()` proceeds it stops the
   * server exactly once.
   */
  readonly adapterServer: 'owned';
  /** Constructed here; the daemon owns its lifetime (no disposal surface). */
  readonly router: 'owned';
  /** Injected drivers are borrowed and never disposed; the default-constructed PaiDriver is owned. */
  readonly drivers: 'owned' | 'borrowed';
}

/** The synchronous constructor-shell resource bundle handed to the daemon. */
export interface BridgeDaemonShell {
  readonly runtimeCoordinator: RuntimeCoordinator;
  readonly stateStore: BridgeStateStore;
  readonly adapterRegistry: AgentAdapterRegistry;
  readonly adapterClient: AgentAdapterClient;
  readonly adapterServer: AgentAdapterServer;
  readonly drivers: AgentDriver[];
  readonly router: CommandRouter;
  readonly ownership: BridgeDaemonShellOwnership;
}

/**
 * Failure-injection/inspection seam for constructor-shell rollback tests
 * (plan Task 1 deferred the post-coordinator/pre-store point to this internal
 * shell factory rather than widening the public `BridgeDaemon` constructor).
 */
export interface BridgeDaemonShellHooks {
  /** Runs after the coordinator is claimed and before the deferred state store is constructed. */
  beforeStateStoreConstruction?(coordinator: RuntimeCoordinator): void;
}

export interface BridgeDaemonShellOptions {
  readonly config: BridgeConfig;
  /** Borrowed; when omitted the shell constructs the default PaiDriver (owned). */
  readonly drivers?: AgentDriver[];
  /** Borrowed registry clock; passed through to the registry unchanged. */
  readonly registryNow?: () => Date;
  /** Daemon lifecycle callback invoked on registry mutation (reconciliation scheduling). */
  readonly onRegistryMutation: () => void;
  /** Constructor-shell rollback test seam; omitted in production. */
  readonly hooks?: BridgeDaemonShellHooks;
}

export function createBridgeDaemonShell(options: BridgeDaemonShellOptions): BridgeDaemonShell {
  assertHostDomainResetStartAllowed(options.config);
  const runtimeCoordinator = acquireRuntimeCoordinator(options.config.statePath);
  let stateStore: BridgeStateStore | undefined;
  try {
    options.hooks?.beforeStateStoreConstruction?.(runtimeCoordinator);
    const store = new BridgeStateStore(options.config.statePath, undefined, {
      deferRuntimePreflight: true,
      runtimeCoordinator,
    });
    stateStore = store;
    const adapterRegistry = new AgentAdapterRegistry(
      options.config.hostId,
      store,
      options.onRegistryMutation,
      options.registryNow,
    );
    const adapterClient = new AgentAdapterClient(adapterRegistry);
    const adapterServer = new AgentAdapterServer(
      { port: options.config.agentAdapter.port, secret: options.config.agentAdapter.secret, hostId: options.config.hostId },
      adapterRegistry,
      () => store.getRuntimeHealth(),
    );
    const drivers = options.drivers ?? [new PaiDriver(adapterClient, options.config.hostId)];
    const router = new CommandRouter(
      store,
      new Map(drivers.map((driver) => [driver.name, driver])),
      options.config.hostId,
    );
    return {
      runtimeCoordinator,
      stateStore: store,
      adapterRegistry,
      adapterClient,
      adapterServer,
      drivers,
      router,
      ownership: {
        runtimeCoordinator: 'owned',
        stateStore: 'owned',
        adapterRegistry: 'owned',
        adapterClient: 'owned',
        adapterServer: 'owned',
        router: 'owned',
        drivers: options.drivers === undefined ? 'owned' : 'borrowed',
      },
    };
  } catch (error) {
    stateStore?.dispose();
    runtimeCoordinator.dispose();
    throw error;
  }
}

/**
 * Async activation phase (spec §6.2 items 1-4, plan Task 5 Phase 5B).
 *
 * `activateBridgeRuntime(...)` performs, in the baseline order:
 *
 *   1. production runtime / node crypto self-test guards;
 *   2. filesystem verification (daemon-owned `verifyFilesystem` callback);
 *   3. current identity load + validation (daemon-owned `loadValidatedIdentity`
 *      callback; the deterministic persisted-identity comparison stays in
 *      daemon.ts per Task 3);
 *   4. Host-bound encrypted-spool preflight (`initializeEncryptedSpool`);
 *   5. Host encryption identity store/identity/binding and keyring
 *      construction, then `validateCommandExecutionPins`;
 *   6. Relay client creation (daemon-owned abort signal);
 *   7. best-effort command recovery (daemon-owned callback; it adopts the
 *      relay client and keyring into the daemon fields so the characterized
 *      Task 1 seams — `refreshCommandAuthority` / `pruneCommandRuntime` — run
 *      exactly as during normal sync);
 *   8. binding of exactly one `EncryptedUploadActions` instance.
 *
 * Non-transactionality is preserved: this function NEVER disposes anything.
 * When any step throws, the caller's `validateStartup` catch performs the
 * characterized disposal (state store + coordinator). The remaining activation
 * steps (adapter server start, discovery evidence write) have the distinct
 * retain-runtime failure semantics and live in `activateBridgeDaemonServer`;
 * timer scheduling stays in `BridgeDaemon.start()`.
 */

/**
 * Explicit ownership metadata for every activation-created resource. All are
 * daemon-owned; none has a disposal surface in the characterized baseline
 * (they are released with the daemon instance). Literal types make the
 * contract static.
 */
export interface BridgeDaemonActiveRuntimeOwnership {
  readonly relayClient: 'owned';
  readonly encryptionStore: 'owned';
  readonly encryptionIdentity: 'owned';
  readonly keyring: 'owned';
  readonly keyringMigrationContext: 'owned';
  readonly uploadActions: 'owned';
}

/** The explicit async-activation resource bundle handed back to the daemon. */
export interface BridgeDaemonActiveRuntime {
  readonly relayClient: RelayClient;
  readonly encryptionStore: HostEncryptionIdentityStore;
  readonly encryptionIdentity: HostEncryptionIdentity;
  readonly keyring: LocalLinkKeyring;
  readonly keyringMigrationContext: ConstructorParameters<typeof LocalLinkKeyring>[2];
  readonly uploadActions: EncryptedUploadActions;
  readonly ownership: BridgeDaemonActiveRuntimeOwnership;
}

export interface BridgeDaemonActivationOptions {
  readonly config: BridgeConfig;
  /** The shell-constructed deferred state store; activation preflights it in place. */
  readonly stateStore: BridgeStateStore;
  /** Daemon-owned Relay abort signal (the daemon's AbortController). */
  readonly signal: () => AbortSignal;
  /** Filesystem verification (daemon-owned `filesystemVerified` state). */
  readonly verifyFilesystem: () => void;
  /** Loads and validates the current Host identity; the deterministic comparison stays in daemon.ts. */
  readonly loadValidatedIdentity: () => Promise<HostIdentity>;
  /** Unreadable-spool-drop notice (daemon-owned stderr formatting). */
  readonly onDroppedUnreadableItems: (count: number) => void;
  /**
   * Best-effort startup command recovery (authority refresh, orphan recovery,
   * blocked-receipt recovery, outbox drain, prune). Runs through the daemon's
   * field-based seams exactly as the baseline did.
   */
  readonly runCommandRecovery: (relayClient: RelayClient, keyring: LocalLinkKeyring) => Promise<void>;
  /** Upload failure hook (daemon-owned logger). */
  readonly onEventFailure: (failure: EncryptedEventFailure) => void;
  /**
   * Progressive commit of each activation-created resource at its exact
   * baseline assignment point. The daemon mirrors these into its fields as
   * they are published, so a failure mid-activation leaves the same partial
   * visibility the baseline had (e.g. post-keyring pin validation failure:
   * keyring visible, Relay client not yet created).
   */
  readonly commit: (partial: BridgeDaemonActivationCommit) => void;
}

/** One progressive resource commit; only the fields acquired so far are present. */
export interface BridgeDaemonActivationCommit {
  readonly relayClient?: RelayClient;
  readonly encryptionStore?: HostEncryptionIdentityStore;
  readonly encryptionIdentity?: HostEncryptionIdentity;
  readonly keyring?: LocalLinkKeyring;
  readonly keyringMigrationContext?: ConstructorParameters<typeof LocalLinkKeyring>[2];
  readonly uploadActions?: EncryptedUploadActions;
}

export async function activateBridgeRuntime(options: BridgeDaemonActivationOptions): Promise<BridgeDaemonActiveRuntime> {
  assertProductionNodeRuntime();
  assertNodeCryptoSelfTest();
  options.verifyFilesystem();
  const identity = await options.loadValidatedIdentity();
  // Preflight runtime state before creating dependent encryption material in Bun and Node.
  const recovery = options.stateStore.initializeEncryptedSpool(
    identity.hostId, options.config.identityPath, options.config.runtimePlatform ?? process.platform,
  );
  options.onDroppedUnreadableItems(recovery.droppedUnreadableItems);
  const encryptionStore = createRuntimeHostEncryptionIdentityStore(options.config.identityPath, options.config.runtimePlatform ?? process.platform);
  options.commit({ encryptionStore });
  const encryptionIdentity = encryptionStore.loadOrCreate(identity.hostId);
  options.commit({ encryptionIdentity });
  const hostBinding = await createHostEncryptionBinding(identity, encryptionIdentity);
  const keyringMigrationContext: ConstructorParameters<typeof LocalLinkKeyring>[2] = { currentHostIdentity: identity, signedCurrentHostBinding: hostBinding };
  options.commit({ keyringMigrationContext });
  const keyring = new LocalLinkKeyring(
    `${options.config.identityPath}.e2e-keyring.json`, encryptionStore, keyringMigrationContext,
  );
  options.commit({ keyring });
  options.stateStore.validateCommandExecutionPins(keyring, { allowUnavailableForTerminal: true });
  const relayClient = new RelayClient(
    { baseUrl: options.config.relayBaseUrl, signer: identity.signer },
    options.signal,
  );
  options.commit({ relayClient });
  await options.runCommandRecovery(relayClient, keyring);
  const uploadActions = createEncryptedUploadActions({
    stateStore: options.stateStore,
    relayClient,
    crypto: DEFAULT_ENCRYPTED_UPLOAD_CRYPTO,
    keyring,
    hooks: { eventFailure: options.onEventFailure },
  });
  options.commit({ uploadActions });
  return {
    relayClient,
    encryptionStore,
    encryptionIdentity,
    keyring,
    keyringMigrationContext,
    uploadActions,
    ownership: {
      relayClient: 'owned',
      encryptionStore: 'owned',
      encryptionIdentity: 'owned',
      keyring: 'owned',
      keyringMigrationContext: 'owned',
      uploadActions: 'owned',
    },
  };
}

/**
 * Final non-transactional activation steps (spec §6.2 items 5-6): adapter
 * server start, then discovery evidence write. Task 1 characterized failures
 * here as retain-runtime: the daemon never rolls back; `stop()` performs the
 * explicit cleanup. Timer scheduling (item 7) remains the final step inside
 * `BridgeDaemon.start()`.
 */
export interface BridgeDaemonServerActivationOptions {
  readonly adapterServer: Pick<AgentAdapterServer, 'url' | 'start'>;
  readonly config: BridgeConfig;
  /** Discovery write (daemon-owned `writeAdapterConfig`; tests inject failures here). */
  readonly writeDiscovery: (evidence: AgentAdapterDiscoveryFile) => void;
}

export async function activateBridgeDaemonServer(options: BridgeDaemonServerActivationOptions): Promise<void> {
  await options.adapterServer.start();
  options.writeDiscovery({
    url: options.adapterServer.url,
    secret: options.config.agentAdapter.secret,
    protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
  });
}

/**
 * Reset guard / platform-profile path precheck (spec §6.1 step 1). Moved
 * verbatim from the daemon constructor so the shell boundary owns it; the
 * daemon still re-runs it before each sync via a delegating private method.
 * A failure here happens before any resource is claimed, so no rollback is
 * needed by the caller.
 */
export function assertHostDomainResetStartAllowed(config: BridgeConfig): void {
  const journalPath = resolve(dirname(config.configPath), 'host-domain-reset.json');
  if (!pathHasFilesystemEvidence(journalPath)) return;
  const profile = configPathMatchesProfile(config.configPath, 'dev') ? createDevProfile() : createDefaultProfile();
  const resources = profile.resolveResources(resolvePersistedAriavaConfig(config.configPath));
  assertHostDomainResetRuntimeStartAllowed(resources);
}

function configPathMatchesProfile(configPath: string, profile: 'dev'): boolean {
  return profile === 'dev' && resolve(configPath) === resolve(resolveAriavaDevProfilePaths().configPath);
}
