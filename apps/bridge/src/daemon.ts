import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  BridgePairWatchResponse,
  CanonicalEvent,
  CanonicalSessionState,
  ReplaceE2ECurrentSessionsRequestV1,
  HostEnrollmentRequest,
  HostProjection,
} from '@ariava/protocol';
import { AGENT_ADAPTER_PROTOCOL_VERSION, canonicalE2ECurrentSessionsDigestV1, validateCommandResult,
  type CommandResult, type E2ERecipientSnapshotV1 } from '@ariava/protocol';
import { isoNow } from '@ariava/shared-utils';
import { AgentAdapterClient } from './agent-adapter/client';
import { writeAgentAdapterConfig } from './agent-adapter/config';
import { AgentAdapterRegistry } from './agent-adapter/registry';
import { AgentAdapterServer } from './agent-adapter/server';
import { CommandRouter } from './command-router';
import { PaiDriver } from './drivers/pi';
import { probeHostPlatform } from './host-platform';
import { loadUserConfig, resolveAriavaConfig, resolvePersistedAriavaConfig } from './host-manager/config';
import { ensureAriavaSecureDirectories, pathHasFilesystemEvidence, readSecureJson, redactSensitive } from './host-manager/secure-files';
import { createHostEncryptionBinding, createRuntimeHostEncryptionIdentityStore, HostIdentityError, LinuxJsonHostIdentityStore, MacOSKeychainHostIdentityStore, type HostEncryptionIdentity, type HostEncryptionIdentityStore, type HostIdentity, type HostIdentityStore } from './identity';
import { RelayClient, RelayClientError } from './relay-client';
import { BridgeStateStore } from './state-store';
import { assertProductionNodeRuntime } from './runtime/node-runtime';
import { assertNodeCryptoSelfTest } from './e2e/node-crypto-self-test';
import type { AgentDriver, BridgeConfig, BridgeSyncResult } from './types';
import { LocalLinkKeyring, type PinRetentionReferences } from './e2e/link-keyring';
import { prepareCommandForExecution } from './e2e/command-execution';
import { EncryptedUploadOrchestrator } from './e2e/upload-orchestrator';
import { acquireRuntimeCoordinator, type RuntimeCoordinator } from './runtime-lock';
import { createDefaultProfile } from './cli/profiles/default';
import { createDevProfile } from './cli/profiles/dev';
import { assertHostDomainResetRuntimeStartAllowed } from './cli/operations/host-domain-reset-journal';
import { resolveAriavaDevProfilePaths } from './host-manager/dev-profile';
import {
  drainPendingCommandReceipts,
  persistTerminalCommandResult,
  recoverBlockedCommandReceipts,
  type CommandReceiptConstructionDependencies,
} from './e2e/command-receipt-recovery';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const BRIDGE_VERSION = readPackageVersion();

function readPackageVersion(): string {
  const manifest = JSON.parse(readFileSync(resolve(PACKAGE_ROOT, 'package.json'), 'utf8')) as { version?: string };
  return manifest.version ?? '0.0.0';
}

export function loadBridgeConfig(configPath?: string): BridgeConfig {
  const resolved = configPath ? resolvePersistedAriavaConfig(configPath) : resolveAriavaConfig();
  const hostPlatform = probeHostPlatform(process.platform);
  return {
    hostId: resolved.identity?.hostId ?? '',
    hostName: resolved.hostName?.trim() || hostname(),
    hostPlatform,
    relayBaseUrl: resolved.relayBaseUrl,
    statePath: resolved.statePath,
    identityPath: resolved.identityPath,
    configPath: resolved.configPath,
    runtimePlatform: process.platform,
    identity: resolved.identity,
    pollIntervalMs: resolved.pollIntervalMs ?? (configPath ? 15_000 : Number.parseInt(process.env.ARIAVA_POLL_INTERVAL_MS ?? '15000', 10)),
    bridgeVersion: BRIDGE_VERSION,
    agentAdapter: {
      port: resolved.agentAdapterPort,
      secret: resolved.agentAdapterSecret ?? generateAgentAdapterSecret(),
      configPath: resolved.agentAdapterConfigPath,
    },
  };
}

function generateAgentAdapterSecret(): string {
  return randomBytes(32).toString('hex');
}

export interface ReconciliationScheduler {
  schedule(callback: () => void, delayMs: number): unknown;
  cancel(handle: unknown): void;
}

const DEFAULT_RECONCILIATION_SCHEDULER: ReconciliationScheduler = {
  schedule: (callback, delayMs) => {
    const timer = setTimeout(callback, delayMs);
    timer.unref();
    return timer;
  },
  cancel: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};
const HOST_PRESENCE_HEARTBEAT_INTERVAL_MS = 30_000;

export interface PollWaitScheduler {
  schedule(callback: () => void, delayMs: number): unknown;
  cancel(handle: unknown): void;
}

const DEFAULT_POLL_WAIT_SCHEDULER: PollWaitScheduler = {
  schedule: (callback, delayMs) => setTimeout(callback, delayMs),
  cancel: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export class RuntimeHealthLogger {
  private readonly failures = new Map<string, { lastLogAt: number; suppressed: number }>();
  private readonly active = new Set<string>();
  private readonly recovered = new Set<string>();

  constructor(
    private readonly write: (line: string) => void = (line) => { process.stderr.write(line); },
    private readonly now: () => number = () => Date.now(),
  ) {}

  failure(scope: 'driver' | 'relay_presence', driver: string | undefined, count: number): void {
    const key = `${scope}:${driver ?? ''}`;
    const timestamp = this.now();
    const current = this.failures.get(key) ?? { lastLogAt: 0, suppressed: 0 };
    this.active.add(key);
    this.recovered.delete(key);
    if (timestamp - current.lastLogAt < 30_000) {
      current.suppressed += 1;
      this.failures.set(key, current);
      return;
    }
    this.write(`${JSON.stringify({
      component: 'bridge_runtime_health', outcome: 'degraded',
      code: scope === 'driver' ? 'driver_reconciliation_failed' : 'relay_presence_refresh_failed',
      ...(driver ? { driver } : {}), count, suppressed: current.suppressed,
    })}\n`);
    this.failures.set(key, { lastLogAt: timestamp, suppressed: 0 });
  }

  recovery(scope: 'driver' | 'relay_presence', driver: string | undefined, count: number): void {
    const key = `${scope}:${driver ?? ''}`;
    if (this.recovered.has(key)) return;
    this.recovered.add(key);
    this.active.delete(key);
    this.write(`${JSON.stringify({
      component: 'bridge_runtime_health', outcome: 'recovered',
      code: scope === 'driver' ? 'driver_reconciliation_failed' : 'relay_presence_refresh_failed',
      ...(driver ? { driver } : {}), count,
    })}\n`);
    this.failures.delete(key);
  }
}

export class EncryptedEventFailureLogger {
  private lastLogAt = 0;
  private suppressed = 0;

  constructor(
    private readonly write: (line: string) => void = (line) => { process.stderr.write(line); },
    private readonly now: () => number = () => Date.now(),
  ) {}

  record(failure: import('./e2e/upload-orchestrator').EncryptedEventFailure): void {
    const timestamp = this.now();
    if (timestamp - this.lastLogAt < 30_000) {
      this.suppressed += 1;
      return;
    }

    const suppressed = this.suppressed;
    this.suppressed = 0;
    this.lastLogAt = timestamp;
    this.write(`Ariava encrypted Event upload failure: ${JSON.stringify({
      outcome: failure.outcome,
      category: failure.category,
      status: failure.status,
      suppressed,
    })}\n`);
  }
}

export class BridgeDaemon {
  private relayClient?: RelayClient;
  private readonly stateStore: BridgeStateStore;
  private readonly runtimeCoordinator: RuntimeCoordinator;
  private readonly adapterRegistry: AgentAdapterRegistry;
  private readonly adapterClient: AgentAdapterClient;
  private readonly adapterServer: AgentAdapterServer;
  private readonly drivers: AgentDriver[];
  private readonly router: CommandRouter;
  private encryptionStore?: HostEncryptionIdentityStore;
  private encryptionIdentity?: HostEncryptionIdentity;
  private keyring?: LocalLinkKeyring;
  private keyringMigrationContext?: ConstructorParameters<typeof LocalLinkKeyring>[2];
  private filesystemVerified = false;
  private startupValidated = false;
  private syncFlight?: Promise<BridgeSyncResult>;
  private reconciliationTimer?: unknown;
  private presenceHeartbeatTimer?: unknown;
  private presenceFlight?: Promise<void>;
  private reconciliationRequested = true;
  private currentSessionsSnapshotFailureCount = 0;
  private lastCurrentSessionsSnapshotFailureLogAt = 0;
  private readonly encryptedEventFailureLogger = new EncryptedEventFailureLogger();
  private readonly runtimeHealthLogger = new RuntimeHealthLogger();
  private pollWaitTimer?: unknown;
  private pollWaitResolve?: () => void;
  private commandReceiptConstruction: CommandReceiptConstructionDependencies = {};
  private receiptDrainFlight?: Promise<number>;
  private commandNow: () => Date = () => new Date(Date.now());
  private commandFlightActive = false;
  private runtimeDisposed = false;
  constructor(
    private readonly config: BridgeConfig,
    drivers?: AgentDriver[],
    private readonly identityStore?: HostIdentityStore,
    registryNow?: () => Date,
    private readonly reconciliationScheduler: ReconciliationScheduler = DEFAULT_RECONCILIATION_SCHEDULER,
    private readonly pollWaitScheduler: PollWaitScheduler = DEFAULT_POLL_WAIT_SCHEDULER,
  ) {
    this.assertHostDomainResetStartAllowed();
    this.runtimeCoordinator = acquireRuntimeCoordinator(config.statePath);
    let stateStore: BridgeStateStore | undefined;
    try {
      stateStore = new BridgeStateStore(config.statePath, undefined, {
        deferRuntimePreflight: true,
        runtimeCoordinator: this.runtimeCoordinator,
      });
      this.stateStore = stateStore;
      this.adapterRegistry = new AgentAdapterRegistry(
        config.hostId, this.stateStore, () => this.scheduleRegistryReconciliation(), registryNow,
      );
      this.adapterClient = new AgentAdapterClient(this.adapterRegistry);
      this.adapterServer = new AgentAdapterServer(
        { port: config.agentAdapter.port, secret: config.agentAdapter.secret, hostId: config.hostId },
        this.adapterRegistry,
        () => this.stateStore.getRuntimeHealth(),
      );
      this.drivers = drivers ?? [new PaiDriver(this.adapterClient, config.hostId)];
      this.router = new CommandRouter(this.stateStore, new Map(this.drivers.map((driver) => [driver.name, driver])), config.hostId);
    } catch (error) {
      stateStore?.dispose();
      this.runtimeCoordinator.dispose();
      throw error;
    }
  }

  private stopped = false;
  private relayAbortController = new AbortController();
  async start(): Promise<void> {
    await this.validateStartup();
    await this.adapterServer.start();
    writeAgentAdapterConfig(this.config.agentAdapter.configPath, {
      url: this.adapterServer.url,
      secret: this.config.agentAdapter.secret,
      protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
    });
    this.schedulePresenceHeartbeat();
  }

  private verifyFilesystem(): void {
    if (this.filesystemVerified) return;
    ensureAriavaSecureDirectories([
      dirname(this.config.configPath), dirname(this.config.statePath), dirname(this.config.agentAdapter.configPath), dirname(this.config.identityPath),
    ]);
    for (const path of [this.config.configPath, this.config.agentAdapter.configPath]) {
      if (pathHasFilesystemEvidence(path)) readSecureJson<unknown>(path);
    }
    this.filesystemVerified = true;
  }

  private async validateStartup(): Promise<void> {
    if (this.startupValidated) return;
    try {
      assertProductionNodeRuntime();
      assertNodeCryptoSelfTest();
      this.verifyFilesystem();
      const identity = await this.resolveIdentityStore().load();
      if (!identity) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not initialized; run `ariava init`');
      if (!this.config.identity || !samePersistedIdentity(this.config.identity, identity, this.config)) {
        throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Configured identity metadata does not match the local Host identity');
      }
      // Preflight runtime state before creating dependent encryption material in Bun and Node.
      const recovery = this.stateStore.initializeEncryptedSpool(
        identity.hostId, this.config.identityPath, this.config.runtimePlatform ?? process.platform,
      );
      if (recovery.droppedUnreadableItems > 0) {
        process.stderr.write(`Ariava dropped ${recovery.droppedUnreadableItems} unreadable encrypted spool item(s).\n`);
      }
      this.encryptionStore = createRuntimeHostEncryptionIdentityStore(this.config.identityPath, this.config.runtimePlatform ?? process.platform);
      this.encryptionIdentity = this.encryptionStore.loadOrCreate(identity.hostId);
      const hostBinding = await createHostEncryptionBinding(identity, this.encryptionIdentity);
      this.keyringMigrationContext = { currentHostIdentity: identity, signedCurrentHostBinding: hostBinding };
      this.keyring = new LocalLinkKeyring(
        `${this.config.identityPath}.e2e-keyring.json`, this.encryptionStore, this.keyringMigrationContext,
      );
      this.stateStore.validateCommandExecutionPins(this.keyring, { allowUnavailableForTerminal: true });
      this.relayClient = new RelayClient(
        { baseUrl: this.config.relayBaseUrl, signer: identity.signer },
        () => this.relayAbortController.signal,
      );
      try {
        await this.refreshCommandAuthority();
        this.stateStore.recoverOrphanedCommandExecutions();
        await recoverBlockedCommandReceipts(this.stateStore, this.keyring, this.commandReceiptConstruction);
        await drainPendingCommandReceipts(this.stateStore, this.keyring, this.client());
        this.pruneCommandRuntime();
      } catch {
        // Command recovery stays frozen until an authoritative snapshot succeeds.
      }
      this.startupValidated = true;
    } catch (error) {
      this.disposeRuntimeCoordinator();
      throw error;
    }
  }

  private resolveIdentityStore(): HostIdentityStore {
    if (this.identityStore) return this.identityStore;
    const platform = this.config.runtimePlatform ?? process.platform;
    if (platform === 'darwin') return new MacOSKeychainHostIdentityStore(this.config.identityPath);
    if (platform === 'linux') return new LinuxJsonHostIdentityStore(this.config.identityPath);
    throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', `Unsupported Host identity platform: ${platform}`);
  }

  private client(): RelayClient {
    if (!this.relayClient) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not loaded');
    return this.relayClient;
  }

  private scheduleRegistryReconciliation(): void {
    if (this.stopped || this.reconciliationTimer) return;
    this.reconciliationTimer = this.reconciliationScheduler.schedule(() => {
      this.reconciliationTimer = undefined;
      this.reconciliationRequested = true;
      this.cancelPollWait();
    }, 300);
  }

  private schedulePresenceHeartbeat(): void {
    if (this.stopped || this.presenceHeartbeatTimer !== undefined) return;
    this.presenceHeartbeatTimer = this.reconciliationScheduler.schedule(() => {
      this.presenceHeartbeatTimer = undefined;
      this.runPresenceHeartbeat();
    }, HOST_PRESENCE_HEARTBEAT_INTERVAL_MS);
  }

  private runPresenceHeartbeat(): void {
    if (this.stopped) return;
    void this.ensureHostPresence()
      .catch(() => {})
      .finally(() => this.schedulePresenceHeartbeat());
  }

  stop(): void {
    this.stopped = true;
    if (this.runtimeDisposed) return;
    let commandRecoveryComplete = !this.startupValidated;
    if (this.startupValidated) {
      try {
        const hasActiveCommands = this.stateStore.listCommandExecutions().some(
          (execution) => execution.state === 'claimed' || execution.state === 'dispatch_started',
        );
        commandRecoveryComplete = !hasActiveCommands;
        if (hasActiveCommands) {
          this.stateStore.recoverOrphanedCommandExecutions();
          commandRecoveryComplete = true;
        }
      } catch {
        commandRecoveryComplete = false;
      }
    }
    try { this.adapterRegistry.dispose(); } catch {}
    if (this.reconciliationTimer !== undefined) {
      this.reconciliationScheduler.cancel(this.reconciliationTimer);
      this.reconciliationTimer = undefined;
    }
    if (this.presenceHeartbeatTimer !== undefined) {
      this.reconciliationScheduler.cancel(this.presenceHeartbeatTimer);
      this.presenceHeartbeatTimer = undefined;
    }
    this.cancelPollWait();
    this.relayAbortController.abort();
    try { this.adapterServer.stop(true); } catch {}
    if (commandRecoveryComplete) this.disposeRuntimeCoordinator();
  }
  private disposeRuntimeCoordinator(): void {
    if (this.runtimeDisposed) return;
    this.stateStore.dispose();
    this.runtimeCoordinator.dispose();
    this.runtimeDisposed = true;
  }

  private markCommandOutcomeUnknownIfActive(commandId: string): void {
    const execution = this.stateStore.getCommandExecution(commandId);
    if (!execution || execution.state === 'outcome_unknown' || this.stopped) return;
    if (execution.state === 'claimed' || execution.state === 'dispatch_started') {
      this.stateStore.markCommandOutcomeUnknown(commandId);
    }
  }
  get adapterUrl(): string { return this.adapterServer.url; }
  get driverNames(): string[] { return this.drivers.map((driver) => driver.name); }

  syncOnce(): Promise<BridgeSyncResult> {
    if (this.syncFlight) {
      this.reconciliationRequested = true;
      return this.syncFlight;
    }
    const flight = this.performSyncOnce();
    this.syncFlight = flight;
    void flight.finally(() => { if (this.syncFlight === flight) this.syncFlight = undefined; }).catch(() => {});
    return flight;
  }

  private assertHostDomainResetStartAllowed(): void {
    const journalPath = resolve(dirname(this.config.configPath), 'host-domain-reset.json');
    if (!pathHasFilesystemEvidence(journalPath)) return;
    const profile = configPathMatchesProfile(this.config.configPath, 'dev') ? createDevProfile() : createDefaultProfile();
    const resources = profile.resolveResources(resolvePersistedAriavaConfig(this.config.configPath));
    assertHostDomainResetRuntimeStartAllowed(resources);
  }

  private async performSyncOnce(): Promise<BridgeSyncResult> {
    try {
      this.assertHostDomainResetStartAllowed();
    } catch (error) {
      this.stop();
      throw error;
    }
    await this.validateStartup();
    this.reconciliationRequested = false;
    let offline = false;
    try {
      await this.ensureHostPresence();
    } catch {
      offline = true;
    }
    if (!offline) await this.reconcileRecipientsAndDrainReceipts();

    const newEvents: CanonicalEvent[] = [];
    let authoritativeSetComplete = true;
    for (const driver of this.drivers) {
      const observedAt = isoNow();
      const nextRetryAt = new Date(Date.parse(observedAt) + this.config.pollIntervalMs).toISOString();
      try {
        const persistedDriverSessions = this.stateStore.listSessions()
          .filter((session) => this.stateStore.getDriverNameForSession(session.sessionId) === driver.name);
        const sessions = await driver.listSessions(this.config.hostId);
        if (driver.isAuthoritativeSetReady?.(persistedDriverSessions) === false) {
          authoritativeSetComplete = false;
          const degradation = this.stateStore.recordDriverReconciliationFailure(driver.name, observedAt, nextRetryAt);
          this.runtimeHealthLogger.failure('driver', driver.name, degradation.count);
          continue;
        }
        this.stateStore.replaceDriverSessions(driver.name, sessions);
        const recovered = this.stateStore.recordDriverReconciliationSuccess(driver.name);
        if (recovered) this.runtimeHealthLogger.recovery('driver', driver.name, recovered.count);
      } catch {
        authoritativeSetComplete = false;
        const degradation = this.stateStore.recordDriverReconciliationFailure(driver.name, observedAt, nextRetryAt);
        this.runtimeHealthLogger.failure('driver', driver.name, degradation.count);
      }
    }
    // A driver failure must never turn a partial list into an authoritative replacement.
    // Successful drivers have been reconciled above, while failed drivers retain their last
    // complete persisted set. Build the Host snapshot only from that reconciled store.
    const nextSessions = this.stateStore.listSessions();
    const activeSessions = nextSessions;
    let encryptedPublishingReady = true;
    if (authoritativeSetComplete && !offline) {
      try { encryptedPublishingReady = await this.flushCurrentSessionsSnapshot(activeSessions); }
      catch (error) {
        if (snapshotError(error, 'session_snapshot_conflict')) throw new Error('Relay rejected the persisted E2E lifecycle revision as conflicting', { cause: error });
        const recovery = await this.handleCurrentSessionsSnapshotFailure(error, activeSessions);
        offline = !recovery.online;
        encryptedPublishingReady = recovery.encryptedPublishingReady;
      }
    }
    const flushedEvents = offline || !encryptedPublishingReady ? 0 : await this.flushPendingEvents();
    const flushedReads = offline ? 0 : await this.flushPendingHandles();
    const handledCommands = offline ? [] : await this.pullAndHandleCommands();
    return { host: this.stateStore.getHost(), sessions: nextSessions, emittedEvents: newEvents, flushedEvents, flushedReads, handledCommands, offline };
  }

  private resetCurrentSessionsSnapshotFailures(): void { this.currentSessionsSnapshotFailureCount = 0; }

  private async handleCurrentSessionsSnapshotFailure(error: unknown, activeSessions: CanonicalSessionState[]): Promise<{ online: boolean; encryptedPublishingReady: boolean }> {
    this.currentSessionsSnapshotFailureCount += 1;
    this.logCurrentSessionsSnapshotFailure(error, activeSessions);
    this.scheduleRegistryReconciliation();
    if (this.currentSessionsSnapshotFailureCount < 2) return { online: false, encryptedPublishingReady: false };
    try {
      await this.recoverCurrentSessionsSnapshotPipeline(activeSessions);
      const recoveredAfter = this.currentSessionsSnapshotFailureCount;
      const encryptedPublishingReady = await this.flushCurrentSessionsSnapshot(activeSessions);
      this.resetCurrentSessionsSnapshotFailures();
      if (!encryptedPublishingReady) {
        if (this.reconciliationTimer !== undefined) {
          this.reconciliationScheduler.cancel(this.reconciliationTimer);
          this.reconciliationTimer = undefined;
        }
        return { online: true, encryptedPublishingReady: false };
      }
      process.stderr.write(`Ariava recovered current-session snapshot publication after ${recoveredAfter} failure(s).\n`);
      return { online: true, encryptedPublishingReady: true };
    } catch (recoveryError) {
      this.logCurrentSessionsSnapshotFailure(recoveryError, activeSessions, 'recovery');
      this.scheduleRegistryReconciliation();
      return { online: false, encryptedPublishingReady: false };
    }
  }

  private async recoverCurrentSessionsSnapshotPipeline(activeSessions: CanonicalSessionState[]): Promise<void> {
    if (this.encryptionStore) {
      this.keyring = new LocalLinkKeyring(
        `${this.config.identityPath}.e2e-keyring.json`, this.encryptionStore, this.keyringMigrationContext,
      );
    }
    this.stateStore.clearInflightSessionUploads(activeSessions.map((session) => session.sessionId));
  }

  private logCurrentSessionsSnapshotFailure(error: unknown, activeSessions: CanonicalSessionState[], phase = 'publish'): void {
    const now = Date.now();
    if (phase === 'publish' && now - this.lastCurrentSessionsSnapshotFailureLogAt < 30_000) return;
    this.lastCurrentSessionsSnapshotFailureLogAt = now;
    const snapshot = this.stateStore.getCurrentSessionsSnapshotState();
    const sessionsWithoutRevision = activeSessions.filter((session) => this.stateStore.currentSessionRevision(session.sessionId) === 0);
    const sessionIdsWithoutRevision = sessionsWithoutRevision.slice(0, 10).map((session) => session.sessionId);
    const detail = {
      phase,
      failures: this.currentSessionsSnapshotFailureCount,
      activeSessionCount: activeSessions.length,
      noRevisionSessionCount: sessionsWithoutRevision.length,
      noRevisionSessionIds: sessionIdsWithoutRevision,
      lastAcceptedRevision: snapshot.lastAcceptedRevision,
      lastAllocatedRevision: snapshot.lastAllocatedRevision,
      lastAcceptedRecipientSetVersion: snapshot.lastAcceptedRecipientSetVersion,
      localRecipientSetVersion: this.stateStore.getRecipientSetVersion(),
      error: this.formatError(error),
      relayStatus: error instanceof RelayClientError ? error.status : undefined,
      relayCode: error instanceof RelayClientError && error.body && typeof error.body === 'object' ? (error.body as Record<string, unknown>).code : undefined,
    };
    process.stderr.write(`Ariava current-session snapshot ${phase} failed: ${JSON.stringify(detail)}\n`);
  }

  async pairWatch(pairingCode: string): Promise<BridgePairWatchResponse> {
    await this.validateStartup();
    await this.ensureHostPresence();
    return this.client().pairWatch(pairingCode);
  }

  async runForever(): Promise<void> {
    this.stopped = false;
    this.reconciliationRequested = true;
    if (this.relayAbortController.signal.aborted) this.relayAbortController = new AbortController();
    while (!this.stopped) {
      try { await this.syncOnce(); }
      catch (error) {
        if (this.stopped || isAbortError(error)) break;
        process.stderr.write(`Ariava bridge loop failed: ${this.formatError(error)}\n`);
      }
      if (this.reconciliationRequested) continue;
      if (!this.stopped) await this.waitForNextPoll();
    }
  }

  private async waitForNextPoll(): Promise<void> {
    await new Promise<void>((resolvePoll) => {
      let fired = false;
      const handle = this.pollWaitScheduler.schedule(() => {
        fired = true;
        this.pollWaitTimer = undefined;
        if (this.pollWaitResolve === resolvePoll) this.pollWaitResolve = undefined;
        resolvePoll();
      }, this.config.pollIntervalMs);
      if (!fired) {
        this.pollWaitTimer = handle;
        this.pollWaitResolve = resolvePoll;
      }
    });
  }

  private cancelPollWait(): void {
    if (this.pollWaitTimer !== undefined) this.pollWaitScheduler.cancel(this.pollWaitTimer);
    this.pollWaitTimer = undefined;
    const resolvePoll = this.pollWaitResolve;
    this.pollWaitResolve = undefined;
    resolvePoll?.();
  }

  private async buildEnrollment(identity: HostIdentity): Promise<HostEnrollmentRequest> {
    if (!this.encryptionIdentity) throw new HostIdentityError('ERR_IDENTITY_MISSING', 'Host encryption identity is not loaded');
    return {
      hostId: identity.hostId, keyId: identity.keyId, algorithm: identity.algorithm, publicKey: identity.publicKey,
      encryptionBinding: await createHostEncryptionBinding(identity, this.encryptionIdentity),
      ...this.buildHostMetadata(),
    };
  }

  private buildHostMetadata(): HostMetadataUpdateRequest {
    return { hostName: this.config.hostName, platform: this.config.hostPlatform, bridgeVersion: this.config.bridgeVersion };
  }

  private ensureHostPresence(): Promise<void> {
    if (this.presenceFlight) return this.presenceFlight;
    const observedAt = isoNow();
    const nextRetryAt = new Date(Date.parse(observedAt) + this.config.pollIntervalMs).toISOString();
    const flight = this.registerHostPresence()
      .then(() => {
        if (this.stopped) return;
        const recovered = this.stateStore.recordRelayPresenceSuccess();
        if (recovered) this.runtimeHealthLogger.recovery('relay_presence', undefined, recovered.count);
      })
      .catch((error: unknown) => {
        if (!this.stopped) {
          const prior = this.stateStore.getHost();
          if (prior) this.stateStore.setHost({ ...prior, bridgeStatus: 'degraded' });
          const degradation = this.stateStore.recordRelayPresenceFailure(observedAt, nextRetryAt);
          this.runtimeHealthLogger.failure('relay_presence', undefined, degradation.count);
        }
        throw error;
      });
    this.presenceFlight = flight;
    void flight.finally(() => {
      if (this.presenceFlight === flight) this.presenceFlight = undefined;
    }).catch(() => {});
    return flight;
  }

  private async registerHostPresence(): Promise<void> {
    const identity = await this.resolveIdentityStore().load();
    if (!identity || !this.config.identity || !samePersistedIdentity(this.config.identity, identity, this.config)) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity changed while daemon was running');
    }
    const response = await this.client().enrollHost(await this.buildEnrollment(identity));
    if (this.stopped) return;
    this.stateStore.setHost(response.host);
  }

  private async sendCurrentSessionsPublication(
    publication: { request: ReplaceE2ECurrentSessionsRequestV1; digest: string; contentDigest: string },
  ): Promise<void> {
    const response = await this.client().replaceE2ECurrentSessions(publication.request);
    if (response.hostId !== publication.request.hostId || response.revision !== publication.request.revision) throw new Error('Relay returned a mismatched current session snapshot response');
    this.stateStore.acceptCurrentSessionsPublication(publication.request, publication.digest, publication.contentDigest);
    this.resetCurrentSessionsSnapshotFailures();
  }

  private async flushCurrentSessionsSnapshot(currentSessions: CanonicalSessionState[]): Promise<boolean> {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      let recipientSnapshot: Awaited<ReturnType<RelayClient['recipientSnapshot']>>;
      try {
        recipientSnapshot = await this.client().recipientSnapshot();
      } catch (error) {
        if (snapshotError(error, 'e2e_recipient_not_ready')) {
          this.resetCurrentSessionsSnapshotFailures();
          return false;
        }
        throw error;
      }
      if (!this.keyring || !this.encryptionIdentity) throw new Error('E2E lifecycle encryption is unavailable');
      const recipients = this.keyring.reconcileRecipients(recipientSnapshot);
      let publication = await this.stateStore.createCurrentSessionsPublication(
        this.config.hostId, currentSessions, recipientSnapshot.recipientSetVersion, isoNow(),
      );
      if (!publication) return true;
      const committed = await this.uploadOrchestrator().publishAuthoritativeSnapshots(
        recipientSnapshot, recipients, currentSessions.map((session) => session.sessionId),
      );
      if (!committed) throw new Error('authoritative encrypted Session snapshot publication failed');
      if (committed.recipientSetVersion !== publication.request.recipientSetVersion) {
        publication = await this.stateStore.createCurrentSessionsPublication(
          this.config.hostId, currentSessions, committed.recipientSetVersion, isoNow(),
        );
        if (!publication) throw new Error('recipient change did not allocate a replacement lifecycle manifest');
      }
      const request: ReplaceE2ECurrentSessionsRequestV1 = {
        ...publication.request,
        sessions: currentSessions.map((session) => ({ sessionId: session.sessionId, sessionRevision: committed.revisions.get(session.sessionId)! })),
      };
      const finalized = { request, contentDigest: publication.contentDigest, digest: await canonicalE2ECurrentSessionsDigestV1(request) };
      try {
        await this.sendCurrentSessionsPublication(finalized);
        return true;
      } catch (error) {
        if (snapshotError(error, 'e2e_recipient_not_ready')) {
          this.resetCurrentSessionsSnapshotFailures();
          return false;
        }
        const stale = snapshotError(error, 'session_snapshot_stale');
        const recipientsChanged = snapshotError(error, 'e2e_recipient_set_changed');
        const invalidReference = snapshotError(error, 'e2e_session_reference_invalid');
        if (!stale && !recipientsChanged && !invalidReference) throw error;
        if (stale?.acceptedRevision !== undefined) this.stateStore.noteCurrentSessionsSnapshotRevisionLowerBound(stale.acceptedRevision);
      }
    }
    throw new Error('E2E lifecycle publication did not converge after recipient/revision conflicts');
  }

  async flushEncryptedUploadsForTest(): Promise<number> { await this.validateStartup(); return this.flushPendingEvents(); }
  async publishRecipientSnapshotsForTest(): Promise<boolean> {
    await this.validateStartup();
    if (!this.encryptionIdentity || !this.keyring) return false;
    const snapshot = await this.client().recipientSnapshot();
    return this.uploadOrchestrator().publishRecipientChangeSnapshots(snapshot, this.keyring.reconcileRecipients(snapshot));
  }

  private async flushPendingEvents(): Promise<number> {
    if (!this.encryptionIdentity || !this.keyring) return 0;
    return this.uploadOrchestrator().flushPendingEvents();
  }

  private uploadOrchestrator(): EncryptedUploadOrchestrator {
    return new EncryptedUploadOrchestrator(this.stateStore, this.client(), this.keyring!, {
      eventFailure: (failure) => this.encryptedEventFailureLogger.record(failure),
    });
  }

  private async flushPendingHandles(): Promise<number> {
    let flushed = 0;
    for (const handle of this.stateStore.peekPendingSessionHandles()) {
      try {
        await this.client().handleSession(handle.sessionId, {
          handledThroughEventId: handle.handledThroughEventId,
          handledThroughEventCreatedAt: handle.handledThroughEventCreatedAt,
          handledAt: handle.handledAt,
          action: handle.action,
        });
        this.stateStore.removePendingSessionHandle(handle.hostId, handle.sessionId, handle.handledThroughEventId);
        flushed += 1;
      } catch { break; }
    }
    return flushed;
  }


  private reconcileRecipientsAndDrainReceipts(): Promise<number> {
    if (this.receiptDrainFlight) return this.receiptDrainFlight;
    const flight = this.performReconciledReceiptDrain();
    this.receiptDrainFlight = flight;
    void flight.finally(() => {
      if (this.receiptDrainFlight === flight) this.receiptDrainFlight = undefined;
    }).catch(() => {});
    return flight;
  }

  private async performReconciledReceiptDrain(): Promise<number> {
    if (!this.keyring || !this.stateStore.listCommandExecutions().some((execution) =>
      execution.state === 'terminal' && execution.receiptOutbox?.state === 'pending')) return 0;
    try {
      await this.refreshCommandAuthority();
    } catch {
      return 0;
    }
    return drainPendingCommandReceipts(this.stateStore, this.keyring, this.client());
  }

  private async pullAndHandleCommands(): Promise<CommandResult[]> {
    if (this.commandFlightActive) return [];
    this.commandFlightActive = true;
    try {
    if (!this.keyring) throw new Error('E2E command keyring is unavailable');
    try {
      await this.refreshCommandAuthority();
    } catch {
      return [];
    }
    await recoverBlockedCommandReceipts(this.stateStore, this.keyring, this.commandReceiptConstruction);
    await drainPendingCommandReceipts(this.stateStore, this.keyring, this.client());
    this.pruneCommandRuntime();
    const commands = await this.client().pullCommands(this.config.hostId);
    const handled: CommandResult[] = [];
    for (const encrypted of commands) {
      const preparation = await prepareCommandForExecution(encrypted, this.keyring, this.commandNow);
      if (!preparation.ok) continue;
      const { prepared } = preparation;
      const claim = this.stateStore.claimCommandExecution({
        originalEncryptedCommand: prepared.originalEncryptedCommand, commandDigest: prepared.commandDigest,
        pinReference: prepared.pinReference, claimedAt: this.commandNow().toISOString(),
      });
      if (claim.status === 'conflict') throw new Error('Relay command replay nonce or body conflict');
      if (claim.status === 'duplicate') continue;
      let dispatchStarted = false;
      let terminalResult: CommandResult | undefined;
      try {
        const outcome = await this.router.handle(prepared.loopbackCommand, { beforeDispatch: () => {
          this.stateStore.markCommandDispatchStarted(encrypted.commandId, this.commandNow().toISOString());
          dispatchStarted = true;
        } });
        if (!validateCommandResult(outcome.result)) {
          if (dispatchStarted) this.markCommandOutcomeUnknownIfActive(encrypted.commandId);
          continue;
        }
        terminalResult = outcome.result;
      } catch {
        this.markCommandOutcomeUnknownIfActive(encrypted.commandId);
        continue;
      }
      if (this.stopped) continue;
      try {
        await this.refreshCommandAuthority();
      } catch {
        this.stateStore.persistTerminalReceiptBlocked(encrypted.commandId, terminalResult);
        handled.push(terminalResult);
        continue;
      }
      await persistTerminalCommandResult(
        this.stateStore, this.keyring, encrypted.commandId, terminalResult, this.commandReceiptConstruction,
      );
      await drainPendingCommandReceipts(this.stateStore, this.keyring, this.client());
      this.pruneCommandRuntime();
      handled.push(terminalResult);
    }
    return handled;
    } finally {
      this.commandFlightActive = false;
    }
  }

  private async refreshCommandAuthority(): Promise<E2ERecipientSnapshotV1> {
    if (!this.keyring) throw new Error('E2E command keyring is unavailable');
    const snapshot = await this.client().recipientSnapshot();
    const acceptedVersion = this.stateStore.getRecipientSetVersion();
    if (acceptedVersion !== undefined && snapshot.recipientSetVersion < acceptedVersion) {
      throw new TypeError('recipient snapshot rollback rejected');
    }
    if (acceptedVersion === snapshot.recipientSetVersion) {
      const active = this.keyring.listActive().map((pin) =>
        `${pin.linkId}:${pin.linkGeneration}:${pin.epoch}:${pin.watchDeviceId}:${pin.watchBinding.encryptionKeyId}`).sort();
      const received = snapshot.recipients.map((recipient) =>
        `${recipient.linkId}:${recipient.linkGeneration}:${recipient.epoch}:${recipient.watchDeviceId}:${recipient.watchBinding.encryptionKeyId}`).sort();
      if (JSON.stringify(active) !== JSON.stringify(received)) {
        throw new TypeError('recipient snapshot version conflict rejected');
      }
    }
    this.keyring.reconcileRecipients(snapshot);
    this.stateStore.setRecipientSetVersion(snapshot.recipientSetVersion);
    return snapshot;
  }

  private pruneCommandRuntime(now = this.commandNow().toISOString()): void {
    if (!this.keyring) return;
    this.stateStore.pruneEligibleCommandExecutions(now);
    const references = mergePinRetentionReferences(
      this.stateStore.durableContentPinRetentionReferences(now),
      this.stateStore.commandExecutionPinRetentionReferences(),
    );
    this.keyring.pruneRetiring(references, now);
  }



  private formatError(error: unknown): string {
    const raw = error instanceof Error ? error.message : String(error);
    const legacy = loadUserConfig(this.config.configPath);
    return String(redactSensitive(raw, [
      this.config.agentAdapter.secret, legacy.agentAdapterSecret,
      ...Object.entries(legacy as Record<string, unknown>)
        .filter(([key, value]) => typeof value === 'string' && /(?:secret|token|password|private.*key|authorization)/iu.test(key))
        .map(([, value]) => value as string),
      ...Object.entries(process.env)
        .filter(([key, value]) => Boolean(value) && /(?:secret|token|password|private.*key|authorization)/iu.test(key))
        .map(([, value]) => value as string),
    ].filter((value): value is string => Boolean(value))));
  }
}


function mergePinRetentionReferences(...inputs: PinRetentionReferences[]): PinRetentionReferences {
  const merged: PinRetentionReferences = {};
  for (const input of inputs) {
    for (const [category, values] of Object.entries(input) as Array<
      [keyof PinRetentionReferences, Record<string, string> | undefined]
    >) {
      if (!values) continue;
      const target = merged[category] ?? {};
      for (const [key, timestamp] of Object.entries(values)) {
        if (!target[key] || target[key]! < timestamp) target[key] = timestamp;
      }
      merged[category] = target;
    }
  }
  return merged;
}


function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}


function samePersistedIdentity(
  configured: import('./identity').HostIdentityMetadata,
  actual: HostIdentity,
  config: BridgeConfig,
 ): boolean {
  const expectedPlatform = config.hostPlatform === 'macos' ? 'macos-keychain' : 'linux-json';
  const storageMatches = configured.privateKeyStorage.type === expectedPlatform
    && actual.privateKeyStorage.type === expectedPlatform
    && JSON.stringify(configured.privateKeyStorage) === JSON.stringify(actual.privateKeyStorage);
  return configured.identityVersion === actual.identityVersion
    && configured.hostId === actual.hostId
    && configured.hostId === config.hostId
    && configured.keyId === actual.keyId
    && configured.publicKey === actual.publicKey
    && configured.publicKeyFingerprint === actual.publicKeyFingerprint
    && configured.algorithm === 'Ed25519'
    && configured.algorithm === actual.algorithm
    && configured.createdAt === actual.createdAt
    && storageMatches;
}


function configPathMatchesProfile(configPath: string, profile: 'dev'): boolean {
  return profile === 'dev' && resolve(configPath) === resolve(resolveAriavaDevProfilePaths().configPath);
}


function snapshotError(
  error: unknown,
  code: 'session_snapshot_stale' | 'session_snapshot_conflict' | 'e2e_recipient_not_ready' | 'e2e_recipient_set_changed' | 'e2e_session_reference_invalid',
): { acceptedRevision?: number } | undefined {
  if (!(error instanceof RelayClientError) || error.status !== 409 || !error.body || typeof error.body !== 'object') return undefined;
  const body = error.body as Record<string, unknown>;
  const reason = typeof body.code === 'string' ? body.code
    : typeof body.error === 'string' ? body.error
      : typeof body.reason === 'string' ? body.reason : error.reason;
  if (reason !== code) return undefined;
  if (code === 'session_snapshot_stale' && (typeof body.acceptedRevision !== 'number' || !Number.isSafeInteger(body.acceptedRevision))) return undefined;
  return typeof body.acceptedRevision === 'number' ? { acceptedRevision: body.acceptedRevision } : {};
}
