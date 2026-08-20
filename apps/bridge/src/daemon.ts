import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  BridgePairWatchResponse,
  CanonicalSessionState,
  ReplaceE2ECurrentSessionsRequestV1,
  HostEnrollmentRequest,
  HostProjection,
} from '@ariava/protocol';
import {
  canonicalE2ECurrentSessionsDigestV1,
  type CommandResult,
  type E2ERecipientSnapshotV1,
} from '@ariava/protocol';
import { isoNow } from '@ariava/shared-utils';
import { writeAgentAdapterConfig, type AgentAdapterDiscoveryFile } from './agent-adapter/config';
import { AgentAdapterRegistry } from './agent-adapter/registry';
import { AgentAdapterServer } from './agent-adapter/server';
import { CommandRouter } from './command-router';
import { probeHostPlatform } from './host-platform';
import { loadUserConfig, resolveAriavaConfig, resolvePersistedAriavaConfig } from './host-manager/config';
import { ensureAriavaSecureDirectories, pathHasFilesystemEvidence, readSecureJson, redactSensitive } from './host-manager/secure-files';
import { createHostEncryptionBinding, HostIdentityError, LinuxJsonHostIdentityStore, MacOSKeychainHostIdentityStore, type HostEncryptionIdentity, type HostEncryptionIdentityStore, type HostIdentity, type HostIdentityStore } from './identity';
import { RelayClientError, type RelayClient } from './relay-client';
import { BridgeStateStore } from './state-store';
import type { AgentDriver, BridgeConfig, BridgeSyncResult } from './types';
import { LocalLinkKeyring } from './e2e/link-keyring';
import { DEFAULT_ENCRYPTED_UPLOAD_CRYPTO, createEncryptedUploadActions, type EncryptedEventFailure, type EncryptedUploadActions } from './e2e/upload-actions';
import type { RuntimeCoordinator } from './runtime-lock';
import type { CommandReceiptConstructionDependencies } from './e2e/command-receipt-recovery';
import {
  buildHostEnrollmentRequest,
  buildHostMetadata,
} from './daemon/daemon-inputs';
import { isAbortError, snapshotError } from './daemon/daemon-errors';
import { performHostPresenceRegistration } from './daemon/presence-workflow';
import {
  createInitialSnapshotFailureState,
  decideSnapshotFailure,
  decideSnapshotFailureLog,
  resetSnapshotFailures,
  summarizeSnapshotFailures,
  type SnapshotFailureDecision,
  type SnapshotFailureState,
} from './daemon/snapshot-policy';
import { activateBridgeDaemonServer, activateBridgeRuntime, assertHostDomainResetStartAllowed, createBridgeDaemonShell, type BridgeDaemonActiveRuntime } from './daemon/runtime-composition';
import {
  performCommandPullAndDispatch,
  performReconciledReceiptDrain,
  pruneCommandRuntime,
  recoverStartupCommandPipeline,
  refreshCommandAuthority,
  type CommandWorkflowDependencies,
} from './daemon/command-workflow';
import { performBridgeSyncOnce, type SessionPublicationOutcome } from './daemon/sync-workflow';

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

  record(failure: EncryptedEventFailure): void {
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


/**
 * §6.3 in-memory rate-limited Session publication block/recovery logger.
 * Deliberately NOT the persisted `RuntimeHealthLogger` (which only accepts
 * `driver | relay_presence` and writes `bridge_runtime_health`), and never
 * touches the persisted `BridgeRuntimeHealth` exact schema. Fields are limited
 * to the §6.3 allow-list; sessionId / byte counts / exception text / excerpts /
 * ciphertext / keys / driver names are never written. `recovered` is emitted
 * exactly once after a full publication success and clears the suppression
 * state; after a restart the logger re-observes from scratch (no persistence).
 */
export class SessionPublicationBlockLogger {
  private lastLogAt = Number.NEGATIVE_INFINITY;
  private suppressed = 0;
  private active = false;
  private activeCode: 'protected_content_invalid' | 'session_source_invalid' = 'protected_content_invalid';

  constructor(
    private readonly write: (line: string) => void = (line) => { process.stderr.write(line); },
    private readonly now: () => number = () => Date.now(),
  ) {}

  blocked(
    blockedSessionCount: number,
    code: 'protected_content_invalid' | 'session_source_invalid' = 'protected_content_invalid',
  ): void {
    const timestamp = this.now();
    if (!this.active) this.active = true;
    this.activeCode = code;
    if (timestamp - this.lastLogAt < 30_000) {
      this.suppressed += 1;
      return;
    }
    const suppressed = this.suppressed;
    this.suppressed = 0;
    this.lastLogAt = timestamp;
    this.write(`${JSON.stringify({
      component: 'session_publication', outcome: 'blocked', code,
      blockedSessionCount, suppressed,
    })}\n`);
  }

  recovered(): void {
    if (!this.active) return;
    this.active = false;
    this.suppressed = 0;
    this.lastLogAt = 0;
    this.write(`${JSON.stringify({
      component: 'session_publication', outcome: 'recovered', code: this.activeCode,
    })}\n`);
  }
}

export class BridgeDaemon {
  private relayClient?: RelayClient;
  private activeRuntime?: BridgeDaemonActiveRuntime;
  private readonly stateStore: BridgeStateStore;
  private readonly runtimeCoordinator: RuntimeCoordinator;
  private readonly adapterRegistry: AgentAdapterRegistry;
  private readonly adapterServer: AgentAdapterServer;
  private readonly drivers: AgentDriver[];
  private readonly router: CommandRouter;
  private encryptionStore?: HostEncryptionIdentityStore;
  private encryptionIdentity?: HostEncryptionIdentity;
  private keyring?: LocalLinkKeyring;
  private keyringMigrationContext?: ConstructorParameters<typeof LocalLinkKeyring>[2];
  private uploadActions!: EncryptedUploadActions;
  private filesystemVerified = false;
  private startupValidated = false;
  private syncFlight?: Promise<BridgeSyncResult>;
  private reconciliationTimer?: unknown;
  private presenceHeartbeatTimer?: unknown;
  private presenceFlight?: Promise<void>;
  private reconciliationRequested = true;
  private snapshotFailureState: SnapshotFailureState = createInitialSnapshotFailureState();
  private readonly encryptedEventFailureLogger = new EncryptedEventFailureLogger();
  private readonly sessionPublicationBlockLogger = new SessionPublicationBlockLogger();
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
    const shell = createBridgeDaemonShell({
      config,
      drivers,
      registryNow,
      onRegistryMutation: () => this.scheduleRegistryReconciliation(),
    });
    this.runtimeCoordinator = shell.runtimeCoordinator;
    this.stateStore = shell.stateStore;
    this.adapterRegistry = shell.adapterRegistry;
    this.adapterServer = shell.adapterServer;
    this.drivers = shell.drivers;
    this.router = shell.router;
  }
  private writeAdapterConfig(configPath: string, config: AgentAdapterDiscoveryFile): void {
    writeAgentAdapterConfig(configPath, config);
  }

  private stopped = false;
  private relayAbortController = new AbortController();
  async start(): Promise<void> {
    await this.validateStartup();
    await activateBridgeDaemonServer({
      adapterServer: this.adapterServer,
      config: this.config,
      writeDiscovery: (evidence) => this.writeAdapterConfig(this.config.agentAdapter.configPath, evidence),
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
      const active = await activateBridgeRuntime({
        config: this.config,
        stateStore: this.stateStore,
        signal: () => this.relayAbortController.signal,
        verifyFilesystem: () => this.verifyFilesystem(),
        loadValidatedIdentity: async () => {
          const identity = await this.resolveIdentityStore().load();
          if (!identity) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not initialized; run `ariava init`');
          if (!this.config.identity || !samePersistedIdentity(this.config.identity, identity, this.config)) {
            throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Configured identity metadata does not match the local Host identity');
          }
          return identity;
        },
        onDroppedUnreadableItems: (count) => {
          if (count > 0) process.stderr.write(`Ariava dropped ${count} unreadable encrypted spool item(s).\n`);
        },
        runCommandRecovery: (relayClient, keyring) => this.recoverStartupCommands(relayClient, keyring),
        onEventFailure: (failure) => this.encryptedEventFailureLogger.record(failure),
        commit: (partial) => {
          // Mirror each activation-created resource into its daemon field at
          // the exact baseline assignment point, preserving characterized
          // partial visibility when activation fails mid-way.
          if (partial.encryptionStore !== undefined) this.encryptionStore = partial.encryptionStore;
          if (partial.encryptionIdentity !== undefined) this.encryptionIdentity = partial.encryptionIdentity;
          if (partial.keyringMigrationContext !== undefined) this.keyringMigrationContext = partial.keyringMigrationContext;
          if (partial.keyring !== undefined) this.keyring = partial.keyring;
          if (partial.relayClient !== undefined) this.relayClient = partial.relayClient;
          if (partial.uploadActions !== undefined) this.uploadActions = partial.uploadActions;
        },
      });
      this.activeRuntime = active;
      this.startupValidated = true;
    } catch (error) {
      this.disposeRuntimeCoordinator();
      throw error;
    }
  }

  private async recoverStartupCommands(relayClient: RelayClient, keyring: LocalLinkKeyring): Promise<void> {
    // Adopt the activation-created resources so the characterized recovery seams
    // (refreshCommandAuthority / pruneCommandRuntime) run on the daemon fields
    // exactly as they do during normal sync (Task 1 tests inject the Relay here).
    this.relayClient = relayClient;
    this.keyring = keyring;
    try {
      await recoverStartupCommandPipeline(this.commandDependencies());
    } catch {
      // Command recovery stays frozen until an authoritative snapshot succeeds.
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
    assertHostDomainResetStartAllowed(this.config);
  }

  private async performSyncOnce(): Promise<BridgeSyncResult> {
    // §9: one linear sync pass in `sync-workflow.ts`. Every effect stays
    // daemon-owned (spec §8): single-flight/coalescing, stop, timers/scheduling,
    // presence/receipt/command flights, snapshot failure state, and the
    // logging/health authorities are reached only through this narrow contract.
    return performBridgeSyncOnce({
      assertHostDomainResetStartAllowed: () => this.assertHostDomainResetStartAllowed(),
      stop: () => this.stop(),
      validateStartup: () => this.validateStartup(),
      acknowledgeSyncPass: () => { this.reconciliationRequested = false; },
      ensureHostPresence: () => this.ensureHostPresence(),
      reconcileRecipientsAndDrainReceipts: () => this.reconcileRecipientsAndDrainReceipts(),
      drivers: () => this.drivers,
      hostId: this.config.hostId,
      pollIntervalMs: this.config.pollIntervalMs,
      listSessions: () => this.stateStore.listSessions(),
      getDriverNameForSession: (sessionId) => this.stateStore.getDriverNameForSession(sessionId),
      replaceDriverSessions: (driverName, sessions) => this.stateStore.replaceDriverSessions(driverName, sessions),
      recordDriverReconciliationFailure: (driverName, observedAt, nextRetryAt) => this.recordDriverReconciliationFailure(driverName, observedAt, nextRetryAt),
      recordDriverReconciliationSuccess: (driverName) => this.recordDriverReconciliationSuccess(driverName),
      flushCurrentSessionsSnapshot: (currentSessions) => this.flushCurrentSessionsSnapshot(currentSessions),
      recordLocalSnapshotPublicationFailure: (error, activeSessions) => this.recordLocalSnapshotPublicationFailure(error, activeSessions),
      handleCurrentSessionsSnapshotFailure: (error, activeSessions) => this.handleCurrentSessionsSnapshotFailure(error, activeSessions),
      sessionPublicationRecovered: () => this.sessionPublicationBlockLogger.recovered(),
      sessionPublicationBlocked: (blockedSessionCount, reason) => this.sessionPublicationBlockLogger.blocked(blockedSessionCount, reason),
      eventsMayDrain: (outcome) => this.eventsMayDrain(outcome),
      flushPendingEvents: () => this.flushPendingEvents(),
      flushPendingHandles: () => this.flushPendingHandles(),
      pullAndHandleCommands: () => this.pullAndHandleCommands(),
      getHost: () => this.stateStore.getHost(),
    });
  }

  private recordDriverReconciliationFailure(driverName: string, observedAt: string, nextRetryAt: string): void {
    const degradation = this.stateStore.recordDriverReconciliationFailure(driverName, observedAt, nextRetryAt);
    this.runtimeHealthLogger.failure('driver', driverName, degradation.count);
  }

  private recordDriverReconciliationSuccess(driverName: string): void {
    const recovered = this.stateStore.recordDriverReconciliationSuccess(driverName);
    if (recovered) this.runtimeHealthLogger.recovery('driver', driverName, recovered.count);
  }

  private recordLocalSnapshotPublicationFailure(error: unknown, activeSessions: CanonicalSessionState[]): void {
    const logDecision = decideSnapshotFailureLog(this.snapshotFailureState, Date.now(), 'publish');
    this.snapshotFailureState = logDecision.next;
    if (logDecision.shouldLog) this.logCurrentSessionsSnapshotFailure(error, logDecision.next.count, 'publish', activeSessions);
    this.scheduleRegistryReconciliation();
  }

  /**
   * §6.2: decides whether Event drain may proceed for the current Session
   * publication outcome. `locally-blocked` drains only when the current recipient-
   * set version equals the Bridge's last accepted version and there is no
   * unconverged Session inflight evidence; `deferred`/`fail-closed` keep the
   * existing stop semantics.
   */
  private eventsMayDrain(outcome: SessionPublicationOutcome): boolean {
    if (outcome.type === 'published' || outcome.type === 'unchanged') return true;
    if (outcome.type === 'locally-blocked') {
      // §6.2: drain only when the recipient-set version used for the blocked pass
      // matches the version proven by the last ACCEPTED manifest. The global
      // recipientSetVersion is adopted at Session-ciphertext commit time (BEFORE
      // the manifest is accepted), so it is not proof of accepted coverage.
      const accepted = this.stateStore.getCurrentSessionsSnapshotState();
      return accepted.lastAcceptedRecipientSetVersion === outcome.recipientSetVersion
        && this.stateStore.listInflightSessionIds().length === 0;
    }
    return false;
  }

  private resetCurrentSessionsSnapshotFailures(): void {
    this.snapshotFailureState = resetSnapshotFailures(this.snapshotFailureState);
  }

  private async handleCurrentSessionsSnapshotFailure(error: unknown, activeSessions: CanonicalSessionState[]): Promise<{ online: boolean; outcome: SessionPublicationOutcome }> {
    // The pure reducer runs first with only clock evidence and the next state is
    // assigned before any active-session/revision inspection. Summary evidence is
    // collected only when `shouldLog`, so throttled failures do no summary state-
    // store reads; the baseline log-then-schedule effect order is preserved.
    const decision = this.snapshotFailureDecision('publication-failure');
    this.snapshotFailureState = decision.next;
    if (decision.shouldLog) this.logCurrentSessionsSnapshotFailure(error, decision.next.count, 'publish', activeSessions);
    this.scheduleRegistryReconciliation();
    if (decision.action === 'retry') return { online: false, outcome: { type: 'deferred', reason: 'network' } };
    if (decision.action !== 'recover-pipeline') throw new Error(`Unexpected snapshot failure action: ${decision.action}`);
    try {
      await this.recoverCurrentSessionsSnapshotPipeline(activeSessions);
      const recoveredAfter = this.snapshotFailureState.count;
      const outcome = await this.flushCurrentSessionsSnapshot(activeSessions);
      this.resetCurrentSessionsSnapshotFailures();
      if (outcome.type === 'deferred') {
        if (this.reconciliationTimer !== undefined) {
          this.reconciliationScheduler.cancel(this.reconciliationTimer);
          this.reconciliationTimer = undefined;
        }
        return { online: true, outcome };
      }
      process.stderr.write(`Ariava recovered current-session snapshot publication after ${recoveredAfter} failure(s).\n`);
      return { online: true, outcome };
    } catch (recoveryError) {
      const recoveryDecision = this.snapshotFailureDecision('recovery-failure');
      this.snapshotFailureState = recoveryDecision.next;
      if (recoveryDecision.shouldLog) this.logCurrentSessionsSnapshotFailure(recoveryError, recoveryDecision.next.count, 'recovery', activeSessions);
      this.scheduleRegistryReconciliation();
      // Execute the returned action instead of hardcoding mark-offline.
      if (recoveryDecision.action === 'mark-offline') return { online: false, outcome: { type: 'deferred', reason: 'network' } };
      throw new Error(`Unexpected snapshot recovery action: ${recoveryDecision.action}`);
    }
  }

  private snapshotFailureDecision(type: 'publication-failure' | 'recovery-failure'): SnapshotFailureDecision {
    return decideSnapshotFailure(this.snapshotFailureState, { type, now: Date.now() });
  }

  private async recoverCurrentSessionsSnapshotPipeline(_activeSessions: CanonicalSessionState[]): Promise<void> {
    if (this.encryptionStore) {
      const keyring = new LocalLinkKeyring(
        `${this.config.identityPath}.e2e-keyring.json`, this.encryptionStore, this.keyringMigrationContext,
      );
      this.keyring = keyring;
      // Rebind the upload actions to the rebuilt keyring so the bound instance
      // captures the same keyring instance the daemon uses (the baseline facade
      // captured the current keyring at each on-demand construction).
      this.uploadActions = createEncryptedUploadActions({
        stateStore: this.stateStore,
        relayClient: this.client(),
        crypto: DEFAULT_ENCRYPTED_UPLOAD_CRYPTO,
        keyring,
        hooks: { eventFailure: (failure) => this.encryptedEventFailureLogger.record(failure) },
      });
      if (this.activeRuntime) this.activeRuntime = { ...this.activeRuntime, keyring, uploadActions: this.uploadActions };
    }
    // `flushCurrentSessionsSnapshot()` performs the exact all-inflight reconcile
    // after immutable full-set preflight. Keeping one owner avoids reconciling and
    // then losing the fact that a replacement manifest must be forced.
  }

  private logCurrentSessionsSnapshotFailure(error: unknown, failures: number, phase: 'publish' | 'recovery', activeSessions: CanonicalSessionState[]): void {
    // Called only when the pure decision says `shouldLog`. Summary evidence is
    // aggregated here (state-store revision inspection + capping) so throttled
    // failures perform no state-store reads; only the log effect remains in the
    // class.
    const summary = summarizeSnapshotFailures({
      activeSessionCount: activeSessions.length,
      sessionsWithoutRevision: activeSessions
        .filter((session) => this.stateStore.currentSessionRevision(session.sessionId) === 0)
        .map((session) => session.sessionId),
    });
    const snapshot = this.stateStore.getCurrentSessionsSnapshotState();
    const detail = {
      phase,
      failures,
      activeSessionCount: summary.activeSessionCount,
      noRevisionSessionCount: summary.noRevisionSessionCount,
      noRevisionSessionIds: summary.noRevisionSessionIds,
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
    return buildHostEnrollmentRequest({
      identity,
      encryptionBinding: await createHostEncryptionBinding(identity, this.encryptionIdentity),
      hostMetadata: buildHostMetadata({
        hostName: this.config.hostName,
        hostPlatform: this.config.hostPlatform,
        bridgeVersion: this.config.bridgeVersion,
      }),
    });
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

  private registerHostPresence(): Promise<void> {
    // The enrollment/register effect body lives in the narrow presence runner;
    // single-flight, timer, scheduling, clock, health recording, and stop
    // ownership stay in this class (spec §8).
    return performHostPresenceRegistration({
      loadIdentity: () => this.resolveIdentityStore().load(),
      matchesConfiguredIdentity: (identity) => this.config.identity !== undefined && samePersistedIdentity(this.config.identity, identity, this.config),
      buildEnrollment: (identity) => this.buildEnrollment(identity),
      enrollHost: (request) => this.client().enrollHost(request),
      isStopped: () => this.stopped,
      setHost: (host) => this.stateStore.setHost(host),
    });
  }

  private async sendCurrentSessionsPublication(
    publication: { request: ReplaceE2ECurrentSessionsRequestV1; digest: string; contentDigest: string },
  ): Promise<void> {
    const response = await this.client().replaceE2ECurrentSessions(publication.request);
    if (response.hostId !== publication.request.hostId || response.revision !== publication.request.revision) throw new Error('Relay returned a mismatched current session snapshot response');
    this.stateStore.acceptCurrentSessionsPublication(publication.request, publication.digest, publication.contentDigest);
    this.resetCurrentSessionsSnapshotFailures();
  }

  private async flushCurrentSessionsSnapshot(currentSessions: CanonicalSessionState[]): Promise<SessionPublicationOutcome> {
    // §6.1/§4.4: `currentSessions` is the single immutable snapshot for preflight,
    // revision allocation, encryption, and the manifest — the orchestrator never
    // re-reads the mutable store mid-pass (no split snapshot / TOCTOU).
    for (let attempt = 0; attempt < 4; attempt += 1) {
      let recipientSnapshot: Awaited<ReturnType<RelayClient['recipientSnapshot']>>;
      try {
        recipientSnapshot = await this.client().recipientSnapshot();
      } catch (error) {
        if (snapshotError(error, 'e2e_recipient_not_ready')) {
          this.resetCurrentSessionsSnapshotFailures();
          return { type: 'deferred', reason: 'recipient-set' };
        }
        throw error;
      }
      if (!this.keyring || !this.encryptionIdentity) throw new Error('E2E lifecycle encryption is unavailable');
      const recipients = this.keyring.reconcileRecipients(recipientSnapshot);

      // §6.1: full-set content preflight BEFORE createCurrentSessionsPublication so a
      // content block never allocates a publication revision, never creates/replaces
      // inflight, and never sends a manifest. The Relay keeps its last accepted
      // membership; the local Sessions keep receiving heartbeats/content updates.
      const preflight = this.uploadActions.preflightAuthoritativeSessionSet(currentSessions);
      if (preflight.blockedSessionCount > 0) {
        // §4.4: a content block must NOT strand committed Session inflight evidence;
        // converge it (revision + inflight removal) before returning locally-blocked.
        // Uncommitted/unknown evidence stays byte-preserved; malformed/cross-bound
        // evidence fails closed (recovery-required).
        const reconciled = await this.uploadActions.reconcileSessionInflights(currentSessions);
        if (reconciled.deferred) return { type: 'fail-closed' };
        return {
          type: 'locally-blocked', reason: preflight.reason,
          blockedSessionCount: preflight.blockedSessionCount,
          recipientSetVersion: recipientSnapshot.recipientSetVersion,
        };
      }

      // Even when the canonical content digest is unchanged, a lost Session upload
      // response may leave a committed revision represented only by inflight evidence.
      // Reconcile every active/orphan V2 or legacy record before deciding `unchanged`.
      const hadSessionInflights = this.stateStore.listInflightSessionIds().length > 0;
      const reconciled = await this.uploadActions.reconcileSessionInflights(currentSessions);
      if (reconciled.deferred) return { type: 'fail-closed' };
      const minimumRevision = hadSessionInflights
        ? this.stateStore.getCurrentSessionsSnapshotState().lastAcceptedRevision + 1
        : 0;
      let publication = await this.stateStore.createCurrentSessionsPublication(
        this.config.hostId, currentSessions, recipientSnapshot.recipientSetVersion, isoNow(), minimumRevision,
      );
      if (!publication) return { type: 'unchanged' };
      const outcome = await this.uploadActions.publishAuthoritativeSnapshots(
        recipientSnapshot, recipients, currentSessions,
      );
      if (outcome.type !== 'published') {
        // Preserve the explicit publication taxonomy. Deterministic fail-closed and
        // recipient-set deferrals must not be reclassified as offline network faults.
        if (outcome.type === 'locally-blocked') {
          return {
            type: 'locally-blocked', reason: outcome.reason, blockedSessionCount: 1,
            recipientSetVersion: recipientSnapshot.recipientSetVersion,
          };
        }
        return outcome;
      }
      const committed = outcome;
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
        return { type: 'published' };
      } catch (error) {
        if (snapshotError(error, 'e2e_recipient_not_ready')) {
          this.resetCurrentSessionsSnapshotFailures();
          return { type: 'deferred', reason: 'recipient-set' };
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
    return this.uploadActions.publishRecipientChangeSnapshots(snapshot, this.keyring.reconcileRecipients(snapshot));
  }

  private async flushPendingEvents(): Promise<number> {
    if (!this.encryptionIdentity || !this.keyring) return 0;
    return this.uploadActions.flushPendingEvents();
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
    if (!this.keyring) return 0;
    return performReconciledReceiptDrain(this.commandDependencies());
  }

  private async pullAndHandleCommands(): Promise<CommandResult[]> {
    if (this.commandFlightActive) return [];
    this.commandFlightActive = true;
    try {
      return await performCommandPullAndDispatch(this.commandDependencies());
    } finally {
      this.commandFlightActive = false;
    }
  }

  private async refreshCommandAuthority(): Promise<E2ERecipientSnapshotV1> {
    return refreshCommandAuthority(this.commandDependencies());
  }

  private pruneCommandRuntime(now = this.commandNow().toISOString()): void {
    if (!this.keyring) return;
    pruneCommandRuntime(this.commandDependencies(), now);
  }

  private commandDependencies(): CommandWorkflowDependencies {
    if (!this.keyring) throw new Error('E2E command keyring is unavailable');
    return {
      stateStore: this.stateStore,
      keyring: this.keyring,
      relayClient: () => this.client(),
      router: this.router,
      hostId: this.config.hostId,
      now: () => this.commandNow(),
      receiptConstruction: this.commandReceiptConstruction,
      isStopped: () => this.stopped,
      markOutcomeUnknownIfActive: (commandId) => this.markCommandOutcomeUnknownIfActive(commandId),
      refreshAuthority: () => this.refreshCommandAuthority(),
      prune: (now) => this.pruneCommandRuntime(now),
    };
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
