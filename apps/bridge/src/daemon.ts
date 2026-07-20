import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  BridgePairWatchResponse,
  ActiveSessionSnapshot,
  CanonicalEvent,
  CanonicalSessionState,
  ReplaceCurrentSessionsRequest,
  ReplaceCurrentSessionsResponse,
  HostEnrollmentRequest,
  HostProjection,
} from '@ariava/protocol';
import { createId, isoNow, sleep } from '@ariava/shared-utils';
import { AgentAdapterClient } from './agent-adapter/client';
import { writeAgentAdapterConfig } from './agent-adapter/config';
import { AgentAdapterRegistry } from './agent-adapter/registry';
import { AgentAdapterServer } from './agent-adapter/server';
import { CommandRouter } from './command-router';
import { PaiDriver } from './drivers/pi';
import { probeHostPlatform } from './host-platform';
import { loadUserConfig, resolveAriavaConfig, resolvePersistedAriavaConfig } from './host-manager';
import { ensureAriavaSecureDirectories, pathHasFilesystemEvidence, readSecureJson, redactSensitive } from './host-manager/secure-files';
import { createHostEncryptionBinding, createRuntimeHostEncryptionIdentityStore, HostIdentityError, LinuxJsonHostIdentityStore, MacOSKeychainHostIdentityStore, type HostEncryptionIdentity, type HostIdentity, type HostIdentityStore } from './identity';
import { RelayClient, RelayClientError } from './relay-client';
import { BridgeStateStore } from './state-store';
import { assertProductionNodeRuntime } from './runtime/node-runtime';
import { assertNodeCryptoSelfTest } from './e2e/node-crypto-self-test';
import type { AgentDriver, BridgeConfig, BridgeSyncResult } from './types';
import { prepareCommandForExecution } from './e2e/command-execution';

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
  schedule: (callback, delayMs) => setTimeout(callback, delayMs),
  cancel: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export class BridgeDaemon {
  private relayClient?: RelayClient;
  private readonly stateStore: BridgeStateStore;
  private readonly adapterRegistry: AgentAdapterRegistry;
  private readonly adapterClient: AgentAdapterClient;
  private readonly adapterServer: AgentAdapterServer;
  private readonly drivers: AgentDriver[];
  private readonly router: CommandRouter;
  private encryptionIdentity?: HostEncryptionIdentity;
  private filesystemVerified = false;
  private startupValidated = false;
  private syncFlight?: Promise<BridgeSyncResult>;
  private reconciliationTimer?: unknown;
  private reconciliationRequested = true;

  constructor(
    private readonly config: BridgeConfig,
    drivers?: AgentDriver[],
    private readonly identityStore?: HostIdentityStore,
    registryNow?: () => Date,
    private readonly reconciliationScheduler: ReconciliationScheduler = DEFAULT_RECONCILIATION_SCHEDULER,
  ) {
    this.stateStore = new BridgeStateStore(config.statePath);
    this.adapterRegistry = new AgentAdapterRegistry(
      config.hostId, this.stateStore, () => this.scheduleRegistryReconciliation(), registryNow,
    );
    this.adapterClient = new AgentAdapterClient(this.adapterRegistry);
    this.adapterServer = new AgentAdapterServer(
      { port: config.agentAdapter.port, secret: config.agentAdapter.secret, hostId: config.hostId },
      this.adapterRegistry,
    );
    this.drivers = drivers ?? [new PaiDriver(this.adapterClient, config.hostId)];
    this.router = new CommandRouter(this.stateStore, new Map(this.drivers.map((driver) => [driver.name, driver])), config.hostId);
  }

  private stopped = false;
  private wakeRunLoop?: () => void;
  private relayAbortController = new AbortController();
  async start(): Promise<void> {
    await this.validateStartup();
    await this.adapterServer.start();
    writeAgentAdapterConfig(this.config.agentAdapter.configPath, { url: this.adapterServer.url, secret: this.config.agentAdapter.secret });
  }

  private verifyFilesystem(): void {
    if (this.filesystemVerified) return;
    ensureAriavaSecureDirectories([
      dirname(this.config.configPath), dirname(this.config.statePath), dirname(this.config.agentAdapter.configPath), dirname(this.config.identityPath),
    ]);
    for (const path of [this.config.configPath, this.config.statePath, this.config.agentAdapter.configPath]) {
      if (pathHasFilesystemEvidence(path)) readSecureJson<unknown>(path);
    }
    this.filesystemVerified = true;
  }

  private async validateStartup(): Promise<void> {
    if (this.startupValidated) return;
    assertProductionNodeRuntime();
    assertNodeCryptoSelfTest();
    this.verifyFilesystem();
    const identity = await this.resolveIdentityStore().load();
    if (!identity) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not initialized; run `ariava init`');
    if (!this.config.identity || !samePersistedIdentity(this.config.identity, identity, this.config)) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Configured identity metadata does not match the local Host identity');
    }
    const encryptionStore = createRuntimeHostEncryptionIdentityStore(this.config.identityPath, this.config.runtimePlatform ?? process.platform);
    this.encryptionIdentity = encryptionStore.loadOrCreate(identity.hostId);
    this.relayClient = new RelayClient(
      { baseUrl: this.config.relayBaseUrl, signer: identity.signer },
      () => this.relayAbortController.signal,
    );
    this.startupValidated = true;
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
    this.reconciliationRequested = true;
    if (this.stopped || this.reconciliationTimer) return;
    this.reconciliationTimer = this.reconciliationScheduler.schedule(() => {
      this.reconciliationTimer = undefined;
      this.wakeRunLoop?.();
    }, 300);
  }

  stop(): void {
    this.stopped = true;
    if (this.reconciliationTimer !== undefined) {
      this.reconciliationScheduler.cancel(this.reconciliationTimer);
      this.reconciliationTimer = undefined;
    }
    this.relayAbortController.abort();
    this.adapterServer.stop(true);
    this.wakeRunLoop?.();
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

  private async performSyncOnce(): Promise<BridgeSyncResult> {
    await this.validateStartup();
    this.reconciliationRequested = false;
    let offline = false;
    try {
      await this.registerHostPresence();
    } catch {
      const prior = this.stateStore.getHost();
      if (prior) this.stateStore.setHost({ ...prior, bridgeStatus: 'degraded' });
      offline = true;
    }

    const newEvents: CanonicalEvent[] = [];
    let authoritativeSetComplete = true;
    for (const driver of this.drivers) {
      try {
        const persistedDriverSessions = this.stateStore.listSessions()
          .filter((session) => this.stateStore.getDriverNameForSession(session.sessionId) === driver.name);
        const sessions = await driver.listSessions(this.config.hostId);
        if (driver.isAuthoritativeSetReady?.(persistedDriverSessions) === false) {
          authoritativeSetComplete = false;
          continue;
        }
        this.stateStore.replaceDriverSessions(driver.name, sessions);
      } catch (error) {
        if (!this.stateStore.hasReconciledDriver(driver.name)) authoritativeSetComplete = false;
        const event = this.buildDriverErrorEvent(driver.name, error);
        this.stateStore.queuePendingEvent(event);
        newEvents.push(event);
      }
    }
    // A driver failure must never turn a partial list into an authoritative replacement.
    // Successful drivers have been reconciled above, while failed drivers retain their last
    // complete persisted set. Build the Host snapshot only from that reconciled store.
    const nextSessions = this.stateStore.listSessions();
    const activeSessions = nextSessions
      .filter((session) => !isDiagnosticSession(session))
      .map((session): ActiveSessionSnapshot => ({ ...session, presence: 'active' }));
    if (authoritativeSetComplete) {
      const pending = await this.stateStore.stageCurrentSessionsSnapshot(this.config.hostId, activeSessions, isoNow());
      if (!offline && (pending || this.stateStore.getPendingCurrentSessionsSnapshot())) {
        try {
          await this.flushCurrentSessionsSnapshot(activeSessions);
        } catch (error) {
          if (snapshotError(error, 'session_snapshot_conflict')) {
            throw new Error('Relay rejected the persisted current session snapshot revision as conflicting', { cause: error });
          }
          offline = true;
        }
      }
    }
    const flushedEvents = offline ? 0 : await this.flushPendingEvents();
    const flushedReads = offline ? 0 : await this.flushPendingHandles();
    const handledCommands = offline ? [] : await this.pullAndHandleCommands();
    return { host: this.stateStore.getHost(), sessions: nextSessions, emittedEvents: newEvents, flushedEvents, flushedReads, handledCommands, offline };
  }

  async pairWatch(pairingCode: string): Promise<BridgePairWatchResponse> {
    await this.validateStartup();
    await this.registerHostPresence();
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
        this.stateStore.queuePendingEvent(this.buildBridgeFailureEvent(error));
        await this.flushPendingEvents();
      }
      if (this.reconciliationRequested) continue;
      if (!this.stopped) await this.waitForNextPoll();
    }
  }

  private async waitForNextPoll(): Promise<void> {
    await Promise.race([
      sleep(this.config.pollIntervalMs),
      new Promise<void>((resolveStop) => { this.wakeRunLoop = resolveStop; }),
    ]);
    this.wakeRunLoop = undefined;
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

  private async registerHostPresence(): Promise<void> {
    const identity = await this.resolveIdentityStore().load();
    if (!identity || !this.config.identity || !samePersistedIdentity(this.config.identity, identity, this.config)) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity changed while daemon was running');
    }
    const response = await this.client().enrollHost(await this.buildEnrollment(identity));
    this.stateStore.setHost(response.host);
  }

  private async sendCurrentSessionsSnapshot(
    pending: { request: ReplaceCurrentSessionsRequest; digest: string },
  ): Promise<void> {
    const response: ReplaceCurrentSessionsResponse = await this.client().replaceCurrentSessions(pending.request);
    if (response.hostId !== pending.request.hostId || response.revision !== pending.request.revision) {
      throw new Error('Relay returned a mismatched current session snapshot response');
    }
    this.stateStore.acceptCurrentSessionsSnapshot(pending.request.revision, pending.digest);
  }

  private async flushCurrentSessionsSnapshot(currentSessions: ActiveSessionSnapshot[]): Promise<void> {
    let pending = this.stateStore.getPendingCurrentSessionsSnapshot();
    if (!pending) return;
    try {
      await this.sendCurrentSessionsSnapshot(pending);
    } catch (error) {
      const stale = snapshotError(error, 'session_snapshot_stale');
      if (stale) {
        this.stateStore.noteCurrentSessionsSnapshotRevisionLowerBound(stale.acceptedRevision);
        this.stateStore.clearPendingCurrentSessionsSnapshot(pending.request.revision, pending.digest);
        pending = await this.stateStore.stageCurrentSessionsSnapshot(
          this.config.hostId, currentSessions, isoNow(), stale.acceptedRevision,
        );
        if (pending) await this.sendCurrentSessionsSnapshot(pending);
        return;
      }
      throw error;
    }
  }

  private async flushPendingEvents(): Promise<number> {
    let flushed = 0;
    for (const event of this.stateStore.peekPendingEvents()) {
      const session = this.stateStore.getSession(event.sessionId);
      // Relay's event-ingest contract still requires a session envelope for diagnostic
      // history. This synthetic envelope is transport-only: driver:/host: IDs are excluded
      // from authoritative current-session snapshots above and by Relay defense in depth.
      const syntheticSession = session ?? ({
        sessionId: event.sessionId, hostId: event.hostId, provider: event.provider, projectName: 'system',
        nameText: event.contextText ?? event.sessionId, openingText: undefined, latestActivityText: event.assistantText,
        stateLabel: 'Unknown', status: event.status, updatedAt: event.createdAt,
      } satisfies CanonicalSessionState);
      try {
        await this.client().publishEvent(event, syntheticSession);
        this.stateStore.removePendingEvent(event.eventId);
        flushed += 1;
      } catch { break; }
    }
    return flushed;
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


  private async pullAndHandleCommands() {
    const response = await this.client().pullCommands(this.config.hostId);
    const handled = [];
    for (const command of response.commands) {
      const prepared = await prepareCommandForExecution(command);
      if (!prepared.ok) {
        const result = {
          commandId: command.commandId,
          hostId: command.hostId,
          sessionId: command.sessionId,
          accepted: false,
          status: 'failed' as const,
          message: 'Encrypted reply execution is unavailable until the local E2E keyring is configured.',
          correlationId: prepared.code,
          updatedAt: isoNow(),
        };
        this.stateStore.rememberCommandResult(result);
        handled.push(result);
        await this.client().submitCommandResult(result);
        continue;
      }
      const outcome = await this.router.handle(prepared.command);
      handled.push(outcome.result);
      await this.client().submitCommandResult(outcome.result);
    }
    return handled;
  }

  private buildDriverErrorEvent(driverName: string, error: unknown): CanonicalEvent {
    return { eventId: createId('evt'), hostId: this.config.hostId, sessionId: `driver:${driverName}`, provider: driverName,
      type: 'driver_error', status: 'unknown', typeLabel: deriveEventTypeLabel('driver_error'),
      assistantText: `Driver ${driverName} failed: ${this.formatError(error)}`, contextText: `driver:${driverName}`, createdAt: isoNow() };
  }

  private buildBridgeFailureEvent(error: unknown): CanonicalEvent {
    return { eventId: createId('evt'), hostId: this.config.hostId, sessionId: `host:${this.config.hostId}`, provider: 'bridge',
      type: 'host_unavailable', status: 'unknown', typeLabel: deriveEventTypeLabel('host_unavailable'),
      assistantText: `Bridge loop recovered from an error: ${this.formatError(error)}`, contextText: this.config.hostName, createdAt: isoNow() };
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

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

function deriveEventTypeLabel(type: CanonicalEvent['type']): string {
  switch (type) {
    case 'question_requested': return 'Agent question';
    case 'blocked': return 'Session blocked';
    case 'done': return 'Task complete';
    case 'working': return 'In progress';
    case 'driver_error': return 'Driver error';
    case 'host_unavailable': return 'Host unavailable';
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

function isDiagnosticSession(session: CanonicalSessionState): boolean {
  return session.sessionId.startsWith('driver:') || session.sessionId.startsWith('host:');
}

function snapshotError(
  error: unknown,
  code: 'session_snapshot_stale' | 'session_snapshot_conflict',
): { acceptedRevision: number } | undefined {
  if (!(error instanceof RelayClientError) || error.status !== 409 || !error.body || typeof error.body !== 'object') return undefined;
  const body = error.body as Record<string, unknown>;
  if (body.code !== code || typeof body.acceptedRevision !== 'number' || !Number.isSafeInteger(body.acceptedRevision)) return undefined;
  return { acceptedRevision: body.acceptedRevision };
}
