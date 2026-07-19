import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  BridgePairWatchResponse,
  CanonicalEvent,
  CanonicalSessionState,
  HostEnrollmentRequest,
  HostMetadataUpdateRequest,
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
import { HostIdentityError, LinuxJsonHostIdentityStore, MacOSKeychainHostIdentityStore, type HostIdentity, type HostIdentityStore } from './identity';
import { RelayClient, RelayClientError } from './relay-client';
import { BridgeStateStore } from './state-store';
import type { AgentDriver, BridgeConfig, BridgeSyncResult } from './types';

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

export class BridgeDaemon {
  private relayClient?: RelayClient;
  private readonly stateStore: BridgeStateStore;
  private readonly adapterRegistry: AgentAdapterRegistry;
  private readonly adapterClient: AgentAdapterClient;
  private readonly adapterServer: AgentAdapterServer;
  private readonly drivers: AgentDriver[];
  private readonly router: CommandRouter;
  private filesystemVerified = false;
  private startupValidated = false;

  constructor(private readonly config: BridgeConfig, drivers?: AgentDriver[], private readonly identityStore?: HostIdentityStore) {
    this.stateStore = new BridgeStateStore(config.statePath);
    this.adapterRegistry = new AgentAdapterRegistry(config.hostId, this.stateStore);
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
    this.verifyFilesystem();
    const identity = await this.resolveIdentityStore().load();
    if (!identity) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not initialized; run `ariava init`');
    if (!this.config.identity || !samePersistedIdentity(this.config.identity, identity, this.config)) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Configured identity metadata does not match the local Host identity');
    }
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

  stop(): void {
    this.stopped = true;
    this.relayAbortController.abort();
    this.adapterServer.stop(true);
    this.wakeRunLoop?.();
  }
  get adapterUrl(): string { return this.adapterServer.url; }
  get driverNames(): string[] { return this.drivers.map((driver) => driver.name); }

  async syncOnce(): Promise<BridgeSyncResult> {
    await this.validateStartup();
    const metadata = this.buildHostMetadata();
    let offline = false;
    try {
      await this.registerHostPresence(metadata);
    } catch {
      const prior = this.stateStore.getHost();
      if (prior) this.stateStore.setHost({ ...prior, bridgeStatus: 'degraded' });
      offline = true;
    }

    const nextSessions: CanonicalSessionState[] = [];
    const newEvents: CanonicalEvent[] = [];
    for (const driver of this.drivers) {
      try {
        const sessions = await driver.listSessions(this.config.hostId);
        nextSessions.push(...sessions);
        this.stateStore.replaceDriverSessions(driver.name, sessions);
      } catch (error) {
        const event = this.buildDriverErrorEvent(driver.name, error);
        this.stateStore.queuePendingEvent(event);
        newEvents.push(event);
      }
    }
    const flushedEvents = offline ? 0 : await this.flushPendingEvents();
    const flushedReads = offline ? 0 : await this.flushPendingHandles();
    const handledCommands = offline ? [] : await this.pullAndHandleCommands();
    return { host: this.stateStore.getHost(), sessions: nextSessions, emittedEvents: newEvents, flushedEvents, flushedReads, handledCommands, offline };
  }

  async pairWatch(pairingCode: string): Promise<BridgePairWatchResponse> {
    await this.validateStartup();
    await this.registerHostPresence(this.buildHostMetadata());
    return this.client().pairWatch(pairingCode);
  }

  async runForever(): Promise<void> {
    this.stopped = false;
    if (this.relayAbortController.signal.aborted) this.relayAbortController = new AbortController();
    while (!this.stopped) {
      try { await this.syncOnce(); }
      catch (error) {
        if (this.stopped || isAbortError(error)) break;
        this.stateStore.queuePendingEvent(this.buildBridgeFailureEvent(error));
        await this.flushPendingEvents();
      }
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

  private buildEnrollment(identity: HostIdentity): HostEnrollmentRequest {
    return {
      hostId: identity.hostId, keyId: identity.keyId, algorithm: identity.algorithm, publicKey: identity.publicKey,
      ...this.buildHostMetadata(),
    };
  }

  private buildHostMetadata(): HostMetadataUpdateRequest {
    return { hostName: this.config.hostName, platform: this.config.hostPlatform, bridgeVersion: this.config.bridgeVersion };
  }

  private async registerHostPresence(metadata: HostMetadataUpdateRequest): Promise<void> {
    const identity = await this.resolveIdentityStore().load();
    if (!identity || !this.config.identity || !samePersistedIdentity(this.config.identity, identity, this.config)) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity changed while daemon was running');
    }
    let response;
    try {
      response = await this.client().updateHost(metadata);
    } catch (error) {
      if (!(error instanceof RelayClientError) || error.status !== 404) throw error;
      response = await this.client().enrollHost(this.buildEnrollment(identity));
    }
    this.stateStore.setHost(response.host);
  }

  private async flushPendingEvents(): Promise<number> {
    let flushed = 0;
    for (const event of this.stateStore.peekPendingEvents()) {
      const session = this.stateStore.getSession(event.sessionId);
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
      const outcome = await this.router.handle(command);
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
