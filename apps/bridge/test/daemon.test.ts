import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BridgeDaemon,
  EncryptedEventFailureLogger,
  loadBridgeConfig,
  type ReconciliationScheduler,
} from '../src/daemon';
import { LinuxJsonHostIdentityStore, publicIdentityMetadata } from '../src/identity';
import { spoolKeyIdForKey } from '../src/e2e/local-spool';

const roots: string[] = [];
const servers: Array<{ stop(closeActiveConnections?: boolean): void }> = [];
const decoder = new TextDecoder();
const bunPath = process.execPath;
const cliPath = './apps/bridge/src/cli.ts';

afterEach(() => {
  for (const server of servers.splice(0)) {
    server.stop(true);
  }
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function decode(bytes: Uint8Array | ArrayBuffer | SharedArrayBuffer | null | undefined): string {
  if (!bytes) {
    return '';
  }
  return decoder.decode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).trim();
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
}

interface EnrollmentRequest {
  hostId: string;
  hostName: string;
  platform: string;
  bridgeVersion: string;
}

interface HostResponseOverrides {
  hostName?: string;
  registeredAt?: string;
  lastSeenAt?: string;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function waitFor(condition: () => boolean, context: string, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${context}`);
    await Bun.sleep(1);
  }
}

async function waitForPromise<T>(promise: Promise<T>, context: string, timeoutMs = 1_000): Promise<T> {
  return Promise.race([
    promise,
    Bun.sleep(timeoutMs).then(() => { throw new Error(`Timed out waiting for ${context}`); }),
  ]);
}

function createEnrollmentResponse(body: EnrollmentRequest, overrides: HostResponseOverrides = {}): Response {
  const now = new Date().toISOString();
  return Response.json({
    host: {
      hostId: body.hostId,
      hostName: overrides.hostName ?? body.hostName,
      platform: body.platform,
      bridgeVersion: body.bridgeVersion,
      registeredAt: overrides.registeredAt ?? now,
      lastSeenAt: overrides.lastSeenAt ?? now,
      bridgeStatus: 'online',
    },
  });
}

class ControllableScheduler implements ReconciliationScheduler {
  readonly scheduled: Array<{ callback: () => void; delayMs: number; canceled: boolean }> = [];

  schedule(callback: () => void, delayMs: number): unknown {
    const handle = { callback, delayMs, canceled: false };
    this.scheduled.push(handle);
    return handle;
  }

  cancel(handle: unknown): void {
    (handle as (typeof this.scheduled)[number]).canceled = true;
  }

  run(index: number): void {
    this.scheduled[index]?.callback();
  }
}

async function createPresenceDaemon(
  relayBaseUrl: string,
  scheduler: ReconciliationScheduler,
  listSessions: () => Promise<[]>,
): Promise<{ daemon: BridgeDaemon; statePath: string }> {
  const root = join(tmpdir(), `bridge-daemon-presence-${Date.now()}-${roots.length}`);
  roots.push(root);
  mkdirSync(root, { mode: 0o700 });
  const identityPath = join(root, 'identity.json');
  const store = new LinuxJsonHostIdentityStore(identityPath);
  const identity = await store.createFirstRun();
  const statePath = join(root, 'state.json');
  const config = loadBridgeConfig();
  Object.assign(config, {
    runtimePlatform: 'linux',
    hostPlatform: 'linux',
    hostId: identity.hostId,
    identity: publicIdentityMetadata(identity),
    relayBaseUrl,
    pollIntervalMs: 60_000,
    configPath: join(root, 'config.json'),
    statePath,
    identityPath,
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  return { daemon: new BridgeDaemon(config, [{ name: 'test', listSessions }], store, undefined, scheduler), statePath };
}

async function createLongPollingDaemon(relayBaseUrl: string): Promise<BridgeDaemon> {
  const root = join(tmpdir(), `bridge-daemon-stop-${Date.now()}-${roots.length}`);
  roots.push(root);
  mkdirSync(root, { mode: 0o700 });
  const identityPath = join(root, 'identity.json');
  const store = new LinuxJsonHostIdentityStore(identityPath);
  const identity = await store.createFirstRun();
  const config = loadBridgeConfig();
  Object.assign(config, {
    runtimePlatform: 'linux',
    hostPlatform: 'linux',
    hostId: identity.hostId,
    identity: publicIdentityMetadata(identity),
    relayBaseUrl,
    pollIntervalMs: 60_000,
    configPath: join(root, 'config.json'),
    statePath: join(root, 'state.json'),
    identityPath,
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  return new BridgeDaemon(config, [{ name: 'test', listSessions: async () => [] }], store);
}

describe('BridgeDaemon', () => {
  test('loads PaiDriver by default', () => {
    const config = loadBridgeConfig();
    config.statePath = `${process.cwd()}/.state/ariava/test-bridge-state-${Date.now()}.json`;
    const daemon = new BridgeDaemon(config);
    expect(daemon.driverNames).toEqual(['pi']);
    daemon.stop();
  });

  test('Bun source daemon defers schema 2 state to startup preflight', async () => {
    const root = join(tmpdir(), `bridge-daemon-schema2-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const identityStore = new LinuxJsonHostIdentityStore(identityPath);
    const identity = await identityStore.createFirstRun();
    const statePath = join(root, 'state.json');
    const epoch = '00000000-0000-4000-8000-000000000002';
    const state = {
      schemaVersion: 2, runtimeResetEpoch: epoch, host: null, sessions: {}, sessionDrivers: {}, reconciledDrivers: {},
      recentEvents: [], sessionRevisions: {}, pendingHandles: {}, commandResults: {}, seenCommands: {},
      currentSessionsSnapshot: { version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 },
      runtimeHealth: { status: 'healthy', drivers: [] },
    };
    const key = new Uint8Array(32).fill(7);
    const keyId = spoolKeyIdForKey(key);
    writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    writeFileSync(`${statePath}.spool.json`, `${JSON.stringify({
      version: 2, runtimeStateSchemaVersion: 2, runtimeResetEpoch: epoch, hostId: identity.hostId, keyId, items: [],
    })}\n`, { mode: 0o600 });
    writeFileSync(`${identityPath}.spool-key.json`, `${JSON.stringify({
      version: 1, hostId: identity.hostId, key: Buffer.from(key).toString('base64url'),
    })}\n`, { mode: 0o600 });
    const config = loadBridgeConfig();
    Object.assign(config, {
      runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, identity: publicIdentityMetadata(identity),
      relayBaseUrl: 'http://relay.invalid', configPath: join(root, 'config.json'), statePath, identityPath,
      agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
    });
    const daemon = new BridgeDaemon(config, [], identityStore);
    expect(JSON.parse(readFileSync(statePath, 'utf8')).schemaVersion).toBe(2);
    await (daemon as any).validateStartup();
    expect(JSON.parse(readFileSync(statePath, 'utf8'))).toMatchObject({ schemaVersion: 3, recentEvents: [], sessions: {} });
    daemon.stop();
  });

  test('rejects first-run and corrupt identity before any Relay call', async () => {
    const root = join(tmpdir(), `bridge-daemon-identity-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    let relayCalls = 0;
    const server = Bun.serve({ port: 0, fetch: () => { relayCalls += 1; return new Response('unexpected'); } });
    servers.push(server);
    const config = loadBridgeConfig();
    Object.assign(config, {
      runtimePlatform: 'linux', hostPlatform: 'linux', hostId: 'host-test', relayBaseUrl: `http://127.0.0.1:${server.port}`,
      configPath: join(root, 'config.json'), statePath: join(root, 'state.json'), identityPath: join(root, 'identity.json'),
      agentAdapter: { ...config.agentAdapter, configPath: join(root, 'adapter.json') },
    });
    await expect(new BridgeDaemon(config).syncOnce()).rejects.toMatchObject({ code: 'ERR_IDENTITY_NOT_INITIALIZED' });
    expect(relayCalls).toBe(0);
    writeFileSync(config.identityPath, '{bad json', { mode: 0o600 });
    await expect(new BridgeDaemon(config).syncOnce()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect(relayCalls).toBe(0);
  });

  test('rejects config hostId mismatch before any Relay call', async () => {
    const root = join(tmpdir(), `bridge-daemon-mismatch-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    let relayCalls = 0;
    const server = Bun.serve({ port: 0, fetch: () => { relayCalls += 1; return new Response('unexpected'); } });
    servers.push(server);
    const identityPath = join(root, 'identity.json');
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const config = loadBridgeConfig();
    Object.assign(config, {
      runtimePlatform: 'linux', hostPlatform: 'linux', hostId: 'host-wrong', relayBaseUrl: `http://127.0.0.1:${server.port}`,
      identity: publicIdentityMetadata(identity),
      configPath: join(root, 'config.json'), statePath: join(root, 'state.json'), identityPath,
      agentAdapter: { ...config.agentAdapter, configPath: join(root, 'adapter.json') },
    });
    await expect(new BridgeDaemon(config).syncOnce()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect(relayCalls).toBe(0);
  });

  test.each(['keyId', 'publicKey', 'publicKeyFingerprint', 'algorithm', 'createdAt', 'privateKeyStorage'] as const)('rejects full config identity %s mismatch before Relay writes', async (field) => {
    const root = join(tmpdir(), `bridge-daemon-full-mismatch-${field}-${Date.now()}`); roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    let relayCalls = 0;
    const server = Bun.serve({ port: 0, fetch: () => { relayCalls += 1; return new Response('unexpected'); } }); servers.push(server);
    const identityPath = join(root, 'identity.json');
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const metadata: any = publicIdentityMetadata(identity);
    if (field === 'algorithm') metadata.algorithm = 'RSA';
    else if (field === 'privateKeyStorage') metadata.privateKeyStorage = { type: 'linux-json', path: join(root, 'other.json') };
    else metadata[field] = `${metadata[field]}-wrong`;
    const config = loadBridgeConfig();
    Object.assign(config, { runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, identity: metadata,
      relayBaseUrl: `http://127.0.0.1:${server.port}`, configPath: join(root, 'config.json'), statePath: join(root, 'state.json'), identityPath,
      agentAdapter: { ...config.agentAdapter, configPath: join(root, 'adapter.json') } });
    await expect(new BridgeDaemon(config).syncOnce()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect(relayCalls).toBe(0);
  });

  test('logs redacted driver failures without persisting diagnostic Event or state', async () => {
    const root = join(tmpdir(), `bridge-daemon-redaction-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const statePath = join(root, 'state.json');
    const envSecret = 'daemon-env-super-secret';
    const persistedSecret = 'daemon-persisted-super-secret';
    const adapterSecret = 'daemon-adapter-super-secret';
    const relayRemnant = 'daemon-relay-remnant';
    const previousSecret = process.env.ARIAVA_TEST_PRIVATE_KEY;
    process.env.ARIAVA_TEST_PRIVATE_KEY = envSecret;
    try {
      const config = loadBridgeConfig();
      Object.assign(config, {
        runtimePlatform: 'linux', hostId: identity.hostId, relayBaseUrl: 'http://127.0.0.1:1',
        hostPlatform: 'linux', identity: publicIdentityMetadata(identity),
        configPath: join(root, 'config.json'), statePath, identityPath,
        agentAdapter: { ...config.agentAdapter, secret: adapterSecret, configPath: join(root, 'adapter.json') },
      });
      writeFileSync(config.configPath, JSON.stringify({
        hostAuthToken: persistedSecret, relayToken: relayRemnant, agentAdapterSecret: 'persisted-adapter-secret',
      }), { mode: 0o600 });
      const failingDriver = {
        name: 'failing',
        listSessions: async () => {
          throw new Error(`failed ${envSecret} ${persistedSecret} ${adapterSecret} ${relayRemnant} persisted-adapter-secret`);
        },
        executeCommand: async () => { throw new Error('not used'); },
      };
      const lines: string[] = [];
      const originalWrite = process.stderr.write.bind(process.stderr);
      process.stderr.write = ((chunk: string | Uint8Array) => { lines.push(String(chunk)); return true; }) as typeof process.stderr.write;
      try {
        const result = await new BridgeDaemon(config, [failingDriver]).syncOnce();
        expect(result.emittedEvents).toEqual([]);
      } finally {
        process.stderr.write = originalWrite;
      }
      const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : { recentEvents: [], sessions: {} };
      const persisted = existsSync(statePath) ? readFileSync(statePath, 'utf8') : '';
      expect(state.recentEvents).toEqual([]);
      expect(state).not.toHaveProperty('pendingEvents');
      expect(JSON.stringify(state.sessions)).not.toMatch(/driver:|host:/u);
      for (const secret of [envSecret, persistedSecret, adapterSecret, relayRemnant, 'persisted-adapter-secret']) {
        expect(persisted).not.toContain(secret);
        expect(lines.join('')).not.toContain(secret);
      }
      expect(lines.join('')).toContain('"component":"bridge_runtime_health"');
      expect(lines.join('')).toContain('"code":"driver_reconciliation_failed"');
      expect(lines.join('')).not.toContain('failed ');
    } finally {
      if (previousSecret === undefined) delete process.env.ARIAVA_TEST_PRIVATE_KEY;
      else process.env.ARIAVA_TEST_PRIVATE_KEY = previousSecret;
    }
  });

  test('refreshes Host presence while a full synchronization remains blocked', async () => {
    let enrollments = 0;
    const relay = Bun.serve({ port: 0, fetch: async (request) => {
      if (new URL(request.url).pathname !== '/v2/bridge/enroll') return new Response('unexpected', { status: 500 });
      const body = await request.json() as EnrollmentRequest;
      enrollments += 1;
      return createEnrollmentResponse(body);
    } });
    servers.push(relay);
    const scheduler = new ControllableScheduler();
    const sessionsStarted = deferred<void>();
    const sessions = deferred<[]>();
    const { daemon } = await createPresenceDaemon(`http://127.0.0.1:${relay.port}`, scheduler, () => {
      sessionsStarted.resolve();
      return sessions.promise;
    });
    let run: Promise<void> | undefined;
    try {
      await daemon.start();
      run = daemon.runForever();
      await waitForPromise(sessionsStarted.promise, 'initial synchronization to enter blocked session listing');
      expect(enrollments).toBe(1);
      scheduler.run(0);
      await waitFor(() => enrollments >= 2, 'heartbeat enrollment during blocked synchronization');
      expect(enrollments).toBe(2);
    } finally {
      daemon.stop();
      sessions.resolve([]);
      if (run) await waitForPromise(run.catch(() => {}), 'blocked synchronization cleanup');
    }
  });

  test('joins heartbeat and explicit synchronization into one presence flight', async () => {
    let enrollments = 0;
    let enrollment!: EnrollmentRequest;
    const enrollmentStarted = deferred<void>();
    const secondEnrollmentStarted = deferred<void>();
    const enrollmentResponse = deferred<Response>();
    const sessionsStarted = deferred<void>();
    const sessions = deferred<[]>();
    const relay = Bun.serve({ port: 0, fetch: async (request) => {
      if (new URL(request.url).pathname !== '/v2/bridge/enroll') return new Response('unexpected', { status: 500 });
      enrollment = await request.json() as EnrollmentRequest;
      enrollments += 1;
      if (enrollments === 1) enrollmentStarted.resolve();
      if (enrollments === 2) secondEnrollmentStarted.resolve();
      return enrollmentResponse.promise;
    } });
    servers.push(relay);
    const scheduler = new ControllableScheduler();
    const { daemon } = await createPresenceDaemon(`http://127.0.0.1:${relay.port}`, scheduler, async () => {
      sessionsStarted.resolve();
      return sessions.promise;
    });
    let sync: Promise<unknown> | undefined;
    try {
      await daemon.start();
      scheduler.run(0);
      await waitForPromise(enrollmentStarted.promise, 'heartbeat enrollment to start');
      sync = daemon.syncOnce();
      expect(await Promise.race([
        secondEnrollmentStarted.promise.then(() => 'second-enrollment'),
        Bun.sleep(50).then(() => 'shared-flight'),
      ])).toBe('shared-flight');
      expect(enrollments).toBe(1);
      enrollmentResponse.resolve(createEnrollmentResponse(enrollment, { hostName: 'Heartbeat host' }));
      await waitForPromise(sessionsStarted.promise, 'joined synchronization to enter session listing');
    } finally {
      daemon.stop();
      enrollmentResponse.resolve(new Response('stopped', { status: 503 }));
      sessions.resolve([]);
      if (sync) await waitForPromise(sync.catch(() => {}), 'joined synchronization cleanup');
    }
  });

  test('keeps background presence heartbeats single-flight and cancels scheduling on stop', async () => {
    let enrollments = 0;
    let enrollment!: EnrollmentRequest;
    const enrollmentStarted = deferred<void>();
    const heldEnrollment = deferred<Response>();
    const relay = Bun.serve({ port: 0, fetch: async (request) => {
      enrollment = await request.json() as EnrollmentRequest;
      enrollments += 1;
      enrollmentStarted.resolve();
      return heldEnrollment.promise;
    } });
    servers.push(relay);
    const scheduler = new ControllableScheduler();
    const { daemon } = await createPresenceDaemon(`http://127.0.0.1:${relay.port}`, scheduler, async () => []);
    try {
      await daemon.start();
      expect(scheduler.scheduled[0]?.delayMs).toBe(30_000);
      scheduler.run(0);
      await waitForPromise(enrollmentStarted.promise, 'background heartbeat enrollment to start');
      scheduler.run(0);
      await Bun.sleep(0);
      expect(enrollments).toBe(1);
      heldEnrollment.resolve(createEnrollmentResponse(enrollment, { hostName: 'Heartbeat host' }));
      await waitFor(() => scheduler.scheduled.length >= 2, 'next presence heartbeat schedule');
      daemon.stop();
      expect(scheduler.scheduled[1]?.canceled).toBe(true);
      scheduler.run(1);
      await Bun.sleep(0);
      expect(enrollments).toBe(1);
    } finally {
      daemon.stop();
      heldEnrollment.resolve(new Response('stopped', { status: 503 }));
    }
  });

  test('degrades after a failed presence heartbeat and restores the authoritative Host projection on recovery', async () => {
    const initialLastSeenAt = '2026-08-01T00:00:00.000Z';
    const recoveredLastSeenAt = '2026-08-01T00:01:00.000Z';
    let enrollmentAttempt = 0;
    let enrollment!: EnrollmentRequest;
    const relay = Bun.serve({ port: 0, fetch: async (request) => {
      if (new URL(request.url).pathname !== '/v2/bridge/enroll') return new Response('unexpected', { status: 500 });
      enrollment = await request.json() as EnrollmentRequest;
      enrollmentAttempt += 1;
      if (enrollmentAttempt === 2 || enrollmentAttempt === 3) return new Response('offline', { status: 503 });
      const recovered = enrollmentAttempt === 4;
      return createEnrollmentResponse(enrollment, {
        hostName: recovered ? 'Relay authoritative host' : enrollment.hostName,
        registeredAt: '2026-07-01T00:00:00.000Z',
        lastSeenAt: recovered ? recoveredLastSeenAt : initialLastSeenAt,
      });
    } });
    servers.push(relay);
    const scheduler = new ControllableScheduler();
    const { daemon, statePath } = await createPresenceDaemon(`http://127.0.0.1:${relay.port}`, scheduler, async () => []);
    try {
      await daemon.start();
      scheduler.run(0);
      await waitFor(() => scheduler.scheduled.length >= 2, 'heartbeat schedule after initial presence');
      const initialState = await Bun.file(statePath).json() as { host: { hostId: string; bridgeStatus: string; lastSeenAt: string } };
      expect(initialState.host).toMatchObject({
        hostId: enrollment.hostId, bridgeStatus: 'online', lastSeenAt: initialLastSeenAt,
      });

      scheduler.run(1);
      await waitFor(() => scheduler.scheduled.length >= 3, 'heartbeat schedule after failed presence');
      const degradedState = await Bun.file(statePath).json() as { host: { bridgeStatus: string; lastSeenAt: string } };
      expect(degradedState.host).toMatchObject({ bridgeStatus: 'degraded', lastSeenAt: initialLastSeenAt });
      const operationalSync = await daemon.syncOnce();
      expect(operationalSync).toMatchObject({ offline: true, host: { bridgeStatus: 'degraded', lastSeenAt: initialLastSeenAt } });

      scheduler.run(2);
      await waitFor(() => scheduler.scheduled.length >= 4, 'heartbeat schedule after recovered presence');
      const recoveredState = await Bun.file(statePath).json() as { host: { hostName: string; bridgeStatus: string; lastSeenAt: string } };
      expect(recoveredState.host).toMatchObject({
        hostName: 'Relay authoritative host', bridgeStatus: 'online', lastSeenAt: recoveredLastSeenAt,
      });
    } finally {
      daemon.stop();
    }
  });

  test('flushes a durably bound handle and removes it only after Relay acknowledgement', async () => {
    const daemon = await createLongPollingDaemon('http://127.0.0.1:1');
    const registry = (daemon as any).adapterRegistry;
    const stateStore = (daemon as any).stateStore;
    stateStore.initializeEncryptedSpool(
      (daemon as any).config.hostId, (daemon as any).config.identityPath, 'linux',
      { loadOrCreate: () => new Uint8Array(32).fill(7) },
    );
    registry.register({ sessionId: 'sess-handle', provider: 'pi', projectName: 'project', cwd: '/' });
    stateStore.appendRecentEvent({
      eventId: 'evt-handle', hostId: (daemon as any).config.hostId, sessionId: 'sess-handle', provider: 'pi',
      type: 'done', status: 'idle', agentText: 'Done', createdAt: '2026-08-07T00:00:00.000Z',
    });
    registry.handleSession('sess-handle', { handledThroughEventId: 'evt-handle', action: 'pi_input' });
    const delivered: unknown[] = [];
    (daemon as any).relayClient = {
      handleSession: async (sessionId: string, request: unknown) => { delivered.push({ sessionId, request }); return { ok: true }; },
    };
    await expect((daemon as any).flushPendingHandles()).resolves.toBe(1);
    expect(delivered).toEqual([expect.objectContaining({ sessionId: 'sess-handle' })]);
    expect(stateStore.peekPendingSessionHandles()).toEqual([]);
    daemon.stop();
  });

  test('does not request reconciliation until the scheduled delay elapses', async () => {
    let scheduledCallback: (() => void) | undefined;
    const scheduler = {
      schedule: (callback: () => void, delayMs: number) => {
        expect(delayMs).toBe(300);
        scheduledCallback = callback;
        return Symbol('reconciliation');
      },
      cancel: () => {},
    };
    const daemon = await createLongPollingDaemon('http://127.0.0.1:1');
    const daemonConfig = (daemon as any).config;
    const daemonIdentityStore = (daemon as any).identityStore;
    daemon.stop();
    const scheduledDaemon = new BridgeDaemon(
      daemonConfig,
      [{ name: 'test', listSessions: async () => [] }],
      daemonIdentityStore,
      undefined,
      scheduler,
    );
    (scheduledDaemon as any).reconciliationRequested = false;

    (scheduledDaemon as any).scheduleRegistryReconciliation();

    expect((scheduledDaemon as any).reconciliationRequested).toBe(false);
    expect(scheduledCallback).toBeDefined();
    scheduledCallback!();
    expect((scheduledDaemon as any).reconciliationRequested).toBe(true);
    scheduledDaemon.stop();
  });

  test('stop disposes Registry retry lifecycle', async () => {
    const daemon = await createLongPollingDaemon('http://127.0.0.1:1');
    let disposed = 0;
    (daemon as any).adapterRegistry.dispose = () => { disposed += 1; };
    daemon.stop();
    daemon.stop();
    expect(disposed).toBe(2);
  });

  test('stop cancels the polling delay and runForever terminates', async () => {
    const daemon = await createLongPollingDaemon('http://127.0.0.1:1');
    await daemon.start();
    const run = daemon.runForever();
    await Bun.sleep(20);
    daemon.stop();
    await expect(Promise.race([run.then(() => 'stopped'), Bun.sleep(500).then(() => 'timeout')])).resolves.toBe('stopped');
  });

  test('stop cancels the owned long poll timer with an injected scheduler', async () => {
    const base = await createLongPollingDaemon('http://127.0.0.1:1');
    const baseConfig = (base as any).config;
    const baseIdentityStore = (base as any).identityStore;
    base.stop();
    const callbacks: Array<() => void> = [];
    const canceled: symbol[] = [];
    const pollScheduler = {
      schedule(callback: () => void, delayMs: number) {
        expect(delayMs).toBe(60_000);
        const handle = Symbol('poll');
        callbacks.push(callback);
        return handle;
      },
      cancel(handle: unknown) { canceled.push(handle as symbol); },
    };
    const daemon = new BridgeDaemon(
      baseConfig,
      [{ name: 'test', listSessions: async () => [] }],
      baseIdentityStore,
      undefined,
      undefined,
      pollScheduler,
    );
    (daemon as any).startupValidated = true;
    (daemon as any).performSyncOnce = async () => { (daemon as any).reconciliationRequested = false; return {}; };
    const run = daemon.runForever();
    await Promise.resolve();
    await Promise.resolve();
    expect(callbacks).toHaveLength(1);
    daemon.stop();
    await expect(run).resolves.toBeUndefined();
    expect(canceled).toHaveLength(1);
    callbacks[0]!();
    expect((daemon as any).pollWaitTimer).toBeUndefined();
  });

  test('stop aborts an in-flight Relay request and terminates the run loop', async () => {
    let requestStarted!: () => void;
    const started = new Promise<void>((resolveStarted) => { requestStarted = resolveStarted; });
    const relay = Bun.serve({ port: 0, fetch: () => new Promise<Response>(() => {
      requestStarted();
    }) });
    servers.push(relay);
    const daemon = await createLongPollingDaemon(`http://127.0.0.1:${relay.port}`);
    await daemon.start();
    const run = daemon.runForever();
    await started;
    daemon.stop();
    await expect(Promise.race([run.then(() => 'stopped'), Bun.sleep(500).then(() => 'timeout')])).resolves.toBe('stopped');
  });

  test('rate-limits and redacts encrypted Event failure logs', () => {
    let now = 30_000;
    const lines: string[] = [];
    const logger = new EncryptedEventFailureLogger((line) => lines.push(line), () => now);

    logger.record({ eventId: 'event-secret', sessionId: 'session-secret', outcome: 'retry-deferred', status: 503, category: 'http' });
    now += 1_000;
    logger.record({ eventId: 'event-secret-2', sessionId: 'session-secret-2', outcome: 'quarantined', status: 409, category: 'event-content' });
    now += 30_000;
    logger.record({ eventId: 'event-secret-3', sessionId: 'session-secret-3', outcome: 'retry-deferred', category: 'network' });

    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('"outcome":"retry-deferred"');
    expect(lines[0]).toContain('"category":"http"');
    expect(lines[1]).toContain('"suppressed":1');
    const output = lines.join('');
    expect(output).not.toContain('event-secret');
    expect(output).not.toContain('session-secret');
  });

  test('CLI help advertises identity-safe pair and no claim-code flow', () => {
    const result = Bun.spawnSync({ cmd: [bunPath, 'run', cliPath], cwd: process.cwd(), env: process.env });
    expect(result.exitCode).toBe(0);
    expect(decode(result.stdout)).toContain('pair <PAIRING_CODE>');
    expect(decode(result.stdout)).not.toContain('claim-code');
  });

  test('pairs through signed v2 enrollment and pairing without owner or bearer headers', async () => {
    const root = join(tmpdir(), `bridge-v2-pair-${Date.now()}`); roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const paths: string[] = [];
    const server = Bun.serve({ port: 0, fetch: async (request) => {
      const url = new URL(request.url); paths.push(url.pathname);
      expect(request.headers.get('x-ariava-entity-id')).toBe(identity.hostId);
      expect(request.headers.get('x-ariava-key-id')).toBe(identity.keyId);
      expect(request.headers.has('x-host-auth')).toBe(false);
      expect(request.headers.has('authorization')).toBe(false);
      if (url.pathname === '/v2/bridge/enroll') {
        const body = await request.json() as any;
        expect(body).toMatchObject({ hostId: identity.hostId, platform: 'linux' });
        expect(body).not.toHaveProperty('ownerUserId');
        return Response.json({ host: { hostId: identity.hostId, hostName: 'Linux host', platform: 'linux', bridgeVersion: '0.1.2', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
      }
      if (url.pathname === '/v2/bridge/pair-watch') {
        expect(await request.json()).toEqual({ pairingCode: 'PEYX7K' });
        return Response.json({
          host: { hostId: identity.hostId, hostName: 'Linux host', platform: 'linux', bridgeVersion: '0.1.2', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' },
          watchDevice: { watchDeviceId: `watch_${'C'.repeat(43)}`, selectedHostIds: [identity.hostId], registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), pairingStatus: 'paired' },
          link: { hostId: identity.hostId, watchDeviceId: `watch_${'C'.repeat(43)}`, pairedAt: new Date().toISOString(), generation: 1, updatedAt: new Date().toISOString() }, alreadyPaired: false,
        });
      }
      return new Response('not found', { status: 404 });
    } }); servers.push(server);
    const config = loadBridgeConfig();
    Object.assign(config, { runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, hostName: 'Linux host',
      identity: publicIdentityMetadata(identity),
      bridgeVersion: '0.1.2', relayBaseUrl: `http://127.0.0.1:${server.port}`, identityPath,
      configPath: join(root, 'config.json'), statePath: join(root, 'state.json'), agentAdapter: { ...config.agentAdapter, configPath: join(root, 'adapter.json') } });
    const result = await new BridgeDaemon(config).pairWatch('peyx7k');
    expect(result.watchDevice.watchDeviceId).toBe(`watch_${'C'.repeat(43)}`);
    expect(paths).toEqual(['/v2/bridge/enroll', '/v2/bridge/pair-watch']);
  });
});
