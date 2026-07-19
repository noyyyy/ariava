import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeDaemon, loadBridgeConfig } from '../src/daemon';
import { LinuxJsonHostIdentityStore, publicIdentityMetadata } from '../src/identity';

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

  test('redacts daemon errors before state persistence or Relay publication', async () => {
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
      await new BridgeDaemon(config, [failingDriver]).syncOnce();
      const persisted = String(await Bun.file(statePath).text());
      for (const secret of [envSecret, persistedSecret, adapterSecret, relayRemnant, 'persisted-adapter-secret']) {
        expect(persisted).not.toContain(secret);
      }
      expect(persisted).toContain('<redacted>');
    } finally {
      if (previousSecret === undefined) delete process.env.ARIAVA_TEST_PRIVATE_KEY;
      else process.env.ARIAVA_TEST_PRIVATE_KEY = previousSecret;
    }
  });

  test('stop cancels the polling delay and runForever terminates', async () => {
    const daemon = await createLongPollingDaemon('http://127.0.0.1:1');
    await daemon.start();
    const run = daemon.runForever();
    await Bun.sleep(20);
    daemon.stop();
    await expect(Promise.race([run.then(() => 'stopped'), Bun.sleep(500).then(() => 'timeout')])).resolves.toBe('stopped');
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
