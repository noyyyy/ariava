import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { writeAgentAdapterConfig } from '../src/agent-adapter/config';
import {
  createDefaultDevProfileDependencies,
  runDevProfileCommand,
  type DevProfileDependencies,
} from '../src/dev-profile-app';
import { resolveAriavaDevProfilePaths } from '../src/host-manager';
import { createRuntimeHostIdentityStore } from '../src/identity';
import {
  MACOS_IDENTITY_EVIDENCE_ACCOUNTS,
  MacOSKeychainHostIdentityStore,
} from '../src/identity/macos-keychain-store';
import { MacOSEncryptionKeyStore } from '../src/identity/macos-encryption-key-store';
import type { BridgeConfig } from '../src/types';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import { FakeKeychain } from './fixtures/fake-keychain';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function createHarness(): {
  root: string;
  deps: DevProfileDependencies;
  stdout: PassThrough;
  stderr: PassThrough;
  output(): string;
  errorOutput(): string;
} {
  const root = mkdtempSync(join(tmpdir(), 'ariava-dev-cli-'));
  roots.push(root);
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const stdin = new PassThrough();
  const defaults = createDefaultDevProfileDependencies();
  const deps: DevProfileDependencies = {
    ...defaults,
    paths: resolveAriavaDevProfilePaths(root),
    profile: withHome(root, createDevProfile),
    platform: 'linux',
    stdout,
    stderr,
    stdin,
    interactive: false,
    hostName: () => 'test-host',
    environment: { HOME: root, PATH: process.env.PATH, ARIAVA_RELAY_BASE_URL: 'https://stale.invalid' },
    generateSecret: () => 'dev-secret',
    createIdentityStore: (path, platform, profile) => {
      expect(profile).toBe('dev');
      return createRuntimeHostIdentityStore(path, platform, profile);
    },
  };
  let text = '';
  let errorText = '';
  stdout.on('data', (chunk) => { text += chunk.toString(); });
  stderr.on('data', (chunk) => { errorText += chunk.toString(); });
  return { root, deps, stdout, stderr, output: () => text, errorOutput: () => errorText };
}

function withHome<T>(home: string, run: () => T): T {
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = home;
  delete process.env.XDG_CONFIG_HOME;
  try {
    return run();
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousXdg;
  }
}

describe('source dev profile commands', () => {
  test('init writes only the dev tree and reuses its identity', async () => {
    const harness = createHarness();
    const defaultRoot = join(harness.root, '.config', 'ariava');
    mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });
    const defaultConfig = join(defaultRoot, 'config.json');
    const original = '{"production":true}\n';
    writeFileSync(defaultConfig, original, { mode: 0o600 });

    let saves = 0;
    const save = harness.deps.saveUserConfig;
    harness.deps.saveUserConfig = (config, path) => { saves += 1; save(config, path); };
    expect(await runDevProfileCommand(['init'], harness.deps)).toBe(0);
    const first = JSON.parse(readFileSync(harness.deps.paths.configPath, 'utf8'));
    expect(first).toMatchObject({
      relayBaseUrl: 'http://127.0.0.1:8790',
      hostName: 'test-host (Dev)',
      agentAdapterPort: 7273,
      agentAdapterSecret: 'dev-secret',
      agentAdapterConfigPath: harness.deps.paths.agentAdapterConfigPath,
      statePath: harness.deps.paths.statePath,
      identityPath: harness.deps.paths.identityPath,
    });
    expect(first.identity.hostId).toBeString();
    expect(readFileSync(defaultConfig, 'utf8')).toBe(original);
    const firstBytes = readFileSync(harness.deps.paths.configPath, 'utf8');
    expect(saves).toBe(1);

    expect(await runDevProfileCommand(['init'], harness.deps)).toBe(0);
    const secondBytes = readFileSync(harness.deps.paths.configPath, 'utf8');
    const second = JSON.parse(secondBytes);
    expect(second.identity.hostId).toBe(first.identity.hostId);
    expect(secondBytes).toBe(firstBytes);
    expect(saves).toBe(1);
    expect(readFileSync(defaultConfig, 'utf8')).toBe(original);
  });

  test('config uses the dev file, ignores ambient Ariava values, and redacts secrets', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const defaultRoot = join(harness.root, '.config', 'ariava');
    mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });
    const defaultConfig = join(defaultRoot, 'config.json');
    const defaultBytes = Buffer.from('{"production":"sentinel"}\n\u0000', 'utf8');
    writeFileSync(defaultConfig, defaultBytes, { mode: 0o600 });
    const outputOffset = harness.output().length;

    expect(await runDevProfileCommand(['config', 'set', 'hostName', 'configured-dev'], harness.deps)).toBe(0);
    expect(await runDevProfileCommand(['config', 'show', '--json'], harness.deps)).toBe(0);

    const envelope = JSON.parse(harness.output().slice(outputOffset).split('\n').slice(1).join('\n'));
    expect(envelope.data.config.hostName).toBe('configured-dev');
    expect(envelope.data.resolved.relayBaseUrl).toBe('http://127.0.0.1:8790');
    expect(envelope.data.config.agentAdapterSecret).toBeUndefined();
    expect(envelope.data.resolved.agentAdapterSecret).toBe('<redacted>');
    expect(harness.output().slice(outputOffset)).not.toContain('dev-secret');
    expect(harness.output().slice(outputOffset)).not.toContain('https://stale.invalid');
    expect(readFileSync(defaultConfig)).toEqual(defaultBytes);
  });

  test('identity status is adapter-only presentation over the shared dev inspection', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const outputBefore = harness.output().length;
    const defaultRoot = join(harness.root, '.config', 'ariava');
    mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });
    const defaultConfig = join(defaultRoot, 'config.json');
    const sentinel = Buffer.from('default-identity-status-sentinel\u0000', 'utf8');
    writeFileSync(defaultConfig, sentinel, { mode: 0o600 });

    expect(await runDevProfileCommand(['identity', 'status'], harness.deps)).toBe(0);
    const inspection = JSON.parse(harness.output().slice(outputBefore));
    expect(inspection).toMatchObject({
      profile: 'dev',
      status: 'ready',
      path: harness.deps.paths.identityPath,
    });
    expect(readFileSync(defaultConfig)).toEqual(sentinel);
  });

  test('bare identity is rejected before profile effects', async () => {
    const harness = createHarness();
    let configReads = 0;
    let identityCalls = 0;
    harness.deps.loadUserConfig = () => { configReads += 1; throw new Error('config effect'); };
    harness.deps.createIdentityStore = () => { identityCalls += 1; throw new Error('identity effect'); };

    expect(await runDevProfileCommand(['identity', '--json'], harness.deps)).toBe(1);
    expect(configReads).toBe(0);
    expect(identityCalls).toBe(0);
    expect(JSON.parse(harness.errorOutput())).toMatchObject({
      code: 'ERR_CLI',
      message: 'Usage: dev-profile-cli identity status | dev-profile-cli identity reset --confirm',
    });
  });

  test.each([
    { mode: 'human', json: false },
    { mode: 'JSON', json: true },
  ])('unconfirmed identity reset is effect-free in $mode mode', async ({ json }) => {
    const harness = createHarness();
    let identityCalls = 0;
    let encryptionCalls = 0;
    let configReads = 0;
    harness.deps.loadUserConfig = () => { configReads += 1; throw new Error('config effect'); };
    harness.deps.createIdentityStore = () => { identityCalls += 1; throw new Error('identity effect'); };
    harness.deps.createEncryptionIdentityStore = () => { encryptionCalls += 1; throw new Error('encryption effect'); };

    expect(await runDevProfileCommand([
      'identity',
      'reset',
      ...(json ? ['--json'] : []),
    ], harness.deps)).toBe(1);
    expect(harness.output()).toBe('');
    expect(identityCalls).toBe(0);
    expect(encryptionCalls).toBe(0);
    expect(configReads).toBe(0);
    const expectedMessage = 'Usage: dev-profile-cli identity reset --confirm';
    if (json) {
      expect(JSON.parse(harness.errorOutput())).toEqual({
        ok: false,
        code: 'ERR_CONFIRMATION_REQUIRED',
        message: expectedMessage,
        data: {},
      });
    } else {
      expect(harness.errorOutput()).toBe(`ariava: ${expectedMessage}\n`);
    }
  });

  test.each([
    { mode: 'human', json: false },
    { mode: 'JSON', json: true },
  ])('invalid identity usage uses the universal $mode boundary', async ({ json }) => {
    const harness = createHarness();
    expect(await runDevProfileCommand([
      'identity',
      'invalid',
      ...(json ? ['--json'] : []),
    ], harness.deps)).toBe(1);
    expect(harness.output()).toBe('');
    const expectedMessage = 'Usage: dev-profile-cli identity status | dev-profile-cli identity reset --confirm';
    if (json) {
      expect(JSON.parse(harness.errorOutput())).toEqual({
        ok: false,
        code: 'ERR_CLI',
        message: expectedMessage,
        data: {},
      });
    } else {
      expect(harness.errorOutput()).toBe(`ariava: ${expectedMessage}\n`);
    }
  });

  test('incomplete macOS dev identity recovers only through confirmed dev reset and reuses replacement', async () => {
    const harness = createHarness();
    const keychain = new FakeKeychain();
    const defaultProfile = withHome(harness.root, createDefaultProfile);
    const defaultIdentityPath = defaultProfile.resources.identityMetadataPath;
    mkdirSync(defaultProfile.resources.root, { recursive: true, mode: 0o700 });
    const defaultStore = new MacOSKeychainHostIdentityStore(defaultIdentityPath, keychain, {}, 'default');
    const defaultIdentity = await defaultStore.createFirstRun();
    const defaultEncryption = new MacOSEncryptionKeyStore(`${defaultIdentityPath}.e2e.json`, keychain);
    const defaultEncryptionIdentity = defaultEncryption.loadOrCreate(defaultIdentity.hostId);
    const defaultEncryptionAccount = `host-e2e:${defaultEncryptionIdentity.encryptionKeyId}`;
    const defaultConfigPath = defaultProfile.resources.configPath;
    const defaultConfig = Buffer.from('{"production":"sentinel"}\n\u0000', 'utf8');
    writeFileSync(defaultConfigPath, defaultConfig, { mode: 0o600 });

    harness.deps.platform = 'darwin';
    harness.deps.createIdentityStore = (path, _platform, profile) => new MacOSKeychainHostIdentityStore(path, keychain, {}, profile);
    harness.deps.createEncryptionIdentityStore = (path) => new MacOSEncryptionKeyStore(`${path}.e2e.json`, keychain);
    const orphanDevHostId = `host_${'I'.repeat(43)}`;
    const orphanDevKeyId = `key_${'I'.repeat(43)}`;
    mkdirSync(harness.deps.paths.root, { recursive: true, mode: 0o700 });
    writeFileSync(`${harness.deps.paths.identityPath}.creating`, JSON.stringify({
      schema: 'ariava-macos-identity-creation-v1',
      phase: 'creating',
      hostId: orphanDevHostId,
      keyId: orphanDevKeyId,
    }), { mode: 0o600 });
    keychain.items.set(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev, Buffer.from('incomplete-dev-evidence'));
    keychain.items.set(orphanDevHostId, Buffer.from('incomplete-dev-private-account'));

    const defaultMetadataBefore = readFileSync(defaultIdentityPath);
    const defaultEncryptionBefore = readFileSync(`${defaultIdentityPath}.e2e.json`);
    const defaultEvidenceBefore = keychain.snapshot(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default);
    const defaultAccountBefore = keychain.snapshot(defaultIdentity.hostId);
    const defaultEncryptionAccountBefore = keychain.snapshot(defaultEncryptionAccount);
    const devEvidenceBefore = keychain.snapshot(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev);
    const unconfirmedItemsBefore = snapshotItems(keychain);
    keychain.resetCalls();
    const sentinelBefore = readFileSync(`${harness.deps.paths.identityPath}.creating`);
    let encryptionFactoryCalls = 0;
    let spawnCalls = 0;
    let bridgeCalls = 0;
    const createEncryptionIdentityStore = harness.deps.createEncryptionIdentityStore;
    harness.deps.createEncryptionIdentityStore = (...args) => {
      encryptionFactoryCalls += 1;
      return createEncryptionIdentityStore(...args);
    };
    harness.deps.spawn = () => { spawnCalls += 1; return { status: 0 }; };
    harness.deps.createBridge = () => { bridgeCalls += 1; throw new Error('bridge effect'); };

    expect(await runDevProfileCommand(['init', '--json'], harness.deps)).toBe(1);
    expect(JSON.parse(harness.errorOutput())).toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    const callsAfterInit = keychain.calls.length;
    expect(await runDevProfileCommand(['identity', 'reset', '--json'], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain('ERR_IDENTITY_RESET_REQUIRED');
    expect(harness.errorOutput()).toContain('Usage: dev-profile-cli identity reset --confirm');
    expect(keychain.calls).toHaveLength(callsAfterInit);
    expect(harness.deps.pathExists(harness.deps.paths.configPath)).toBe(false);
    expect(snapshotItems(keychain)).toEqual(unconfirmedItemsBefore);
    expect(readFileSync(`${harness.deps.paths.identityPath}.creating`)).toEqual(sentinelBefore);
    expect(encryptionFactoryCalls).toBe(0);
    expect(spawnCalls).toBe(0);
    expect(bridgeCalls).toBe(0);

    const relayRequests: Array<{ path: string; hostId: string; keyId: string | null }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const body = await request.json() as { hostId: string; hostName: string; platform: 'macos' | 'linux'; bridgeVersion: string };
      relayRequests.push({
        path: new URL(request.url).pathname,
        hostId: body.hostId,
        keyId: request.headers.get('x-ariava-key-id'),
      });
      return Response.json({ host: hostProjection(body) });
    }) as typeof fetch;
    let replacementHostId: string;
    try {
      expect(
        await runDevProfileCommand(['identity', 'reset', '--confirm'], harness.deps),
        harness.errorOutput(),
      ).toBe(0);
      const devConfig = JSON.parse(readFileSync(harness.deps.paths.configPath, 'utf8'));
      replacementHostId = devConfig.identity.hostId;
      expect(replacementHostId).not.toBe(defaultIdentity.hostId);
      expect(relayRequests).toEqual([{
        path: '/v2/bridge/enroll',
        hostId: replacementHostId,
        keyId: devConfig.identity.keyId,
      }]);
      expect(harness.output()).toContain('links: 0');
      expect(readFileSync(harness.deps.paths.identityPath, 'utf8')).toContain(replacementHostId);
      expect(keychain.items.has(orphanDevHostId)).toBe(false);
      expect(keychain.callsFor(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev).some((call) => call.action === 'write')).toBe(true);
      expect(keychain.callsFor(orphanDevHostId).some((call) => call.action === 'delete')).toBe(true);
      const replacementEncryptionMetadata = JSON.parse(
        readFileSync(`${harness.deps.paths.identityPath}.e2e.json`, 'utf8'),
      ) as { version: 2; hostId: string; currentKeyId: string; identities: Array<{ encryptionKeyId: string; account: string }> };
      const replacementEncryptionIdentity = replacementEncryptionMetadata.identities.find(
        (identity) => identity.encryptionKeyId === replacementEncryptionMetadata.currentKeyId,
      );
      const replacementEncryptionAccount = `host-e2e:${replacementEncryptionMetadata.currentKeyId}`;
      expect(replacementEncryptionMetadata.hostId).toBe(replacementHostId);
      expect(replacementEncryptionIdentity?.account).toBe(replacementEncryptionAccount);
      expect(keychain.snapshot(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev)).not.toEqual(devEvidenceBefore);
      expect(keychain.snapshot(replacementHostId)).toBeDefined();
      expect(keychain.snapshot(replacementEncryptionAccount)).toBeDefined();
      expect(keychain.callsFor(replacementEncryptionAccount).some((call) => call.action === 'write')).toBe(true);

      const configBeforeReuse = readFileSync(harness.deps.paths.configPath);
      const devMetadataBeforeReuse = readFileSync(harness.deps.paths.identityPath);
      const callsBeforeReuse = keychain.calls.length;
      expect(await runDevProfileCommand(['init'], harness.deps)).toBe(0);
      expect(readFileSync(harness.deps.paths.configPath)).toEqual(configBeforeReuse);
      expect(readFileSync(harness.deps.paths.identityPath)).toEqual(devMetadataBeforeReuse);
      expect(keychain.calls.slice(callsBeforeReuse).some((call) => call.action === 'write')).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(readFileSync(defaultConfigPath)).toEqual(defaultConfig);
    expect(readFileSync(defaultIdentityPath)).toEqual(defaultMetadataBefore);
    expect(readFileSync(`${defaultIdentityPath}.e2e.json`)).toEqual(defaultEncryptionBefore);
    expect(keychain.snapshot(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default)).toEqual(defaultEvidenceBefore);
    expect(keychain.snapshot(defaultIdentity.hostId)).toEqual(defaultAccountBefore);
    expect(keychain.snapshot(defaultEncryptionAccount)).toEqual(defaultEncryptionAccountBefore);
    expect(keychain.callsFor(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default).filter((call) => call.action !== 'read')).toEqual([]);
    expect(keychain.callsFor(defaultIdentity.hostId).filter((call) => call.action !== 'read')).toEqual([]);
    expect(keychain.callsFor(defaultEncryptionAccount).filter(
      (call) => call.action === 'write' || call.action === 'delete',
    )).toEqual([]);
  });

  test('setup initializes the isolated profile, prepares Pi, and leaves Pi startup to the user', async () => {
    const harness = createHarness();
    const defaultRoot = join(harness.root, '.config', 'ariava');
    mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });
    const defaultConfig = join(defaultRoot, 'config.json');
    writeFileSync(defaultConfig, '{"production":true}\n', { mode: 0o600 });
    const extensionPath = join(harness.root, 'index.ts');
    writeFileSync(extensionPath, 'export default {}', { mode: 0o600 });
    harness.deps.sourcePiExtensionPath = extensionPath;
    harness.deps.interactive = false;

    let bridgeStopped = false;
    let finishBridge!: () => void;
    harness.deps.createBridge = (config) => ({
      start: async () => {
        writeAgentAdapterConfig(harness.deps.paths.agentAdapterConfigPath, {
          url: `http://127.0.0.1:${config.agentAdapter.port}`, secret: 'dev-secret', protocolVersion: 2,
        });
      },
      runForever: () => new Promise<void>((resolveRun) => { finishBridge = resolveRun; }),
      stop: () => { bridgeStopped = true; finishBridge(); },
    });
    let piSpawns = 0;
    harness.deps.spawn = () => { piSpawns += 1; return { status: 0 }; };
    harness.deps.waitForShutdown = async () => {};

    expect(await runDevProfileCommand(['setup', '--extension', 'pi'], harness.deps)).toBe(0);
    expect(piSpawns).toBe(0);
    expect(harness.output()).toContain('npm run dev:cli -- pi');
    expect(bridgeStopped).toBe(true);
    expect(readFileSync(defaultConfig, 'utf8')).toBe('{"production":true}\n');
    expect(JSON.parse(readFileSync(harness.deps.paths.configPath, 'utf8'))).toMatchObject({
      relayBaseUrl: 'http://127.0.0.1:8790', agentAdapterPort: 7273,
    });
  });

  test('setup requires an explicit adapter when noninteractive', async () => {
    const harness = createHarness();
    harness.deps.interactive = false;
    expect(await runDevProfileCommand(['setup'], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain('requires --extension pi or --no-extensions');
    expect(harness.deps.pathExists(harness.deps.paths.configPath)).toBe(false);
  });

  test('bridge uses persisted config despite stale environment and explicitly selects dev identity', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    let captured: BridgeConfig | undefined;
    let stopped = false;
    let finishRun!: () => void;
    harness.deps.createBridge = (config) => {
      captured = config;
      return {
        start: async () => {},
        runForever: () => new Promise<void>((resolveRun) => { finishRun = resolveRun; }),
        stop: () => { stopped = true; finishRun(); },
      };
    };
    harness.deps.waitForShutdown = async () => {};
    const previousRelay = process.env.ARIAVA_RELAY_BASE_URL;
    const previousPort = process.env.ARIAVA_AGENT_ADAPTER_PORT;
    process.env.ARIAVA_RELAY_BASE_URL = 'https://production.invalid';
    process.env.ARIAVA_AGENT_ADAPTER_PORT = '7272';
    try {
      expect(await runDevProfileCommand(['bridge'], harness.deps)).toBe(0);
    } finally {
      if (previousRelay === undefined) delete process.env.ARIAVA_RELAY_BASE_URL;
      else process.env.ARIAVA_RELAY_BASE_URL = previousRelay;
      if (previousPort === undefined) delete process.env.ARIAVA_AGENT_ADAPTER_PORT;
      else process.env.ARIAVA_AGENT_ADAPTER_PORT = previousPort;
    }
    expect(captured?.relayBaseUrl).toBe('http://127.0.0.1:8790');
    expect(captured?.agentAdapter.port).toBe(7273);
    expect(captured?.identityPath).toBe(harness.deps.paths.identityPath);
    expect(harness.output()).toContain('Adapter http://127.0.0.1:7273');
    expect(harness.output()).toContain('Relay http://127.0.0.1:8790');
    expect(stopped).toBe(true);
  });

  test('bridge shutdown is bounded when a daemon does not terminate', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    harness.deps.createBridge = () => ({
      start: async () => {},
      runForever: () => new Promise<void>(() => {}),
      stop: () => {},
    });
    harness.deps.waitForShutdown = async () => {};
    const startedAt = Date.now();
    expect(await runDevProfileCommand(['bridge'], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain('did not stop within 2000ms');
    expect(Date.now() - startedAt).toBeLessThan(3_000);
  });

  test.each([
    ['identityPath', (harness: ReturnType<typeof createHarness>) => join(harness.root, '.config', 'ariava', 'host-identity.json')],
    ['statePath', (harness: ReturnType<typeof createHarness>) => join(harness.root, '.config', 'ariava', 'state', 'bridge-state.json')],
    ['agentAdapterConfigPath', (harness: ReturnType<typeof createHarness>) => join(harness.root, '.config', 'ariava', 'agent-adapter.json')],
    ['agentAdapterPort', () => 7272],
  ] as const)('bridge and status fail closed for mismatched fixed dev %s', async (field, maliciousValue) => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const config = JSON.parse(readFileSync(harness.deps.paths.configPath, 'utf8'));
    config[field] = maliciousValue(harness);
    writeFileSync(harness.deps.paths.configPath, JSON.stringify(config), { mode: 0o600 });
    let bridges = 0;
    harness.deps.createBridge = () => { bridges += 1; throw new Error('must not create bridge'); };
    expect(await runDevProfileCommand(['bridge'], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain(`invalid: ${field}`);
    expect(await runDevProfileCommand(['status'], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain(`invalid: ${field}`);
    expect(bridges).toBe(0);
  });

  test('fixed dev bridge coexists with occupied production port 7272', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const production = await listenOrUseExisting(7272);
    let attemptedPort: number | undefined;
    let finishRun: (() => void) | undefined;
    harness.deps.createBridge = (config) => ({
      start: async () => { attemptedPort = config.agentAdapter.port; },
      runForever: () => new Promise<void>((resolveRun) => { finishRun = resolveRun; }),
      stop: () => { finishRun?.(); },
    });
    harness.deps.waitForShutdown = async () => {};
    try {
      expect(await runDevProfileCommand(['bridge'], harness.deps)).toBe(0);
      expect(attemptedPort).toBe(7273);
      expect(production.server?.listening ?? true).toBe(true);
    } finally {
      production.server?.close();
    }
  });

  test('occupied dev port 7273 fails without fallback or process actions', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const occupiedDev = await listenOrUseExisting(7273);
    const attemptedPorts: number[] = [];
    let spawnCalls = 0;
    harness.deps.createBridge = (config) => ({
      start: async () => { attemptedPorts.push(config.agentAdapter.port); await listen(config.agentAdapter.port); },
      runForever: async () => {},
      stop: () => {},
    });
    harness.deps.spawn = () => { spawnCalls += 1; return { status: 0 }; };
    try {
      expect(await runDevProfileCommand(['bridge'], harness.deps)).toBe(1);
      expect(harness.errorOutput()).toContain('Failed to listen at 127.0.0.1');
      expect(occupiedDev.server?.listening ?? true).toBe(true);
      expect(spawnCalls).toBe(0);
      expect(attemptedPorts).toEqual([7273]);
    } finally {
      occupiedDev.server?.close();
    }
  });

  test('pi fails before spawn when required files are missing', async () => {
    const harness = createHarness();
    let spawns = 0;
    harness.deps.spawn = () => { spawns += 1; return { status: 0 }; };
    expect(await runDevProfileCommand(['pi'], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain('discovery is missing');
    expect(spawns).toBe(0);

    writeAgentAdapterConfig(harness.deps.paths.agentAdapterConfigPath, { url: 'http://127.0.0.1:7273', secret: 'secret', protocolVersion: 2 });
    harness.deps.sourcePiExtensionPath = join(harness.root, 'missing-index.ts');
    expect(await runDevProfileCommand(['pi'], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain('Source pi extension is missing');
    expect(spawns).toBe(0);
  });

  test('pi launches the source extension with only dev Ariava overrides', async () => {
    const harness = createHarness();
    writeAgentAdapterConfig(harness.deps.paths.agentAdapterConfigPath, { url: 'http://127.0.0.1:7273', secret: 'secret', protocolVersion: 2 });
    const extensionPath = join(harness.root, 'index.ts');
    writeFileSync(extensionPath, 'export default {}', { mode: 0o600 });
    harness.deps.sourcePiExtensionPath = extensionPath;
    harness.deps.environment = {
      HOME: harness.root,
      PATH: '/usr/bin',
      MODEL_TOKEN: 'preserved',
      ARIAVA_RELAY_BASE_URL: 'https://stale.invalid',
      ARIAVA_AGENT_ADAPTER_SECRET: 'stale-secret',
    };
    let invocation: { command: string; args: string[]; options: any } | undefined;
    harness.deps.spawn = (command, args, options) => {
      invocation = { command, args, options };
      return { status: 0 };
    };

    expect(await runDevProfileCommand(['pi', '--model', 'test'], harness.deps)).toBe(0);
    expect(invocation?.command).toBe('pi');
    expect(invocation?.args).toEqual(['--no-extensions', '-e', extensionPath, '--model', 'test']);
    expect(invocation?.options.stdio).toBe('inherit');
    expect(invocation?.options.env).toEqual({
      HOME: harness.root,
      PATH: '/usr/bin',
      MODEL_TOKEN: 'preserved',
      ARIAVA_AGENT_ADAPTER_CONFIG_PATH: harness.deps.paths.agentAdapterConfigPath,
      ARIAVA_PI_LOG_PATH: harness.deps.paths.piExtensionLogPath,
    });
  });

  test('status is read-only, redacts the discovery secret, and never reads default profile files', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const defaultRoot = join(harness.root, '.config', 'ariava');
    mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });
    writeFileSync(join(defaultRoot, 'config.json'), '{not-json', { mode: 0o600 });
    writeAgentAdapterConfig(harness.deps.paths.agentAdapterConfigPath, {
      url: 'http://127.0.0.1:7273',
      secret: 'must-not-appear', protocolVersion: 2,
    });
    const offset = harness.output().length;
    expect(await runDevProfileCommand(['status'], harness.deps)).toBe(0);
    const statusOutput = harness.output().slice(offset);
    expect(statusOutput).toMatch(/^Ariava\n\n  Profile\s{2,}dev\n/);
    expect(statusOutput).not.toMatch(/^\{/);
    expect(() => JSON.parse(statusOutput)).toThrow();
    expect(statusOutput).toContain('http://127.0.0.1:7273');
    expect(statusOutput).toContain('Bridge');
    expect(statusOutput).toContain('local API · http://127.0.0.1:7273');
    expect(statusOutput).not.toContain('Adapter');
    expect(statusOutput).toContain('Pi extension');
    expect(statusOutput).toContain(harness.deps.paths.configPath);
    expect(statusOutput).not.toContain('must-not-appear');
    expect(readFileSync(join(defaultRoot, 'config.json'), 'utf8')).toBe('{not-json');
  });

  test('dev status and doctor expose source-only lifecycle evidence with independent readiness', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    writeAgentAdapterConfig(harness.deps.paths.agentAdapterConfigPath, {
      url: 'http://127.0.0.1:7273',
      secret: 'source-only-secret', protocolVersion: 2,
    });
    mkdirSync(join(harness.deps.paths.statePath, '..'), { recursive: true, mode: 0o700 });
    writeFileSync(harness.deps.paths.statePath, '{}', { mode: 0o600 });
    harness.deps.sourcePiExtensionPath = join(harness.root, 'source-pi-index.ts');
    writeFileSync(harness.deps.sourcePiExtensionPath, 'export default {}', { mode: 0o600 });
    const offset = harness.output().length;
    expect(await runDevProfileCommand(['status', '--json'], harness.deps)).toBe(0);
    const status = JSON.parse(harness.output().slice(offset));
    expect(status.data).toMatchObject({
      profile: 'dev',
      configPath: harness.deps.paths.configPath,
      identityPath: harness.deps.paths.identityPath,
      relayUrl: 'http://127.0.0.1:8790',
      adapterUrl: 'http://127.0.0.1:7273',
      adapterPort: 7273,
      piLogPath: harness.deps.paths.piExtensionLogPath,
      source: {
        bridge: { mode: 'foreground', ready: true },
        pi: { mode: 'source-extension', discoveryRequired: true },
      },
    });
    expect(JSON.stringify(status)).not.toContain('source-only-secret');
    expect(status.data).not.toHaveProperty('service');
    expect(status.data).not.toHaveProperty('strictReadiness');
    expect(status.data).not.toHaveProperty('managedPiPackage');

    const doctorOffset = harness.output().length;
    expect(await runDevProfileCommand(['doctor', '--json'], harness.deps)).toBe(0);
    const doctor = JSON.parse(harness.output().slice(doctorOffset));
    expect(doctor).toMatchObject({
      ok: true,
      code: 'ok',
      data: {
        profile: 'dev',
        sourceBridge: { mode: 'foreground', ready: true },
        sourcePi: { mode: 'source-extension', discoveryRequired: true },
      },
    });
    expect(doctor.data).not.toHaveProperty('serviceRunning');
    expect(doctor.data).not.toHaveProperty('piExtensionManaged');
    expect(doctor.data).not.toHaveProperty('strictReadiness');
  });

  test.each([false, true])('unhealthy dev doctor writes %s mode to stdout and exits 1', async (json) => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const offset = harness.output().length;
    expect(await runDevProfileCommand(['doctor', ...(json ? ['--json'] : [])], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toBe('');
    const output = harness.output().slice(offset);
    expect(output).not.toBe('');
    if (json) expect(JSON.parse(output)).toMatchObject({ ok: false, code: 'ERR_DOCTOR' });
    else expect(output).toContain('sourceBridge:');
  });

  test('dev discovery on production port is invalid and not ready', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    writeAgentAdapterConfig(harness.deps.paths.agentAdapterConfigPath, {
      url: 'http://127.0.0.1:7272',
      secret: 'dev-wrong-port-secret', protocolVersion: 2,
    });
    mkdirSync(join(harness.deps.paths.statePath, '..'), { recursive: true, mode: 0o700 });
    writeFileSync(harness.deps.paths.statePath, '{}', { mode: 0o600 });

    const offset = harness.output().length;
    expect(await runDevProfileCommand(['status', '--json'], harness.deps)).toBe(0);
    const status = JSON.parse(harness.output().slice(offset));
    expect(status.data.source.bridge).toEqual({
      mode: 'foreground',
      statePresent: true,
      discoveryPresent: true,
      discoveryValid: false,
      ready: false,
    });
    expect(status.data.adapterUrl).toBeNull();
    expect(JSON.stringify(status)).not.toContain('dev-wrong-port-secret');
  });

  test('production service evidence cannot make dev source status ready', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const defaultRoot = join(harness.root, '.config', 'ariava');
    mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });
    writeFileSync(join(defaultRoot, 'install.json'), JSON.stringify({
      service: { installed: true, enabled: true, loaded: true, processRunning: true },
      strictReadiness: true,
    }), { mode: 0o600 });
    const offset = harness.output().length;
    expect(await runDevProfileCommand(['status', '--json'], harness.deps)).toBe(0);
    const status = JSON.parse(harness.output().slice(offset));
    expect(status.data.source.bridge.ready).toBe(false);
    expect(status.data).not.toHaveProperty('service');
    expect(status.data).not.toHaveProperty('strictReadiness');
  });

  test('pair enrolls the dev Host then pairs the Watch using only the isolated profile', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const defaultRoot = join(harness.root, '.config', 'ariava');
    mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });
    const defaultConfig = join(defaultRoot, 'config.json');
    writeFileSync(defaultConfig, '{"production":true}\n', { mode: 0o600 });

    const identity = await harness.deps.createIdentityStore(
      harness.deps.paths.identityPath,
      harness.deps.platform,
      'dev',
    ).load();
    expect(identity).not.toBeNull();

    const paths: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      expect(url.origin).toBe('http://127.0.0.1:8790');
      paths.push(url.pathname);
      if (url.pathname === '/v2/bridge/enroll') {
        const body = await request.json() as { hostId: string; hostName: string; platform: 'macos' | 'linux'; bridgeVersion: string };
        expect(body.hostId).toBe(identity!.hostId);
        expect(body.hostName).toBe('test-host (Dev)');
        return Response.json({ host: hostProjection(body) });
      }
      if (url.pathname === '/v2/bridge/pair-watch') {
        expect(await request.json()).toEqual({ pairingCode: 'PEYX7K' });
        const now = new Date().toISOString();
        const watchDeviceId = `watch_${'C'.repeat(43)}`;
        return Response.json({
          host: {
            hostId: identity!.hostId,
            hostName: 'test-host (Dev)',
            platform: 'linux',
            bridgeVersion: '0.0.0-test',
            status: 'active',
            registeredAt: now,
            lastSeenAt: now,
            bridgeStatus: 'online',
          },
          watchDevice: {
            watchDeviceId,
            selectedHostIds: [identity!.hostId],
            registeredAt: now,
            lastSeenAt: now,
            pairingStatus: 'paired',
          },
          link: {
            hostId: identity!.hostId,
            watchDeviceId,
            pairedAt: now,
            generation: 1,
            updatedAt: now,
          },
          alreadyPaired: false,
        });
      }
      throw new Error(`unexpected path ${url.pathname}`);
    }) as typeof fetch;

    try {
      expect(await runDevProfileCommand(['pair', 'peyx7k'], harness.deps), harness.errorOutput()).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(paths).toEqual(['/v2/bridge/enroll', '/v2/bridge/pair-watch']);
    expect(harness.output()).toContain(`watch_${'C'.repeat(43)}`);
    expect(harness.output()).toContain(identity!.hostId);
    expect(harness.output()).toContain('test-host (Dev)');
    expect(harness.output()).toContain(
      `Pairing code accepted for watch watch_${'C'.repeat(43)} with host test-host (Dev) (${identity!.hostId}).\n`
      + 'Pairing is not complete until both sides confirm the Safety Code.\n',
    );
    expect(harness.output()).toContain('Safety Code activation was skipped');
    expect(readFileSync(defaultConfig, 'utf8')).toBe('{"production":true}\n');
  });

  test('pair requires a pairing code and fails closed when the profile is not initialized', async () => {
    const harness = createHarness();
    expect(await runDevProfileCommand(['pair'], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain('Usage: dev-profile-cli pair <PAIRING_CODE> [--codes-match]');
    expect(await runDevProfileCommand(['pair', 'peyx7k'], harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain('Dev profile is not initialized');
    expect(harness.deps.pathExists(harness.deps.paths.configPath)).toBe(false);
  });
  test.each([
    { name: 'noninteractive', environment: {}, json: false, interactive: false },
    { name: 'CI', environment: { CI: '1' }, json: false, interactive: true },
    { name: 'TERM=dumb', environment: { TERM: 'dumb' }, json: false, interactive: true },
    { name: 'JSON', environment: {}, json: true, interactive: true },
  ])('pair refuses implicit confirmation in $name mode and --codes-match is explicit', async ({ environment, json, interactive }) => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    harness.deps.interactive = interactive;
    harness.deps.environment = { ...harness.deps.environment, ...environment };
    let confirmCalls = 0;
    delete harness.deps.confirmSafetyCodeMatch;
    harness.deps.createPairDependencies = () => fakePairDependencies(harness, async (input) => {
      confirmCalls += 1;
      return await input.confirmMatch() ? 'activated' : 'cancelled';
    });
    const args = ['pair', 'peyx7k', ...(json ? ['--json'] : [])];
    expect(await runDevProfileCommand(args, harness.deps)).toBe(1);
    expect(harness.errorOutput()).toContain('Noninteractive Safety Code confirmation requires --codes-match');
    expect(confirmCalls).toBe(1);

    confirmCalls = 0;
    expect(await runDevProfileCommand([...args, '--codes-match'], harness.deps)).toBe(0);
    expect(confirmCalls).toBe(1);
  });

  test.each([false, true])('pair cancellation maps once to the stable %s JSON contract', async (json) => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    harness.deps.confirmSafetyCodeMatch = async () => false;
    harness.deps.createPairDependencies = () => fakePairDependencies(harness, async (input) => {
      const matched = await input.confirmMatch();
      input.write('Safety Code confirmation cancelled. Re-pair if the codes differed.');
      return matched ? 'activated' : 'cancelled';
    });
    expect(await runDevProfileCommand(['pair', 'peyx7k', ...(json ? ['--json'] : [])], harness.deps)).toBe(1);
    if (json) {
      expect(harness.output()).toBe('Initialized dev Host identity ' + JSON.parse(
        readFileSync(harness.deps.paths.configPath, 'utf8'),
      ).identity.hostId + '\n');
      expect(JSON.parse(harness.errorOutput())).toEqual({
        ok: false,
        code: 'ERR_PAIR_CANCELLED',
        message: 'Safety Code confirmation cancelled.',
        data: {},
      });
    } else {
      expect(harness.errorOutput()).toBe('ariava: Safety Code confirmation cancelled.\n');
    }
  });

});

function fakePairDependencies(
  harness: ReturnType<typeof createHarness>,
  activate: ReturnType<DevProfileDependencies['createPairDependencies']>['activate'],
): ReturnType<DevProfileDependencies['createPairDependencies']> {
  return {
    bridgeVersion: '0.0.0-test',
    normalizePairingCode: (value) => value.toUpperCase(),
    enroll: async () => {},
    createRelay: () => ({} as never),
    pairWatch: async () => {
      const identity = await harness.deps.createIdentityStore(
        harness.deps.paths.identityPath,
        harness.deps.platform,
        'dev',
      ).load();
      const now = new Date().toISOString();
      const watchDeviceId = `watch_${'C'.repeat(43)}`;
      return {
        host: { ...hostProjection(identity!.hostId), hostName: 'test-host (Dev)' },
        watchDevice: {
          watchDeviceId,
          selectedHostIds: [identity!.hostId],
          registeredAt: now,
          lastSeenAt: now,
          pairingStatus: 'paired',
        },
        link: { hostId: identity!.hostId, watchDeviceId, pairedAt: now, generation: 1, updatedAt: now },
        alreadyPaired: false,
      };
    },
    createKeyring: () => ({} as never),
    createHostBinding: async () => ({} as never),
    activate,
  };
}

function snapshotItems(keychain: FakeKeychain): Array<[string, string]> {
  return [...keychain.items.entries()]
    .map(([account, value]) => [account, Buffer.from(value).toString('hex')] as [string, string])
    .sort(([left], [right]) => left.localeCompare(right));
}

function hostProjection(input: string | { hostId: string; hostName: string; platform: 'macos' | 'linux'; bridgeVersion: string }) {
  const metadata = typeof input === 'string'
    ? { hostId: input, hostName: 'test-host (Dev)', platform: 'linux' as const, bridgeVersion: '0.0.0-test' }
    : input;
  return {
    hostId: metadata.hostId,
    hostName: metadata.hostName,
    platform: metadata.platform,
    bridgeVersion: metadata.bridgeVersion,
    registeredAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    bridgeStatus: 'online' as const,
    status: 'active' as const,
  };
}

function listen(port: number): Promise<Server> {
  return new Promise((resolveServer, rejectServer) => {
    const server = createServer();
    server.once('error', rejectServer);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', rejectServer);
      resolveServer(server);
    });
  });
}

async function listenOrUseExisting(port: number): Promise<{ server?: Server }> {
  try {
    return { server: await listen(port) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EADDRINUSE') return {};
    throw error;
  }
}
