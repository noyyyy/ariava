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
import type { BridgeConfig } from '../src/types';

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
} {
  const root = mkdtempSync(join(tmpdir(), 'ariava-dev-cli-'));
  roots.push(root);
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const defaults = createDefaultDevProfileDependencies();
  const deps: DevProfileDependencies = {
    ...defaults,
    paths: resolveAriavaDevProfilePaths(root),
    platform: 'linux',
    stdout,
    stderr,
    hostName: () => 'test-host',
    environment: { HOME: root, PATH: process.env.PATH, ARIAVA_RELAY_BASE_URL: 'https://stale.invalid' },
    generateSecret: () => 'dev-secret',
    createIdentityStore: (path, platform, profile) => {
      expect(profile).toBe('dev');
      return createRuntimeHostIdentityStore(path, platform, profile);
    },
  };
  let text = '';
  stdout.on('data', (chunk) => { text += chunk.toString(); });
  return { root, deps, stdout, stderr, output: () => text };
}

describe('source dev profile commands', () => {
  test('init writes only the dev tree and reuses its identity', async () => {
    const harness = createHarness();
    const defaultRoot = join(harness.root, '.config', 'ariava');
    mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });
    const defaultConfig = join(defaultRoot, 'config.json');
    const original = '{"production":true}\n';
    writeFileSync(defaultConfig, original, { mode: 0o600 });

    expect(await runDevProfileCommand(['init'], harness.deps)).toBe(0);
    const first = JSON.parse(readFileSync(harness.deps.paths.configPath, 'utf8'));
    expect(first).toMatchObject({
      relayBaseUrl: 'http://127.0.0.1:8787',
      hostName: 'test-host (Dev)',
      agentAdapterPort: 7273,
      agentAdapterSecret: 'dev-secret',
      agentAdapterConfigPath: harness.deps.paths.agentAdapterConfigPath,
      statePath: harness.deps.paths.statePath,
      identityPath: harness.deps.paths.identityPath,
    });
    expect(first.identity.hostId).toBeString();
    expect(readFileSync(defaultConfig, 'utf8')).toBe(original);

    expect(await runDevProfileCommand(['init'], harness.deps)).toBe(0);
    const second = JSON.parse(readFileSync(harness.deps.paths.configPath, 'utf8'));
    expect(second.identity.hostId).toBe(first.identity.hostId);
    expect(readFileSync(defaultConfig, 'utf8')).toBe(original);
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
    expect(captured?.relayBaseUrl).toBe('http://127.0.0.1:8787');
    expect(captured?.agentAdapter.port).toBe(7273);
    expect(captured?.identityPath).toBe(harness.deps.paths.identityPath);
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
    await expect(runDevProfileCommand(['bridge'], harness.deps)).rejects.toThrow('did not stop within 2000ms');
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
    await expect(runDevProfileCommand(['bridge'], harness.deps)).rejects.toThrow(`invalid: ${field}`);
    await expect(runDevProfileCommand(['status'], harness.deps)).rejects.toThrow(`invalid: ${field}`);
    expect(bridges).toBe(0);
  });

  test('fixed dev bridge coexists with occupied production port 7272', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const production = await listenOrUseExisting(7272);
    let active: Server | undefined;
    let finishRun: (() => void) | undefined;
    harness.deps.createBridge = (config) => ({
      start: async () => { active = await listen(config.agentAdapter.port); },
      runForever: () => new Promise<void>((resolveRun) => { finishRun = resolveRun; }),
      stop: () => { active?.close(); finishRun?.(); },
    });
    harness.deps.waitForShutdown = async () => {};
    try {
      expect(await runDevProfileCommand(['bridge'], harness.deps)).toBe(0);
      expect(production.server?.listening ?? true).toBe(true);
    } finally {
      production.server?.close();
      active?.close();
    }
  });

  test('occupied dev port 7273 fails without fallback or process actions', async () => {
    const harness = createHarness();
    await runDevProfileCommand(['init'], harness.deps);
    const occupiedDev = await listen(7273);
    const attemptedPorts: number[] = [];
    let spawnCalls = 0;
    harness.deps.createBridge = (config) => ({
      start: async () => { attemptedPorts.push(config.agentAdapter.port); await listen(config.agentAdapter.port); },
      runForever: async () => {},
      stop: () => {},
    });
    harness.deps.spawn = () => { spawnCalls += 1; return { status: 0 }; };
    try {
      await expect(runDevProfileCommand(['bridge'], harness.deps)).rejects.toMatchObject({ code: 'EADDRINUSE' });
      expect(occupiedDev.listening).toBe(true);
      expect(spawnCalls).toBe(0);
      expect(attemptedPorts).toEqual([7273]);
    } finally {
      occupiedDev.close();
    }
  });

  test('pi fails before spawn when required files are missing', async () => {
    const harness = createHarness();
    let spawns = 0;
    harness.deps.spawn = () => { spawns += 1; return { status: 0 }; };
    await expect(runDevProfileCommand(['pi'], harness.deps)).rejects.toThrow('discovery is missing');
    expect(spawns).toBe(0);

    writeAgentAdapterConfig(harness.deps.paths.agentAdapterConfigPath, { url: 'http://127.0.0.1:7273', secret: 'secret' });
    harness.deps.sourcePiExtensionPath = join(harness.root, 'missing-index.ts');
    await expect(runDevProfileCommand(['pi'], harness.deps)).rejects.toThrow('Source pi extension is missing');
    expect(spawns).toBe(0);
  });

  test('pi launches the source extension with only dev Ariava overrides', async () => {
    const harness = createHarness();
    writeAgentAdapterConfig(harness.deps.paths.agentAdapterConfigPath, { url: 'http://127.0.0.1:7273', secret: 'secret' });
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
      secret: 'must-not-appear',
    });
    expect(await runDevProfileCommand(['status'], harness.deps)).toBe(0);
    expect(harness.output()).toContain('http://127.0.0.1:7273');
    expect(harness.output()).toContain(harness.deps.paths.configPath);
    expect(harness.output()).not.toContain('must-not-appear');
    expect(readFileSync(join(defaultRoot, 'config.json'), 'utf8')).toBe('{not-json');
  });
});

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
