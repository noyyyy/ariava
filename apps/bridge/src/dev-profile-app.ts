import { spawnSync, type SpawnSyncOptions } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BridgeDaemon, loadBridgeConfig } from './daemon';
import {
  loadUserConfig,
  resolveAriavaDevProfilePaths,
  resolvePersistedAriavaConfig,
  saveUserConfig,
  type AriavaDevProfilePaths,
  type AriavaUserConfig,
} from './host-manager';
import { readSecureJson } from './host-manager/secure-files';
import {
  createRuntimeHostIdentityStore,
  ensureFirstRunIdentity,
  publicIdentityMetadata,
  type HostIdentityStore,
} from './identity';
import type { BridgeConfig } from './types';

const PUBLIC_CORE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const SOURCE_PI_EXTENSION_PATH = resolve(PUBLIC_CORE_ROOT, 'extensions', 'pi', 'index.ts');

interface DevBridgeDaemon {
  start(): Promise<void>;
  runForever(): Promise<void>;
  stop(): void;
}

const DEV_BRIDGE_SHUTDOWN_TIMEOUT_MS = 2_000;

interface SpawnResult {
  status: number | null;
  signal?: NodeJS.Signals | null;
  error?: Error;
}

export interface DevProfileDependencies {
  paths: AriavaDevProfilePaths;
  platform: NodeJS.Platform | string;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
  sourcePiExtensionPath: string;
  pathExists(path: string): boolean;
  loadUserConfig(path: string): AriavaUserConfig;
  saveUserConfig(config: AriavaUserConfig, path: string): void;
  createIdentityStore(path: string, platform: NodeJS.Platform | string, profile: 'dev'): HostIdentityStore;
  createBridge(config: BridgeConfig, identityStore: HostIdentityStore): DevBridgeDaemon;
  spawn(command: string, args: string[], options: SpawnSyncOptions): SpawnResult;
  waitForShutdown(): Promise<void>;
  environment: NodeJS.ProcessEnv;
  hostName(): string;
  generateSecret(): string;
}

export function createDefaultDevProfileDependencies(): DevProfileDependencies {
  return {
    paths: resolveAriavaDevProfilePaths(),
    platform: process.platform,
    stdout: process.stdout,
    stderr: process.stderr,
    sourcePiExtensionPath: SOURCE_PI_EXTENSION_PATH,
    pathExists: existsSync,
    loadUserConfig,
    saveUserConfig,
    createIdentityStore: (path, platform, profile) => createRuntimeHostIdentityStore(path, platform, profile),
    createBridge: (config, identityStore) => new BridgeDaemon(config, undefined, identityStore),
    spawn: (command, args, options) => spawnSync(command, args, options),
    waitForShutdown: waitForShutdownSignal,
    environment: process.env,
    hostName: hostname,
    generateSecret: () => randomBytes(32).toString('hex'),
  };
}

export async function runDevProfileCommand(
  argv: string[],
  dependencies: DevProfileDependencies = createDefaultDevProfileDependencies(),
): Promise<number> {
  const command = argv[0];
  switch (command) {
    case 'init':
      return initDevProfile(dependencies);
    case 'bridge':
      return runDevBridge(dependencies);
    case 'pi':
      return runDevPi(argv.slice(1), dependencies);
    case 'status':
      return showDevStatus(dependencies);
    default:
      throw new Error('Usage: dev-profile-cli <init|bridge|pi|status>');
  }
}

async function initDevProfile(deps: DevProfileDependencies): Promise<number> {
  const existing = deps.loadUserConfig(deps.paths.configPath);
  const base: AriavaUserConfig = {
    relayBaseUrl: existing.relayBaseUrl ?? 'http://127.0.0.1:8787',
    hostName: existing.hostName ?? `${deps.hostName()} (Dev)`,
    agentAdapterPort: deps.paths.agentAdapterPort,
    agentAdapterSecret: existing.agentAdapterSecret ?? deps.generateSecret(),
    agentAdapterConfigPath: deps.paths.agentAdapterConfigPath,
    statePath: deps.paths.statePath,
    identityPath: deps.paths.identityPath,
    ...(existing.pollIntervalMs === undefined ? {} : { pollIntervalMs: existing.pollIntervalMs }),
  };
  deps.saveUserConfig(base, deps.paths.configPath);
  const store = deps.createIdentityStore(deps.paths.identityPath, deps.platform, 'dev');
  const ensured = await ensureFirstRunIdentity(store);
  deps.saveUserConfig({ ...base, identity: publicIdentityMetadata(ensured.identity) }, deps.paths.configPath);
  deps.stdout.write(`${ensured.created ? 'Initialized' : 'Reused'} dev Host identity ${ensured.identity.hostId}\n`);
  return 0;
}

async function runDevBridge(deps: DevProfileDependencies): Promise<number> {
  requireInitializedConfig(deps);
  const config = loadBridgeConfig(deps.paths.configPath);
  const identityStore = deps.createIdentityStore(deps.paths.identityPath, deps.platform, 'dev');
  const daemon = deps.createBridge(config, identityStore);
  await daemon.start();
  deps.stdout.write(`Ariava source Bridge listening on ${config.agentAdapter.port} using ${deps.paths.configPath}\n`);
  const runPromise = daemon.runForever();
  try {
    await Promise.race([runPromise, deps.waitForShutdown()]);
  } finally {
    daemon.stop();
    await waitForBridgeShutdown(runPromise);
  }
  return 0;
}

async function waitForBridgeShutdown(runPromise: Promise<void>): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeout = setTimeout(
      () => reject(new Error(`Ariava source Bridge did not stop within ${DEV_BRIDGE_SHUTDOWN_TIMEOUT_MS}ms`)),
      DEV_BRIDGE_SHUTDOWN_TIMEOUT_MS,
    );
  });
  try {
    await Promise.race([runPromise, timeoutPromise]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function runDevPi(args: string[], deps: DevProfileDependencies): number {
  if (!deps.pathExists(deps.paths.agentAdapterConfigPath)) {
    throw new Error(`Dev Agent Adapter discovery is missing at ${deps.paths.agentAdapterConfigPath}; start dev:bridge first`);
  }
  if (!deps.pathExists(deps.sourcePiExtensionPath)) {
    throw new Error(`Source pi extension is missing at ${deps.sourcePiExtensionPath}`);
  }
  const environment = sanitizeAriavaEnvironment(deps.environment);
  environment.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = deps.paths.agentAdapterConfigPath;
  environment.ARIAVA_PI_LOG_PATH = deps.paths.piExtensionLogPath;
  const result = deps.spawn('pi', ['--no-extensions', '-e', deps.sourcePiExtensionPath, ...args], {
    env: environment,
    stdio: 'inherit',
  });
  if (result.error) throw result.error;
  if (result.signal) throw new Error(`pi exited from signal ${result.signal}`);
  return result.status ?? 1;
}

async function showDevStatus(deps: DevProfileDependencies): Promise<number> {
  requireInitializedConfig(deps);
  const resolved = resolvePersistedAriavaConfig(deps.paths.configPath);
  let adapterUrl: string | null = null;
  if (deps.pathExists(deps.paths.agentAdapterConfigPath)) {
    const discovery = readSecureJson<{ url?: unknown }>(deps.paths.agentAdapterConfigPath);
    adapterUrl = typeof discovery.url === 'string' ? discovery.url : null;
  }
  deps.stdout.write(`${JSON.stringify({
    profile: 'dev',
    configPath: deps.paths.configPath,
    identityPath: resolved.identityPath,
    hostId: resolved.identity?.hostId ?? null,
    statePath: resolved.statePath,
    discoveryPath: resolved.agentAdapterConfigPath,
    adapterUrl,
    adapterPort: resolved.agentAdapterPort,
    piLogPath: deps.paths.piExtensionLogPath,
    relayUrl: resolved.relayBaseUrl,
  }, null, 2)}\n`);
  return 0;
}

function requireInitializedConfig(deps: DevProfileDependencies): void {
  if (!deps.pathExists(deps.paths.configPath)) {
    throw new Error(`Dev profile is not initialized at ${deps.paths.configPath}; run dev:init first`);
  }
  const config = resolvePersistedAriavaConfig(deps.paths.configPath);
  assertFixedDevConfig(config, deps.paths);
  if (!config.identity) throw new Error(`Dev identity is not initialized at ${deps.paths.identityPath}; run dev:init first`);
}

function assertFixedDevConfig(
  config: Pick<ReturnType<typeof resolvePersistedAriavaConfig>, 'identityPath' | 'statePath' | 'agentAdapterConfigPath' | 'agentAdapterPort'>,
  paths: AriavaDevProfilePaths,
): void {
  const mismatches = [
    config.identityPath === paths.identityPath ? undefined : 'identityPath',
    config.statePath === paths.statePath ? undefined : 'statePath',
    config.agentAdapterConfigPath === paths.agentAdapterConfigPath ? undefined : 'agentAdapterConfigPath',
    config.agentAdapterPort === paths.agentAdapterPort ? undefined : 'agentAdapterPort',
  ].filter((value): value is string => value !== undefined);
  if (mismatches.length > 0) {
    throw new Error(`Dev profile config must use fixed dev resources; invalid: ${mismatches.join(', ')}`);
  }
}

function sanitizeAriavaEnvironment(environment: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(environment).filter(([name]) => !name.startsWith('ARIAVA_')));
}

function waitForShutdownSignal(): Promise<void> {
  return new Promise((resolveShutdown) => {
    process.once('SIGINT', resolveShutdown);
    process.once('SIGTERM', resolveShutdown);
  });
}
