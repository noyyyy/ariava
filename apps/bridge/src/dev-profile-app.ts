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
import { createReadlineOnboardingPrompt, promptForOnboardingSelection } from './ui/onboarding-renderer';

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
  selectAdapter(): Promise<'pi' | 'bridge-only'>;
  interactive: boolean;
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
    selectAdapter: selectDevAdapter,
    interactive: process.stdin.isTTY === true && process.stdout.isTTY === true,
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
    case 'setup':
      return runDevSetup(argv.slice(1), dependencies);
    case 'init':
      return initDevProfile(dependencies);
    case 'bridge':
      return runDevBridge(dependencies);
    case 'pi':
      return runDevPi(argv.slice(1), dependencies);
    case 'status':
      return showDevStatus(dependencies);
    default:
      throw new Error('Usage: dev-profile-cli <setup|init|bridge|pi|status>');
  }
}

async function runDevSetup(args: string[], deps: DevProfileDependencies): Promise<number> {
  const usePi = await selectDevSetupPi(args, deps);
  await initDevProfile(deps);
  const { daemon, runPromise } = await startDevBridge(deps);
  try {
    if (usePi) {
      requireSourcePiExtension(deps);
      deps.stdout.write('Pi source adapter ready. Start Pi in another terminal with:\n');
      deps.stdout.write('  bun run --cwd open-source/ariava dev:pi\n');
    } else {
      deps.stdout.write('Dev profile ready without agent extensions.\n');
    }
    deps.stdout.write('Press Ctrl-C to stop the source Bridge.\n');
    const outcome = await Promise.race([
      runPromise.then(() => 'bridge' as const),
      deps.waitForShutdown().then(() => 'shutdown' as const),
    ]);
    if (outcome === 'bridge') throw new Error('Ariava source Bridge stopped unexpectedly');
    return 0;
  } finally {
    daemon.stop();
    await waitForBridgeShutdown(runPromise);
  }
}

async function selectDevSetupPi(args: string[], deps: DevProfileDependencies): Promise<boolean> {
  let piSelected = false;
  let noExtensions = false;
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (value === '--extension') {
      if (args[++index] !== 'pi') throw new Error('dev:setup supports only --extension pi');
      piSelected = true;
    } else if (value === '--no-extensions') {
      noExtensions = true;
    } else {
      throw new Error(`Unknown dev:setup option: ${value}`);
    }
  }
  if (piSelected && noExtensions) throw new Error('Choose either --extension or --no-extensions');
  if (piSelected) return true;
  if (noExtensions) return false;
  if (!deps.interactive) throw new Error('Noninteractive dev:setup requires --extension pi or --no-extensions');
  return await deps.selectAdapter() === 'pi';
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
  const store = deps.createIdentityStore(deps.paths.identityPath, deps.platform, 'dev');
  const ensured = await ensureFirstRunIdentity(store);
  const config = { ...base, identity: publicIdentityMetadata(ensured.identity) };
  if (JSON.stringify(existing) !== JSON.stringify(config)) deps.saveUserConfig(config, deps.paths.configPath);
  deps.stdout.write(`${ensured.created ? 'Initialized' : 'Reused'} dev Host identity ${ensured.identity.hostId}\n`);
  return 0;
}

async function runDevBridge(deps: DevProfileDependencies): Promise<number> {
  const { daemon, runPromise } = await startDevBridge(deps);
  try {
    await Promise.race([runPromise, deps.waitForShutdown()]);
  } finally {
    daemon.stop();
    await waitForBridgeShutdown(runPromise);
  }
  return 0;
}

async function startDevBridge(deps: DevProfileDependencies): Promise<{ daemon: DevBridgeDaemon; runPromise: Promise<void> }> {
  requireInitializedConfig(deps);
  const config = loadBridgeConfig(deps.paths.configPath);
  const identityStore = deps.createIdentityStore(deps.paths.identityPath, deps.platform, 'dev');
  const daemon = deps.createBridge(config, identityStore);
  await daemon.start();
  deps.stdout.write(`Ariava source Bridge listening on ${config.agentAdapter.port} using ${deps.paths.configPath}\n`);
  return { daemon, runPromise: daemon.runForever() };
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
  requireDevPiFiles(deps);
  const environment = sanitizeAriavaEnvironment(deps.environment);
  environment.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = deps.paths.agentAdapterConfigPath;
  environment.ARIAVA_PI_LOG_PATH = deps.paths.piExtensionLogPath;
  return exitCode(deps.spawn(
    'pi',
    ['--no-extensions', '-e', deps.sourcePiExtensionPath, ...args],
    { env: environment, stdio: 'inherit' },
  ));
}

function requireDevPiFiles(deps: DevProfileDependencies): void {
  if (!deps.pathExists(deps.paths.agentAdapterConfigPath)) {
    throw new Error(`Dev Agent Adapter discovery is missing at ${deps.paths.agentAdapterConfigPath}; start dev:bridge first`);
  }
  requireSourcePiExtension(deps);
}

function requireSourcePiExtension(deps: DevProfileDependencies): void {
  if (!deps.pathExists(deps.sourcePiExtensionPath)) {
    throw new Error(`Source pi extension is missing at ${deps.sourcePiExtensionPath}`);
  }
}

function exitCode(result: SpawnResult): number {
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

async function selectDevAdapter(): Promise<'pi' | 'bridge-only'> {
  const prompt = createReadlineOnboardingPrompt(process.stdin, process.stdout);
  try {
    const selection = await promptForOnboardingSelection({ pi: { present: true } }, prompt, false);
    return selection.extensions.includes('pi') ? 'pi' : 'bridge-only';
  } finally {
    prompt.close?.();
  }
}

function waitForShutdownSignal(): Promise<void> {
  return new Promise((resolveShutdown) => {
    process.once('SIGINT', resolveShutdown);
    process.once('SIGTERM', resolveShutdown);
  });
}
