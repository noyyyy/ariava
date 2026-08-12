import { spawnSync, type SpawnSyncOptions } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BridgeDaemon, loadBridgeConfig } from '../../daemon';
import {
  loadUserConfig,
  resolvePersistedAriavaConfig,
  saveUserConfig,
  type AriavaUserConfig,
} from '../../host-manager/config';
import { resolveAriavaDevProfilePaths, type AriavaDevProfilePaths } from '../../host-manager/dev-profile';
import {
  createRuntimeHostEncryptionIdentityStore,
  createRuntimeHostIdentityStore,
  type HostEncryptionIdentityStore,
  type HostIdentityStore,
} from '../../identity';
import type { BridgeConfig } from '../../types';
import { createReadlineOnboardingPrompt, promptForOnboardingSelection } from '../../ui/onboarding-renderer';
import { createDevProfile } from '../profiles/dev';
import { createProfileCliContext, type AriavaCliApplicationContext } from '../context';
import { initializeProfile } from '../operations/initialize';
import { createDefaultProfileIdentityResetDependencies } from '../operations/identity';
import type { AriavaProfileDescriptor } from '../profile';
import { createDefaultPairProfileDependencies } from '../operations/pair';
import { createDefaultWatchesProfileDependencies } from '../operations/watches';
import { runSharedHostCommand } from '../commands';
import { formatDoctorChecks } from '../commands/doctor';
import { runAriavaCli, resolveCliVersion } from '../app';
import { inspectCurrentNodeRuntime } from '../../runtime/node-runtime';
import { runNodeCryptoSelfTest } from '../../e2e/node-crypto-self-test';
import type { ProfileProbeEvidence, ProfileRuntimeProbe } from '../probes/profile';

function resolvePublicRepoRoot(modulePath: string): string {
  let candidate = dirname(modulePath);
  while (true) {
    const packagePath = resolve(candidate, 'package.json');
    if (existsSync(packagePath)) {
      try {
        const manifest = JSON.parse(readFileSync(packagePath, 'utf8')) as { name?: unknown };
        if (manifest.name === 'ariava' && existsSync(resolve(candidate, 'apps', 'bridge'))) return candidate;
      } catch {}
    }
    const parent = dirname(candidate);
    if (parent === candidate) break;
    candidate = parent;
  }
  throw new Error(`Unable to locate the Ariava Public Repo root from ${modulePath}`);
}

const PUBLIC_REPO_ROOT = resolvePublicRepoRoot(fileURLToPath(import.meta.url));
const SOURCE_PI_EXTENSION_PATH = resolve(PUBLIC_REPO_ROOT, 'extensions', 'pi', 'index.ts');
const DEV_BRIDGE_VERSION = resolveCliVersion('dev', () => (
  JSON.parse(readFileSync(resolve(PUBLIC_REPO_ROOT, 'package.json'), 'utf8')) as { version?: unknown }
));

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
  profile: AriavaProfileDescriptor;
  platform: NodeJS.Platform | string;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
  stdin: NodeJS.ReadableStream;
  sourcePiExtensionPath: string;
  pathExists(path: string): boolean;
  loadUserConfig(path: string): AriavaUserConfig;
  saveUserConfig(config: AriavaUserConfig, path: string): void;
  createIdentityStore(path: string, platform: NodeJS.Platform | string, profile: 'dev'): HostIdentityStore;
  createEncryptionIdentityStore(path: string, platform: NodeJS.Platform | string, profile: 'dev'): HostEncryptionIdentityStore;
  createBridge(config: BridgeConfig, identityStore: HostIdentityStore): DevBridgeDaemon;
  spawn(command: string, args: string[], options: SpawnSyncOptions): SpawnResult;
  waitForShutdown(): Promise<void>;
  selectAdapter(): Promise<'pi' | 'bridge-only'>;
  interactive: boolean;
  environment: NodeJS.ProcessEnv;
  hostName(): string;
  generateSecret(): string;
  confirmSafetyCodeMatch?(): Promise<boolean>;
  sleep?(ms: number): Promise<void>;
  createPairDependencies(bridgeVersion: string): ReturnType<typeof createDefaultPairProfileDependencies>;
}

export function createDefaultDevProfileDependencies(): DevProfileDependencies {
  return {
    paths: resolveAriavaDevProfilePaths(),
    profile: createDevProfile(),
    platform: process.platform,
    stdout: process.stdout,
    stderr: process.stderr,
    stdin: process.stdin,
    sourcePiExtensionPath: SOURCE_PI_EXTENSION_PATH,
    pathExists: existsSync,
    loadUserConfig,
    saveUserConfig,
    createIdentityStore: (path, platform, profile) => createRuntimeHostIdentityStore(path, platform, profile),
    createEncryptionIdentityStore: (path, platform, profile) => createRuntimeHostEncryptionIdentityStore(path, platform, profile),
    createBridge: (config, identityStore) => new BridgeDaemon(config, undefined, identityStore),
    spawn: (command, args, options) => spawnSync(command, args, options),
    waitForShutdown: waitForShutdownSignal,
    selectAdapter: selectDevAdapter,
    interactive: process.stdin.isTTY === true && process.stdout.isTTY === true,
    environment: process.env,
    hostName: hostname,
    generateSecret: () => randomBytes(32).toString('hex'),
    createPairDependencies: createDefaultPairProfileDependencies,
  };
}

export function createDevCliApplicationContext(
  dependencies: DevProfileDependencies = createDefaultDevProfileDependencies(),
): AriavaCliApplicationContext {
  const lifecycle = createDevLifecycleAdapter(dependencies);
  return {
    profileId: 'dev',
    profile: () => dependencies.profile,
    validateDescriptor: () => dependencies.profile.assertDescriptor(),
    output: { stdout: dependencies.stdout, stderr: dependencies.stderr },
    version: () => DEV_BRIDGE_VERSION,
    shared: {
      execute: (args, options) => runSharedHostCommand(args, options, {
        context: () => createDevProfileContext(dependencies),
        profileId: 'dev',
        reset: createDefaultProfileIdentityResetDependencies(DEV_BRIDGE_VERSION),
        pair: dependencies.createPairDependencies(DEV_BRIDGE_VERSION),
        watches: createDefaultWatchesProfileDependencies(DEV_BRIDGE_VERSION),
        status: createDevStatusDependencies(dependencies),
        doctor: createDevDoctorDependencies(dependencies),
        stdin: dependencies.stdin,
        stdout: dependencies.stdout,
        interactive: dependencies.interactive,
        environment: dependencies.environment,
        ...(dependencies.confirmSafetyCodeMatch
          ? { confirmSafetyCodeMatch: dependencies.confirmSafetyCodeMatch }
          : {}),
        ...(dependencies.sleep ? { sleep: dependencies.sleep } : {}),
      }),
    },
    legacy: lifecycle,
    lifecycle,
  };
}

export function runDevProfileCommand(
  argv: string[],
  dependencies: DevProfileDependencies = createDefaultDevProfileDependencies(),
): Promise<number> {
  return runAriavaCli(argv, createDevCliApplicationContext(dependencies));
}

export function createDevLifecycleAdapter(dependencies: DevProfileDependencies) {
  return {
    execute: (args: string[]) => dispatchDevProfileCommand(args, dependencies),
  };
}

async function dispatchDevProfileCommand(
  argv: string[],
  dependencies: DevProfileDependencies,
): Promise<number> {
  const command = argv[0];
  switch (command) {
    case 'setup': return runDevSetup(argv.slice(1), dependencies);
    case 'bridge': return runDevBridge(dependencies);
    case 'pi': return runDevPi(argv.slice(1), dependencies);
    default: throw new Error(`Unknown command: ${command}`);
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
      deps.stdout.write('  npm run dev:cli -- pi\n');
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
  const result = await initializeProfile(createDevProfileContext(deps));
  deps.stdout.write(`${result.identityCreated ? 'Initialized' : 'Reused'} dev Host identity ${result.inspection.hostId}\n`);
  return 0;
}


function createDevProfileContext(deps: DevProfileDependencies) {
  return createProfileCliContext({
    profile: deps.profile,
    platform: deps.platform,
    hostName: deps.hostName,
    generateSecret: deps.generateSecret,
    environment: deps.environment,
    allowProductionEnvironmentDefaults: false,
    saveBaseBeforeIdentity: false,
    config: {
      load: (path) => deps.loadUserConfig(path),
      save: (config, path) => deps.saveUserConfig(config, path),
    },
    identity: {
      create: (resources) => deps.createIdentityStore(resources.identityMetadataPath, deps.platform, 'dev'),
    },
    encryptionIdentity: {
      create: (resources) => deps.createEncryptionIdentityStore(
        resources.identityMetadataPath,
        deps.platform,
        'dev',
      ),
    },
  });
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
  deps.stdout.write(
    `Ariava source Bridge ready; Adapter http://127.0.0.1:${config.agentAdapter.port}; Relay ${config.relayBaseUrl}; config ${deps.paths.configPath}\n`,
  );
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
    throw new Error(`Dev Agent Adapter discovery is missing at ${deps.paths.agentAdapterConfigPath}; run npm run dev:cli -- bridge first`);
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




function createDevStatusDependencies(deps: DevProfileDependencies) {
  return {
    context: () => createDevProfileContext(deps),
    pathExists: deps.pathExists,
    runtime: devRuntimeProbe,
    lifecycle: {
      buildStatus: (shared: ProfileProbeEvidence) => ({
        profile: 'dev' as const,
        configPath: shared.paths.configPath,
        identityPath: shared.paths.identityPath,
        hostId: shared.identity.hostId ?? shared.config.identity?.hostId ?? null,
        statePath: shared.paths.statePath,
        discoveryPath: shared.paths.discoveryPath,
        adapterUrl: shared.adapter.url,
        adapterPort: shared.adapter.port,
        piLogPath: shared.paths.piLogPath,
        relayUrl: shared.relay.baseUrl,
        runtime: shared.runtime,
        source: {
          bridge: {
            mode: 'foreground' as const,
            statePresent: shared.paths.statePresent,
            discoveryPresent: shared.adapter.present,
            discoveryValid: shared.adapter.valid,
            ready: !shared.hostDomainReset.pending && shared.paths.statePresent && shared.adapter.valid,
          },
          pi: {
            mode: 'source-extension' as const,
            command: 'pi --no-extensions -e <source-extension>',
            extensionPath: deps.sourcePiExtensionPath,
            extensionPresent: deps.pathExists(deps.sourcePiExtensionPath),
            discoveryRequired: true,
          },
        },
      }),
      formatStatus: (status: unknown) => formatDevStatus(status as DevStatusSnapshot),
    },
  };
}

function createDevDoctorDependencies(deps: DevProfileDependencies) {
  return {
    context: () => createDevProfileContext(deps),
    pathExists: deps.pathExists,
    runtime: devRuntimeProbe,
    lifecycle: {
      buildChecks: (shared: ProfileProbeEvidence) => ({
        profile: 'dev' as const,
        configComplete: shared.configComplete,
        identity: shared.identity,
        identityReady: shared.identity.status === 'ready',
        relayConfigured: shared.relay.configured,
        agentAdapterConfigPath: shared.adapter.configPath,
        agentAdapterConfigPresent: shared.adapter.present,
        agentAdapterConfigValid: shared.adapter.valid,
        runtimeNameIsNode: shared.runtime.runtimeNameIsNode,
        runtimeVersionSupported: shared.runtime.runtimeVersionSupported,
        runtimeCryptoSelfTestPassed: shared.runtime.runtimeCryptoSelfTestPassed,
        sourceBridge: {
          mode: 'foreground' as const,
          statePresent: shared.paths.statePresent,
          discoveryPresent: shared.adapter.present,
          discoveryValid: shared.adapter.valid,
          ready: !shared.hostDomainReset.pending && shared.paths.statePresent && shared.adapter.valid,
        },
        sourcePi: {
          mode: 'source-extension' as const,
          command: 'pi --no-extensions -e <source-extension>',
          extensionPath: deps.sourcePiExtensionPath,
          extensionPresent: deps.pathExists(deps.sourcePiExtensionPath),
          discoveryRequired: true,
        },
      }),
      healthy: (checks: Record<string, unknown>) => {
        const sourceBridge = checks.sourceBridge as { ready?: boolean };
        const sourcePi = checks.sourcePi as { extensionPresent?: boolean };
        return Boolean(checks.configComplete && checks.identityReady && checks.relayConfigured
          && checks.runtimeNameIsNode && checks.runtimeVersionSupported
          && checks.runtimeCryptoSelfTestPassed && sourceBridge.ready && sourcePi.extensionPresent);
      },
      formatDoctor: formatDoctorChecks,
    },
  };
}

function devRuntimeProbe(): ProfileRuntimeProbe {
  const runtime = inspectCurrentNodeRuntime();
  return {
    nodeFound: Boolean(process.execPath),
    runtimeNameIsNode: runtime.runtimeNameIsNode,
    runtimeVersionSupported: runtime.runtimeVersionSupported,
    runtimeCryptoSelfTestPassed: runNodeCryptoSelfTest(),
  };
}

type DevStatusSnapshot = {
  profile: 'dev';
  configPath: string;
  identityPath: string;
  hostId: string | null;
  statePath: string;
  discoveryPath: string;
  adapterUrl: string | null;
  adapterPort: number | null;
  piLogPath: string;
  relayUrl: string | null;
  runtime: ProfileRuntimeProbe;
  source: {
    bridge: {
      mode: 'foreground';
      statePresent: boolean;
      discoveryPresent: boolean;
      discoveryValid: boolean;
      ready: boolean;
    };
    pi: {
      mode: 'source-extension';
      command: string;
      extensionPath: string;
      extensionPresent: boolean;
      discoveryRequired: boolean;
    };
  };
};

function formatDevStatus(status: DevStatusSnapshot): string {
  const bridge = status.source.bridge.ready
    ? 'ready'
    : status.source.bridge.statePresent
      ? 'degraded'
      : 'offline';
  const piExtension = status.source.pi.extensionPresent ? 'source file · present' : 'source file · missing';
  const fields: Array<{ label: string; value: string; detail?: string }> = [
    { label: 'Profile', value: 'dev' },
    {
      label: 'Bridge',
      value: bridge,
      detail: status.adapterUrl ? `local API · ${status.adapterUrl}` : 'local API · unavailable',
    },
    { label: 'Host', value: status.hostId ?? '(not initialized)' },
    { label: 'Relay', value: status.relayUrl ?? '(not configured)' },
    { label: 'Config', value: status.configPath },
    { label: 'Pi extension', value: piExtension, detail: status.source.pi.extensionPath },
  ];
  const labelWidth = Math.max(...fields.map(({ label }) => label.length));

  return [
    'Ariava',
    '',
    ...fields.flatMap(({ label, value, detail }) => [
      `  ${label.padEnd(labelWidth)}  ${value}`,
      ...(detail ? [`  ${' '.repeat(labelWidth)}  ${detail}`] : []),
    ]),
  ].join('\n');
}


function requireInitializedConfig(deps: DevProfileDependencies): void {
  if (!deps.pathExists(deps.paths.configPath)) {
    throw new Error(`Dev profile is not initialized at ${deps.paths.configPath}; run npm run dev:cli -- init first`);
  }
  const config = resolvePersistedAriavaConfig(deps.paths.configPath);
  assertFixedDevConfig(config, deps.paths);
  if (!config.identity) throw new Error(`Dev identity is not initialized at ${deps.paths.identityPath}; run npm run dev:cli -- init first`);
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
