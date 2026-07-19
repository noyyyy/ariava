import { normalizePairingCode } from '@ariava/protocol';
import { randomBytes } from 'node:crypto';
import { accessSync, constants, existsSync, lstatSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { spawn as spawnChild, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { BridgeDaemon, loadBridgeConfig } from './daemon';
import {
  createRuntimeHostIdentityStore,
  enrollCurrentIdentity,
  HostIdentityError,
  inspectPublicIdentity,
  publicIdentityMetadata,
  resetHostIdentity,
  rotateHostIdentity,
  type HostIdentity,
  type HostIdentityStore,
} from './identity';
import { RelayClient, RelayClientError } from './relay-client';
import { probeHostPlatform } from './host-platform';
import {
  createReadlineOnboardingPrompt,
  promptForOnboardingSelection,
  renderOnboardingProgress,
  renderOnboardingResult,
  restoreOnboardingTerminal,
  type OnboardingPrompt,
  type OnboardingTerminal,
} from './ui/onboarding-renderer';
import {
  AriavaCliError,
  buildInitializedConfig,
  createServiceManager,
  getPiExtensionStatus,
  installPiExtension,
  initializeHost,
  installPiPackage,
  loadInstallMetadata,
  loadInstallMetadataDetailed,
  loadUserConfig,
  mergeInstallMetadata,
  okEnvelope,
  printJson,
  removePiExtension,
  removePiPackage,
  resolveAriavaConfig,
  resolveDevPiSource,
  upgradePiPackage,
  saveInstallMetadata,
  saveUserConfig,
  supportError,
  sanitizeCommandDetail,
  acquireOnboardingLock,
  ephemeralBootstrapLockPath,
  bootstrapStableCli,
  checkStrictOnboardingReadiness,
  pollForDiscoveryAndHealth,
  detectOnboardingEnvironment,
  ensureExactPiPackage,
  resolveAriavaDevProfilePaths,
  runOnboardingOrchestrator,
  validateOnboardingSelection,
  ARIAVA_ONBOARDING_LOCK_PATH,
  SpawnSyncCommandRunner,
  type OnboardingDetection,
  type OnboardingOrchestratorDependencies,
  type OnboardingResult,
  type AriavaAssetSource,
  type AriavaInstallMetadata,
  type AriavaUserConfig,
  type InstallMetadataLoadResult,
  type ResolvedAriavaConfig,
  type AriavaInstallerManager,
  type ServiceManager,
  type ServiceStatus,
} from './host-manager';
import { ARIAVA_CONFIG_ROOT } from './host-manager/paths';
import { buildHostManagerStatus, isConfigComplete } from './host-manager/status';
import { readAgentAdapterConfig } from './agent-adapter/config';
import { inspectCurrentNodeRuntime, probeNodeRuntimePath } from './runtime/node-runtime';
import { runNodeCryptoSelfTest } from './e2e/node-crypto-self-test';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const CLI_VERSION = readPackageVersion();
const RELEASE_PI_VERSION = CLI_VERSION;

function readPackageVersion(): string {
  const manifest = JSON.parse(readFileSync(resolve(PACKAGE_ROOT, 'package.json'), 'utf8')) as { version?: string };
  return manifest.version ?? '0.0.0';
}

export interface PublicCliDependencies {
  createServiceManager(): ServiceManager;
  currentRuntimePath(): string;
  currentAriavaBinPath(): string;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
  loadUserConfig(): AriavaUserConfig;
  saveUserConfig(config: AriavaUserConfig): void;
  resolveAriavaConfig(): ResolvedAriavaConfig;
  loadInstallMetadata(): AriavaInstallMetadata;
  loadInstallMetadataDetailed(): InstallMetadataLoadResult;
  mergeInstallMetadata(patch: Partial<AriavaInstallMetadata>): AriavaInstallMetadata;
  saveInstallMetadata(metadata: AriavaInstallMetadata): void;
  commandExists(name: string): boolean;
  pathExists(path: string): boolean;
  removePath(path: string): void;
  realpath(path: string): string;
  spawn(command: string, args: string[], options?: Parameters<typeof spawnSync>[2]): ReturnType<typeof spawnSync>;
  spawnAsync(command: string, args: string[], options: { signal?: AbortSignal }): Promise<{ status: number | null; stdout: string; stderr: string; error?: Error }>;
  createHostIdentityStore(path: string, platform: NodeJS.Platform | string): HostIdentityStore;
  inspectRuntime(): ReturnType<typeof inspectCurrentNodeRuntime>;
  probeRuntimePath(path: string): ReturnType<typeof inspectCurrentNodeRuntime>;
  cryptoSelfTest(): boolean;
}

export interface PublicCliOnboardingDependencies {
  detect(machineOutput: boolean, interactive: boolean): OnboardingDetection;
  run(input: { target: 'host-ready' | 'adapter-installed'; publicArgs: readonly string[]; resumed: boolean; bootstrapVersion?: string; relayBaseUrl?: string; signal?: AbortSignal }): Promise<OnboardingResult>;
  prompt: OnboardingPrompt;
  terminal: OnboardingTerminal;
}

const defaultDependencies: PublicCliDependencies = {
  createServiceManager,
  currentRuntimePath: () => process.execPath,
  currentAriavaBinPath,
  stdout: process.stdout,
  stderr: process.stderr,
  loadUserConfig,
  saveUserConfig,
  resolveAriavaConfig,
  loadInstallMetadata,
  loadInstallMetadataDetailed,
  mergeInstallMetadata,
  saveInstallMetadata,
  commandExists,
  pathExists: existsSync,
  removePath: (path) => rmSync(path, { recursive: true, force: true }),
  realpath: realpathSync,
  spawn: spawnSync,
  spawnAsync: spawnOnboardingChild,
  createHostIdentityStore: createRuntimeHostIdentityStore,
  inspectRuntime: inspectCurrentNodeRuntime,
  probeRuntimePath: probeNodeRuntimePath,
  cryptoSelfTest: runNodeCryptoSelfTest,
};

export async function runPublicCli(
  argv: string[],
  overrides: Partial<PublicCliDependencies> = {},
  onboardingOverrides: Partial<PublicCliOnboardingDependencies> = {},
): Promise<number> {
  const deps = { ...defaultDependencies, ...overrides };
  const args = [...argv];
  const json = stripFlag(args, '--json');
  const command = args[0] ?? 'help';
  if (command === 'setup') {
    return runSetup(deps, args.slice(1), json, onboardingOverrides);
  }
  try {
    if (command === 'internal') requireProductionRuntime(deps.inspectRuntime());
    if (command === 'internal') {
      await runInternal(args.slice(1), deps);
      return 0;
    }
    switch (command) {
      case '--help':
      case 'help': print(deps, json, okEnvelope('ok', 'Ariava CLI', { commands: commandSummary(), runtime: deps.inspectRuntime() }), formatHelp()); break;
      case 'version': print(deps, json, okEnvelope('ok', CLI_VERSION, { version: CLI_VERSION, runtime: deps.inspectRuntime() }), CLI_VERSION); break;
      default: requireProductionRuntime(deps.inspectRuntime());
    }
    switch (command) {
      case '--help':
      case 'help':
      case 'version': break;
      case 'init': await runInit(deps, json); break;
      case 'config': await runConfig(deps, args.slice(1), json); break;
      case 'status': await runStatus(deps, args.slice(1), json); break;
      case 'doctor': return await runDoctor(deps, json);
      case 'pair': await runPair(deps, args.slice(1), json); break;
      case 'watches': await runWatches(deps, args.slice(1), json); break;
      case 'identity': await runIdentity(deps, args.slice(1), json); break;
      case 'host': await runHost(deps, args.slice(1), json); break;
      case 'service': await runService(deps, args.slice(1), json); break;
      case 'install': await runInstall(deps, args.slice(1), json); break;
      case 'upgrade': await runUpgrade(deps, args.slice(1), json); break;
      case 'remove': await runRemove(deps, args.slice(1), json); break;
      case 'dev': await runDev(deps, args.slice(1), json); break;
      case 'logs': await runLogs(deps, json); break;
      case 'uninstall': await runUninstall(deps, args.slice(1), json); break;
      default: throw new Error(`Unknown command: ${command}`);
    }
    return 0;
  } catch (error) {
    if (error instanceof AriavaCliError) {
      printJson({ ok: false, code: error.code, message: error.message, data: error.data }, deps.stderr);
    } else if (error instanceof HostIdentityError) {
      printJson({ ok: false, code: error.code, message: error.message, data: {} }, deps.stderr);
    } else if (error instanceof RelayClientError) {
      printJson({ ok: false, code: 'ERR_RELAY', message: error.message, data: { status: error.status } }, deps.stderr);
    } else {
      printJson({ ok: false, code: 'ERR_CLI', message: error instanceof Error ? error.message : String(error), data: {} }, deps.stderr);
    }
    return 1;
  }
}

async function runInit(deps: PublicCliDependencies, json: boolean): Promise<void> {
  const manager = deps.createServiceManager();
  requireServiceSupport(manager);
  let store: HostIdentityStore | undefined;
  const initialized = await initializeHost({}, {
    loadUserConfig: deps.loadUserConfig,
    saveUserConfig: deps.saveUserConfig,
    createIdentityStore(identityPath) {
      store = deps.createHostIdentityStore(identityPath, manager.support.platform);
      return store;
    },
    hostName: hostname,
    generateSecret: generateAgentAdapterSecret,
    environment: process.env,
  });
  const resolved = deps.resolveAriavaConfig();
  if (!store) throw new Error('Host identity store was not initialized');
  print(deps, json, okEnvelope('ok', initialized.identityCreated ? 'Ariava identity initialized.' : 'Ariava identity already initialized.', {
    configPath: resolved.configPath, config: redactUserConfig(initialized.config), identity: await inspectPublicIdentity(store), created: initialized.identityCreated,
  }), `${initialized.identityCreated ? 'Initialized' : 'Reused'} Host identity ${initialized.config.identity?.hostId}`);
}

async function runConfig(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  const subcommand = argv[0] ?? 'show';
  const resolved = deps.resolveAriavaConfig();
  const fileConfig = deps.loadUserConfig();

  switch (subcommand) {
    case 'path':
      print(deps, json, okEnvelope('ok', 'Resolved Ariava config path.', { configPath: resolved.configPath }), resolved.configPath);
      return;
    case 'show':
      print(deps, json, okEnvelope('ok', 'Loaded Ariava config.', { config: redactUserConfig(fileConfig), resolved: redactResolvedConfig(resolved) }), JSON.stringify({ config: redactUserConfig(fileConfig), resolved: redactResolvedConfig(resolved) }, null, 2));
      return;
    case 'agent-secret':
      await runAgentSecretConfig(deps, argv.slice(1), json, fileConfig);
      return;
    case 'get': {
      const key = argv[1];
      if (!key) throw new Error('Usage: ariava config get <key>');
      const value = fileConfig[key as keyof typeof fileConfig];
      const displayValue = key === 'agentAdapterSecret' && value ? '<redacted>' : value;
      print(
        deps,
        json,
        okEnvelope('ok', `Read config key ${key}.`, { key, value: displayValue }),
        displayValue == null ? '' : String(displayValue),
      );
      return;
    }
    case 'set': {
      const key = argv[1];
      const value = argv[2];
      if (!key || value == null) throw new Error('Usage: ariava config set <key> <value>');
      if (IDENTITY_MANAGED_CONFIG_KEYS.has(key)) throw new AriavaCliError('ERR_IDENTITY_MANAGED_CONFIG', `${key} is managed by the identity subsystem and cannot be set manually.`);
      const next = { ...fileConfig, [key]: parseConfigValue(value) };
      deps.saveUserConfig(next);
      print(deps, json, okEnvelope('ok', `Updated config key ${key}.`, { key, value: key === 'agentAdapterSecret' ? '<redacted>' : next[key as keyof typeof next] }), `Updated ${key}`);
      return;
    }
    default:
      throw new Error(`Unknown config command: ${subcommand}`);
  }
}

async function runStatus(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  if (argv[0] === 'pi') {
    const piStatus = getPiExtensionStatus(RELEASE_PI_VERSION);
    print(deps, json, okEnvelope('ok', 'pi extension status.', piStatus), formatPiStatus(piStatus));
    return;
  }

  const manager = deps.createServiceManager();
  const resolved = deps.resolveAriavaConfig();
  const loadedBridgeConfig = loadBridgeConfig();
  const bridgeConfig = { ...loadedBridgeConfig,
    hostId: resolved.identity?.hostId ?? loadedBridgeConfig.hostId,
    hostPlatform: manager.support.platform === 'linux' ? 'linux' as const : 'macos' as const,
  };
  const installMetadata = deps.loadInstallMetadata();
  const serviceStatus = currentServiceStatus(deps, manager, installMetadata);
  const piStatus = getPiExtensionStatus(RELEASE_PI_VERSION);
  const identityInspection = manager.support.platform === 'darwin' || manager.support.platform === 'linux'
    ? await inspectPublicIdentity(deps.createHostIdentityStore(resolved.identityPath, manager.support.platform))
    : unsupportedIdentityInspection(resolved.identityPath);
  const status = buildHostManagerStatus({
    config: resolved, bridgeConfig, installMetadata, serviceStatus, piStatus, cliVersion: CLI_VERSION, identityInspection,
  });
  print(deps, json, okEnvelope('ok', 'Ariava host status.', status), formatStatus(status));
}

async function runDoctor(deps: PublicCliDependencies, json: boolean): Promise<number> {
  const manager = deps.createServiceManager();
  const resolved = deps.resolveAriavaConfig();
  const metadataResult = deps.loadInstallMetadataDetailed();
  const installMetadata = metadataResult.metadata;
  const serviceStatus = currentServiceStatus(deps, manager, installMetadata);
  const piStatus = getPiExtensionStatus(RELEASE_PI_VERSION);
  const identity = manager.support.platform === 'darwin' || manager.support.platform === 'linux'
    ? await inspectPublicIdentity(deps.createHostIdentityStore(resolved.identityPath, manager.support.platform))
    : unsupportedIdentityInspection(resolved.identityPath);
  const checks = {
    platform: manager.support.platform,
    isWsl: manager.support.isWsl,
    serviceBackend: manager.backend,
    serviceSupported: manager.support.supported,
    serviceSupportReason: manager.support.reason,
    ...serviceSupportInstructions(manager),
    nodeFound: Boolean(deps.currentRuntimePath()),
    runtimeNameIsNode: deps.inspectRuntime().runtimeNameIsNode,
    runtimeVersionSupported: deps.inspectRuntime().runtimeVersionSupported,
    runtimePathMatchesCurrent: Boolean(serviceStatus.runtimePathMatchesCurrent ?? true),
    serviceRuntimeNameIsNode: serviceStatus.runtimeNameIsNode ?? null,
    serviceRuntimeVersionSupported: serviceStatus.runtimeVersionSupported ?? null,
    runtimeCryptoSelfTestPassed: deps.cryptoSelfTest(),
    piFound: deps.commandExists('pi'),
    configComplete: isConfigComplete(resolved),
    serviceInstalled: serviceStatus.installed,
    serviceEnabled: serviceStatus.enabled,
    serviceLoaded: serviceStatus.loaded,
    serviceRunning: serviceStatus.processRunning,
    servicePathCurrent: Boolean(serviceStatus.runtimePathMatchesCurrent ?? true) && Boolean(serviceStatus.ariavaBinPathMatchesCurrent ?? true),
    serviceMetadataValid: metadataResult.diagnostics.serviceMetadataValid,
    installerMetadataValid: metadataResult.diagnostics.installerMetadataValid !== false,
    documentMetadataValid: metadataResult.diagnostics.documentMetadataValid !== false,
    logsAvailable: manager.logsAvailable(),
    statePathParentExists: deps.pathExists(dirname(resolved.statePath)),
    relayConfigured: Boolean(resolved.relayBaseUrl),
    identity,
    agentAdapterConfigPath: resolved.agentAdapterConfigPath,
    agentAdapterConfigPresent: deps.pathExists(resolved.agentAdapterConfigPath),
    piExtensionManaged: piStatus.managed,
    piExtensionInstalled: piStatus.installed,
    piExtensionNeedsUpgrade: Boolean(piStatus.needsUpgrade),
    environmentOverrides: resolved.environmentOverrides,
    bridgeSource: installMetadata.bridgeSource ?? { kind: 'release-bundle' },
    piSource: installMetadata.piSource,
  };
  const identityReady = identity.status === 'ready';
  Object.assign(checks, {
    identityReady,
    identityWarning: identity.status === 'rotation-pending' ? 'Host key rotation is pending; recover it before normal operation.' : undefined,
  });
  const healthy = manager.support.supported && checks.nodeFound && checks.runtimeNameIsNode
    && checks.runtimeVersionSupported && checks.runtimePathMatchesCurrent
    && checks.serviceRuntimeNameIsNode !== false && checks.serviceRuntimeVersionSupported !== false
    && checks.runtimeCryptoSelfTestPassed && checks.configComplete && checks.serviceMetadataValid
    && checks.installerMetadataValid && checks.documentMetadataValid && identityReady;
  const envelope = {
    ok: healthy,
    code: healthy ? 'ok' : 'ERR_DOCTOR',
    message: healthy ? 'Ariava doctor completed.' : 'Ariava doctor found issues.',
    data: checks,
  };
  print(deps, json, envelope, formatDoctor(checks));
  return healthy ? 0 : 1;
}

async function runPair(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  const pairingCode = argv[0];
  if (!pairingCode) throw new Error('Usage: ariava pair <PAIRING_CODE>');
  const normalizedPairingCode = normalizePairingCode(pairingCode);
  const context = await loadIdentityClient(deps);
  await ensureHostEnrollment(context);
  const result = await context.client.pairWatch(normalizedPairingCode);
  print(deps, json, okEnvelope('ok', 'Watch paired successfully.', result),
    `Paired watch ${result.watchDevice.watchDeviceId} with host ${result.host.hostName} (${result.host.hostId})`);
}

async function runWatches(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  const action = argv[0] ?? 'list';
  const context = await loadIdentityClient(deps);
  await ensureHostEnrollment(context);
  const { client } = context;
  if (action === 'list') {
    const result = await client.listWatches();
    print(deps, json, okEnvelope('ok', 'Linked watches.', result), JSON.stringify(result.watches, null, 2));
    return;
  }
  if (action === 'remove') {
    const watchDeviceId = argv[1];
    if (!watchDeviceId) throw new Error('Usage: ariava watches remove <WATCH_DEVICE_ID>');
    await client.removeWatch(watchDeviceId);
    print(deps, json, okEnvelope('ok', 'Watch link removed.', { watchDeviceId }), `Removed watch ${watchDeviceId}`);
    return;
  }
  throw new Error('Usage: ariava watches list | ariava watches remove <WATCH_DEVICE_ID>');
}

async function runIdentity(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  if ((argv[0] ?? 'status') !== 'status') throw new Error('Usage: ariava identity status');
  const resolved = deps.resolveAriavaConfig();
  const platform = deps.createServiceManager().support.platform;
  const inspection = await inspectPublicIdentity(deps.createHostIdentityStore(resolved.identityPath, platform));
  print(deps, json, okEnvelope('ok', 'Host identity status.', inspection), JSON.stringify(inspection, null, 2));
}

async function runHost(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  const action = argv[0];
  const resolved = deps.resolveAriavaConfig();
  const platform = deps.createServiceManager().support.platform;
  const store = deps.createHostIdentityStore(resolved.identityPath, platform);
  if (action === 'rotate-key') {
    const result = await rotateHostIdentity(store, resolved.relayBaseUrl);
    const identity = await store.load();
    if (!identity) throw new HostIdentityError('ERR_IDENTITY_MISSING', 'Rotated identity could not be loaded');
    // saveUserConfig uses the secure atomic-write boundary; never expose partially written public metadata.
    deps.saveUserConfig({ ...deps.loadUserConfig(), identity: publicIdentityMetadata(identity) });
    print(deps, json, okEnvelope('ok', 'Host key rotated.', result), `Rotated Host key to ${result.newKeyId}`);
    return;
  }
  if (action === 'reset') {
    if (!argv.includes('--confirm')) throw new AriavaCliError('ERR_CONFIRMATION_REQUIRED', 'Usage: ariava host reset --confirm');
    const result = await resetHostIdentity(store, resolved.relayBaseUrl);
    deps.saveUserConfig({ ...buildInitializedConfig(deps.loadUserConfig()), identity: publicIdentityMetadata(result.identity) });
    await enrollCurrentIdentity(resolved.relayBaseUrl, result.identity, hostMetadataContext(deps));
    print(deps, json, okEnvelope('ok', 'Host identity reset.', {
      hostId: result.identity.hostId, keyId: result.identity.keyId, revokedOldIdentity: result.revokedOldIdentity, links: [],
      ...(result.warning ? { warning: result.warning } : {}),
    }), `Reset Host identity to ${result.identity.hostId}; links: 0${result.warning ? `; warning: ${result.warning}` : ''}`);
    return;
  }
  throw new Error('Usage: ariava host rotate-key | ariava host reset --confirm');
}

interface IdentityClientContext {
  client: RelayClient;
  identity: HostIdentity;
  metadata: ReturnType<typeof hostMetadataContext>;
}

async function loadIdentityClient(deps: PublicCliDependencies): Promise<IdentityClientContext> {
  const resolved = deps.resolveAriavaConfig();
  const platform = deps.createServiceManager().support.platform;
  const identity = await deps.createHostIdentityStore(resolved.identityPath, platform).load();
  if (!identity) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not initialized; run `ariava init`.');
  return {
    client: new RelayClient({ baseUrl: resolved.relayBaseUrl, signer: identity.signer }),
    identity,
    metadata: hostMetadataContext(deps),
  };
}

async function ensureHostEnrollment(context: IdentityClientContext): Promise<void> {
  await context.client.enrollHost({
    hostId: context.identity.hostId,
    keyId: context.identity.keyId,
    algorithm: context.identity.algorithm,
    publicKey: context.identity.publicKey,
    ...context.metadata,
  });
}

function hostMetadataContext(deps: PublicCliDependencies) {
  const resolved = deps.resolveAriavaConfig();
  return {
    hostName: resolved.hostName,
    platform: probeHostPlatform(deps.createServiceManager().support.platform),
    bridgeVersion: CLI_VERSION,
  };
}

async function runService(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  const subcommand = argv[0] ?? 'status';
  const manager = deps.createServiceManager();
  const installMetadata = deps.loadInstallMetadata();
  const service = installMetadata.service;

  switch (subcommand) {
    case 'install':
    case 'reinstall': {
      requireServiceSupport(manager);
      const resolved = deps.resolveAriavaConfig();
      const record = manager.install(serviceInstallInput(deps, resolved));
      deps.mergeInstallMetadata({
        service: record, identityPath: resolved.identityPath,
        bridgeSource: installMetadata.bridgeSource ?? { kind: 'release-bundle', updatedAt: record.installedAt },
        ...installerPatch(deps, installMetadata),
      });
      print(deps, json, okEnvelope('ok', `Ariava service ${subcommand}ed.`, record), `Installed ${record.backend} service at ${record.definitionPath}`);
      return;
    }
    case 'uninstall':
      requireServiceSupport(manager);
      if (service?.backend === manager.backend) {
        manager.uninstall(service);
        deps.mergeInstallMetadata({ service: undefined });
      } else if (!service) {
        manager.uninstall();
      }
      print(deps, json, okEnvelope('ok', 'Ariava service uninstalled.', {}), service && service.backend !== manager.backend ? 'Current service backend is not installed. Foreign service metadata retained.' : 'Service uninstalled.');
      return;
    case 'status': {
      const status = currentServiceStatus(deps, manager, installMetadata);
      const resolved = deps.resolveAriavaConfig();
      const data = { ...status, relayBaseUrl: loadBridgeConfig().relayBaseUrl, logDir: resolved.logDir };
      print(deps, json, okEnvelope('ok', 'Ariava service status.', data), formatServiceStatus(data));
      return;
    }
    case 'start':
    case 'restart': {
      requireServiceSupport(manager);
      if (!service || service.backend !== manager.backend || !currentServiceStatus(deps, manager, installMetadata).installed) {
        throw new AriavaCliError('ERR_SERVICE_NOT_INSTALLED', `Ariava service is not installed. Run \`ariava service install\` first.`, { advice: 'ariava service install' });
      }
      manager[subcommand](service);
      print(deps, json, okEnvelope('ok', `Ariava service ${subcommand}ed.`, {}), `Service ${subcommand}ed.`);
      return;
    }
    case 'stop':
      requireServiceSupport(manager);
      if (service?.backend === manager.backend && currentServiceStatus(deps, manager, installMetadata).loaded) {
        manager.stop(service);
      }
      print(deps, json, okEnvelope('ok', 'Ariava service stopped.', {}), 'Service stopped.');
      return;
    default:
      throw new Error(`Unknown service command: ${subcommand}`);
  }
}

async function runInstall(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  if (argv[0] !== 'pi') throw new Error('Usage: ariava install pi');
  const record = installPiPackage(RELEASE_PI_VERSION);
  mergeInstallMetadata({ piExtension: record, piSource: record.source });
  print(deps, json, okEnvelope('ok', 'Installed Ariava pi package.', record), `Installed ${record.source.package} through pi at ${record.managedPath}. Reload pi or run /reload.`);
}

async function runUpgrade(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  if (argv[0] === 'pi') {
    const record = upgradePiExtension();
    print(deps, json, okEnvelope('ok', 'Upgraded Ariava pi package.', record), `Upgraded ${record.source.package} through pi at ${record.managedPath}. Reload pi or run /reload.`);
    return;
  }

  const installMetadataBeforeUpgrade = deps.loadInstallMetadata();
  const selfUpgrade = process.env.ARIAVA_UPGRADE_SELF_DONE === '1'
    ? { skipped: true, reason: 'already-upgraded' }
    : runSelfUpgradeAndReenter(deps, installMetadataBeforeUpgrade, json);
  if (!selfUpgrade.skipped) return;

  const configResult = reconcileUserConfig(deps);
  const manager = deps.createServiceManager();
  const serviceResult = reconcileServiceInstall(deps, manager, serviceRestartSkipped());
  const piRecord = upgradePiExtension();
  const resolved = deps.resolveAriavaConfig();
  const installMetadata = deps.loadInstallMetadata();
  const serviceStatus = currentServiceStatus(deps, manager, installMetadata);
  const piStatus = getPiExtensionStatus(RELEASE_PI_VERSION);

  const data = {
    cliVersion: CLI_VERSION,
    selfUpgrade,
    config: { updated: configResult.updated, configPath: resolved.configPath, config: redactUserConfig(configResult.config) },
    service: serviceResult,
    piExtension: { updated: true, record: piRecord, status: piStatus },
    doctor: {
      configComplete: isConfigComplete(resolved),
      serviceInstalled: serviceStatus.installed,
      serviceLoaded: serviceStatus.loaded,
      serviceRunning: serviceStatus.processRunning,
      piExtensionInstalled: piStatus.installed,
      piExtensionManaged: piStatus.managed,
    },
  };
  print(deps, json, okEnvelope('ok', 'Ariava upgraded.', data), formatUpgradeResult(data));
}

function reconcileUserConfig(deps: PublicCliDependencies): { updated: boolean; config: AriavaUserConfig } {
  const existing = deps.loadUserConfig();
  const next = buildInitializedConfig(existing);
  const updated = JSON.stringify(existing) !== JSON.stringify(next);
  if (updated) deps.saveUserConfig(next);
  return { updated, config: next };
}

function upgradePiExtension() {
  const record = upgradePiPackage(RELEASE_PI_VERSION);
  mergeInstallMetadata({ piExtension: record, piSource: record.source });
  return record;
}

function reconcileServiceInstall(
  deps: PublicCliDependencies,
  manager: ServiceManager,
  skipRestart: boolean,
 ): { updated: boolean; restarted: boolean; installed: boolean; reason?: string; detail?: string } {
  const installMetadata = deps.loadInstallMetadata();
  if (installMetadata.service?.backend !== manager.backend) {
    return { updated: false, restarted: false, installed: false, reason: installMetadata.service ? 'backend-mismatch' : 'not-installed' };
  }
  const status = currentServiceStatus(deps, manager, installMetadata);
  if (!status.installed) return { updated: false, restarted: false, installed: false, reason: 'not-installed' };

  const resolved = deps.resolveAriavaConfig();
  const record = manager.install(serviceInstallInput(deps, resolved));
  deps.mergeInstallMetadata({
    service: record, identityPath: resolved.identityPath,
    bridgeSource: installMetadata.bridgeSource ?? { kind: 'release-bundle', updatedAt: record.installedAt },
    ...installerPatch(deps, installMetadata),
  });
  if (skipRestart) {
    return { updated: true, restarted: false, installed: true, reason: 'service-restart-skipped' };
  }
  try {
    manager.restart(record);
    return { updated: true, restarted: true, installed: true };
  } catch (error) {
    const raw = error instanceof Error ? error.message : String(error);
    return {
      updated: true,
      restarted: false,
      installed: true,
      reason: 'restart-failed',
      detail: sanitizeCommandDetail(raw, [record.runtimePath, record.ariavaBinPath]),
    };
  }
}

function serviceRestartSkipped(): boolean {
  const neutral = process.env.ARIAVA_UPGRADE_SKIP_SERVICE_RESTART;
  if (neutral !== undefined) return neutral === '1';
  return process.env.ARIAVA_UPGRADE_SKIP_LAUNCHCTL === '1';
}

function runSelfUpgradeAndReenter(deps: PublicCliDependencies, metadata: AriavaInstallMetadata, json: boolean): { skipped: boolean; reason?: string } {
  const manager = detectPackageManager(deps, metadata);
  if (!manager) throw new Error('Could not determine how Ariava was installed. Please upgrade manually, then run ariava upgrade again.');
  const result = deps.spawn(manager.command, manager.args, { stdio: json ? 'pipe' : 'inherit', encoding: 'utf8' });
  if ((result.status ?? 1) !== 0) {
    throw new Error(`Failed to upgrade Ariava CLI with ${manager.command} ${manager.args.join(' ')}${result.stderr ? `: ${String(result.stderr).trim()}` : ''}`);
  }
  const reentry = deps.spawn(deps.realpath(deps.currentAriavaBinPath()), ['upgrade', ...(json ? ['--json'] : [])], {
    stdio: 'inherit', env: { ...process.env, ARIAVA_UPGRADE_SELF_DONE: '1' },
  });
  process.exit(reentry.status ?? 1);
}

type PackageManagerCommand = { manager: AriavaInstallerManager; command: string; args: string[] };

function packageManagerCommand(manager: AriavaInstallerManager): PackageManagerCommand {
  if (manager === 'npm') return { manager, command: 'npm', args: ['install', '-g', 'ariava@latest'] };
  if (manager === 'pnpm') return { manager, command: 'pnpm', args: ['add', '-g', 'ariava@latest'] };
  if (manager === 'bun') return { manager, command: 'bun', args: ['add', '-g', 'ariava@latest'] };
  return { manager, command: 'brew', args: ['upgrade', 'ariava'] };
}

export function detectPackageManager(deps: Pick<PublicCliDependencies, 'currentAriavaBinPath' | 'realpath'>, metadata: AriavaInstallMetadata): PackageManagerCommand | undefined {
  const forced = process.env.ARIAVA_UPGRADE_PACKAGE_MANAGER;
  if (forced === 'npm' || forced === 'pnpm' || forced === 'bun') return packageManagerCommand(forced);
  if (forced === 'brew') return packageManagerCommand('homebrew');
  if (metadata.installer) {
    if (!isAbsolute(metadata.installer.ariavaBinRealPath)
      || resolve(metadata.installer.ariavaBinRealPath) !== metadata.installer.ariavaBinRealPath) return undefined;
    return packageManagerCommand(metadata.installer.manager);
  }
  let realPath: string;
  try { realPath = deps.realpath(deps.currentAriavaBinPath()); } catch { return undefined; }
  if (!isAbsolute(realPath) || resolve(realPath) !== realPath) return undefined;
  try {
    const stat = lstatSync(realPath);
    if (!stat.isFile() || stat.isSymbolicLink()) return undefined;
  } catch {
    // Tests and already-moved package paths can provide a canonical realpath that no longer exists.
  }
  if (/\/(?:Cellar|Homebrew)\//.test(realPath)) return packageManagerCommand('homebrew');
  if (/\/\.bun\/install\/global\//.test(realPath)) return packageManagerCommand('bun');
  if (/\/\.pnpm\//.test(realPath) || /\/pnpm\/global\//.test(realPath) || /\/\.local\/share\/pnpm\//.test(realPath)) return packageManagerCommand('pnpm');
  if (/\/node_modules\/ariava\/apps\/bridge\/dist\/public-cli\.js$/.test(realPath)) return packageManagerCommand('npm');
  return undefined;
}

async function runRemove(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  if (argv[0] !== 'pi') throw new Error('Usage: ariava remove pi');
  removePiPackage();
  const installMetadata = loadInstallMetadata();
  mergeInstallMetadata({ ...installMetadata, piExtension: undefined, piSource: undefined });
  print(deps, json, okEnvelope('ok', 'Removed Ariava pi package.', {}), 'Removed Ariava pi package through pi.');
}

async function runDev(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  const command = argv[0];
  const target = argv[1];
  const from = readOption(argv, '--from');
  const installMetadata = loadInstallMetadata();

  if (command === 'install' && target === 'pi') {
    const sourcePath = resolveDevPiSource(from);
    const sourceKind: AriavaAssetSource['kind'] = from ? 'explicit-path' : 'dev-repo';
    const record = installPiExtension({ sourcePath, sourceKind, version: RELEASE_PI_VERSION, force: true });
    mergeInstallMetadata({ piExtension: record, piSource: record.source });
    print(deps, json, okEnvelope('ok', 'Installed dev pi extension.', record), `Installed dev pi extension from ${sourcePath}`);
    return;
  }

  if (command === 'upgrade' && target === 'pi') {
    const sourcePath = resolveDevPiSource(from);
    const sourceKind: AriavaAssetSource['kind'] = from ? 'explicit-path' : 'dev-repo';
    const record = installPiExtension({ sourcePath, sourceKind, version: RELEASE_PI_VERSION, force: true });
    mergeInstallMetadata({ piExtension: record, piSource: record.source });
    print(deps, json, okEnvelope('ok', 'Upgraded dev pi extension.', record), `Upgraded dev pi extension from ${sourcePath}`);
    return;
  }

  if (command === 'bridge' && target === 'use') {
    const sourcePath = from ? resolve(from) : resolve(process.cwd(), 'apps/bridge/dist/cli.js');
    if (!existsSync(sourcePath)) {
      throw new Error(`Dev bridge entry not found: ${sourcePath}. Run bun run build:bridge first or pass --from.`);
    }
    const source = { kind: from ? 'explicit-path' : 'dev-repo', path: sourcePath, updatedAt: new Date().toISOString() } as AriavaAssetSource;
    mergeInstallMetadata({ bridgeSource: source });
    print(deps, json, okEnvelope('ok', 'Switched bridge source.', source), `Bridge source set to ${sourcePath}`);
    return;
  }

  if (command === 'status') {
    const data = {
      bridgeSource: installMetadata.bridgeSource ?? { kind: 'release-bundle' },
      piSource: installMetadata.piSource ?? { kind: 'release-bundle' },
    };
    print(deps, json, okEnvelope('ok', 'Ariava dev source status.', data), JSON.stringify(data, null, 2));
    return;
  }

  throw new Error('Usage: ariava dev install pi [--from <path>] | ariava dev upgrade pi [--from <path>] | ariava dev bridge use [--from <path>] | ariava dev status');
}

async function runLogs(deps: PublicCliDependencies, json: boolean): Promise<void> {
  const manager = deps.createServiceManager();
  requireServiceSupport(manager);
  const record = deps.loadInstallMetadata().service;
  const logs = manager.logs(record?.backend === manager.backend ? record : undefined);
  const human = logs.source === 'files'
    ? [`Stdout: ${logs.stdoutPath}`, `Stderr: ${logs.stderrPath}`, logs.text].join('\n')
    : logs.text;
  print(deps, json, okEnvelope('ok', 'Ariava service logs.', logs), human);
}

async function runUninstall(deps: PublicCliDependencies, argv: string[], json: boolean): Promise<void> {
  const purge = argv.includes('--purge');
  const removePi = argv.includes('--remove-pi') || purge;
  const installMetadata = deps.loadInstallMetadata();
  const manager = deps.createServiceManager();
  const currentService = installMetadata.service?.backend === manager.backend ? installMetadata.service : undefined;
  const backendMismatch = Boolean(installMetadata.service && !currentService);

  if (!backendMismatch) {
    requireServiceSupport(manager);
    manager.uninstall(currentService);
  }

  if (removePi) removePiPackage();

  if (purge) {
    deps.removePath(ARIAVA_CONFIG_ROOT);
  } else {
    deps.saveInstallMetadata({
      ...installMetadata,
      service: currentService ? undefined : installMetadata.service,
      ...(removePi ? { piExtension: undefined, piSource: undefined } : {}),
    });
  }

  const data = { purge, removedPi: removePi, ...(backendMismatch ? { backendMismatch: true } : {}) };
  print(deps, json, okEnvelope('ok', 'Ariava uninstall completed.', data), purge ? 'Ariava config, service, and managed assets removed.' : backendMismatch ? 'Current service backend is not installed. Foreign service metadata retained.' : 'Ariava service removed. Config retained.');
}

async function runInternal(argv: string[], deps: Pick<PublicCliDependencies, 'stdout'>): Promise<void> {
  const subcommand = argv[0];
  if (subcommand === 'render-onboarding-success') {
    if (argv.length !== 5 || argv[1] !== '--target' || argv[3] !== '--columns') throw new Error('internal render-onboarding-success accepts only --target and --columns');
    const target = argv[2];
    if (target !== 'host-ready' && target !== 'adapter-installed') throw new Error('internal render-onboarding-success requires --target <host-ready|adapter-installed>');
    const columns = Number.parseInt(argv[4] ?? '', 10);
    if (!Number.isSafeInteger(columns) || String(columns) !== argv[4] || columns < 1) throw new Error('internal render-onboarding-success requires --columns <positive-integer>');
    const result: OnboardingResult = {
      target,
      readiness: target === 'host-ready' ? 'host-ready' : 'reload-pending',
      steps: [{ id: 'completion', status: 'ready' }],
      nextActions: target === 'host-ready' ? [] : [{ id: 'reload-pi', command: '/reload' }],
    };
    deps.stdout.write(`${renderOnboardingResult(result, {
      terminal: { stdout: deps.stdout, stderr: deps.stdout, interactive: true, color: false, columns },
    })}\n`);
    return;
  }
  if (subcommand !== 'bridge-daemon') throw new Error(`Unknown internal command: ${subcommand}`);
  const configPath = readOption(argv, '--config');
  if (!configPath || !configPath.startsWith('/')) throw new Error('internal bridge-daemon requires --config <absolute-config-path>');
  const daemon = new BridgeDaemon(loadBridgeConfig(configPath));
  await daemon.start();
  process.on('SIGINT', () => {
    daemon.stop();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    daemon.stop();
    process.exit(0);
  });
  await daemon.runForever();
}

function serviceInstallInput(deps: PublicCliDependencies, resolved: ResolvedAriavaConfig) {
  if (!resolved.identity) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not initialized; run `ariava init`');
  const runtimePath = deps.realpath(deps.currentRuntimePath());
  const runtime = deps.probeRuntimePath(runtimePath);
  requireProductionRuntime(runtime);
  return {
    runtimePath,
    runtimeName: 'node' as const,
    runtimeVersion: runtime.runtimeVersion,
    ariavaBinPath: deps.realpath(deps.currentAriavaBinPath()),
    configPath: resolved.configPath,
    identityReference: structuredClone(resolved.identity.privateKeyStorage),
  };
}

function installerPatch(deps: PublicCliDependencies, metadata: AriavaInstallMetadata) {
  const detected = detectPackageManager(deps, metadata);
  if (!detected) return {};
  return { installer: {
    manager: detected.manager,
    ariavaBinRealPath: deps.realpath(deps.currentAriavaBinPath()),
    recordedAt: new Date().toISOString(),
  } };
}

function requireProductionRuntime(runtime: ReturnType<typeof inspectCurrentNodeRuntime>): void {
  if (!runtime.runtimeNameIsNode || !runtime.runtimeVersionSupported) {
    throw new AriavaCliError(
      'ERR_NODE_RUNTIME_UNSUPPORTED',
      `Ariava requires Node.js 22 or newer for its production Bridge runtime. Current runtime: ${runtime.runtimeName} ${runtime.runtimeVersion}`,
      { runtimeName: runtime.runtimeName, runtimeVersion: runtime.runtimeVersion },
    );
  }
}

async function runSetup(
  deps: PublicCliDependencies,
  argv: string[],
  json: boolean,
  overrides: Partial<PublicCliOnboardingDependencies>,
): Promise<number> {
  const terminal = overrides.terminal ?? onboardingTerminal(deps, json);
  let prompt = overrides.prompt;
  const cancellation = new AbortController();
  const signalHandler = () => {
    cancellation.abort();
    prompt?.close?.();
    restoreOnboardingTerminal(terminal);
  };
  process.once('SIGINT', signalHandler);
  process.once('SIGTERM', signalHandler);
  try {
    const options = parseOnboardingArguments(argv);
    const detectEnvironment = overrides.detect ?? ((machineOutput: boolean, interactive: boolean) => createOnboardingDetection(deps, machineOutput, interactive));
    const detection = detectEnvironment(json || !terminal.interactive, terminal.interactive);
    let selection;
    if (options.extensions || options.noExtensions || !terminal.interactive || options.yes) {
      selection = validateOnboardingSelection({
        extensions: options.extensions, noExtensions: options.noExtensions, yes: options.yes, interactive: terminal.interactive,
      });
    } else {
      prompt ??= createReadlineOnboardingPrompt(process.stdin, deps.stdout);
      selection = await promptForOnboardingSelection(detection, prompt, options.yes);
    }
    if (selection.extensions.includes('pi') && !detection.pi.present) {
      throw new AriavaCliError('ERR_AGENT_RUNTIME_NOT_FOUND', 'Pi is not installed. Install Pi, then rerun `ariava setup --extension pi`.', {
        step: 'adapter-detect', retryable: true, remediation: { command: 'ariava setup --extension pi' },
      });
    }
    renderOnboardingProgress('Setting up Ariava…', terminal);
    // Interactive selections are not present on argv. Persist them into publicArgs so
    // stable-CLI re-entry (which forces --json / non-interactive) keeps the same target.
    const publicArgs = selectionPublicArgs(selection, options.publicArgs);
    const runOnboarding = overrides.run ?? ((input: Parameters<PublicCliOnboardingDependencies['run']>[0]) => runDefaultOnboarding(deps, input));
    const result = await runOnboarding({
      target: selection.target, publicArgs, resumed: options.resumed,
      bootstrapVersion: options.bootstrapVersion, relayBaseUrl: options.relayBaseUrl, signal: cancellation.signal,
    });
    restoreOnboardingTerminal(terminal);
    const failed = result.readiness === 'failed';
    if (json) {
      printJson({
        ok: !failed,
        code: failed ? onboardingFailureCode(result) : 'ok',
        message: failed ? 'Ariava onboarding is incomplete.' : 'Ariava onboarding completed.',
        data: result,
      }, deps.stdout);
    } else {
      deps.stdout.write(`${renderOnboardingResult(result, { terminal })}\n`);
    }
    return failed ? 1 : 0;
  } catch (error) {
    const normalized = normalizeOnboardingError(error);
    if (json) printJson(normalized, deps.stderr);
    else {
      deps.stderr.write(`Onboarding stopped: ${normalized.message}\n`);
      const remediation = normalized.data.remediation as { message?: string; command?: string } | undefined;
      if (remediation?.message) deps.stderr.write(`${remediation.message}\n`);
      if (remediation?.command) deps.stderr.write(`Next: ${remediation.command}\n`);
    }
    return 1;
  } finally {
    prompt?.close?.();
    process.off('SIGINT', signalHandler);
    process.off('SIGTERM', signalHandler);
  }
}

interface ParsedOnboardingArguments {
  extensions?: string[];
  noExtensions: boolean;
  resumed: boolean;
  yes: boolean;
  relayBaseUrl?: string;
  bootstrapVersion?: string;
  publicArgs: string[];
}

function parseOnboardingArguments(argv: string[]): ParsedOnboardingArguments {
  const result: ParsedOnboardingArguments = { noExtensions: false, resumed: false, yes: false, publicArgs: [] };
  let bootstrapOnce = false;
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index]!;
    if (value === '--extension' || value === '--relay-base-url' || value === '--bootstrap-version') {
      const option = argv[++index];
      if (!option || option.startsWith('--')) throw new AriavaCliError('ERR_ONBOARDING_NOT_READY', `${value} requires a value.`, { step: 'preflight', retryable: false });
      if (value === '--extension') (result.extensions ??= []).push(option);
      else if (value === '--relay-base-url') result.relayBaseUrl = validateRelayUrl(option);
      else result.bootstrapVersion = option;
      if (value !== '--bootstrap-version') result.publicArgs.push(value, option);
      continue;
    }
    if (value === '--no-extensions') { result.noExtensions = true; result.publicArgs.push(value); continue; }
    if (value === '--resume') { result.resumed = true; continue; }
    if (value === '--yes') { result.yes = true; result.publicArgs.push(value); continue; }
    if (value === '--bootstrap-once') { bootstrapOnce = true; continue; }
    throw new AriavaCliError('ERR_ONBOARDING_NOT_READY', `Unknown onboarding option: ${value}`, { step: 'preflight', retryable: false });
  }
  const internalPresent = result.bootstrapVersion !== undefined || bootstrapOnce;
  if (internalPresent && (!result.resumed || !bootstrapOnce || result.bootstrapVersion !== CLI_VERSION)) {
    throw new AriavaCliError('ERR_STABLE_CLI_PATH', 'Internal onboarding re-entry markers are incomplete or mismatched.', { step: 'stable-cli', retryable: false });
  }
  return result;
}

function validateRelayUrl(value: string): string {
  try {
    const url = new URL(value);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('invalid');
    return url.origin;
  } catch {
    throw new AriavaCliError('ERR_RELAY_CONFIG_REQUIRED', 'Relay base URL must be an HTTP(S) origin without credentials, path, query, or fragment.', { step: 'relay-config', retryable: false });
  }
}

function onboardingTerminal(deps: PublicCliDependencies, json: boolean): OnboardingTerminal {
  const stdout = deps.stdout as NodeJS.WritableStream & { isTTY?: boolean; columns?: number };
  const interactive = !json && stdout.isTTY === true && process.stdin.isTTY === true && process.env.CI === undefined && process.env.TERM !== 'dumb';
  return { stdout: deps.stdout, stderr: deps.stderr, columns: stdout.columns, interactive, color: interactive && process.env.NO_COLOR === undefined };
}

function createOnboardingDetection(deps: PublicCliDependencies, machineOutput: boolean, interactive: boolean): OnboardingDetection {
  const runner = new SpawnSyncCommandRunner();
  const manager = deps.createServiceManager();
  const binPath = deps.realpath(deps.currentAriavaBinPath());
  const prefix = resolveNpmPrefix(runner);
  return detectOnboardingEnvironment({
    platform: manager.support.platform as NodeJS.Platform, architecture: process.arch, nodeVersion: process.version, runner,
    detectServiceSupport: () => manager.support, isTty: interactive, machineOutput, configPath: deps.resolveAriavaConfig().configPath,
    devConfigPath: resolveAriavaDevProfilePaths().configPath, pathExists: deps.pathExists, loadConfig: deps.loadUserConfig,
    loadInstallMetadata: deps.loadInstallMetadata, currentCli: {
      executablePath: binPath, packageRoot: PACKAGE_ROOT, packageVersion: CLI_VERSION, npmPrefix: prefix, npmBinPath: prefix ? join(prefix, 'bin') : undefined,
    },
  });
}

function spawnOnboardingChild(command: string, args: string[], options: { signal?: AbortSignal }): Promise<{ status: number | null; stdout: string; stderr: string; error?: Error }> {
  return new Promise((resolve) => {
    const child = spawnChild(command, args, { stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let error: Error | undefined;
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', (cause) => { error = cause; });
    const abort = () => child.kill('SIGTERM');
    if (options.signal?.aborted) abort();
    else options.signal?.addEventListener('abort', abort, { once: true });
    child.once('close', (status) => {
      options.signal?.removeEventListener('abort', abort);
      resolve({ status, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'), ...(error ? { error } : {}) });
    });
  });
}

async function runDefaultOnboarding(deps: PublicCliDependencies, input: Parameters<PublicCliOnboardingDependencies['run']>[0]): Promise<OnboardingResult> {
  const manager = deps.createServiceManager();
  const runner = new SpawnSyncCommandRunner();
  const detectMachineEnvironment = () => createOnboardingDetection(deps, true, false);
  const orchestratorDeps: OnboardingOrchestratorDependencies = {
    detect: detectMachineEnvironment,
    bootstrap: (bootstrapInput) => bootstrapStableCli(bootstrapInput, {
      runner, realpath: deps.realpath, readPackageVersion: readVersionAtRoot, assertPrefixWritable: (path) => accessSync(path, constants.W_OK | constants.X_OK),
      resolveGlobalPrefix: () => resolveNpmPrefix(runner), resolveStableExecutable: (prefix) => {
        const path = join(prefix, 'bin', 'ariava');
        return deps.pathExists(path) ? deps.realpath(path) : undefined;
      }, currentCli: detectMachineEnvironment().currentCli,
    }),
    reenter: async (command, args) => {
      throwIfOnboardingAborted(input.signal);
      const child = await deps.spawnAsync(command, [...args, '--json'], { signal: input.signal });
      const envelope = parseStableChildEnvelope(child.stdout, child.stderr);
      if ((child.status ?? 1) !== 0) {
        if (envelope?.data && isOnboardingResult(envelope.data)) return envelope.data;
        if (envelope && typeof envelope.code === 'string') {
          throw new AriavaCliError(envelope.code as AriavaCliError['code'], typeof envelope.message === 'string' ? envelope.message : 'Stable Ariava CLI re-entry failed.',
            envelope.data && typeof envelope.data === 'object' ? envelope.data as Record<string, unknown> : { step: 'stable-cli', retryable: true });
        }
        throw new AriavaCliError('ERR_STABLE_CLI_PATH', child.error?.message ?? 'Stable Ariava CLI re-entry failed before returning a structured error.', { step: 'stable-cli', retryable: true });
      }
      if (!envelope?.data || !isOnboardingResult(envelope.data)) {
        throw new AriavaCliError('ERR_STABLE_CLI_PATH', 'Stable Ariava CLI re-entry returned malformed output.', { step: 'stable-cli', retryable: true });
      }
      throwIfOnboardingAborted(input.signal);
      return envelope.data;
    },
    acquireBootstrapLock: () => acquireOnboardingLock(ephemeralBootstrapLockPath(CLI_VERSION)),
    acquireLock: () => acquireOnboardingLock(ARIAVA_ONBOARDING_LOCK_PATH),
    loadUserConfig: deps.loadUserConfig, saveUserConfig: deps.saveUserConfig,
    initializeHost: (relayBaseUrl) => initializeOnboardingHost(deps, manager, relayBaseUrl),
    loadHostState: () => loadOnboardingHostState(deps, manager),
    loadInstallMetadata: deps.loadInstallMetadata, saveInstallMetadata: deps.saveInstallMetadata, serviceManager: manager,
    adapterProbe: () => detectMachineEnvironment().pi,
    proveBridgeHealth: async (state) => { await pollForDiscoveryAndHealth({ config: state.config, identity: state.identity, signal: input.signal }); },
    installPi: (version) => ensureExactPiPackage(version),
    checkReadiness: ({ target, stableCli, state, installMetadata, service, pi }) => checkStrictOnboardingReadiness({ ...buildReadinessInput(deps, manager, state, target, stableCli, installMetadata, service, pi), signal: input.signal }, { serviceStatus: () => currentServiceStatus(deps, manager, deps.loadInstallMetadata()) }),
    cancellation: { throwIfCancelled: () => throwIfOnboardingAborted(input.signal) },
  };
  return runOnboardingOrchestrator({ ...input, cliVersion: CLI_VERSION, runtimePath: deps.realpath(deps.currentRuntimePath()) }, orchestratorDeps);
}

async function initializeOnboardingHost(deps: PublicCliDependencies, manager: ServiceManager, relayBaseUrl: string) {
  return initializeHost({ relayBaseUrl }, { loadUserConfig: deps.loadUserConfig, saveUserConfig: deps.saveUserConfig, createIdentityStore: (path) => deps.createHostIdentityStore(path, manager.support.platform), hostName: hostname, generateSecret: generateAgentAdapterSecret, environment: process.env });
}

async function loadOnboardingHostState(deps: PublicCliDependencies, manager: ServiceManager) {
  const config = deps.resolveAriavaConfig();
  const store = deps.createHostIdentityStore(config.identityPath, manager.support.platform);
  const [identityInspection, identity] = await Promise.all([store.inspect(), store.load()]);
  return identity ? { config, identityInspection, identity } : undefined;
}

function buildReadinessInput(
  deps: PublicCliDependencies, manager: ServiceManager, state: NonNullable<Awaited<ReturnType<typeof loadOnboardingHostState>>>, target: 'host-ready' | 'adapter-installed',
  stableCli: { executablePath: string; packageRoot?: string; packageVersion?: string; npmPrefix?: string; npmBinPath?: string },
  installMetadata: AriavaInstallMetadata, service: AriavaInstallMetadata['service'], pi: ReturnType<typeof getPiExtensionStatus>,
) {
  return {
    target, cliVersion: CLI_VERSION, stableCli, installMetadata, config: state.config, identityInspection: state.identityInspection, identity: state.identity,
    serviceRecord: service, expectedRuntimePath: deps.realpath(deps.currentRuntimePath()), expectedAriavaBinPath: stableCli.executablePath,
    hostMetadata: { hostName: state.config.hostName, platform: probeHostPlatform(manager.support.platform), bridgeVersion: CLI_VERSION }, piStatus: pi,
  };
}

function resolveNpmPrefix(runner: SpawnSyncCommandRunner): string | undefined {
  const result = runner.run('npm', ['prefix', '--global']);
  const value = result.status === 0 ? result.stdout.trim() : '';
  return value && isAbsolute(value) ? resolve(value) : undefined;
}

function readVersionAtRoot(root: string): string | undefined {
  try { return (JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: string }).version; } catch { return undefined; }
}

function throwIfOnboardingAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  throw new AriavaCliError('ERR_ONBOARDING_NOT_READY', 'Ariava onboarding was cancelled.', {
    step: 'preflight', retryable: true, remediation: { command: 'ariava setup --resume' },
  });
}

function parseStableChildEnvelope(stdout: unknown, stderr: unknown): Record<string, unknown> | undefined {
  for (const raw of [stdout, stderr]) {
    const text = String(raw ?? '').trim();
    if (!text) continue;
    try {
      const value = JSON.parse(text) as unknown;
      if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
    } catch {
      // Stable children are required to return one JSON envelope; try the other stream.
    }
  }
  return undefined;
}

function isOnboardingResult(value: unknown): value is OnboardingResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const result = value as Partial<OnboardingResult>;
  return (result.target === 'host-ready' || result.target === 'adapter-installed')
    && typeof result.readiness === 'string' && Array.isArray(result.steps) && Array.isArray(result.nextActions);
}

function normalizeOnboardingError(error: unknown): { ok: false; code: string; message: string; data: Record<string, unknown> } {
  if (error instanceof AriavaCliError) return { ok: false, code: error.code, message: error.message, data: error.data };
  if (error instanceof HostIdentityError) return { ok: false, code: error.code, message: error.message, data: { step: 'host-init', retryable: false } };
  return { ok: false, code: 'ERR_ONBOARDING_NOT_READY', message: error instanceof Error ? error.message : String(error), data: { step: 'preflight', retryable: true } };
}

function onboardingFailureCode(result: OnboardingResult): string {
  const failed = result.steps.find((step) => step.status === 'failed');
  if (typeof failed?.detail?.code === 'string') return failed.detail.code;
  const checks = failed?.detail?.checks;
  if (Array.isArray(checks)) {
    for (const check of checks) {
      if (!check || typeof check !== 'object' || Array.isArray(check)) continue;
      const entry = check as { ready?: unknown; code?: unknown };
      if (entry.ready === false && typeof entry.code === 'string') return entry.code;
    }
  }
  return 'ERR_ONBOARDING_NOT_READY';
}

function selectionPublicArgs(selection: { extensions: readonly string[] }, publicArgs: readonly string[]): string[] {
  if (publicArgs.includes('--extension') || publicArgs.includes('--no-extensions')) return [...publicArgs];
  if (selection.extensions.includes('pi')) return ['--extension', 'pi', ...publicArgs];
  return ['--no-extensions', ...publicArgs];
}


function requireServiceSupport(manager: ServiceManager): void {
  if (!manager.support.supported) throw supportError(manager.support);
}

function serviceSupportInstructions(manager: ServiceManager): {
  serviceSupportInstructions?: Record<string, unknown>;
} {
  if (manager.support.supported) return {};
  const error = supportError(manager.support);
  const instructions = error.data.instructions;
  return instructions && typeof instructions === 'object'
    ? { serviceSupportInstructions: instructions as Record<string, unknown> }
    : {};
}

function currentServiceStatus(
  deps: PublicCliDependencies,
  manager: ServiceManager,
  installMetadata: AriavaInstallMetadata,
 ): ServiceStatus {
  return manager.status(
    installMetadata.service,
    deps.realpath(deps.currentRuntimePath()),
    deps.realpath(deps.currentAriavaBinPath()),
  );
}

function stripFlag(argv: string[], flag: string): boolean {
  const index = argv.indexOf(flag);
  if (index === -1) return false;
  argv.splice(index, 1);
  return true;
}

function readOption(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function print(deps: PublicCliDependencies, json: boolean, envelope: unknown, human: string): void {
  if (json) {
    printJson(envelope, deps.stdout);
    return;
  }
  deps.stdout.write(`${human}\n`);
}

function parseConfigValue(value: string): string | number | boolean {
  if (value === 'true') return true;
  if (value === 'false') return false;
  const asNumber = Number(value);
  return Number.isFinite(asNumber) && value.trim() !== '' ? asNumber : value;
}

const IDENTITY_MANAGED_CONFIG_KEYS = new Set([
  'identity', 'identityPath', 'hostId', 'keyId', 'publicKey', 'publicKeyFingerprint', 'privateKeyStorage',
]);

function commandSummary(): string[] {
  return [
    'ariava setup [--extension pi ... | --no-extensions] [--resume] [--json] [--yes] [--relay-base-url <URL>]',
    'ariava version',
    'ariava init',
    'ariava status [pi]',
    'ariava pair <PAIRING_CODE>',
    'ariava watches list',
    'ariava watches remove <WATCH_DEVICE_ID>',
    'ariava identity status',
    'ariava host rotate-key',
    'ariava host reset --confirm',
    'ariava doctor',
    'ariava logs',
    'ariava upgrade [pi]',
    'ariava uninstall [--purge] [--remove-pi]',
    'ariava config path|show|get|set',
    'ariava config agent-secret ensure|rotate',
    'ariava service install|reinstall|status|start|stop|restart|uninstall',
    'ariava install pi',
    'ariava remove pi',
    'ariava dev install pi [--from <path>]',
    'ariava dev upgrade pi [--from <path>]',
    'ariava dev bridge use [--from <path>]',
    'ariava dev status',
  ];
}

function formatHelp(): string {
  return [
    'Ariava — Apple Watch-first collaboration for coding agents',
    '',
    'Usage:',
    '  ariava <command> [options]',
    '',
    'Get started:',
    '  setup [options]                 Set up the Host, Bridge, and selected agent extensions',
    '    --extension pi                 Install an agent extension; repeat for multiple extensions',
    '    --no-extensions                Set up the Host and Bridge without agent extensions',
    '    --resume                      Resume an interrupted setup',
    '    --relay-base-url <URL>        Use a specific Relay URL',
    '    --yes                         Accept setup prompts where possible',
    '  init                            Initialize Host configuration and identity manually',
    '',
    'Status and diagnostics:',
    '  status                          Show Host, service, identity, and pi status',
    '  status pi                       Show pi extension status',
    '  doctor                          Run configuration and installation checks',
    '  logs                            Show Bridge service logs',
    '',
    'Watch pairing:',
    '  pair <PAIRING_CODE>             Pair this Host with a Watch',
    '  watches list                    List Watches linked to this Host',
    '  watches remove <WATCH_DEVICE_ID>',
    '                                  Remove one Watch link',
    '',
    'Host identity:',
    '  identity status                 Inspect the Host identity',
    '  host rotate-key                 Rotate the Host signing key',
    '  host reset --confirm            Replace the Host identity and remove all links',
    '',
    'Service management:',
    '  service install                 Install and start the user service',
    '  service reinstall               Reinstall and start the user service',
    '  service status                  Show service state',
    '  service start|stop|restart       Control the service',
    '  service uninstall               Remove the user service',
    '',
    'pi integration:',
    '  install pi                      Install the Ariava pi extension',
    '  upgrade pi                      Upgrade the Ariava pi extension',
    '  remove pi                       Remove the Ariava pi extension',
    '',
    'Configuration:',
    '  config path                     Print the active configuration path',
    '  config show                     Show configuration with secrets redacted',
    '  config get <KEY>                Read a configuration value',
    '  config set <KEY> <VALUE>        Set a configuration value',
    '  config agent-secret ensure      Create the Agent Adapter secret if absent',
    '  config agent-secret rotate      Replace the Agent Adapter secret',
    '',
    'Maintenance:',
    '  upgrade                         Upgrade Ariava, its service, and pi extension',
    '  uninstall [--purge] [--remove-pi]',
    '                                  Remove Ariava components and optional local data',
    '',
    'Development:',
    '  dev install pi [--from <PATH>]  Install a pi extension from source',
    '  dev upgrade pi [--from <PATH>]  Upgrade a source-installed pi extension',
    '  dev bridge use [--from <PATH>]  Point the service at a development Bridge build',
    '  dev status                      Show active development sources',
    '',
    'Global options:',
    '  --json                          Emit machine-readable JSON',
    '  --help                          Show this help',
    '',
    'Examples:',
    '  npx --yes ariava@latest setup',
    '  ariava pair ABCD-1234',
    '  ariava doctor --json',
    '',
    'Run `ariava <command> --help` is not yet supported; use this command reference.',
  ].join('\n');
}

async function runAgentSecretConfig(deps: PublicCliDependencies, argv: string[], json: boolean, fileConfig: AriavaUserConfig): Promise<void> {
  const action = argv[0] ?? 'ensure';
  const current = fileConfig.agentAdapterSecret?.trim();

  if (action === 'ensure') {
    const generated = !current;
    const nextSecret = current || generateAgentAdapterSecret();
    if (generated) {
      deps.saveUserConfig({ ...fileConfig, agentAdapterSecret: nextSecret });
    }
    print(
      deps,
      json,
      okEnvelope('ok', generated ? 'Generated Agent Adapter secret.' : 'Agent Adapter secret already configured.', { generated, rotated: false }),
      generated ? 'Generated Agent Adapter secret.' : 'Agent Adapter secret already configured.',
    );
    return;
  }

  if (action === 'rotate') {
    deps.saveUserConfig({ ...fileConfig, agentAdapterSecret: generateAgentAdapterSecret() });
    const message = 'Rotated Agent Adapter secret. Restart the Ariava service and reload pi sessions.';
    print(deps, json, okEnvelope('ok', message, { generated: true, rotated: true }), message);
    return;
  }

  throw new Error('Usage: ariava config agent-secret ensure|rotate');
}

function generateAgentAdapterSecret(): string {
  return randomBytes(32).toString('hex');
}

function redactUserConfig(config: AriavaUserConfig): AriavaUserConfig {
  const { agentAdapterSecret: _agentAdapterSecret, ...rest } = config;
  return rest;
}

function redactResolvedConfig(config: ResolvedAriavaConfig): ResolvedAriavaConfig {
  if (!config.agentAdapterSecret) return config;
  return { ...config, agentAdapterSecret: '<redacted>' };
}

function formatStatus(status: ReturnType<typeof buildHostManagerStatus>): string {
  return [
    `CLI version: ${status.cliVersion}`,
    `Config complete: ${status.configComplete ? 'yes' : 'no'}`,
    `Service backend: ${status.service.backend ?? '(unavailable)'}`,
    `Service supported: ${status.service.supported ? 'yes' : 'no'}`,
    `Service: ${status.service.installed ? 'installed' : 'not installed'}`,
    `Service enabled: ${status.service.enabled ? 'yes' : 'no'}`,
    `Service loaded: ${status.service.loaded ? 'yes' : 'no'}`,
    `Process running: ${status.service.processRunning ? 'yes' : 'no'}`,
    `Bridge health: ${status.bridgeHealth}`,
    `Bridge source: ${status.bridgeSourceKind ?? 'release-bundle'}`,
    `Host: ${status.hostName} (${status.hostId || status.identity.hostId || '(not initialized)'})`,
    `Identity: ${status.identity.status}${status.identity.keyId ? ` (${status.identity.keyId})` : ''}`,
    `Relay: ${status.relayBaseUrl}`,
    `pi extension: ${status.piExtension.installed ? 'installed' : 'not installed'}`,
  ].join('\n');
}

function formatDoctor(checks: Record<string, unknown>): string {
  return Object.entries(checks)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value)}`)
    .join('\n');
}

function formatServiceStatus(status: ServiceStatus & { relayBaseUrl?: string; logDir?: string }): string {
  return [
    `Service backend: ${status.backend ?? '(unavailable)'}`,
    `Supported: ${status.support.supported}`,
    `Installed: ${status.installed}`,
    `Enabled: ${status.enabled}`,
    `Loaded: ${status.loaded}`,
    `Running: ${status.processRunning}`,
    `Relay base URL: ${status.relayBaseUrl ?? '(not configured)'}`,
    `Log dir: ${status.logDir ?? '(not configured)'}`,
    ...(status.stdoutLogPath ? [`Stdout log: ${status.stdoutLogPath}`] : []),
    ...(status.stderrLogPath ? [`Stderr log: ${status.stderrLogPath}`] : []),
    `Definition: ${status.definitionPath ?? '(not recorded)'}`,
    `Runtime path: ${status.runtimePath ?? '(not recorded)'}`,
    `Ariava bin: ${status.ariavaBinPath ?? '(not recorded)'}`,
  ].join('\n');
}

function formatUpgradeResult(data: {
  cliVersion: string;
  selfUpgrade: { skipped: boolean; reason?: string; manager?: string };
  config: { updated: boolean; configPath: string };
  service: { updated: boolean; restarted: boolean; installed: boolean; reason?: string; detail?: string };
  piExtension: { updated: boolean; record: { managedPath: string } };
  doctor: Record<string, unknown>;
}): string {
  return [
    'Ariava upgrade',
    `CLI version: ${data.cliVersion}`,
    `Self upgrade: ${data.selfUpgrade.skipped ? `skipped (${data.selfUpgrade.reason ?? 'unknown'})` : data.selfUpgrade.manager ?? 'completed'}`,
    `Config: ${data.config.updated ? 'updated' : 'unchanged'} (${data.config.configPath})`,
    `Service: ${data.service.installed ? data.service.updated ? 'updated' : 'unchanged' : `skipped (${data.service.reason ?? 'not installed'})`}`,
    `Service restart: ${data.service.restarted ? 'yes' : 'no'}`,
    `pi extension: updated (${data.piExtension.record.managedPath})`,
    `Doctor: ${JSON.stringify(data.doctor)}`,
  ].join('\n');
}

function formatPiStatus(status: ReturnType<typeof getPiExtensionStatus>): string {
  return [
    `Installed: ${status.installed}`,
    `Managed: ${status.managed}`,
    `Install path: ${status.installPath}`,
    `Installed version: ${status.installedVersion ?? '(unknown)'}`,
    `Bundled version: ${status.bundledVersion ?? '(unknown)'}`,
    `Source: ${status.source?.kind ?? 'unknown'}${status.source?.path ? ` (${status.source.path})` : ''}`,
  ].join('\n');
}

function currentAriavaBinPath(): string {
  return resolve(process.argv[1] ?? 'apps/bridge/src/public-cli.ts');
}

function commandExists(name: string): boolean {
  const result = spawnSync('sh', ['-lc', `command -v ${name}`], { encoding: 'utf8' });
  return result.status === 0;
}

function unsupportedIdentityInspection(path: string) {
  return {
    status: 'not-initialized' as const,
    storageType: 'linux-json' as const,
    storageReference: { type: 'linux-json' as const, path },
    path,
    ownerIntegrity: false,
    permissionIntegrity: false,
    metadataIntegrity: false,
    pendingRotation: false,
  };
}
