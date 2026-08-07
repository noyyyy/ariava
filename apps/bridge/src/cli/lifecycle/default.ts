import { randomBytes } from 'node:crypto';
import { accessSync, constants, existsSync, lstatSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { hostname } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { spawn as spawnChild, spawnSync } from 'node:child_process';
import { BridgeDaemon, loadBridgeConfig } from '../../daemon';
import {
  createRuntimeHostIdentityStore,
  createRuntimeHostEncryptionIdentityStore,
  HostIdentityError,
  inspectPublicIdentity,
  type HostIdentityStore,
} from '../../identity';
import { probeHostPlatform } from '../../host-platform';
import {
  createReadlineOnboardingPrompt,
  promptForOnboardingSelection,
  renderOnboardingProgress,
  renderOnboardingResult,
  restoreOnboardingTerminal,
  type OnboardingPrompt,
  type OnboardingTerminal,
} from '../../ui/onboarding-renderer';
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
} from '../../host-manager';
import { ARIAVA_CONFIG_PATH, ARIAVA_CONFIG_ROOT } from '../../host-manager/paths';
import { buildHostManagerStatus, isConfigComplete } from '../../host-manager/status';
import { readAgentAdapterConfig } from '../../agent-adapter/config';
import { inspectCurrentNodeRuntime, probeNodeRuntimePath } from '../../runtime/node-runtime';
import { runNodeCryptoSelfTest } from '../../e2e/node-crypto-self-test';
import { createDefaultProfile } from '../profiles/default';
import { createProfileCliContext, type AriavaCliApplicationContext } from '../context';
import type { AriavaProfileDescriptor } from '../profile';
import { createDefaultProfileIdentityResetDependencies } from '../operations/identity';
import { createDefaultPairProfileDependencies } from '../operations/pair';
import { normalizeCliFailure, type CliFailure } from '../failure';
import { runSharedHostCommand } from '../commands';
import { formatDoctorChecks } from '../commands/doctor';
import { createDefaultWatchesProfileDependencies } from '../operations/watches';
import { runAriavaCli, resolveCliVersion } from '../app';
import { renderCliFailure } from '../output';
import type { ProfileProbeEvidence, ProfileRuntimeProbe } from '../probes/profile';
import { findAriavaPackageAuthority } from '../package-authority';

const PACKAGE_AUTHORITY = findAriavaPackageAuthority(import.meta.url);
const PACKAGE_ROOT = PACKAGE_AUTHORITY.packageRoot;
const CLI_VERSION = resolveCliVersion('default', () => PACKAGE_AUTHORITY.manifest);
const RELEASE_PI_VERSION = CLI_VERSION;

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
  createHostIdentityStore(
    path: string,
    platform: NodeJS.Platform | string,
    identityProfile?: AriavaProfileDescriptor['resources']['identityProfile'],
  ): HostIdentityStore;
  createProfile(): AriavaProfileDescriptor;
  inspectRuntime(): ReturnType<typeof inspectCurrentNodeRuntime>;
  probeRuntimePath(path: string): ReturnType<typeof inspectCurrentNodeRuntime>;
  cryptoSelfTest(): boolean;
  createPairDependencies(bridgeVersion: string): ReturnType<typeof createDefaultPairProfileDependencies>;
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
  createProfile: createDefaultProfile,
  inspectRuntime: inspectCurrentNodeRuntime,
  probeRuntimePath: probeNodeRuntimePath,
  cryptoSelfTest: runNodeCryptoSelfTest,
  createPairDependencies: createDefaultPairProfileDependencies,
};

export function createDefaultLifecycleAdapter(
  deps: PublicCliDependencies,
  onboardingOverrides: Partial<PublicCliOnboardingDependencies>,
  preflightInitManager?: ServiceManager,
) {
  return {
    execute: (args: string[], options: { json: boolean }) => dispatchPublicCli(
      args, options.json, deps, onboardingOverrides, preflightInitManager,
    ),
  };
}

export function createDefaultCliApplicationContext(
  overrides: Partial<PublicCliDependencies> = {},
  onboardingOverrides: Partial<PublicCliOnboardingDependencies> = {},
): AriavaCliApplicationContext {
  const deps = { ...defaultDependencies, ...overrides };
  let preflightInitManager: ServiceManager | undefined;
  const lifecycle = createDefaultLifecycleAdapter(deps, onboardingOverrides);
  return {
    profileId: 'default',
    profile: deps.createProfile,
    preflight: (args) => {
      if (args[0] === 'setup') return;
      requireProductionRuntime(deps.inspectRuntime());
      if (args[0] === 'init') {
        preflightInitManager = deps.createServiceManager();
        requireServiceSupport(preflightInitManager);
      }
    },
    validateDescriptor: (args) => {
      if (args[0] !== 'setup') deps.createProfile().assertDescriptor();
    },
    output: { stdout: deps.stdout, stderr: deps.stderr },
    version: () => CLI_VERSION,
    helpData: () => ({ runtime: deps.inspectRuntime() }),
    shared: {
      execute: (args, options) => runSharedHostCommand(args, options, {
        context: () => createDefaultProfileContext(
          deps,
          args[0] === 'init' ? preflightInitManager?.support.platform : undefined,
          args[0] === 'config',
        ),
        profileId: 'default',
        reset: createDefaultProfileIdentityResetDependencies(CLI_VERSION),
        pair: deps.createPairDependencies(CLI_VERSION),
        watches: createDefaultWatchesProfileDependencies(CLI_VERSION),
        stdin: process.stdin,
        stdout: deps.stdout,
        interactive: (deps.stdout as NodeJS.WritableStream & { isTTY?: boolean }).isTTY === true
          && process.stdin.isTTY === true,
        environment: process.env,
        status: createDefaultStatusDependencies(deps),
        doctor: createDefaultDoctorDependencies(deps),
      }),
    },
    legacy: lifecycle,
    lifecycle,
  };
}

export function runDefaultCli(
  argv: string[],
  overrides: Partial<PublicCliDependencies> = {},
  onboardingOverrides: Partial<PublicCliOnboardingDependencies> = {},
): Promise<number> {
  return runAriavaCli(argv, createDefaultCliApplicationContext(overrides, onboardingOverrides));
}

async function dispatchPublicCli(
  args: string[],
  json: boolean,
  deps: PublicCliDependencies,
  onboardingOverrides: Partial<PublicCliOnboardingDependencies>,
  preflightInitManager?: ServiceManager,
): Promise<number> {
  const command = args[0]!;
  if (command === 'setup') return runSetup(deps, args.slice(1), json, onboardingOverrides);
  if (command === 'internal') {
    await runInternal(args.slice(1), deps);
    return 0;
  }
  switch (command) {
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
}




function createDefaultStatusDependencies(deps: PublicCliDependencies) {
  return {
    context: () => {
      const manager = deps.createServiceManager();
      return createDefaultProfileContext(deps, manager.support.platform, true);
    },
    pathExists: deps.pathExists,
    runtime: () => defaultRuntimeProbe(deps),
    readAdapter: readAgentAdapterConfig,
    runPiStatus: () => {
      const piStatus = getPiExtensionStatus(RELEASE_PI_VERSION);
      return {
        envelope: { ok: true, code: 'ok', message: 'pi extension status.', data: piStatus },
        human: formatPiStatus(piStatus),
      };
    },
    lifecycle: {
      buildStatus: (shared: ProfileProbeEvidence) => {
        const manager = deps.createServiceManager();
        const installMetadata = deps.loadInstallMetadata();
        const serviceStatus = currentServiceStatus(deps, manager, installMetadata);
        serviceStatus.runtimeCryptoSelfTestPassed = shared.runtime.runtimeCryptoSelfTestPassed;
        const bridgeConfig = {
          hostId: shared.config.identity?.hostId ?? '',
          hostName: shared.config.hostName || hostname(),
          hostPlatform: manager.support.platform === 'linux' ? 'linux' as const : 'macos' as const,
          relayBaseUrl: shared.config.relayBaseUrl,
          statePath: shared.config.statePath,
          identityPath: shared.config.identityPath,
          configPath: shared.config.configPath,
          runtimePlatform: manager.support.platform as NodeJS.Platform,
          identity: shared.config.identity,
          pollIntervalMs: shared.config.pollIntervalMs ?? 15_000,
          bridgeVersion: CLI_VERSION,
          agentAdapter: {
            port: shared.config.agentAdapterPort,
            secret: shared.config.agentAdapterSecret ?? '',
            configPath: shared.config.agentAdapterConfigPath,
          },
        };
        return buildHostManagerStatus({
          config: shared.config,
          bridgeConfig,
          installMetadata,
          serviceStatus,
          piStatus: getPiExtensionStatus(RELEASE_PI_VERSION),
          cliVersion: CLI_VERSION,
          identityInspection: shared.identity,
          statePresent: shared.paths.statePresent,
        });
      },
      formatStatus: (status: unknown) => formatStatus(status as ReturnType<typeof buildHostManagerStatus>),
    },
  };
}

function createDefaultDoctorDependencies(deps: PublicCliDependencies) {
  return {
    context: () => {
      const manager = deps.createServiceManager();
      return createDefaultProfileContext(deps, manager.support.platform, true);
    },
    pathExists: deps.pathExists,
    runtime: () => defaultRuntimeProbe(deps),
    readAdapter: readAgentAdapterConfig,
    lifecycle: {
      buildChecks: (shared: ProfileProbeEvidence) => {
        const manager = deps.createServiceManager();
        const metadataResult = deps.loadInstallMetadataDetailed();
        const installMetadata = metadataResult.metadata;
        const serviceStatus = currentServiceStatus(deps, manager, installMetadata);
        const piStatus = getPiExtensionStatus(RELEASE_PI_VERSION);
        const checks = {
          platform: manager.support.platform,
          isWsl: manager.support.isWsl,
          serviceBackend: manager.backend,
          serviceSupported: manager.support.supported,
          serviceSupportReason: manager.support.reason,
          ...serviceSupportInstructions(manager),
          nodeFound: shared.runtime.nodeFound,
          runtimeNameIsNode: shared.runtime.runtimeNameIsNode,
          runtimeVersionSupported: shared.runtime.runtimeVersionSupported,
          runtimePathMatchesCurrent: Boolean(serviceStatus.runtimePathMatchesCurrent ?? true),
          serviceRuntimeNameIsNode: serviceStatus.runtimeNameIsNode ?? null,
          serviceRuntimeVersionSupported: serviceStatus.runtimeVersionSupported ?? null,
          serviceRuntimeVersionMatchesRecorded: serviceStatus.runtimeVersionMatchesRecorded ?? null,
          runtimeCryptoSelfTestPassed: shared.runtime.runtimeCryptoSelfTestPassed,
          piFound: deps.commandExists('pi'),
          configComplete: shared.configComplete,
          serviceInstalled: serviceStatus.installed,
          serviceEnabled: serviceStatus.enabled,
          serviceLoaded: serviceStatus.loaded,
          serviceRunning: serviceStatus.processRunning,
          servicePathCurrent: Boolean(serviceStatus.runtimePathMatchesCurrent ?? true) && Boolean(serviceStatus.ariavaBinPathMatchesCurrent ?? true),
          serviceRuntimeCurrent: Boolean(serviceStatus.runtimeNameIsNode ?? true)
            && Boolean(serviceStatus.runtimeVersionSupported ?? true)
            && Boolean(serviceStatus.runtimeVersionMatchesRecorded ?? true),
          serviceReinstallRecommendation: serviceNeedsReinstall(serviceStatus) ? 'Run `ariava service reinstall`.' : undefined,
          serviceMetadataValid: metadataResult.diagnostics.serviceMetadataValid,
          installerMetadataValid: metadataResult.diagnostics.installerMetadataValid !== false,
          documentMetadataValid: metadataResult.diagnostics.documentMetadataValid !== false,
          logsAvailable: manager.logsAvailable(),
          statePathParentExists: shared.paths.statePathParentExists,
          relayConfigured: shared.relay.configured,
          identity: shared.identity,
          agentAdapterConfigPath: shared.adapter.configPath,
          agentAdapterConfigPresent: shared.adapter.present,
          piExtensionManaged: piStatus.managed,
          piExtensionInstalled: piStatus.installed,
          piExtensionNeedsUpgrade: Boolean(piStatus.needsUpgrade),
          environmentOverrides: shared.config.environmentOverrides,
          bridgeSource: installMetadata.bridgeSource ?? { kind: 'release-bundle' },
          piSource: installMetadata.piSource,
        };
        Object.assign(checks, {
          identityReady: shared.identity.status === 'ready',
          identityWarning: shared.identity.status === 'rotation-pending'
            ? 'Host key rotation is pending; recover it before normal operation.'
            : undefined,
        });
        return checks;
      },
      healthy: (checks: Record<string, unknown>) => Boolean(
        checks.serviceSupported && checks.nodeFound && checks.runtimeNameIsNode
        && checks.runtimeVersionSupported && checks.runtimeCryptoSelfTestPassed && checks.configComplete
        && checks.servicePathCurrent && checks.serviceRuntimeCurrent
        && checks.serviceMetadataValid && checks.installerMetadataValid && checks.documentMetadataValid
        && checks.identityReady
      ),
      formatDoctor: formatDoctorChecks,
    },
  };
}

function defaultRuntimeProbe(deps: PublicCliDependencies): ProfileRuntimeProbe {
  const runtime = deps.inspectRuntime();
  return {
    nodeFound: Boolean(deps.currentRuntimePath()),
    runtimeNameIsNode: runtime.runtimeNameIsNode,
    runtimeVersionSupported: runtime.runtimeVersionSupported,
    runtimeCryptoSelfTestPassed: deps.cryptoSelfTest(),
  };
}

function createDefaultProfileContext(
  deps: PublicCliDependencies,
  platformOverride?: NodeJS.Platform | string,
  readOnly = false,
) {
  const platform = platformOverride ?? (readOnly ? process.platform : deps.createServiceManager().support.platform);
  return createProfileCliContext({
    profile: deps.createProfile(),
    platform,
    hostName: hostname,
    generateSecret: generateAgentAdapterSecret,
    environment: process.env,
    config: {
      load: () => deps.loadUserConfig(),
      save: (config) => deps.saveUserConfig(config),
    },
    resolveForDisplay: () => deps.resolveAriavaConfig(),
    identity: {
      create: (resources) => deps.createHostIdentityStore(
        resources.identityMetadataPath,
        platform,
        resources.identityProfile,
      ),
    },
    encryptionIdentity: {
      create: (resources) => createRuntimeHostEncryptionIdentityStore(
        resources.identityMetadataPath,
        platform,
        resources.identityProfile,
      ),
    },
  });
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
      throw new Error(`Dev bridge entry not found: ${sourcePath}. Run node ./scripts/build-bridge.mjs first or pass --from.`);
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
    print(deps, json, okEnvelope('ok', 'Ariava dev source status.', data), formatDevSourceStatus(data));
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
        message: failed ? onboardingFailureMessage(result) : 'Ariava onboarding completed.',
        data: result,
      }, deps.stdout);
    } else {
      deps.stdout.write(`${renderOnboardingResult(result, { terminal })}\n`);
    }
    return failed ? 1 : 0;
  } catch (error) {
    // Keep onboarding's step/retryable envelope for JSON; human path matches top-level ariava: prefix.
    const normalized = normalizeOnboardingError(error);
    printCliFailure(deps, json, normalized);
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
    detectServiceSupport: () => manager.support, isTty: interactive, machineOutput, configPath: ARIAVA_CONFIG_PATH,
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
  return initializeHost({ relayBaseUrl, useEnvironmentIdentityPath: false }, {
    loadUserConfig: deps.loadUserConfig,
    saveUserConfig: deps.saveUserConfig,
    createIdentityStore: (path) => deps.createHostIdentityStore(path, manager.support.platform),
    createEncryptionIdentityStore: (path) => createRuntimeHostEncryptionIdentityStore(path, manager.support.platform),
    hostName: hostname,
    generateSecret: generateAgentAdapterSecret,
    environment: process.env,
    profile: deps.createProfile(),
    platform: manager.support.platform,
  });
}

async function loadOnboardingHostState(deps: PublicCliDependencies, manager: ServiceManager) {
  const config = resolveAriavaConfig({}, ARIAVA_CONFIG_PATH, false);
  const store = deps.createHostIdentityStore(config.identityPath, manager.support.platform);
  const identityInspection = await store.inspect();
  // Fail closed with the concrete HostIdentityError when evidence exists but cannot be loaded.
  // Returning undefined here would hide ERR_IDENTITY_* as a generic onboarding failure.
  if (identityInspection.status === 'not-initialized') return undefined;
  const identity = await store.load();
  if (!identity) return undefined;
  return { config, identityInspection, identity };
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
  if (error instanceof HostIdentityError) {
    const failure = normalizeCliFailure(error);
    return {
      ...failure,
      data: { step: 'host-init', retryable: false, ...failure.data },
    };
  }
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

function onboardingFailureMessage(result: OnboardingResult): string {
  const failed = result.steps.find((step) => step.status === 'failed');
  const detail = failed?.detail;
  if (detail && typeof detail.message === 'string' && detail.message.length > 0) return detail.message;
  if (detail?.remediation && typeof detail.remediation === 'object' && !Array.isArray(detail.remediation)) {
    const remediation = detail.remediation as { message?: unknown };
    if (typeof remediation.message === 'string' && remediation.message.length > 0) return remediation.message;
  }
  const action = result.nextActions[0];
  if (action?.message && action.message.length > 0) return action.message;
  const code = onboardingFailureCode(result);
  return code === 'ERR_ONBOARDING_NOT_READY' ? 'Ariava onboarding is incomplete.' : code;
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

function serviceNeedsReinstall(status: ServiceStatus): boolean {
  if (!status.runtimePath && !status.ariavaBinPath) return false;
  return status.runtimePathMatchesCurrent === false
    || status.ariavaBinPathMatchesCurrent === false
    || status.runtimeNameIsNode === false
    || status.runtimeVersionSupported === false
    || status.runtimeVersionMatchesRecorded === false;
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



function printCliFailure(deps: PublicCliDependencies, json: boolean, failure: CliFailure): void {
  renderCliFailure({ stdout: deps.stdout, stderr: deps.stderr }, json, failure);
}


function print(deps: PublicCliDependencies, json: boolean, envelope: unknown, human: string): void {
  if (json) {
    printJson(envelope, deps.stdout);
    return;
  }
  deps.stdout.write(`${human}\n`);
}


function generateAgentAdapterSecret(): string {
  return randomBytes(32).toString('hex');
}

function redactUserConfig(config: AriavaUserConfig): AriavaUserConfig {
  const { agentAdapterSecret: _agentAdapterSecret, ...rest } = config;
  return rest;
}


function formatStatus(status: ReturnType<typeof buildHostManagerStatus>): string {
  const hostId = status.hostId || status.identity.hostId;
  const fields = [
    { label: 'Version', value: status.cliVersion },
    { label: 'Bridge', value: status.bridgeHealth },
    { label: 'Host', value: status.hostName, detail: hostId },
    { label: 'Identity', value: status.identity.status, detail: status.identity.keyId },
    { label: 'Relay', value: status.relayBaseUrl },
    { label: 'Agent', value: `Pi · ${status.piExtension.installed ? 'installed' : 'not installed'}` },
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

function formatDevSourceStatus(data: { bridgeSource: { kind: string; path?: string; package?: string }; piSource: { kind: string; path?: string; package?: string } }): string {
  const fields = [
    { label: 'Bridge source', value: describeDevSource(data.bridgeSource) },
    { label: 'Pi source', value: describeDevSource(data.piSource) },
  ];
  const labelWidth = Math.max(...fields.map(({ label }) => label.length));
  return [
    'Ariava dev sources',
    '',
    ...fields.map(({ label, value }) => `  ${label.padEnd(labelWidth)}  ${value}`),
  ].join('\n');
}

function describeDevSource(source: { kind: string; path?: string; package?: string }): string {
  const kind = source.kind === 'release-bundle' ? 'release bundle' : source.kind.replaceAll('-', ' ');
  return source.path || source.package ? `${kind} (${source.path ?? source.package})` : kind;
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
