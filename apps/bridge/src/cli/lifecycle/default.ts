import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, realpathSync, rmSync } from 'node:fs';
import { hostname } from 'node:os';
import { resolve } from 'node:path';
import { readAgentAdapterConfig } from '../../agent-adapter/config';
import { loadBridgeConfig } from '../../daemon';
import { runNodeCryptoSelfTest } from '../../e2e/node-crypto-self-test';
import { HostIdentityError } from '../../identity/errors';
import {
  createRuntimeHostEncryptionIdentityStore,
  createRuntimeHostIdentityStore,
} from '../../identity/runtime-store';
import {
  loadInstallMetadata,
  loadInstallMetadataDetailed,
  loadUserConfig,
  mergeInstallMetadata,
  resolveAriavaConfig,
  saveInstallMetadata,
  saveUserConfig,
  type AriavaInstallMetadata,
  type ResolvedAriavaConfig,
} from '../../host-manager/config';
import { buildInitializedConfig } from '../../host-manager/initialization';
import { ARIAVA_CONFIG_ROOT } from '../../host-manager/paths';
import { removePiPackage } from '../../host-manager/pi-extension';
import { AriavaCliError } from '../../host-manager/service/errors';
import { createServiceManager } from '../../host-manager/service/manager';
import { supportError } from '../../host-manager/service/platform';
import type { ServiceManager } from '../../host-manager/service/types';
import { inspectCurrentNodeRuntime, probeNodeRuntimePath } from '../../runtime/node-runtime';
import { createDefaultProfile } from '../profiles/default';
import {
  createProfileCliContext,
  type AriavaCliApplicationContext,
} from '../context';
import { createDefaultProfileIdentityResetDependencies } from '../operations/identity';
import { createDefaultPairProfileDependencies } from '../operations/pair';
import { runSharedHostCommand } from '../commands';
import { formatDoctorChecks } from '../commands/doctor';
import { normalizeCliFailure, type CliFailure } from '../failure';
import { createDefaultWatchesProfileDependencies } from '../operations/watches';
import { runAriavaCli } from '../app';
import {
  type PublicCliDependencies,
  type PublicCliOnboardingDependencies,
} from './default-context';
import { formatStatus } from './default-presenters';
import {
  isDefaultDoctorHealthy,
  probeDefaultDoctorChecks,
  probeDefaultRuntime,
  probeDefaultStatus,
} from './default-probes';
import {
  DEFAULT_CLI_VERSION as CLI_VERSION,
  DEFAULT_PACKAGE_ROOT as PACKAGE_ROOT,
  DEFAULT_RELEASE_PI_VERSION as RELEASE_PI_VERSION,
} from './default-runtime';
import { runLogsCommand, runServiceCommand } from './service-commands';
import { createPiCommands } from './pi-commands';
import { installerMetadataPatch, runFullUpgradeCommand } from './upgrade-command';
import { runCompatibilityCommand } from './compatibility-commands';
import { runInternalCommand } from './internal-commands';
import { runUninstallCommand } from './uninstall-command';
import { runSetupCommand } from './setup-command';
import { createDefaultOnboardingAdapter, spawnOnboardingChild } from './onboarding-adapter';
import { createDefaultHostDomainResetLifecycle as createHostResetLifecycle } from './host-reset-adapter';

export type { PublicCliDependencies, PublicCliOnboardingDependencies } from './default-context';
export { detectPackageManager } from './upgrade-command';


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
  const piCommands = createPiCommands(deps, RELEASE_PI_VERSION, deps.piPackageLifecycle);
  const command = args[0]!;
  if (command === 'setup') {
    const onboarding = createDefaultOnboardingAdapter(deps, {
      cliVersion: CLI_VERSION,
      packageRoot: PACKAGE_ROOT,
    });
    return runSetupCommand(args.slice(1), json, {
      stdout: deps.stdout,
      stderr: deps.stderr,
      cliVersion: CLI_VERSION,
      detect: onboardingOverrides.detect ?? onboarding.detect,
      run: onboardingOverrides.run ?? onboarding.run,
      validateSelection: validateDefaultOnboardingSelection,
      normalizeError: normalizeDefaultOnboardingError,
      prompt: onboardingOverrides.prompt,
      terminal: onboardingOverrides.terminal,
    });
  }
  if (command === 'internal') {
    await runInternalCommand(args.slice(1), deps);
    return 0;
  }
  switch (command) {
    case 'service': await runServiceCommand(deps, {
      serviceInstallInput: (resolved) => serviceInstallInput(deps, resolved),
      installerPatch: (metadata) => installerPatch(deps, metadata),
      relayBaseUrl: () => loadBridgeConfig().relayBaseUrl,
    }, args.slice(1), json); break;
    case 'install': await piCommands.install(args.slice(1), json); break;
    case 'upgrade':
      if (args[1] === 'pi') await piCommands.upgrade(args.slice(1), json);
      else await runUpgrade(deps, {
        convergeExactPiPackage: piCommands.convergeExactPackage,
        getExactPiStatus: piCommands.exactStatus,
      }, json);
      break;
    case 'remove': await piCommands.remove(args.slice(1), json); break;
    case 'dev': await runCompatibilityCommand(deps, args.slice(1), json, RELEASE_PI_VERSION); break;
    case 'logs': await runLogsCommand(deps, json); break;
    case 'uninstall': await runUninstallCommand(deps, {
      removePiPackage,
      configRoot: ARIAVA_CONFIG_ROOT,
    }, args.slice(1), json); break;
    default: throw new Error(`Unknown command: ${command}`);
  }
  return 0;
}
function validateDefaultOnboardingSelection(
  selection: { extensions: readonly string[] },
  detection: import('../../host-manager/onboarding/types').OnboardingDetection,
): void {
  if (!selection.extensions.includes('pi') || detection.pi.present) return;
  throw new AriavaCliError(
    'ERR_AGENT_RUNTIME_NOT_FOUND',
    'Pi is not installed. Install Pi, then rerun `ariava setup --extension pi`.',
    {
      step: 'adapter-detect',
      retryable: true,
      remediation: { command: 'ariava setup --extension pi' },
    },
  );
}

function normalizeDefaultOnboardingError(error: unknown): CliFailure {
  if (error instanceof AriavaCliError) {
    return { ok: false, code: error.code, message: error.message, data: error.data };
  }
  if (error instanceof HostIdentityError) {
    const failure = normalizeCliFailure(error);
    return {
      ...failure,
      data: { step: 'host-init', retryable: false, ...failure.data },
    };
  }
  return {
    ok: false,
    code: 'ERR_ONBOARDING_NOT_READY',
    message: error instanceof Error ? error.message : String(error),
    data: { step: 'preflight', retryable: true },
  };
}

function createDefaultStatusDependencies(deps: PublicCliDependencies) {
  return {
    context: () => {
      const manager = deps.createServiceManager();
      return createDefaultProfileContext(deps, manager.support.platform, true);
    },
    pathExists: deps.pathExists,
    runtime: () => probeDefaultRuntime(deps),
    readAdapter: readAgentAdapterConfig,
    runPiStatus: createPiCommands(deps, RELEASE_PI_VERSION, deps.piPackageLifecycle).status,
    lifecycle: {
      buildStatus: (shared: import('../probes/profile').ProfileProbeEvidence) => probeDefaultStatus(
        deps, shared, { cliVersion: CLI_VERSION, releasePiVersion: RELEASE_PI_VERSION },
      ),
      formatStatus: (status: unknown) => formatStatus(status as import('../../host-manager/status').HostManagerStatus),
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
    runtime: () => probeDefaultRuntime(deps),
    readAdapter: readAgentAdapterConfig,
    lifecycle: {
      buildChecks: (shared: import('../probes/profile').ProfileProbeEvidence) => probeDefaultDoctorChecks(
        deps, shared, { releasePiVersion: RELEASE_PI_VERSION },
      ),
      healthy: isDefaultDoctorHealthy,
      formatDoctor: formatDoctorChecks,
    },
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
    hostDomainResetLifecycle: createDefaultHostDomainResetLifecycle(deps),
    hostIdentityOperationLock: deps.hostIdentityOperationLock,
  });
}


export function createDefaultHostDomainResetLifecycle(
  deps: PublicCliDependencies,
) {
  return createHostResetLifecycle({
    createServiceManager: deps.createServiceManager,
    loadInstallMetadataDetailed: deps.loadInstallMetadataDetailed,
    resolveAriavaConfig: deps.resolveAriavaConfig,
    serviceInstallInput: (resolved) => serviceInstallInput(deps, resolved),
    mergeInstallMetadata: deps.mergeInstallMetadata,
    realpath: deps.realpath,
    currentRuntimePath: deps.currentRuntimePath,
    currentAriavaBinPath: deps.currentAriavaBinPath,
  });
}

async function runUpgrade(
  deps: PublicCliDependencies,
  pi: {
    convergeExactPiPackage: () => import('../../host-manager/config').AriavaPiInstallRecord;
    getExactPiStatus: () => import('../../host-manager/pi-extension').PiExtensionStatus;
  },
  json: boolean,
): Promise<void> {
  await runFullUpgradeCommand(deps, {
    cliVersion: CLI_VERSION,
    buildInitializedConfig,
    serviceInstallInput: (resolved) => serviceInstallInput(deps, resolved),
    convergeExactPiPackage: pi.convergeExactPiPackage,
    getPiExtensionStatus: pi.getExactPiStatus,
    process: {
      environment: process.env,
      exit: (code) => process.exit(code),
    },
  }, json);
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
  return installerMetadataPatch(deps, metadata);
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

function requireServiceSupport(manager: ServiceManager): void {
  if (!manager.support.supported) throw supportError(manager.support);
}
function generateAgentAdapterSecret(): string {
  return randomBytes(32).toString('hex');
}
function currentAriavaBinPath(): string {
  return resolve(process.argv[1] ?? 'apps/bridge/src/public-cli.ts');
}

function commandExists(name: string): boolean {
  const result = spawnSync('sh', ['-lc', `command -v ${name}`], { encoding: 'utf8' });
  return result.status === 0;
}
