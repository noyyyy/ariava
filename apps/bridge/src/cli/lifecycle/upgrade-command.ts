import { lstatSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import type {
  AriavaInstallMetadata,
  AriavaInstallerManager,
  AriavaPiInstallRecord,
  ResolvedAriavaConfig,
} from '../../host-manager/config';
import type { PiExtensionStatus } from '../../host-manager/pi-extension';
import { okEnvelope, printJson } from '../../host-manager/output';
import { sanitizeCommandDetail } from '../../host-manager/service/errors';
import type { ServiceInstallInput } from '../../host-manager/service/types';
import { isConfigComplete } from '../../host-manager/status';
import { redactUserConfig } from '../config-redaction';
import type { PackageManagerCommand, PublicCliDependencies } from './default-context';
import { formatUpgradeResult, selectDefaultPresentation } from './default-presenters';

type UpgradeCommandDependencies = Pick<PublicCliDependencies,
  | 'createServiceManager'
  | 'currentRuntimePath'
  | 'currentAriavaBinPath'
  | 'stdout'
  | 'loadUserConfig'
  | 'saveUserConfig'
  | 'resolveAriavaConfig'
  | 'loadInstallMetadata'
  | 'mergeInstallMetadata'
  | 'realpath'
  | 'spawn'>;

type PackageManagerDetectionDependencies = Pick<PublicCliDependencies,
  | 'currentAriavaBinPath'
  | 'realpath'>;

export interface UpgradeCommandPorts {
  cliVersion: string;
  buildInitializedConfig(config: import('../../host-manager/config').AriavaUserConfig): import('../../host-manager/config').AriavaUserConfig;
  serviceInstallInput(resolved: ResolvedAriavaConfig): ServiceInstallInput;
  convergeExactPiPackage(): AriavaPiInstallRecord;
  getPiExtensionStatus(): PiExtensionStatus;
  process: {
    environment: NodeJS.ProcessEnv;
    exit(code: number): never;
  };
}

export async function runFullUpgradeCommand(
  deps: UpgradeCommandDependencies,
  ports: UpgradeCommandPorts,
  json: boolean,
): Promise<void> {
  const installMetadataBeforeUpgrade = deps.loadInstallMetadata();
  const selfUpgrade = ports.process.environment.ARIAVA_UPGRADE_SELF_DONE === '1'
    ? { skipped: true, reason: 'already-upgraded' }
    : runSelfUpgradeAndReenter(deps, installMetadataBeforeUpgrade, json, ports.process);
  if (!selfUpgrade.skipped) return;

  const configResult = reconcileUserConfig(deps, ports.buildInitializedConfig);
  const manager = deps.createServiceManager();
  const serviceResult = reconcileServiceInstall(
    deps,
    manager,
    ports.serviceInstallInput,
    serviceRestartSkipped(ports.process.environment),
  );
  const piRecord = ports.convergeExactPiPackage();
  const resolved = deps.resolveAriavaConfig();
  const installMetadata = deps.loadInstallMetadata();
  const serviceStatus = currentServiceStatus(deps, manager, installMetadata);
  const piStatus = ports.getPiExtensionStatus();

  const data = {
    cliVersion: ports.cliVersion,
    selfUpgrade,
    config: {
      updated: configResult.updated,
      configPath: resolved.configPath,
      config: redactUserConfig(configResult.config),
    },
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

export function installerMetadataPatch(
  deps: PackageManagerDetectionDependencies,
  metadata: AriavaInstallMetadata,
): Partial<AriavaInstallMetadata> {
  const detected = detectPackageManager(deps, metadata);
  if (!detected) return {};
  return {
    installer: {
      manager: detected.manager,
      ariavaBinRealPath: deps.realpath(deps.currentAriavaBinPath()),
      recordedAt: new Date().toISOString(),
    },
  };
}

export function detectPackageManager(
  deps: PackageManagerDetectionDependencies,
  metadata: AriavaInstallMetadata,
): PackageManagerCommand | undefined {
  return detectPackageManagerForEnvironment(deps, metadata, process.env);
}

function reconcileUserConfig(
  deps: Pick<UpgradeCommandDependencies, 'loadUserConfig' | 'saveUserConfig'>,
  buildConfig: UpgradeCommandPorts['buildInitializedConfig'],
) {
  const existing = deps.loadUserConfig();
  const next = buildConfig(existing);
  const updated = JSON.stringify(existing) !== JSON.stringify(next);
  if (updated) deps.saveUserConfig(next);
  return { updated, config: next };
}

function reconcileServiceInstall(
  deps: UpgradeCommandDependencies,
  manager: ReturnType<UpgradeCommandDependencies['createServiceManager']>,
  serviceInstallInput: UpgradeCommandPorts['serviceInstallInput'],
  skipRestart: boolean,
): { updated: boolean; restarted: boolean; installed: boolean; reason?: string; detail?: string } {
  const installMetadata = deps.loadInstallMetadata();
  if (installMetadata.service?.backend !== manager.backend) {
    return {
      updated: false,
      restarted: false,
      installed: false,
      reason: installMetadata.service ? 'backend-mismatch' : 'not-installed',
    };
  }
  const status = currentServiceStatus(deps, manager, installMetadata);
  if (!status.installed) {
    return { updated: false, restarted: false, installed: false, reason: 'not-installed' };
  }

  const resolved = deps.resolveAriavaConfig();
  const record = manager.install(serviceInstallInput(resolved));
  deps.mergeInstallMetadata({
    service: record,
    identityPath: resolved.identityPath,
    bridgeSource: installMetadata.bridgeSource ?? {
      kind: 'release-bundle',
      updatedAt: record.installedAt,
    },
    ...installerMetadataPatch(deps, installMetadata),
  });
  if (skipRestart) {
    return {
      updated: true,
      restarted: false,
      installed: true,
      reason: 'service-restart-skipped',
    };
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

function currentServiceStatus(
  deps: Pick<UpgradeCommandDependencies, 'realpath' | 'currentRuntimePath' | 'currentAriavaBinPath'>,
  manager: ReturnType<UpgradeCommandDependencies['createServiceManager']>,
  installMetadata: AriavaInstallMetadata,
) {
  return manager.status(
    installMetadata.service,
    deps.realpath(deps.currentRuntimePath()),
    deps.realpath(deps.currentAriavaBinPath()),
  );
}

function serviceRestartSkipped(environment: NodeJS.ProcessEnv): boolean {
  const neutral = environment.ARIAVA_UPGRADE_SKIP_SERVICE_RESTART;
  if (neutral !== undefined) return neutral === '1';
  return environment.ARIAVA_UPGRADE_SKIP_LAUNCHCTL === '1';
}

function runSelfUpgradeAndReenter(
  deps: Pick<UpgradeCommandDependencies, 'currentAriavaBinPath' | 'realpath' | 'spawn'>,
  metadata: AriavaInstallMetadata,
  json: boolean,
  processPort: UpgradeCommandPorts['process'],
): { skipped: boolean; reason?: string } {
  const manager = detectPackageManagerForEnvironment(deps, metadata, processPort.environment);
  if (!manager) {
    throw new Error('Could not determine how Ariava was installed. Please upgrade manually, then run ariava upgrade again.');
  }
  const result = deps.spawn(manager.command, manager.args, {
    stdio: json ? 'pipe' : 'inherit',
    encoding: 'utf8',
  });
  if ((result.status ?? 1) !== 0) {
    throw new Error(
      `Failed to upgrade Ariava CLI with ${manager.command} ${manager.args.join(' ')}`
      + `${result.stderr ? `: ${String(result.stderr).trim()}` : ''}`,
    );
  }
  const reentry = deps.spawn(
    deps.realpath(deps.currentAriavaBinPath()),
    ['upgrade', ...(json ? ['--json'] : [])],
    {
      stdio: 'inherit',
      env: { ...processPort.environment, ARIAVA_UPGRADE_SELF_DONE: '1' },
    },
  );
  processPort.exit(reentry.status ?? 1);
}

function detectPackageManagerForEnvironment(
  deps: PackageManagerDetectionDependencies,
  metadata: AriavaInstallMetadata,
  environment: NodeJS.ProcessEnv,
): PackageManagerCommand | undefined {
  const forced = environment.ARIAVA_UPGRADE_PACKAGE_MANAGER;
  if (forced === 'npm' || forced === 'pnpm' || forced === 'bun') {
    return packageManagerCommand(forced);
  }
  if (forced === 'brew') return packageManagerCommand('homebrew');
  if (metadata.installer) {
    if (!isCanonicalAbsolutePath(metadata.installer.ariavaBinRealPath)) return undefined;
    return packageManagerCommand(metadata.installer.manager);
  }
  let realPath: string;
  try {
    realPath = deps.realpath(deps.currentAriavaBinPath());
  } catch {
    return undefined;
  }
  if (!isCanonicalAbsolutePath(realPath)) return undefined;
  try {
    const stat = lstatSync(realPath);
    if (!stat.isFile() || stat.isSymbolicLink()) return undefined;
  } catch {
    // Tests and already-moved package paths can provide a canonical realpath that no longer exists.
  }
  if (/\/(?:Cellar|Homebrew)\//.test(realPath)) return packageManagerCommand('homebrew');
  if (/\/\.bun\/install\/global\//.test(realPath)) return packageManagerCommand('bun');
  if (/\/\.pnpm\//.test(realPath)
    || /\/pnpm\/global\//.test(realPath)
    || /\/\.local\/share\/pnpm\//.test(realPath)) {
    return packageManagerCommand('pnpm');
  }
  if (/\/node_modules\/ariava\/apps\/bridge\/dist\/public-cli\.js$/.test(realPath)) {
    return packageManagerCommand('npm');
  }
  return undefined;
}

function packageManagerCommand(manager: AriavaInstallerManager): PackageManagerCommand {
  if (manager === 'npm') {
    return { manager, command: 'npm', args: ['install', '-g', 'ariava@latest'] };
  }
  if (manager === 'pnpm') {
    return { manager, command: 'pnpm', args: ['add', '-g', 'ariava@latest'] };
  }
  if (manager === 'bun') {
    return { manager, command: 'bun', args: ['add', '-g', 'ariava@latest'] };
  }
  return { manager, command: 'brew', args: ['upgrade', 'ariava'] };
}

function isCanonicalAbsolutePath(path: string): boolean {
  return isAbsolute(path) && resolve(path) === path;
}

function print(
  deps: Pick<UpgradeCommandDependencies, 'stdout'>,
  json: boolean,
  envelope: unknown,
  human: string,
): void {
  const presentation = selectDefaultPresentation(json, envelope, human);
  if (presentation.channel === 'json') {
    printJson(presentation.value, deps.stdout);
    return;
  }
  deps.stdout.write(`${presentation.value}\n`);
}
