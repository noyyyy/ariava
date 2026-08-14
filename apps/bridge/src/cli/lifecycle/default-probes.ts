import { hostname } from 'node:os';
import type { AriavaInstallMetadata } from '../../host-manager/config';
import { getPiExtensionStatus } from '../../host-manager/pi-extension';
import { supportError } from '../../host-manager/service/platform';
import type { ServiceManager, ServiceStatus } from '../../host-manager/service/types';
import { buildHostManagerStatus, type HostManagerStatus } from '../../host-manager/status';
import { readCurrentRuntimeHealth } from '../../state-store';
import type { ProfileProbeEvidence, ProfileRuntimeProbe } from '../probes/profile';
import type { PublicCliDependencies } from './default-context';

export interface DefaultStatusProbeDependencies {
  cliVersion: string;
  releasePiVersion: string;
}

export interface DefaultDoctorProbeDependencies {
  releasePiVersion: string;
}

export function probeDefaultRuntime(
  deps: Pick<PublicCliDependencies, 'currentRuntimePath' | 'inspectRuntime' | 'cryptoSelfTest'>,
): ProfileRuntimeProbe {
  const runtime = deps.inspectRuntime();
  return {
    nodeFound: Boolean(deps.currentRuntimePath()),
    runtimeNameIsNode: runtime.runtimeNameIsNode,
    runtimeVersionSupported: runtime.runtimeVersionSupported,
    runtimeCryptoSelfTestPassed: deps.cryptoSelfTest(),
  };
}

export function probeDefaultStatus(
  deps: Pick<PublicCliDependencies, 'createServiceManager' | 'loadInstallMetadata' | 'realpath' | 'currentRuntimePath' | 'currentAriavaBinPath'>,
  shared: ProfileProbeEvidence,
  constants: DefaultStatusProbeDependencies,
): HostManagerStatus {
  const manager = deps.createServiceManager();
  const installMetadata = deps.loadInstallMetadata();
  const serviceStatus = probeCurrentServiceStatus(deps, manager, installMetadata);
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
    bridgeVersion: constants.cliVersion,
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
    piStatus: getPiExtensionStatus(constants.releasePiVersion),
    cliVersion: constants.cliVersion,
    identityInspection: shared.identity,
    statePresent: shared.paths.statePresent,
    runtimeHealth: shared.hostDomainReset.pending
      ? undefined
      : readCurrentRuntimeHealth(shared.paths.statePath),
  });
}

export function probeDefaultDoctorChecks(
  deps: Pick<PublicCliDependencies,
    | 'createServiceManager'
    | 'loadInstallMetadataDetailed'
    | 'realpath'
    | 'currentRuntimePath'
    | 'currentAriavaBinPath'
    | 'commandExists'>,
  shared: ProfileProbeEvidence,
  constants: DefaultDoctorProbeDependencies,
): Record<string, unknown> {
  const manager = deps.createServiceManager();
  const metadataResult = deps.loadInstallMetadataDetailed();
  const installMetadata = metadataResult.metadata;
  const serviceStatus = probeCurrentServiceStatus(deps, manager, installMetadata);
  const piStatus = getPiExtensionStatus(constants.releasePiVersion);
  const checks = {
    platform: manager.support.platform,
    isWsl: manager.support.isWsl,
    serviceBackend: manager.backend,
    serviceSupported: manager.support.supported,
    serviceSupportReason: manager.support.reason,
    ...probeServiceSupportInstructions(manager),
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
    servicePathCurrent: Boolean(serviceStatus.runtimePathMatchesCurrent ?? true)
      && Boolean(serviceStatus.ariavaBinPathMatchesCurrent ?? true),
    serviceRuntimeCurrent: Boolean(serviceStatus.runtimeNameIsNode ?? true)
      && Boolean(serviceStatus.runtimeVersionSupported ?? true)
      && Boolean(serviceStatus.runtimeVersionMatchesRecorded ?? true),
    serviceReinstallRecommendation: serviceNeedsReinstall(serviceStatus)
      ? 'Run `ariava service reinstall`.'
      : undefined,
    serviceMetadataValid: metadataResult.diagnostics.serviceMetadataValid,
    installerMetadataValid: metadataResult.diagnostics.installerMetadataValid !== false,
    documentMetadataValid: metadataResult.diagnostics.documentMetadataValid !== false,
    logsAvailable: manager.logsAvailable(),
    statePathParentExists: shared.paths.statePathParentExists,
    bridgeRuntimeHealth: shared.hostDomainReset.pending
      ? undefined
      : readCurrentRuntimeHealth(shared.paths.statePath),
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
    identityWarning: shared.identity.status === 'invalid'
      ? 'Host identity signing state requires reset; run `ariava identity reset --confirm` and re-pair Watches.'
      : undefined,
  });
  return checks;
}

export function isDefaultDoctorHealthy(checks: Record<string, unknown>): boolean {
  return Boolean(
    checks.serviceSupported && checks.nodeFound && checks.runtimeNameIsNode
    && checks.runtimeVersionSupported && checks.runtimeCryptoSelfTestPassed && checks.configComplete
    && checks.servicePathCurrent && checks.serviceRuntimeCurrent
    && checks.serviceMetadataValid && checks.installerMetadataValid && checks.documentMetadataValid
    && checks.identityReady
  );
}

export function probeCurrentServiceStatus(
  deps: Pick<PublicCliDependencies, 'realpath' | 'currentRuntimePath' | 'currentAriavaBinPath'>,
  manager: ServiceManager,
  installMetadata: AriavaInstallMetadata,
): ServiceStatus {
  return manager.status(
    installMetadata.service,
    deps.realpath(deps.currentRuntimePath()),
    deps.realpath(deps.currentAriavaBinPath()),
  );
}

export function probeServiceSupportInstructions(manager: ServiceManager): {
  serviceSupportInstructions?: Record<string, unknown>;
} {
  if (manager.support.supported) return {};
  const error = supportError(manager.support);
  const instructions = error.data.instructions;
  return instructions && typeof instructions === 'object'
    ? { serviceSupportInstructions: instructions as Record<string, unknown> }
    : {};
}

function serviceNeedsReinstall(status: ServiceStatus): boolean {
  if (!status.runtimePath && !status.ariavaBinPath) return false;
  return status.runtimePathMatchesCurrent === false
    || status.ariavaBinPathMatchesCurrent === false
    || status.runtimeNameIsNode === false
    || status.runtimeVersionSupported === false
    || status.runtimeVersionMatchesRecorded === false;
}
