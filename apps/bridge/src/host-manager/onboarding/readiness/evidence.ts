import type { HostPrivateKeyStorage } from '../../../identity/types';
import type { PiExtensionStatus } from '../../pi-extension';
import type { ServiceStatus } from '../../service/types';
import type { StrictReadinessInput } from './check';

export function stableCliMatches(input: StrictReadinessInput): boolean {
  const installer = input.installMetadata.installer;
  return input.stableCli.packageVersion === input.cliVersion
    && Boolean(input.stableCli.packageRoot && input.stableCli.npmPrefix && input.stableCli.npmBinPath)
    && installer?.ariavaBinRealPath === input.stableCli.executablePath;
}

export function persistedConfigReady(input: StrictReadinessInput): boolean {
  const config = input.config;
  return Boolean(config.relayBaseUrl && config.hostName && config.agentAdapterSecret
    && config.identity?.hostId === input.identity.hostId
    && config.identityPath && config.configPath && config.environmentOverrides.length === 0);
}

export function identityReady(input: StrictReadinessInput): boolean {
  const inspected = input.identityInspection;
  return inspected.status === 'ready' && inspected.ownerIntegrity && inspected.permissionIntegrity
    && inspected.metadataIntegrity && !inspected.pendingRotation
    && inspected.hostId === input.identity.hostId && inspected.keyId === input.identity.keyId;
}

export function servicePathsReady(input: StrictReadinessInput, status: ServiceStatus): boolean {
  return status.runtimePath === input.expectedRuntimePath && status.ariavaBinPath === input.expectedAriavaBinPath
    && status.runtimePathMatchesCurrent === true && status.ariavaBinPathMatchesCurrent === true;
}

export function serviceReferencesReady(input: StrictReadinessInput): boolean {
  const record = input.serviceRecord;
  return Boolean(record && record.configPath === input.config.configPath
    && sameStorage(record.identityReference, input.config.identity?.privateKeyStorage));
}

export function exactPiPackageReady(status: PiExtensionStatus | undefined, version: string): boolean {
  return Boolean(status?.installed && status.managed && status.sourceOwnership === 'managed-exact'
    && status.registeredSource === status.expectedSource
    && status.manifestName === '@ariava/pi-extension' && status.manifestVersion === version
    && status.installPath === status.expectedManagedPath && status.mismatchReasons.length === 0);
}

function sameStorage(left: HostPrivateKeyStorage | undefined, right: HostPrivateKeyStorage | undefined): boolean {
  return Boolean(left && right && JSON.stringify(left) === JSON.stringify(right));
}
