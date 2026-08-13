import type { HostIdentity, HostIdentityInspection, HostIdentityMetadata, HostPrivateKeyStorage } from '../../../identity/types';
import type { AriavaInstallMetadata, ResolvedAriavaConfig } from '../../config';
import type { PiExtensionStatus } from '../../pi-extension';
import type { AriavaServiceInstallRecord, ServiceStatus } from '../../service/types';
import type { OnboardingCliEvidence } from '../types';

type StableCliInput = {
  cliVersion: string;
  stableCli: OnboardingCliEvidence;
  installMetadata: Pick<AriavaInstallMetadata, 'installer'>;
};

type PersistedConfigInput = {
  config: Pick<ResolvedAriavaConfig,
    'relayBaseUrl' | 'hostName' | 'agentAdapterSecret' | 'identity' | 'identityPath' | 'configPath' | 'environmentOverrides'>;
  identity: Pick<HostIdentity, 'hostId'>;
};

type IdentityInput = {
  identityInspection: HostIdentityInspection;
  identity: Pick<HostIdentity, 'hostId' | 'keyId'>;
};

type ServicePathsInput = {
  expectedRuntimePath: string;
  expectedAriavaBinPath: string;
};

type ServiceReferencesInput = {
  serviceRecord?: Pick<AriavaServiceInstallRecord, 'configPath' | 'identityReference'>;
  config: {
    configPath: ResolvedAriavaConfig['configPath'];
    identity?: Pick<HostIdentityMetadata, 'privateKeyStorage'>;
  };
};

export function stableCliMatches(input: StableCliInput): boolean {
  const installer = input.installMetadata.installer;
  return input.stableCli.packageVersion === input.cliVersion
    && Boolean(input.stableCli.packageRoot && input.stableCli.npmPrefix && input.stableCli.npmBinPath)
    && installer?.ariavaBinRealPath === input.stableCli.executablePath;
}

export function persistedConfigReady(input: PersistedConfigInput): boolean {
  const config = input.config;
  return Boolean(config.relayBaseUrl && config.hostName && config.agentAdapterSecret
    && config.identity?.hostId === input.identity.hostId
    && config.identityPath && config.configPath && config.environmentOverrides.length === 0);
}

export function identityReady(input: IdentityInput): boolean {
  const inspected = input.identityInspection;
  return inspected.status === 'ready' && inspected.ownerIntegrity && inspected.permissionIntegrity
    && inspected.metadataIntegrity && !inspected.pendingRotation
    && inspected.hostId === input.identity.hostId && inspected.keyId === input.identity.keyId;
}

export function servicePathsReady(
  input: ServicePathsInput,
  status: ServiceStatus,
): boolean {
  return status.runtimePath === input.expectedRuntimePath && status.ariavaBinPath === input.expectedAriavaBinPath
    && status.runtimePathMatchesCurrent === true && status.ariavaBinPathMatchesCurrent === true;
}

export function serviceReferencesReady(input: ServiceReferencesInput): boolean {
  const record = input.serviceRecord;
  return Boolean(record && record.configPath === input.config.configPath
    && sameStorage(record.identityReference, input.config.identity?.privateKeyStorage));
}

export function sameStorage(
  left: HostPrivateKeyStorage | undefined,
  right: HostPrivateKeyStorage | undefined,
): boolean {
  if (!left || !right || left.type !== right.type) return false;
  if (left.type === 'linux-json') return left.path === right.path;
  return left.service === right.service && left.account === right.account;
}

export function exactPiPackageReady(status: PiExtensionStatus | undefined, version: string): boolean {
  return Boolean(status?.installed && status.managed && status.sourceOwnership === 'managed-exact'
    && status.registeredSource === status.expectedSource
    && status.manifestName === '@ariava/pi-extension' && status.manifestVersion === version
    && status.installPath === status.expectedManagedPath && status.mismatchReasons.length === 0);
}
