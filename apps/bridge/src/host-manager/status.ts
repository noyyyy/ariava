import { existsSync } from 'node:fs';
import type { BridgeConfig } from '../types';
import type { AriavaInstallMetadata, ResolvedAriavaConfig } from './config';
import type { PiExtensionStatus } from './pi-extension';
import type { ServiceBackend, ServiceSupportReason } from './service/index';

export interface HostServiceStatusInput {
  backend?: ServiceBackend;
  support: {
    supported: boolean;
    reason: ServiceSupportReason;
  };
  installed: boolean;
  enabled: boolean;
  loaded: boolean;
  processRunning: boolean;
  runtimeNameIsNode?: boolean;
  runtimeVersionSupported?: boolean;
  runtimeVersionMatchesRecorded?: boolean;
  runtimePathMatchesCurrent?: boolean;
  ariavaBinPathMatchesCurrent?: boolean;
  runtimeCryptoSelfTestPassed?: boolean;
}

export interface HostManagerStatus {
  cliVersion: string;
  configComplete: boolean;
  bridgeHealth: 'online' | 'degraded' | 'offline';
  hostId: string;
  hostName: string;
  relayBaseUrl: string;
  service: {
    backend?: ServiceBackend;
    supported: boolean;
    supportReason: ServiceSupportReason;
    installed: boolean;
    enabled: boolean;
    loaded: boolean;
    processRunning: boolean;
    runtimeNameIsNode?: boolean;
    runtimeVersionSupported?: boolean;
    runtimeVersionMatchesRecorded?: boolean;
    runtimePathMatchesCurrent?: boolean;
    ariavaBinPathMatchesCurrent?: boolean;
    runtimeCryptoSelfTestPassed?: boolean;
  };
  piExtension: PiExtensionStatus;
  environmentOverrides: string[];
  bridgeSourceKind?: AriavaInstallMetadata['bridgeSource'] extends infer T ? (T extends { kind: infer K } ? K : never) : never;
  identity: {
    status: 'not-initialized' | 'configured' | 'ready' | 'rotation-pending' | 'invalid';
    storageType?: 'linux-json' | 'macos-keychain';
    storageReference?: import('../identity/types').HostPrivateKeyStorage;
    path?: string;
    hostId?: string;
    keyId?: string;
    algorithm?: 'Ed25519';
    publicKeyFingerprint?: string;
    ownerIntegrity?: boolean;
    permissionIntegrity?: boolean;
    metadataIntegrity?: boolean;
    pendingRotation?: boolean;
    pendingOperationId?: string;
  };
}

export function buildHostManagerStatus(args: {
  config: ResolvedAriavaConfig;
  bridgeConfig: BridgeConfig;
  installMetadata: AriavaInstallMetadata;
  serviceStatus: HostServiceStatusInput;
  piStatus: PiExtensionStatus;
  cliVersion: string;
  identityInspection?: HostManagerStatus['identity'];
}): HostManagerStatus {
  const { config, bridgeConfig, installMetadata, serviceStatus, piStatus, cliVersion, identityInspection } = args;
  return {
    cliVersion,
    configComplete: isConfigComplete(config),
    bridgeHealth: deriveBridgeHealth(bridgeConfig.statePath, serviceStatus.installed),
    hostId: config.identity?.hostId ?? bridgeConfig.hostId,
    hostName: config.hostName || bridgeConfig.hostName,
    relayBaseUrl: bridgeConfig.relayBaseUrl,
    service: {
      ...(serviceStatus.backend ? { backend: serviceStatus.backend } : {}),
      supported: serviceStatus.support.supported,
      supportReason: serviceStatus.support.reason,
      installed: serviceStatus.installed,
      enabled: serviceStatus.enabled,
      loaded: serviceStatus.loaded,
      processRunning: serviceStatus.processRunning,
      ...(serviceStatus.runtimeNameIsNode === undefined ? {} : { runtimeNameIsNode: serviceStatus.runtimeNameIsNode }),
      ...(serviceStatus.runtimeVersionSupported === undefined ? {} : { runtimeVersionSupported: serviceStatus.runtimeVersionSupported }),
      ...(serviceStatus.runtimeVersionMatchesRecorded === undefined ? {} : { runtimeVersionMatchesRecorded: serviceStatus.runtimeVersionMatchesRecorded }),
      ...(serviceStatus.runtimePathMatchesCurrent === undefined
        ? {}
        : { runtimePathMatchesCurrent: serviceStatus.runtimePathMatchesCurrent }),
      ...(serviceStatus.ariavaBinPathMatchesCurrent === undefined
        ? {}
        : { ariavaBinPathMatchesCurrent: serviceStatus.ariavaBinPathMatchesCurrent }),
      ...(serviceStatus.runtimeCryptoSelfTestPassed === undefined ? {} : { runtimeCryptoSelfTestPassed: serviceStatus.runtimeCryptoSelfTestPassed }),
    },
    piExtension: piStatus,
    environmentOverrides: config.environmentOverrides,
    bridgeSourceKind: installMetadata.bridgeSource?.kind,
    identity: identityInspection ?? (config.identity ? {
      status: 'configured',
      hostId: config.identity.hostId,
      keyId: config.identity.keyId,
      algorithm: config.identity.algorithm,
      publicKeyFingerprint: config.identity.publicKeyFingerprint,
      storageType: config.identity.privateKeyStorage.type,
      storageReference: config.identity.privateKeyStorage,
      ownerIntegrity: false,
      permissionIntegrity: false,
      metadataIntegrity: false,
      pendingRotation: false,
    } : { status: 'not-initialized', pendingRotation: false }),
  };
}

export function isConfigComplete(config: ResolvedAriavaConfig): boolean {
  return Boolean(config.relayBaseUrl && config.hostName && config.identity?.hostId && config.identity?.keyId);
}

function deriveBridgeHealth(statePath: string, serviceInstalled: boolean): 'online' | 'degraded' | 'offline' {
  if (existsSync(statePath)) return 'online';
  return serviceInstalled ? 'degraded' : 'offline';
}
