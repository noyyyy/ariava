import type { HostPrivateKeyStorage } from '../../identity/types';
import type { AriavaInstallMetadata } from '../config';
import { AriavaCliError } from '../service/errors';
import type { AriavaServiceInstallRecord, ServiceManager, ServiceStatus } from '../service/types';

export type OnboardingServiceManager = Pick<
  ServiceManager,
  'support' | 'backend' | 'install' | 'status'
>;

export interface ServiceReconcileInput {
  runtimePath: string;
  ariavaBinPath: string;
  configPath: string;
  identityReference: HostPrivateKeyStorage;
  metadata: AriavaInstallMetadata;
}

export interface ServiceReconcileDependencies {
  serviceManager: OnboardingServiceManager;
  now?(): string;
}

export interface ServiceReconcilePlan {
  existing?: AriavaServiceInstallRecord;
  status: ServiceStatus;
  installRequired: boolean;
  reused: boolean;
  action: 'reused' | 'started' | 'installed' | 'reconciled';
}

export interface InstalledServiceResult {
  record: AriavaServiceInstallRecord;
  metadata: AriavaInstallMetadata;
  action: 'installed' | 'reconciled';
}

export function inspectOnboardingService(
  input: ServiceReconcileInput,
  deps: ServiceReconcileDependencies,
): ServiceReconcilePlan {
  const manager = deps.serviceManager;
  if (!manager.support.supported || !manager.backend) {
    throw serviceError('ERR_UNSUPPORTED_PLATFORM', 'No supported service backend is available.', false);
  }
  const existing = input.metadata.service;
  if (existing && existing.backend !== manager.backend) {
    throw serviceError('ERR_SERVICE_METADATA', 'Service metadata belongs to a different backend.', false);
  }

  const status = serviceStatus(input, existing, manager);
  const referencesMatch = serviceReferencesMatch(existing, input.configPath, input.identityReference);
  const pathsMatch = servicePathsMatch(status, input.runtimePath, input.ariavaBinPath);
  const reused = Boolean(existing && referencesMatch && pathsMatch && serviceStatusReady(status));
  if (reused) {
    return { existing, status, installRequired: false, reused: true, action: 'reused' };
  }

  if (existing && (!referencesMatch || !pathsMatch) && !releaseOwnershipProven(input.metadata, input.ariavaBinPath)) {
    throw serviceError('ERR_SERVICE_METADATA', 'Stale service state cannot be reconciled without proven release ownership.', false);
  }

  const installRequired = !existing || !status.installed || !referencesMatch || !pathsMatch || !status.enabled || !status.loaded;
  return {
    ...(existing ? { existing } : {}),
    status,
    installRequired,
    reused: false,
    action: installRequired ? (existing ? 'reconciled' : 'installed') : 'started',
  };
}

export function installOnboardingService(
  input: ServiceReconcileInput,
  deps: ServiceReconcileDependencies,
): InstalledServiceResult {
  const record = deps.serviceManager.install({
    runtimePath: input.runtimePath,
    ariavaBinPath: input.ariavaBinPath,
    configPath: input.configPath,
    identityReference: input.identityReference,
    installedAt: deps.now?.(),
  });
  return {
    record,
    metadata: { ...input.metadata, service: record },
    action: input.metadata.service ? 'reconciled' : 'installed',
  };
}

export function serviceStatus(
  input: Pick<ServiceReconcileInput, 'runtimePath' | 'ariavaBinPath'>,
  record: AriavaServiceInstallRecord | undefined,
  manager: OnboardingServiceManager,
): ServiceStatus {
  return manager.status(record, input.runtimePath, input.ariavaBinPath);
}

export function servicePollWait(
  elapsed: number,
  timeoutMs: number | undefined,
  pollIntervalMs: number | undefined,
): number | undefined {
  const timeout = timeoutMs ?? 10_000;
  if (elapsed >= timeout) return undefined;
  return Math.min(pollIntervalMs ?? 100, timeout - elapsed);
}

export function requireReadyOnboardingService(status: ServiceStatus): void {
  if (!serviceStatusReady(status)) {
    throw serviceError('ERR_ONBOARDING_NOT_READY', 'Bridge service did not reach running state.', true);
  }
}

export function serviceStatusReady(status: ServiceStatus): boolean {
  return status.support.supported && status.installed && status.enabled && status.loaded && status.processRunning;
}

function servicePathsMatch(status: ServiceStatus, runtimePath: string, ariavaBinPath: string): boolean {
  return status.runtimePath === runtimePath
    && status.ariavaBinPath === ariavaBinPath
    && status.runtimePathMatchesCurrent === true
    && status.ariavaBinPathMatchesCurrent === true;
}

function serviceReferencesMatch(
  record: AriavaServiceInstallRecord | undefined,
  configPath: string,
  identityReference: HostPrivateKeyStorage,
): boolean {
  return Boolean(record && record.configPath === configPath
    && JSON.stringify(record.identityReference) === JSON.stringify(identityReference));
}

function releaseOwnershipProven(metadata: AriavaInstallMetadata, ariavaBinPath: string): boolean {
  const installer = metadata.installer;
  const source = metadata.bridgeSource?.kind;
  return Boolean(installer
    && installer.ariavaBinRealPath === ariavaBinPath
    && (!source || source === 'release-bundle' || source === 'npm-package'));
}

function serviceError(
  code: 'ERR_UNSUPPORTED_PLATFORM' | 'ERR_SERVICE_METADATA' | 'ERR_ONBOARDING_NOT_READY',
  message: string,
  retryable: boolean,
): AriavaCliError {
  return new AriavaCliError(code, message, { step: 'bridge-service', retryable });
}
