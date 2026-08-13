import type { HostPrivateKeyStorage } from '../../identity/types';
import type { AriavaInstallMetadata } from '../config';
import { AriavaCliError } from '../service/errors';
import type {
  AriavaServiceInstallRecord,
  ServiceBackend,
  ServiceManager,
  ServiceStatus,
} from '../service/types';

export type OnboardingServiceManager = Pick<ServiceManager, 'support' | 'backend' | 'install' | 'status'>;

export type OnboardingServiceAction = 'reused' | 'started' | 'installed' | 'reconciled';
export type OnboardingServiceManagerPort = Pick<ServiceManager, 'status' | 'install' | 'start'> & {
  readonly backend: ServiceBackend;
};

export interface OnboardingServiceReconcileInput {
  runtimePath: string;
  ariavaBinPath: string;
  configPath: string;
  identityReference: HostPrivateKeyStorage;
  metadata: AriavaInstallMetadata;
}

export interface OnboardingServiceReconcileDependencies {
  serviceManager: OnboardingServiceManagerPort;
  persistServiceInstallMetadata(metadata: AriavaInstallMetadata): void;
  throwIfCancelled(): void;
  now?(): string;
  sleep?(milliseconds: number): Promise<void>;
  timeoutMs?: number;
  pollIntervalMs?: number;
}

interface OnboardingServiceReconcileResultBase {
  record: AriavaServiceInstallRecord;
  metadata: AriavaInstallMetadata;
}

export type OnboardingServiceReconcileResult =
  | OnboardingServiceReconcileResultBase & { reused: true; action: 'reused' }
  | OnboardingServiceReconcileResultBase & {
    reused: false;
    action: Exclude<OnboardingServiceAction, 'reused'>;
  };

export async function reconcileOnboardingService(
  input: OnboardingServiceReconcileInput,
  deps: OnboardingServiceReconcileDependencies,
): Promise<OnboardingServiceReconcileResult> {
  const manager = deps.serviceManager;
  const existing = input.metadata.service;
  if (existing && existing.backend !== manager.backend) {
    throw serviceError('ERR_SERVICE_METADATA', 'Service metadata belongs to a different backend.', false);
  }

  let metadata = input.metadata;
  let status = manager.status(existing, input.runtimePath, input.ariavaBinPath);
  const referencesMatch = serviceReferencesMatch(existing, input.configPath, input.identityReference);
  const pathsMatch = status.runtimePath === input.runtimePath
    && status.ariavaBinPath === input.ariavaBinPath
    && status.runtimePathMatchesCurrent === true
    && status.ariavaBinPathMatchesCurrent === true;
  const fullyReady = Boolean(existing && referencesMatch && pathsMatch && serviceStatusReady(status));
  if (fullyReady) return { record: existing!, metadata, reused: true, action: 'reused' };

  if (existing && (!referencesMatch || !pathsMatch) && !releaseOwnershipProven(metadata, input.ariavaBinPath)) {
    throw serviceError('ERR_SERVICE_METADATA', 'Stale service state cannot be reconciled without proven release ownership.', false);
  }

  deps.throwIfCancelled();
  let record = existing;
  let action: Exclude<OnboardingServiceAction, 'reused'> = 'started';
  if (!existing || !status.installed || !referencesMatch || !pathsMatch || !status.enabled || !status.loaded) {
    record = manager.install({
      runtimePath: input.runtimePath,
      ariavaBinPath: input.ariavaBinPath,
      configPath: input.configPath,
      identityReference: input.identityReference,
      installedAt: deps.now?.(),
    });
    metadata = { ...metadata, service: record };
    deps.persistServiceInstallMetadata(metadata);
    action = existing ? 'reconciled' : 'installed';
    status = manager.status(record, input.runtimePath, input.ariavaBinPath);
  }
  if (!status.processRunning) {
    deps.throwIfCancelled();
    manager.start(record);
    action = action === 'started' ? 'started' : action;
  }
  status = await waitForReadyService(record!, input.runtimePath, deps);
  if (!serviceStatusReady(status)) {
    throw serviceError('ERR_ONBOARDING_NOT_READY', 'Bridge service did not reach running state.', true);
  }
  return { record: record!, metadata, reused: false, action };
}

async function waitForReadyService(
  record: AriavaServiceInstallRecord,
  runtimePath: string,
  deps: OnboardingServiceReconcileDependencies,
): Promise<ServiceStatus> {
  const timeout = deps.timeoutMs ?? 10_000;
  const interval = deps.pollIntervalMs ?? 100;
  const sleep = deps.sleep ?? ((milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  let elapsed = 0;
  let status = deps.serviceManager.status(record, runtimePath, record.ariavaBinPath);
  while (!serviceStatusReady(status) && elapsed < timeout) {
    deps.throwIfCancelled();
    const wait = Math.min(interval, timeout - elapsed);
    await sleep(wait);
    elapsed += wait;
    status = deps.serviceManager.status(record, runtimePath, record.ariavaBinPath);
  }
  return status;
}

function serviceStatusReady(status: ServiceStatus): boolean {
  return status.support.supported && status.installed && status.enabled && status.loaded && status.processRunning;
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

function serviceError(code: AriavaCliError['code'], message: string, retryable: boolean): AriavaCliError {
  return new AriavaCliError(code, message, { step: 'bridge-service', retryable });
}
