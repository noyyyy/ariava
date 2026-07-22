import type { HostIdentity, HostIdentityInspection } from '../../identity/types';
import {
  ARIAVA_PRODUCTION_RELAY_BASE_URL,
  type AriavaInstallMetadata,
  type AriavaUserConfig,
  type ResolvedAriavaConfig,
} from '../config';
import type { HostInitializationResult } from '../initialization';
import type { PiPackageLifecycleResult } from '../pi-extension';
import { AriavaCliError } from '../service/errors';
import type { AriavaServiceInstallRecord, ServiceManager, ServiceStatus } from '../service/types';
import type { StableBootstrapInput, StableBootstrapResult } from './bootstrap';
import type { OwnedOnboardingLock } from './lock';
import type {
  OnboardingDetection,
  OnboardingResult,
  OnboardingStepId,
  OnboardingStepResult,
  OnboardingTarget,
  RuntimeProbe,
  StrictReadinessResult,
} from './types';

export interface OnboardingHostState {
  config: ResolvedAriavaConfig;
  identityInspection: HostIdentityInspection;
  identity: HostIdentity;
}

export interface OnboardingOrchestratorInput {
  target: OnboardingTarget;
  cliVersion: string;
  publicArgs: readonly string[];
  resumed: boolean;
  bootstrapVersion?: string;
  relayBaseUrl?: string;
  runtimePath: string;
}

export interface OnboardingCancellation {
  throwIfCancelled(): void;
}

export interface OnboardingOrchestratorDependencies {
  detect(): OnboardingDetection;
  bootstrap(input: StableBootstrapInput): StableBootstrapResult;
  reenter(command: string, args: readonly string[]): Promise<OnboardingResult>;
  acquireLock(): OwnedOnboardingLock;
  acquireBootstrapLock?(): OwnedOnboardingLock;
  loadUserConfig(): AriavaUserConfig;
  saveUserConfig(config: AriavaUserConfig): void;
  initializeHost(relayBaseUrl: string): Promise<HostInitializationResult>;
  loadHostState(): Promise<OnboardingHostState | undefined>;
  loadInstallMetadata(): AriavaInstallMetadata;
  saveInstallMetadata(metadata: AriavaInstallMetadata): void;
  serviceManager: ServiceManager;
  adapterProbe(): RuntimeProbe;
  proveBridgeHealth(state: OnboardingHostState, service: AriavaServiceInstallRecord): Promise<void>;
  installPi(cliVersion: string): PiPackageLifecycleResult;
  checkReadiness(input: {
    target: OnboardingTarget;
    stableCli: StableBootstrapResult['evidence'];
    state: OnboardingHostState;
    installMetadata: AriavaInstallMetadata;
    service: AriavaServiceInstallRecord;
    pi?: PiPackageLifecycleResult['status'];
  }): Promise<StrictReadinessResult>;
  cancellation?: OnboardingCancellation;
  now?(): string;
  sleep?(milliseconds: number): Promise<void>;
  serviceTimeoutMs?: number;
  servicePollIntervalMs?: number;
}

const noCancellation: OnboardingCancellation = { throwIfCancelled() {} };

/**
 * Composes onboarding primitives without owning CLI parsing or rendering.
 * Every decision is derived from injected read-only evidence or current persisted state.
 */
export async function runOnboardingOrchestrator(
  input: OnboardingOrchestratorInput,
  deps: OnboardingOrchestratorDependencies,
): Promise<OnboardingResult> {
  const steps: OnboardingStepResult[] = [];
  let currentStep: OnboardingStepId = 'preflight';
  const cancellation = deps.cancellation ?? noCancellation;

  try {
    const detection = deps.detect();
    requireSupportedPreflight(detection);
    steps.push(step('preflight', 'reused', { backend: detection.serviceSupport.backend }));

    currentStep = 'stable-cli';
    let bootstrap: StableBootstrapResult;
    // The parent owns this lock through the awaited stable-child handoff. The
    // authenticated internal bootstrap marker tells that child to prove its
    // stable path without attempting to acquire the parent's lock again.
    const bootstrapLock = input.bootstrapVersion === undefined ? deps.acquireBootstrapLock?.() : undefined;
    try {
      bootstrap = deps.bootstrap({
        version: input.cliVersion,
        publicArgs: input.publicArgs,
        resumed: input.resumed,
        ...(input.bootstrapVersion ? { bootstrapVersion: input.bootstrapVersion } : {}),
      });
      if (bootstrap.reentry) {
        const result = await deps.reenter(bootstrap.reentry.command, bootstrap.reentry.args);
        cancellation.throwIfCancelled();
        return result;
      }
    } finally {
      bootstrapLock?.release();
    }
    steps.push(step('stable-cli', 'reused', { version: input.cliVersion }));

    cancellation.throwIfCancelled();
    const lock = deps.acquireLock();
    try {
      currentStep = 'relay-config';
      cancellation.throwIfCancelled();
      const relay = persistRelaySelection(input.relayBaseUrl, deps);
      steps.push(step('relay-config', relay.changed ? 'installed' : 'reused'));

      currentStep = 'host-init';
      cancellation.throwIfCancelled();
      let state = await deps.loadHostState();
      const hostWasReady = state ? reusableHostState(state) : false;
      if (!hostWasReady) {
        await deps.initializeHost(relay.value);
        state = await deps.loadHostState();
        if (!state) throw onboardingError('ERR_IDENTITY_INVALID', 'Host initialization did not produce readable identity state.', currentStep, false);
        requireReadyHostState(state);
      }
      steps.push(step('host-init', hostWasReady ? 'reused' : 'installed'));

      currentStep = 'bridge-service';
      cancellation.throwIfCancelled();
      let metadata = deps.loadInstallMetadata();
      const stableMetadata = persistStableInstallerMetadata(metadata, bootstrap, input.cliVersion, deps);
      metadata = stableMetadata.metadata;
      const serviceResult = await reconcileService(input, bootstrap, state, metadata, deps);
      metadata = serviceResult.metadata;
      steps.push(step('bridge-service', serviceResult.reused ? 'reused' : 'ready', {
        backend: serviceResult.record.backend,
        action: serviceResult.action,
      }));

      // Adapter operations are deliberately unreachable until manager status and
      // authenticated local Adapter health both prove the Bridge is healthy.
      await deps.proveBridgeHealth(state, serviceResult.record);
      cancellation.throwIfCancelled();

      currentStep = 'adapter-detect';
      const adapter = deps.adapterProbe();
      if (input.target === 'adapter-installed' && !adapter.present) {
        throw onboardingError('ERR_AGENT_RUNTIME_NOT_FOUND', 'Pi is not available for adapter installation.', currentStep, true);
      }
      steps.push(step('adapter-detect', 'ready', { pi: adapter.present }));

      currentStep = 'adapter-install';
      let pi: PiPackageLifecycleResult | undefined;
      if (input.target === 'adapter-installed') {
        cancellation.throwIfCancelled();
        pi = deps.installPi(input.cliVersion);
        if (pi.action !== 'reused') {
          metadata = { ...metadata, piExtension: pi.record };
          deps.saveInstallMetadata(metadata);
        }
        steps.push(step('adapter-install', pi.action === 'reused' ? 'reused' : 'installed', { action: pi.action }));
      } else {
        steps.push(step('adapter-install', 'skipped'));
      }

      cancellation.throwIfCancelled();
      currentStep = 'strict-readiness';
      const readiness = await deps.checkReadiness({
        target: input.target,
        stableCli: bootstrap.evidence,
        state,
        installMetadata: metadata,
        service: serviceResult.record,
        ...(pi ? { pi: pi.status } : {}),
      });
      cancellation.throwIfCancelled();
      if (!readiness.ready) {
        steps.push(step('strict-readiness', 'failed', { checks: readiness.checks }));
        steps.push(step('completion', 'skipped'));
        return failureResult(input.target, steps, 'strict-readiness', true);
      }
      steps.push(step('strict-readiness', readiness.readiness === 'reload-pending' ? 'reload-pending' : 'ready', {
        checks: readiness.checks,
      }));

      currentStep = 'completion';
      steps.push(step('completion', 'ready'));
      return {
        target: input.target,
        readiness: readiness.readiness,
        steps,
        nextActions: completionActions(input.target),
      };
    } finally {
      lock.release();
    }
  } catch (error) {
    return failureFromError(input.target, steps, currentStep, error);
  }
}

function requireSupportedPreflight(detection: OnboardingDetection): void {
  const support = detection.serviceSupport;
  if (support.supported) return;
  const code = support.reason === 'systemctl-not-found'
    ? 'ERR_SYSTEMCTL_NOT_FOUND'
    : support.reason === 'systemd-user-manager-unavailable'
      ? 'ERR_SYSTEMD_USER_UNAVAILABLE'
      : 'ERR_UNSUPPORTED_PLATFORM';
  const remediation = support.detail ?? support.message;
  throw onboardingError(code, support.message ?? 'A supported user service manager is required.', 'preflight', false, {
    reason: support.reason,
    ...(remediation ? { remediation: { message: remediation } } : {}),
  });
}

function persistRelaySelection(
  requested: string | undefined,
  deps: Pick<OnboardingOrchestratorDependencies, 'loadUserConfig' | 'saveUserConfig'>,
): { value: string; changed: boolean } {
  const config = deps.loadUserConfig();
  const persisted = config.relayBaseUrl?.trim();
  const value = persisted || requested?.trim() || ARIAVA_PRODUCTION_RELAY_BASE_URL;
  if (persisted) return { value, changed: false };
  deps.saveUserConfig({ ...config, relayBaseUrl: value });
  return { value, changed: true };
}

function reusableHostState(state: OnboardingHostState): boolean {
  const inspection = state.identityInspection;
  if (inspection.status === 'not-initialized') return false;
  requireReadyIdentity(state);
  const config = state.config;
  return Boolean(config.relayBaseUrl && config.hostName && config.agentAdapterSecret && config.identity
    && config.identity.hostId === state.identity.hostId);
}

function requireReadyHostState(state: OnboardingHostState): void {
  requireReadyIdentity(state);
  if (!reusableHostState(state)) {
    throw onboardingError('ERR_ONBOARDING_NOT_READY', 'Host initialization did not produce complete persisted configuration.', 'host-init', false);
  }
}

function requireReadyIdentity(state: OnboardingHostState): void {
  const inspection = state.identityInspection;
  if (inspection.status !== 'ready' || inspection.pendingRotation || !inspection.ownerIntegrity
    || !inspection.permissionIntegrity || !inspection.metadataIntegrity
    || inspection.hostId !== state.identity.hostId || inspection.keyId !== state.identity.keyId) {
    throw onboardingError('ERR_IDENTITY_INVALID', 'Existing Host identity state is not safe to reuse.', 'host-init', false);
  }
}

function persistStableInstallerMetadata(
  metadata: AriavaInstallMetadata,
  bootstrap: StableBootstrapResult,
  cliVersion: string,
  deps: Pick<OnboardingOrchestratorDependencies, 'saveInstallMetadata' | 'now'>,
): { metadata: AriavaInstallMetadata; changed: boolean } {
  const recordedAt = deps.now?.() ?? new Date().toISOString();
  const installer = { manager: 'npm' as const, ariavaBinRealPath: bootstrap.evidence.executablePath, recordedAt };
  const bridgeSource = metadata.bridgeSource ?? { kind: 'npm-package' as const, package: `ariava@${cliVersion}`, updatedAt: recordedAt };
  if (metadata.installer?.manager === installer.manager
    && metadata.installer.ariavaBinRealPath === installer.ariavaBinRealPath
    && metadata.bridgeSource) {
    return { metadata, changed: false };
  }
  const next = { ...metadata, installer, bridgeSource };
  deps.saveInstallMetadata(next);
  return { metadata: next, changed: true };
}

async function reconcileService(
  input: OnboardingOrchestratorInput,
  bootstrap: StableBootstrapResult,
  state: OnboardingHostState,
  metadata: AriavaInstallMetadata,
  deps: OnboardingOrchestratorDependencies,
): Promise<{ record: AriavaServiceInstallRecord; metadata: AriavaInstallMetadata; reused: boolean; action: string }> {
  const manager = deps.serviceManager;
  if (!manager.support.supported || !manager.backend) {
    throw onboardingError('ERR_UNSUPPORTED_PLATFORM', 'No supported service backend is available.', 'bridge-service', false);
  }
  const existing = metadata.service;
  if (existing && existing.backend !== manager.backend) {
    throw onboardingError('ERR_SERVICE_METADATA', 'Service metadata belongs to a different backend.', 'bridge-service', false);
  }

  let status = manager.status(existing, input.runtimePath, bootstrap.evidence.executablePath);
  const referencesMatch = serviceReferencesMatch(existing, state);
  const pathsMatch = status.runtimePath === input.runtimePath
    && status.ariavaBinPath === bootstrap.evidence.executablePath
    && status.runtimePathMatchesCurrent === true
    && status.ariavaBinPathMatchesCurrent === true;
  const fullyReady = Boolean(existing && referencesMatch && pathsMatch && serviceStatusReady(status));
  if (fullyReady) return { record: existing!, metadata, reused: true, action: 'reused' };

  if (existing && (!referencesMatch || !pathsMatch) && !releaseOwnershipProven(metadata, bootstrap)) {
    throw onboardingError('ERR_SERVICE_METADATA', 'Stale service state cannot be reconciled without proven release ownership.', 'bridge-service', false);
  }

  cancellationPoint(deps);
  let record = existing;
  let action = 'started';
  if (!existing || !status.installed || !referencesMatch || !pathsMatch || !status.enabled || !status.loaded) {
    record = manager.install({
      runtimePath: input.runtimePath,
      ariavaBinPath: bootstrap.evidence.executablePath,
      configPath: state.config.configPath,
      identityReference: state.identity.privateKeyStorage,
      installedAt: deps.now?.(),
    });
    metadata = { ...metadata, service: record };
    deps.saveInstallMetadata(metadata);
    action = existing ? 'reconciled' : 'installed';
    status = manager.status(record, input.runtimePath, bootstrap.evidence.executablePath);
  }
  if (!status.processRunning) {
    cancellationPoint(deps);
    manager.start(record);
    action = action === 'started' ? 'started' : action;
  }
  status = await waitForReadyService(record!, input, deps);
  if (!serviceStatusReady(status)) {
    throw onboardingError('ERR_ONBOARDING_NOT_READY', 'Bridge service did not reach running state.', 'bridge-service', true);
  }
  return { record: record!, metadata, reused: false, action };
}

async function waitForReadyService(
  record: AriavaServiceInstallRecord,
  input: OnboardingOrchestratorInput,
  deps: OnboardingOrchestratorDependencies,
): Promise<ServiceStatus> {
  const timeout = deps.serviceTimeoutMs ?? 10_000;
  const interval = deps.servicePollIntervalMs ?? 100;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  let elapsed = 0;
  let status = deps.serviceManager.status(record, input.runtimePath, record.ariavaBinPath);
  while (!serviceStatusReady(status) && elapsed < timeout) {
    cancellationPoint(deps);
    const wait = Math.min(interval, timeout - elapsed);
    await sleep(wait);
    elapsed += wait;
    status = deps.serviceManager.status(record, input.runtimePath, record.ariavaBinPath);
  }
  return status;
}

function serviceStatusReady(status: ServiceStatus): boolean {
  return status.support.supported && status.installed && status.enabled && status.loaded && status.processRunning;
}

function serviceReferencesMatch(record: AriavaServiceInstallRecord | undefined, state: OnboardingHostState): boolean {
  return Boolean(record && record.configPath === state.config.configPath
    && JSON.stringify(record.identityReference) === JSON.stringify(state.identity.privateKeyStorage));
}

function releaseOwnershipProven(metadata: AriavaInstallMetadata, bootstrap: StableBootstrapResult): boolean {
  const installer = metadata.installer;
  const source = metadata.bridgeSource?.kind;
  return Boolean(installer
    && installer.ariavaBinRealPath === bootstrap.evidence.executablePath
    && (!source || source === 'release-bundle' || source === 'npm-package'));
}

function cancellationPoint(deps: Pick<OnboardingOrchestratorDependencies, 'cancellation'>): void {
  (deps.cancellation ?? noCancellation).throwIfCancelled();
}

function failureFromError(
  target: OnboardingTarget,
  completed: OnboardingStepResult[],
  current: OnboardingStepId,
  error: unknown,
): OnboardingResult {
  const code = error instanceof AriavaCliError ? error.code : 'ERR_ONBOARDING_NOT_READY';
  const errorData = error instanceof AriavaCliError ? error.data : {};
  const retryable = error instanceof AriavaCliError ? error.data.retryable !== false : true;
  const steps = [...completed];
  if (!steps.some((entry) => entry.id === current)) {
    steps.push(step(current, 'failed', { code, retryable, ...errorData }));
  }
  appendSkippedSteps(steps);
  const remediation = errorData.remediation && typeof errorData.remediation === 'object'
    ? errorData.remediation as { message?: string; command?: string }
    : undefined;
  return failureResult(target, steps, current, retryable, code, remediation);
}

function failureResult(
  target: OnboardingTarget,
  steps: OnboardingStepResult[],
  failedStep: OnboardingStepId,
  retryable: boolean,
  code = 'ERR_ONBOARDING_NOT_READY',
  remediation?: { message?: string; command?: string },
): OnboardingResult {
  return {
    target,
    readiness: 'failed',
    steps,
    nextActions: retryable
      ? [{
          id: failedStep === 'adapter-detect' ? 'install-pi' : 'retry-onboarding',
          message: remediation?.message ?? code,
          ...(remediation?.command ? { command: remediation.command } : {}),
        }]
      : [],
  };
}

function appendSkippedSteps(steps: OnboardingStepResult[]): void {
  const ordered: OnboardingStepId[] = [
    'preflight', 'stable-cli', 'relay-config', 'host-init', 'bridge-service',
    'adapter-detect', 'adapter-install', 'strict-readiness', 'completion',
  ];
  const last = steps.at(-1)?.id;
  const start = last ? ordered.indexOf(last) + 1 : 0;
  for (const id of ordered.slice(start)) steps.push(step(id, 'skipped'));
}

function completionActions(target: OnboardingTarget): OnboardingResult['nextActions'] {
  return target === 'adapter-installed'
    ? [
        { id: 'reload-pi', command: '/reload' },
        { id: 'pair-watch', command: 'ariava pair <PAIRING_CODE>' },
      ]
    : [{ id: 'pair-watch', command: 'ariava pair <PAIRING_CODE>' }];
}

function step(id: OnboardingStepId, status: OnboardingStepResult['status'], detail?: Record<string, unknown>): OnboardingStepResult {
  return { id, status, ...(detail && Object.keys(detail).length > 0 ? { detail } : {}) };
}

function onboardingError(
  code: AriavaCliError['code'],
  message: string,
  stepId: OnboardingStepId,
  retryable: boolean,
  detail: Record<string, unknown> = {},
): AriavaCliError {
  return new AriavaCliError(code, message, { step: stepId, retryable, ...detail });
}
