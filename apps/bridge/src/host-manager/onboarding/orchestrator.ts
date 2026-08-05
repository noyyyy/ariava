import { HostIdentityError } from '../../identity/errors';
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
    steps.push(step('preflight', 'reused', preflightDetail(detection)));

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
        const failedCheck = firstFailedCheck(readiness.checks);
        const failedCode = failedCheck?.code ?? firstFailedCheckCode(readiness.checks);
        const failedMessage = failedCheck?.message
          ?? readiness.nextActions[0]?.message
          ?? (failedCode ? failedCode : 'Strict readiness checks failed.');
        const remediation = readiness.nextActions[0]
          ? {
              message: readiness.nextActions[0].message ?? failedMessage,
              ...(readiness.nextActions[0].command ? { command: readiness.nextActions[0].command } : {}),
            }
          : undefined;
        steps.push(step('strict-readiness', 'failed', {
          checks: readiness.checks,
          ...(failedCode ? { code: failedCode } : { code: 'ERR_ONBOARDING_NOT_READY' }),
          message: failedMessage,
          ...(remediation ? { remediation } : {}),
        }));
        steps.push(step('completion', 'skipped'));
        return failureResult(
          input.target,
          steps,
          'strict-readiness',
          true,
          failedCode ?? 'ERR_ONBOARDING_NOT_READY',
          failedMessage,
          remediation,
        );
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

function preflightDetail(detection: OnboardingDetection): Record<string, unknown> {
  return {
    backend: detection.serviceSupport.backend,
    ...(detection.sourceDev.kind !== 'absent' ? { sourceDev: detection.sourceDev } : {}),
  };
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
  if (inspection.status === 'ready' && !inspection.pendingRotation && inspection.ownerIntegrity
    && inspection.permissionIntegrity && inspection.metadataIntegrity
    && inspection.hostId === state.identity.hostId && inspection.keyId === state.identity.keyId) {
    return;
  }
  const reason = identityNotReadyReason(inspection, state.identity);
  throw onboardingError('ERR_IDENTITY_INVALID', reason, 'host-init', false, {
    identityStatus: inspection.status,
    pendingRotation: inspection.pendingRotation,
    remediation: {
      message: reason,
      command: 'ariava host reset --confirm',
    },
  });
}

function identityNotReadyReason(inspection: HostIdentityInspection, identity: HostIdentity): string {
  if (inspection.status === 'rotation-pending' || inspection.pendingRotation) {
    return 'Host identity key rotation is pending and must be completed or explicitly reset before onboarding can continue.';
  }
  if (inspection.status === 'invalid') {
    return 'Host identity evidence exists but is invalid or unreadable (for example a locked or inaccessible Keychain private key). Explicit reset is required.';
  }
  if (inspection.status === 'not-initialized') {
    return 'Host identity is not initialized.';
  }
  if (!inspection.ownerIntegrity || !inspection.permissionIntegrity || !inspection.metadataIntegrity) {
    return 'Host identity integrity checks failed; the persisted identity is not safe to reuse.';
  }
  if (inspection.hostId !== identity.hostId || inspection.keyId !== identity.keyId) {
    return 'Persisted Host identity metadata does not match the loaded Host key material.';
  }
  return 'Existing Host identity state is not safe to reuse.';
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
  const normalized = normalizeOrchestratorFailure(error, current);
  const steps = [...completed];
  if (!steps.some((entry) => entry.id === current)) {
    steps.push(step(current, 'failed', {
      ...normalized.detail,
      code: normalized.code,
      message: normalized.message,
      retryable: normalized.retryable,
    }));
  }
  appendSkippedSteps(steps);
  return failureResult(
    target,
    steps,
    current,
    normalized.retryable,
    normalized.code,
    normalized.message,
    normalized.remediation,
  );
}

function normalizeOrchestratorFailure(error: unknown, current: OnboardingStepId): {
  code: string;
  message: string;
  retryable: boolean;
  detail: Record<string, unknown>;
  remediation?: { message?: string; command?: string };
} {
  if (error instanceof AriavaCliError) {
    const detail = { ...error.data };
    const remediation = remediationFromUnknown(detail.remediation)
      ?? defaultRemediationForCode(error.code, error.message);
    if (remediation) detail.remediation = remediation;
    return {
      code: error.code,
      message: error.message,
      retryable: error.data.retryable !== false,
      detail,
      ...(remediation ? { remediation } : {}),
    };
  }
  if (error instanceof HostIdentityError) {
    const remediation = defaultRemediationForCode(error.code, error.message) ?? {
      message: error.message,
      command: 'ariava host reset --confirm',
    };
    return {
      code: error.code,
      message: error.message,
      retryable: error.code === 'ERR_IDENTITY_KEYCHAIN_LOCKED',
      detail: { step: current, remediation },
      remediation,
    };
  }
  const message = error instanceof Error ? error.message : String(error);
  return {
    code: 'ERR_ONBOARDING_NOT_READY',
    message,
    retryable: true,
    detail: { step: current },
  };
}

function remediationFromUnknown(value: unknown): { message?: string; command?: string } | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const entry = value as { message?: unknown; command?: unknown };
  const remediation: { message?: string; command?: string } = {};
  if (typeof entry.message === 'string' && entry.message.length > 0) remediation.message = entry.message;
  if (typeof entry.command === 'string' && entry.command.length > 0) remediation.command = entry.command;
  return remediation.message || remediation.command ? remediation : undefined;
}

function defaultRemediationForCode(code: string, message: string): { message: string; command?: string } | undefined {
  if (code === 'ERR_IDENTITY_KEYCHAIN_LOCKED') {
    return { message, command: 'security unlock-keychain "$HOME/Library/Keychains/login.keychain-db"' };
  }
  if (code === 'ERR_IDENTITY_INVALID' || code === 'ERR_IDENTITY_MISSING' || code === 'ERR_IDENTITY_PERMISSIONS' || code === 'ERR_IDENTITY_RESET_REQUIRED') {
    return { message, command: 'ariava host reset --confirm' };
  }
  if (code === 'ERR_IDENTITY_NOT_INITIALIZED') {
    return { message, command: 'ariava setup' };
  }
  if (code === 'ERR_SERVICE_NOT_INSTALLED' || code === 'ERR_SERVICE_METADATA' || code === 'ERR_SERVICE_INSTALL') {
    return { message, command: 'ariava service reinstall' };
  }
  if (code === 'ERR_AGENT_ADAPTER_DISCOVERY' || code === 'ERR_AGENT_ADAPTER_NOT_LOOPBACK') {
    return { message, command: 'ariava service restart' };
  }
  if (code === 'ERR_RELAY_UNREACHABLE' || code === 'ERR_RELAY_AUTH_FAILED' || code === 'ERR_RELAY_CONFIG_REQUIRED') {
    return { message, command: 'ariava doctor' };
  }
  if (code === 'ERR_AGENT_RUNTIME_NOT_FOUND' || code === 'ERR_EXTENSION_INSTALL' || code === 'ERR_EXTENSION_VERSION_MISMATCH' || code === 'ERR_EXTENSION_UNMANAGED') {
    return { message, command: 'ariava setup --extension pi' };
  }
  if (code === 'ERR_STABLE_CLI_PATH' || code === 'ERR_STABLE_CLI_INSTALL') {
    return { message, command: 'npx --yes ariava@latest setup' };
  }
  if (code === 'ERR_ONBOARDING_NOT_READY') {
    return { message, command: 'ariava setup --resume' };
  }
  return { message };
}

function failureResult(
  target: OnboardingTarget,
  steps: OnboardingStepResult[],
  failedStep: OnboardingStepId,
  retryable: boolean,
  code = 'ERR_ONBOARDING_NOT_READY',
  message = code,
  remediation?: { message?: string; command?: string },
): OnboardingResult {
  const actionMessage = remediation?.message ?? message ?? code;
  const action = {
    id: failedStep === 'adapter-detect' ? 'install-pi' : retryable ? 'retry-onboarding' : 'resolve-failure',
    message: actionMessage,
    ...(remediation?.command ? { command: remediation.command } : {}),
  };
  return {
    target,
    readiness: 'failed',
    steps,
    nextActions: [action],
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

function firstFailedCheck(checks: StrictReadinessResult['checks']): StrictReadinessResult['checks'][number] | undefined {
  return checks.find((check) => !check.ready);
}

function firstFailedCheckCode(checks: StrictReadinessResult['checks']): string | undefined {
  for (const check of checks) {
    if (!check.ready && typeof check.code === 'string' && check.code.length > 0) return check.code;
  }
  return undefined;
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
