import type { AriavaInstallMetadata, AriavaUserConfig } from '../config';
import type { HostInitializationResult } from '../initialization';
import type { PiPackageLifecycleResult } from '../pi-extension';
import { AriavaCliError } from '../service/errors';
import type { AriavaServiceInstallRecord } from '../service/types';
import type { StableBootstrapInput, StableBootstrapResult } from './bootstrap';
import {
  evaluateReadyHostState,
  evaluateReusableHostState,
  proposeRelaySelection,
  proposeStableInstallerMetadata,
  type HostIdentityReadinessFailure,
  type OnboardingHostState,
} from './host-state-policy';
import type { OwnedOnboardingLock } from './lock';
import { failureFromOnboardingError } from './onboarding-failure';
import { completionActions, onboardingStep } from './onboarding-result';
import { defaultReadinessRemediation } from './readiness/remediation';
import {
  inspectOnboardingService,
  installOnboardingService,
  requireReadyOnboardingService,
  servicePollWait,
  serviceStatus,
  serviceStatusReady,
  type OnboardingServiceManager,
} from './service-reconcile';
import type {
  OnboardingDetection,
  OnboardingResult,
  OnboardingStepId,
  OnboardingStepResult,
  OnboardingTarget,
  RuntimeProbe,
  StrictReadinessResult,
} from './types';

export type { OnboardingHostState } from './host-state-policy';

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
  serviceManager: OnboardingServiceManager & Pick<import('../service/types').ServiceManager, 'start'>;
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
  let currentStep: Exclude<OnboardingStepId, 'completion'> = 'preflight';
  const cancellation = deps.cancellation ?? noCancellation;

  try {
    const detection = deps.detect();
    requireSupportedPreflight(detection);
    steps.push(onboardingStep('preflight', 'reused', preflightDetail(detection)));

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
    steps.push(onboardingStep('stable-cli', 'reused', { version: input.cliVersion }));

    cancellation.throwIfCancelled();
    const lock = deps.acquireLock();
    try {
      currentStep = 'relay-config';
      cancellation.throwIfCancelled();
      const relay = proposeRelaySelection(deps.loadUserConfig(), input.relayBaseUrl);
      if (relay.changed) deps.saveUserConfig(relay.config);
      steps.push(onboardingStep('relay-config', relay.changed ? 'installed' : 'reused'));

      currentStep = 'host-init';
      cancellation.throwIfCancelled();
      let state = await deps.loadHostState();
      const reusableState = state ? evaluateReusableHostState(state) : { reusable: false as const };
      if (reusableState.identityFailure) throwIdentityNotReady(reusableState.identityFailure);
      const hostWasReady = reusableState.reusable;
      if (!hostWasReady) {
        await deps.initializeHost(relay.value);
        state = await deps.loadHostState();
        if (!state) throw onboardingError('ERR_IDENTITY_INVALID', 'Host initialization did not produce readable identity state.', currentStep, false);
        const readyState = evaluateReadyHostState(state);
        if (readyState.identityFailure) throwIdentityNotReady(readyState.identityFailure);
        if (!readyState.ready) {
          throw onboardingError('ERR_ONBOARDING_NOT_READY', 'Host initialization did not produce complete persisted configuration.', currentStep, false);
        }
      }
      steps.push(onboardingStep('host-init', hostWasReady ? 'reused' : 'installed'));

      currentStep = 'bridge-service';
      cancellation.throwIfCancelled();
      let metadata = deps.loadInstallMetadata();
      const recordedAt = deps.now?.() ?? new Date().toISOString();
      const stableMetadata = proposeStableInstallerMetadata(metadata, bootstrap, input.cliVersion, recordedAt);
      if (stableMetadata.changed) deps.saveInstallMetadata(stableMetadata.metadata);
      metadata = stableMetadata.metadata;
      const serviceInput = {
        runtimePath: input.runtimePath,
        ariavaBinPath: bootstrap.evidence.executablePath,
        configPath: state.config.configPath,
        identityReference: state.identity.privateKeyStorage,
        metadata,
      };
      const serviceDependencies = {
        serviceManager: deps.serviceManager,
        ...(deps.now ? { now: deps.now } : {}),
      };
      const servicePlan = inspectOnboardingService(serviceInput, serviceDependencies);
      let serviceRecord = servicePlan.existing;
      let serviceAction = servicePlan.action;
      let serviceStatusResult = servicePlan.status;

      if (!servicePlan.reused) {
        cancellation.throwIfCancelled();
        if (servicePlan.installRequired) {
          const installed = installOnboardingService(serviceInput, serviceDependencies);
          serviceRecord = installed.record;
          serviceAction = installed.action;
          metadata = installed.metadata;
          deps.saveInstallMetadata(metadata);
          serviceStatusResult = serviceStatus(serviceInput, serviceRecord, deps.serviceManager);
        }
        if (!serviceStatusResult.processRunning) {
          cancellation.throwIfCancelled();
          deps.serviceManager.start(serviceRecord);
        }

        let elapsed = 0;
        serviceStatusResult = serviceStatus(serviceInput, serviceRecord, deps.serviceManager);
        while (!serviceStatusReady(serviceStatusResult)) {
          const wait = servicePollWait(elapsed, deps.serviceTimeoutMs, deps.servicePollIntervalMs);
          if (wait === undefined) break;
          cancellation.throwIfCancelled();
          await (deps.sleep ?? ((milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds))))(wait);
          elapsed += wait;
          serviceStatusResult = serviceStatus(serviceInput, serviceRecord, deps.serviceManager);
        }
        requireReadyOnboardingService(serviceStatusResult);
      }

      const readyServiceRecord = serviceRecord!;
      steps.push(onboardingStep('bridge-service', servicePlan.reused ? 'reused' : 'ready', {
        backend: readyServiceRecord.backend,
        action: serviceAction,
      }));

      // Adapter operations are deliberately unreachable until manager status and
      // authenticated local Adapter health both prove the Bridge is healthy.
      await deps.proveBridgeHealth(state, readyServiceRecord);
      cancellation.throwIfCancelled();

      currentStep = 'adapter-detect';
      const adapter = deps.adapterProbe();
      if (input.target === 'adapter-installed' && !adapter.present) {
        throw onboardingError('ERR_AGENT_RUNTIME_NOT_FOUND', 'Pi is not available for adapter installation.', currentStep, true);
      }
      steps.push(onboardingStep('adapter-detect', 'ready', { pi: adapter.present }));

      currentStep = 'adapter-install';
      let pi: PiPackageLifecycleResult | undefined;
      if (input.target === 'adapter-installed') {
        cancellation.throwIfCancelled();
        pi = deps.installPi(input.cliVersion);
        if (pi.action !== 'reused') {
          metadata = { ...metadata, piExtension: pi.record };
          deps.saveInstallMetadata(metadata);
        }
        steps.push(onboardingStep('adapter-install', pi.action === 'reused' ? 'reused' : 'installed', { action: pi.action }));
      } else {
        steps.push(onboardingStep('adapter-install', 'skipped'));
      }

      cancellation.throwIfCancelled();
      currentStep = 'strict-readiness';
      const readiness = await deps.checkReadiness({
        target: input.target,
        stableCli: bootstrap.evidence,
        state,
        installMetadata: metadata,
        service: readyServiceRecord,
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
        steps.push(onboardingStep('strict-readiness', 'failed', {
          checks: readiness.checks,
          ...(failedCode ? { code: failedCode } : { code: 'ERR_ONBOARDING_NOT_READY' }),
          message: failedMessage,
          ...(remediation ? { remediation } : {}),
        }));
        steps.push(onboardingStep('completion', 'skipped'));
        return {
          target: input.target,
          readiness: 'failed',
          steps,
          nextActions: [{
            id: 'retry-onboarding',
            message: remediation?.message ?? failedMessage,
            ...(remediation?.command ? { command: remediation.command } : {}),
          }],
        };
      }
      steps.push(onboardingStep('strict-readiness', readiness.readiness === 'reload-pending' ? 'reload-pending' : 'ready', {
        checks: readiness.checks,
      }));

      steps.push(onboardingStep('completion', 'ready'));
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
    if (currentStep === 'strict-readiness') {
      return strictReadinessFailureFromError(input.target, steps, error);
    }
    return failureFromOnboardingError(input.target, steps, currentStep, error);
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

function throwIdentityNotReady(failure: HostIdentityReadinessFailure): never {
  throw onboardingError('ERR_IDENTITY_INVALID', failure.reason, 'host-init', false, {
    identityStatus: failure.identityStatus,
    pendingRotation: failure.pendingRotation,
    remediation: {
      message: failure.reason,
      command: 'ariava host reset --confirm',
    },
  });
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

function strictReadinessFailureFromError(
  target: OnboardingTarget,
  completed: OnboardingStepResult[],
  error: unknown,
): OnboardingResult {
  const code = error instanceof AriavaCliError ? error.code : 'ERR_ONBOARDING_NOT_READY';
  const message = error instanceof Error ? error.message : String(error);
  const retryable = error instanceof AriavaCliError ? error.data.retryable !== false : true;
  const detail = error instanceof AriavaCliError ? { ...error.data } : { step: 'strict-readiness' };
  const remediation = remediationFromUnknown(detail.remediation)
    ?? (error instanceof AriavaCliError ? defaultReadinessRemediation(code, message) : undefined);
  if (remediation) detail.remediation = remediation;
  const steps = [...completed];
  steps.push(onboardingStep('strict-readiness', 'failed', {
    ...detail,
    code,
    message,
    retryable,
  }));
  steps.push(onboardingStep('completion', 'skipped'));
  return {
    target,
    readiness: 'failed',
    steps,
    nextActions: [{
      id: retryable ? 'retry-onboarding' : 'resolve-failure',
      message: remediation?.message ?? message,
      ...(remediation?.command ? { command: remediation.command } : {}),
    }],
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

function onboardingError(
  code: AriavaCliError['code'],
  message: string,
  stepId: OnboardingStepId,
  retryable: boolean,
  detail: Record<string, unknown> = {},
): AriavaCliError {
  return new AriavaCliError(code, message, { step: stepId, retryable, ...detail });
}
