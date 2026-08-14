import type { AriavaInstallMetadata, AriavaUserConfig } from '../config';
import type { HostInitializationResult } from '../initialization';
import type { PiPackageLifecycleResult } from '../pi-extension';
import { AriavaCliError } from '../service/errors';
import type { AriavaServiceInstallRecord, ServiceManager } from '../service/types';
import type { StableBootstrapInput, StableBootstrapResult } from './bootstrap';
import {
  decideOnboardingHostState,
  proposeRelaySelection,
  proposeStableInstallerMetadata,
  type OnboardingHostStateDecision,
  type OnboardingHostState,
} from './host-state-policy';
import type { OwnedOnboardingLock } from './lock';
import { failureFromError } from './onboarding-failure';
import {
  reconcileOnboardingService,
  type OnboardingServiceManagerPort,
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
    requireConsistentServiceManager(detection, deps.serviceManager);
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
      const userConfig = deps.loadUserConfig();
      const relay = proposeRelaySelection(userConfig, input.relayBaseUrl);
      if (relay.changed) deps.saveUserConfig({ ...userConfig, relayBaseUrl: relay.value });
      steps.push(step('relay-config', relay.changed ? 'installed' : 'reused'));

      currentStep = 'host-init';
      cancellation.throwIfCancelled();
      let state = await deps.loadHostState();
      const hostDecision = decideOnboardingHostState(state);
      if (hostDecision.kind === 'reject') throwIdentityNotReady(hostDecision);
      const hostWasReady = hostDecision.kind === 'reuse';
      if (!hostWasReady) {
        await deps.initializeHost(relay.value);
        state = await deps.loadHostState();
        if (!state) throw onboardingError('ERR_IDENTITY_INVALID', 'Host initialization did not produce readable identity state.', currentStep, false);
        const initializedHostDecision = decideOnboardingHostState(state);
        if (initializedHostDecision.kind === 'reject') throwIdentityNotReady(initializedHostDecision);
        if (initializedHostDecision.kind !== 'reuse') {
          throw onboardingError('ERR_ONBOARDING_NOT_READY', 'Host initialization did not produce complete persisted configuration.', 'host-init', false);
        }
      }
      steps.push(step('host-init', hostWasReady ? 'reused' : 'installed'));

      currentStep = 'bridge-service';
      cancellation.throwIfCancelled();
      let metadata = deps.loadInstallMetadata();
      const metadataRecordedAt = deps.now?.() ?? new Date().toISOString();
      const stableMetadata = proposeStableInstallerMetadata(
        metadata,
        bootstrap.evidence.executablePath,
        input.cliVersion,
        metadataRecordedAt,
      );
      if (stableMetadata.changed) deps.saveInstallMetadata(stableMetadata.metadata);
      metadata = stableMetadata.metadata;
      const serviceResult = await reconcileOnboardingService({
        runtimePath: input.runtimePath,
        ariavaBinPath: bootstrap.evidence.executablePath,
        configPath: state.config.configPath,
        identityReference: state.identity.privateKeyStorage,
        metadata,
      }, {
        serviceManager: deps.serviceManager,
        persistServiceInstallMetadata: (nextMetadata) => deps.saveInstallMetadata(nextMetadata),
        throwIfCancelled: () => cancellation.throwIfCancelled(),
        ...(deps.now ? { now: () => deps.now!() } : {}),
        ...(deps.sleep ? { sleep: (milliseconds: number) => deps.sleep!(milliseconds) } : {}),
        ...(deps.serviceTimeoutMs !== undefined ? { timeoutMs: deps.serviceTimeoutMs } : {}),
        ...(deps.servicePollIntervalMs !== undefined ? { pollIntervalMs: deps.servicePollIntervalMs } : {}),
      });
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
        return {
          target: input.target,
          readiness: 'failed',
          steps,
          nextActions: readiness.nextActions,
        };
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

function requireConsistentServiceManager(
  detection: OnboardingDetection,
  serviceManager: ServiceManager,
): asserts serviceManager is OnboardingServiceManagerPort {
  const detectedBackend = detection.serviceSupport.backend;
  if (serviceManager.support.supported && serviceManager.backend && serviceManager.backend === detectedBackend) return;
  throw onboardingError(
    'ERR_UNSUPPORTED_PLATFORM',
    'No supported service backend is available.',
    'preflight',
    false,
  );
}

function preflightDetail(detection: OnboardingDetection): Record<string, unknown> {
  return {
    backend: detection.serviceSupport.backend,
    ...(detection.sourceDev.kind !== 'absent' ? { sourceDev: detection.sourceDev } : {}),
  };
}

function throwIdentityNotReady(readiness: Extract<OnboardingHostStateDecision, { kind: 'reject' }>): never {
  throw onboardingError('ERR_IDENTITY_INVALID', readiness.reason, 'host-init', false, {
    identityStatus: readiness.identityStatus,
    remediation: {
      message: readiness.reason,
      command: 'ariava identity reset --confirm',
    },
  });
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
