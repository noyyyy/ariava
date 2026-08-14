import { HostIdentityError } from '../../identity/errors';
import { AriavaCliError } from '../service/errors';
import {
  ONBOARDING_STEP_IDS,
  type OnboardingResult,
  type OnboardingStepId,
  type OnboardingStepResult,
  type OnboardingTarget,
} from './types';

type OnboardingFailureRemediation = { message?: string; command?: string };

export function failureFromError(
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
  remediation?: OnboardingFailureRemediation;
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
      command: 'ariava identity reset --confirm',
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

function remediationFromUnknown(value: unknown): OnboardingFailureRemediation | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const entry = value as { message?: unknown; command?: unknown };
  const remediation: OnboardingFailureRemediation = {};
  if (typeof entry.message === 'string' && entry.message.length > 0) remediation.message = entry.message;
  if (typeof entry.command === 'string' && entry.command.length > 0) remediation.command = entry.command;
  return remediation.message || remediation.command ? remediation : undefined;
}

function defaultRemediationForCode(code: string, message: string): { message: string; command?: string } | undefined {
  if (code === 'ERR_IDENTITY_KEYCHAIN_LOCKED') {
    return { message, command: 'security unlock-keychain "$HOME/Library/Keychains/login.keychain-db"' };
  }
  if (code === 'ERR_IDENTITY_INVALID' || code === 'ERR_IDENTITY_MISSING' || code === 'ERR_IDENTITY_PERMISSIONS' || code === 'ERR_IDENTITY_RESET_REQUIRED') {
    return { message, command: 'ariava identity reset --confirm' };
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
  remediation?: OnboardingFailureRemediation,
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
  const last = steps.at(-1)?.id;
  const start = last ? ONBOARDING_STEP_IDS.indexOf(last) + 1 : 0;
  for (const id of ONBOARDING_STEP_IDS.slice(start)) steps.push(step(id, 'skipped'));
}

function step(
  id: OnboardingStepId,
  status: OnboardingStepResult['status'],
  detail?: Record<string, unknown>,
): OnboardingStepResult {
  return { id, status, ...(detail && Object.keys(detail).length > 0 ? { detail } : {}) };
}
