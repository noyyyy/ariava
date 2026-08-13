import type { PiExtensionStatus } from '../../pi-extension';
import { AriavaCliError } from '../../service/errors';
import type { HostReadinessCheck, StrictReadinessResult } from '../types';

export function errorCode(error: unknown, fallback: string): string {
  return error instanceof AriavaCliError ? error.code : fallback;
}

export function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof AriavaCliError && error.message.trim().length > 0) return error.message;
  if (error instanceof Error && error.message.trim().length > 0) return error.message;
  return fallback;
}

export function firstFailedCheck(checks: HostReadinessCheck[]): HostReadinessCheck | undefined {
  return checks.find((check) => !check.ready);
}

export function readinessFailureActions(checks: HostReadinessCheck[]): StrictReadinessResult['nextActions'] {
  const failed = firstFailedCheck(checks);
  if (!failed) {
    return [{ id: 'retry-onboarding', message: 'Strict readiness checks failed.' }];
  }
  const message = failed.message
    ?? (typeof failed.code === 'string' ? failed.code : 'Strict readiness checks failed.');
  const remediation = defaultReadinessRemediation(failed.code, message);
  return [{
    id: failed.id === 'identity' ? 'resolve-failure' : 'retry-onboarding',
    message: remediation.message,
    ...(remediation.command ? { command: remediation.command } : {}),
  }];
}

export function defaultReadinessRemediation(code: string | undefined, message: string): { message: string; command?: string } {
  if (code === 'ERR_IDENTITY_KEYCHAIN_LOCKED') {
    return { message, command: 'security unlock-keychain "$HOME/Library/Keychains/login.keychain-db"' };
  }
  if (code === 'ERR_IDENTITY_INVALID' || code === 'ERR_IDENTITY_MISSING' || code === 'ERR_IDENTITY_PERMISSIONS' || code === 'ERR_IDENTITY_RESET_REQUIRED') {
    return { message, command: 'ariava host reset --confirm' };
  }
  if (code === 'ERR_SERVICE_NOT_INSTALLED' || code === 'ERR_SERVICE_METADATA') {
    return { message, command: 'ariava service reinstall' };
  }
  if (code === 'ERR_AGENT_ADAPTER_DISCOVERY' || code === 'ERR_AGENT_ADAPTER_NOT_LOOPBACK') {
    return { message, command: 'ariava service restart' };
  }
  if (code === 'ERR_BRIDGE_DEGRADED') {
    return { message, command: 'ariava doctor' };
  }
  if (code === 'ERR_RELAY_UNREACHABLE' || code === 'ERR_RELAY_AUTH_FAILED' || code === 'ERR_RELAY_CONFIG_REQUIRED') {
    return { message, command: 'ariava doctor' };
  }
  if (code === 'ERR_STABLE_CLI_PATH') {
    return { message, command: 'npx --yes ariava@latest setup' };
  }
  return { message, command: 'ariava setup --resume' };
}

export function piPackageNotReadyMessage(status: PiExtensionStatus | undefined, version: string): string {
  if (!status?.installed) {
    return `Exact Pi extension package @ariava/pi-extension@${version} is not installed.`;
  }
  if (!status.managed || status.sourceOwnership !== 'managed-exact') {
    return 'Pi extension is present but not managed by Ariava at the exact CLI version.';
  }
  if (status.manifestVersion !== version) {
    return `Pi extension version ${status.manifestVersion ?? 'unknown'} does not match CLI version ${version}.`;
  }
  if (status.mismatchReasons.length > 0) {
    return `Pi extension readiness failed: ${status.mismatchReasons.join(', ')}.`;
  }
  return `Exact Pi extension package evidence for @ariava/pi-extension@${version} is not ready.`;
}

export function readinessError(
  code: 'ERR_AGENT_ADAPTER_DISCOVERY' | 'ERR_AGENT_ADAPTER_NOT_LOOPBACK' | 'ERR_RELAY_UNREACHABLE' | 'ERR_RELAY_AUTH_FAILED' | 'ERR_IDENTITY_INVALID',
  message: string,
  retryable = true,
): AriavaCliError {
  return new AriavaCliError(code, message, {
    step: 'strict-readiness',
    retryable,
    remediation: defaultReadinessRemediation(code, message),
  });
}
