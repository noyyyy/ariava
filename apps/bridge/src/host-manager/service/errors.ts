import { redactSensitive } from '../secure-files';
import type { HostIdentityErrorCode } from '../../identity/errors';
import type { CommandResult } from './types';

export const ARIAVA_CLI_ERROR_CODES = [
  'ERR_UNSUPPORTED_PLATFORM',
  'ERR_SYSTEMCTL_NOT_FOUND',
  'ERR_SYSTEMD_USER_UNAVAILABLE',
  'ERR_SERVICE_NOT_INSTALLED',
  'ERR_SERVICE_INSTALL',
  'ERR_SERVICE_COMMAND',
  'ERR_SERVICE_METADATA',
  'ERR_LOGS_UNAVAILABLE',
  'ERR_ONBOARDING_LOCKED',
  'ERR_STABLE_CLI_INSTALL',
  'ERR_STABLE_CLI_PATH',
  'ERR_RELAY_CONFIG_REQUIRED',
  'ERR_RELAY_UNREACHABLE',
  'ERR_RELAY_AUTH_FAILED',
  'ERR_ADAPTER_UNKNOWN',
  'ERR_ADAPTER_UNAVAILABLE',
  'ERR_AGENT_RUNTIME_NOT_FOUND',
  'ERR_EXTENSION_INSTALL',
  'ERR_EXTENSION_VERSION_MISMATCH',
  'ERR_EXTENSION_UNMANAGED',
  'ERR_AGENT_ADAPTER_DISCOVERY',
  'ERR_AGENT_ADAPTER_NOT_LOOPBACK',
  'ERR_ONBOARDING_NOT_READY',
] as const;

export type AriavaCliErrorCode = (typeof ARIAVA_CLI_ERROR_CODES)[number] | HostIdentityErrorCode;

export class AriavaCliError extends Error {
  constructor(
    readonly code: AriavaCliErrorCode,
    message: string,
    readonly data: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'AriavaCliError';
  }
}

export function sanitizeCommandDetail(detail: string, secrets: readonly string[] = []): string {
  return String(redactSensitive(detail, secrets)).slice(0, 2_000);
}

export function commandFailureData(
  command: string,
  args: readonly string[],
  result: CommandResult,
  secrets: readonly string[] = [],
): { command: string; exitCode: number | null; stderr: string } {
  return {
    command: sanitizeCommandDetail([command, ...args].join(' '), secrets),
    exitCode: result.status,
    stderr: sanitizeCommandDetail(result.stderr, secrets),
  };
}
