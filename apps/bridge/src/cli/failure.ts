import { HostIdentityError } from '../identity';
import { RelayClientError } from '../relay-client';
import { AriavaCliError } from '../host-manager/service/errors';

const MACOS_KEYCHAIN_UNLOCK_COMMAND = 'security unlock-keychain "$HOME/Library/Keychains/login.keychain-db"';

export interface CliFailure {
  ok: false;
  code: string;
  message: string;
  data: Record<string, unknown>;
}

export function pairCancelledFailure(): AriavaCliError {
  return new AriavaCliError('ERR_PAIR_CANCELLED', 'Safety Code confirmation cancelled.');
}

export function commandUnavailableFailure(profile: 'default' | 'dev', command: string): AriavaCliError {
  return new AriavaCliError(
    'ERR_COMMAND_UNAVAILABLE_FOR_PROFILE',
    `Command \`${command}\` is unavailable for the ${profile} profile.`,
    { profile, command },
  );
}

export function normalizeCliFailure(error: unknown): CliFailure {
  if (error instanceof AriavaCliError) {
    return { ok: false, code: error.code, message: error.message, data: error.data };
  }
  if (error instanceof HostIdentityError) {
    return {
      ok: false,
      code: error.code,
      message: error.message,
      data: error.code === 'ERR_IDENTITY_KEYCHAIN_LOCKED' ? keychainUnlockRemediation() : {},
    };
  }
  if (error instanceof RelayClientError) {
    return { ok: false, code: 'ERR_RELAY', message: error.message, data: { status: error.status } };
  }
  return {
    ok: false,
    code: 'ERR_CLI',
    message: error instanceof Error ? error.message : String(error),
    data: {},
  };
}

export function formatHumanCliFailure(failure: CliFailure): string {
  const lines: string[] = [`ariava: ${failure.message}`];
  const advice = failure.data.advice;
  if (typeof advice === 'string' && advice.trim() !== '') lines.push(`Next: ${advice}`);

  const remediation = failure.data.remediation;
  if (remediation && typeof remediation === 'object' && !Array.isArray(remediation)) {
    const record = remediation as { message?: unknown; command?: unknown };
    if (typeof record.message === 'string' && record.message.trim() !== '') lines.push(record.message);
    if (typeof record.command === 'string' && record.command.trim() !== '') lines.push(`Next: ${record.command}`);
  }

  const instructions = failure.data.instructions;
  if (instructions && typeof instructions === 'object' && !Array.isArray(instructions)) {
    const record = instructions as { wslConfig?: unknown; windowsCommand?: unknown };
    const embedded = failure.message.includes('/etc/wsl.conf')
      || (typeof record.wslConfig === 'string' && record.wslConfig.trim() !== '' && failure.message.includes(record.wslConfig))
      || (typeof record.windowsCommand === 'string' && record.windowsCommand.trim() !== '' && failure.message.includes(record.windowsCommand));
    if (!embedded) {
      if (typeof record.wslConfig === 'string' && record.wslConfig.trim() !== '') {
        lines.push('Add the following to /etc/wsl.conf:', '', record.wslConfig, '');
      }
      if (typeof record.windowsCommand === 'string' && record.windowsCommand.trim() !== '') {
        lines.push(`Then run \`${record.windowsCommand}\` from Windows PowerShell, reopen the distribution, and retry.`);
      }
    }
  }

  if (failure.message.includes('Unknown command:')) lines.push(`Run 'ariava help' for usage.`);
  return `${lines.join('\n')}\n`;
}

export function sanitizePairFailure(error: unknown, secrets: readonly string[]): unknown {
  if (error instanceof AriavaCliError) return error;
  if (!(error instanceof Error)) return error;
  const message = redactPairSecrets(error.message, secrets);
  if (message === error.message) return error;
  const sanitized = Object.create(Object.getPrototypeOf(error)) as Error & Record<string, unknown>;
  Object.assign(sanitized, error);
  sanitized.name = error.name;
  sanitized.message = message;
  return sanitized;
}

function keychainUnlockRemediation(): Record<string, unknown> {
  return {
    retryable: true,
    remediation: {
      message: 'Unlock the macOS login Keychain in this terminal, then retry the Ariava command.',
      command: MACOS_KEYCHAIN_UNLOCK_COMMAND,
    },
  };
}

function redactPairSecrets(message: string, secrets: readonly string[]): string {
  let redacted = message;
  for (const secret of [...new Set(secrets.filter(Boolean))].sort((left, right) => right.length - left.length)) {
    redacted = redacted.replaceAll(secret, '<redacted>');
  }
  redacted = redacted.replace(/Safety Code:\s*[^\s,;]+/giu, 'Safety Code: <redacted>');
  redacted = redacted.replace(/(?:private\s*key|privateKey(?:Pkcs8)?):\s*[^\s,;]+/giu, (value) => {
    const separator = value.indexOf(':');
    return `${value.slice(0, separator + 1)} <redacted>`;
  });
  return redacted;
}
