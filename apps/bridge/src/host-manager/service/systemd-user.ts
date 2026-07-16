import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, resolve } from 'node:path';
import { isoNow } from '@ariava/shared-utils';
import { ARIAVA_CONFIG_PATH, ARIAVA_SYSTEMD_SERVICE_ID, ARIAVA_SYSTEMD_UNIT_PATH } from '../paths';
import { SpawnSyncCommandRunner } from './command-runner';
import { AriavaCliError, commandFailureData, sanitizeCommandDetail } from './errors';
import { supportError } from './platform';
import { removeOwnerControlledFile, writeOwnerControlledFile } from '../secure-files';
import type {
  AriavaServiceInstallRecord,
  CommandResult,
  CommandRunner,
  ServiceInstallInput,
  ServiceLogs,
  ServiceManager,
  ServiceStatus,
  ServiceSupport,
} from './types';

export interface SystemdUserUnitInput {
  runtimePath: string;
  ariavaBinPath: string;
  configPath?: string;
  homeDir?: string;
}

export interface SystemdUserFileSystem {
  existsSync(path: string): boolean;
  writeAtomicSync(path: string, data: string, controlledRoot: string): unknown;
  removeAtomicSync(path: string, controlledRoot: string): unknown;
}

export interface SystemdUserServiceManagerDependencies {
  support: ServiceSupport;
  runner: CommandRunner;
  homeDir: string;
  serviceId: string;
  definitionPath: string;
  fileSystem: SystemdUserFileSystem;
  now?: () => string;
}

const defaultSupport: ServiceSupport = {
  platform: 'linux',
  backend: 'systemd-user',
  supported: true,
  isWsl: false,
  reason: 'supported',
};

const defaultFileSystem: SystemdUserFileSystem = {
  existsSync,
  writeAtomicSync(path, data, controlledRoot) {
    writeOwnerControlledFile(path, Buffer.from(data), controlledRoot);
  },
  removeAtomicSync(path, controlledRoot) {
    removeOwnerControlledFile(path, controlledRoot);
  },
};

export function createDefaultSystemdUserServiceManager(
  support: ServiceSupport = defaultSupport,
): SystemdUserServiceManager {
  return new SystemdUserServiceManager({
    support,
    runner: new SpawnSyncCommandRunner(),
    homeDir: homedir(),
    serviceId: ARIAVA_SYSTEMD_SERVICE_ID,
    definitionPath: ARIAVA_SYSTEMD_UNIT_PATH,
    fileSystem: defaultFileSystem,
  });
}

export class SystemdUserServiceManager implements ServiceManager {
  readonly backend = 'systemd-user' as const;
  readonly support: ServiceSupport;

  private readonly runner: CommandRunner;
  private readonly serviceId: string;
  private readonly definitionPath: string;
  private readonly fileSystem: SystemdUserFileSystem;
  private readonly now: () => string;

  constructor(dependencies: SystemdUserServiceManagerDependencies) {
    this.support = dependencies.support;
    this.runner = dependencies.runner;
    this.serviceId = dependencies.serviceId;
    this.definitionPath = dependencies.definitionPath;
    this.fileSystem = dependencies.fileSystem;
    this.now = dependencies.now ?? isoNow;
  }

  install(input: ServiceInstallInput): AriavaServiceInstallRecord {
    this.assertSupported();
    const runtimePath = absoluteServicePath(input.runtimePath, 'runtimePath');
    const ariavaBinPath = absoluteServicePath(input.ariavaBinPath, 'ariavaBinPath');
    const configPath = absoluteServicePath(input.configPath ?? ARIAVA_CONFIG_PATH, 'configPath');
    const unit = renderSystemdUserUnit({ runtimePath, ariavaBinPath, configPath });
    if (!isAbsolute(this.definitionPath)) {
      throw new AriavaCliError('ERR_SERVICE_INSTALL', 'Systemd service definitionPath must be an absolute path.', {
        backend: this.backend,
        field: 'definitionPath',
      });
    }

    const secrets = [runtimePath, ariavaBinPath, configPath];
    try {
      this.fileSystem.writeAtomicSync(
        this.definitionPath,
        unit,
        dirname(dirname(dirname(this.definitionPath))),
      );
    } catch (error) {
      throw fileSystemFailure(
        'ERR_SERVICE_INSTALL',
        'Unable to atomically write systemd user service definition.',
        error,
        secrets,
      );
    }

    this.runSystemctl(['--user', 'daemon-reload'], 'ERR_SERVICE_INSTALL', secrets);
    this.runSystemctl(
      ['--user', 'enable', '--now', this.serviceId],
      'ERR_SERVICE_INSTALL',
      secrets,
    );

    return {
      backend: this.backend,
      installedAt: input.installedAt ?? this.now(),
      runtimePath,
      ariavaBinPath,
      ...(input.configPath && input.identityReference
        ? { configPath, identityReference: structuredClone(input.identityReference) }
        : {}),
      definitionPath: this.definitionPath,
      serviceId: this.serviceId,
    };
  }

  start(record?: AriavaServiceInstallRecord): void {
    this.assertSupported();
    if (!this.isInstalledRecord(record)) throw serviceNotInstalled();
    this.runSystemctl(
      ['--user', 'start', this.serviceId],
      'ERR_SERVICE_COMMAND',
      record ? [record.runtimePath, record.ariavaBinPath] : [],
    );
  }

  stop(record?: AriavaServiceInstallRecord): void {
    if (record && !this.matchesRecord(record)) return;
    this.assertSupported();
    if (!record || !this.definitionExists()) return;
    const result = this.executeSystemctl(['--user', 'stop', this.serviceId]);
    if (result.status !== 0 && !isOrdinaryAbsentFailure(result, this.serviceId)) {
      throw systemctlFailure(
        'ERR_SERVICE_COMMAND',
        ['--user', 'stop', this.serviceId],
        result,
        [record.runtimePath, record.ariavaBinPath],
      );
    }
  }

  restart(record?: AriavaServiceInstallRecord): void {
    this.assertSupported();
    if (!this.isInstalledRecord(record)) throw serviceNotInstalled();
    this.runSystemctl(
      ['--user', 'restart', this.serviceId],
      'ERR_SERVICE_COMMAND',
      record ? [record.runtimePath, record.ariavaBinPath] : [],
    );
  }

  uninstall(record?: AriavaServiceInstallRecord): void {
    if (record && !this.matchesRecord(record)) return;
    this.assertSupported();
    const secrets = record ? [record.runtimePath, record.ariavaBinPath] : [];
    const fileExists = this.definitionExists('ERR_SERVICE_COMMAND', secrets);
    const showArgs = loadStateArgs(this.serviceId);
    const show = this.executeSystemctl(showArgs);
    const loadState = show.stdout.trim();
    if (show.status !== 0 && loadState !== 'not-found' && !isOrdinaryAbsentFailure(show, this.serviceId)) {
      throw systemctlFailure('ERR_SERVICE_COMMAND', showArgs, show, secrets);
    }
    if (!fileExists && loadState !== 'loaded') return;

    const disableArgs = ['--user', 'disable', '--now', this.serviceId];
    const disable = this.executeSystemctl(disableArgs);
    if (disable.status !== 0 && !isOrdinaryAbsentFailure(disable, this.serviceId)) {
      throw systemctlFailure('ERR_SERVICE_COMMAND', disableArgs, disable, secrets);
    }

    try {
      this.fileSystem.removeAtomicSync(
        this.definitionPath,
        dirname(dirname(dirname(this.definitionPath))),
      );
    } catch (error) {
      throw fileSystemFailure(
        'ERR_SERVICE_COMMAND',
        'Unable to remove systemd user service definition.',
        error,
        secrets,
      );
    }
    this.runSystemctl(['--user', 'daemon-reload'], 'ERR_SERVICE_COMMAND', secrets);
  }

  status(
    record: AriavaServiceInstallRecord | undefined,
    currentRuntimePath: string,
    currentAriavaBinPath: string,
  ): ServiceStatus {
    if (!record || !this.matchesRecord(record)) {
      return {
        backend: this.backend,
        support: this.support,
        definitionPath: this.definitionPath,
        serviceId: this.serviceId,
        installed: false,
        enabled: false,
        loaded: false,
        processRunning: false,
        logBackend: 'journald',
        ...(record ? { detail: `metadata backend ${record.backend} does not match systemd-user` } : {}),
      };
    }

    const base = {
      backend: this.backend,
      support: this.support,
      definitionPath: this.definitionPath,
      serviceId: this.serviceId,
      runtimePath: record.runtimePath,
      ariavaBinPath: record.ariavaBinPath,
      runtimePathMatchesCurrent: resolve(record.runtimePath) === resolve(currentRuntimePath),
      ariavaBinPathMatchesCurrent: resolve(record.ariavaBinPath) === resolve(currentAriavaBinPath),
      logBackend: 'journald' as const,
    };
    let installed: boolean;
    try {
      installed = this.fileSystem.existsSync(this.definitionPath);
    } catch (error) {
      return {
        ...base,
        installed: false,
        enabled: false,
        loaded: false,
        processRunning: false,
        detail: safeFileSystemDetail(error, [record.runtimePath, record.ariavaBinPath]),
      };
    }
    if (!installed) {
      return { ...base, installed: false, enabled: false, loaded: false, processRunning: false };
    }

    const enabledResult = this.executeSystemctl(['--user', 'is-enabled', this.serviceId]);
    const activeResult = this.executeSystemctl(['--user', 'is-active', this.serviceId]);
    const loadedResult = this.executeSystemctl(loadStateArgs(this.serviceId));
    const detail = statusDiagnostic(
      [enabledResult, activeResult, loadedResult],
      this.serviceId,
      [record.runtimePath, record.ariavaBinPath],
    );
    return {
      ...base,
      installed: true,
      enabled: enabledResult.stdout.trim() === 'enabled',
      loaded: loadedResult.stdout.trim() === 'loaded',
      processRunning: activeResult.stdout.trim() === 'active',
      ...(detail ? { detail } : {}),
    };
  }

  logsAvailable(): boolean {
    if (!this.support.supported) return false;
    return this.runner.run('journalctl', ['--version']).status === 0;
  }

  logs(record?: AriavaServiceInstallRecord): ServiceLogs {
    const args = ['--user', '--unit', this.serviceId, '--no-pager', '-n', '200'];
    const result = this.runner.run('journalctl', args);
    if (result.status !== 0) {
      const secrets = record ? [record.runtimePath, record.ariavaBinPath] : [];
      const raw = result.stderr.trim() || result.error?.message.trim() || 'journalctl failed';
      throw new AriavaCliError(
        'ERR_LOGS_UNAVAILABLE',
        sanitizeCommandDetail(raw, secrets),
        { backend: this.backend, ...commandFailureData('journalctl', args, result, secrets) },
      );
    }
    return {
      backend: this.backend,
      source: 'journald',
      text: sanitizeJournalText(result.stdout),
    };
  }

  private assertSupported(): void {
    if (!this.support.supported) throw supportError(this.support);
  }

  private matchesRecord(record: AriavaServiceInstallRecord): boolean {
    return record.backend === this.backend
      && record.serviceId === this.serviceId
      && record.definitionPath === this.definitionPath;
  }

  private isInstalledRecord(record?: AriavaServiceInstallRecord): record is AriavaServiceInstallRecord {
    return record !== undefined && this.matchesRecord(record) && this.definitionExists();
  }

  private definitionExists(
    code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND' = 'ERR_SERVICE_COMMAND',
    secrets: readonly string[] = [],
  ): boolean {
    try {
      return this.fileSystem.existsSync(this.definitionPath);
    } catch (error) {
      throw fileSystemFailure(code, 'Unable to inspect systemd user service definition.', error, secrets);
    }
  }

  private executeSystemctl(args: string[]): CommandResult {
    return this.runner.run('systemctl', args, { env: { ...process.env, LC_ALL: 'C' } });
  }

  private runSystemctl(
    args: string[],
    code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND',
    secrets: readonly string[],
  ): CommandResult {
    const result = this.executeSystemctl(args);
    if (result.status !== 0) throw systemctlFailure(code, args, result, secrets);
    return result;
  }
}

export function quoteSystemdArgument(value: string): string {
  if (/[\0\n\r]/.test(value)) {
    throw new AriavaCliError(
      'ERR_SERVICE_INSTALL',
      'Systemd service arguments cannot contain NUL or line breaks.',
      { backend: 'systemd-user' },
    );
  }

  return `"${value
    .replaceAll('\\', '\\\\')
    .replaceAll('"', '\\"')
    .replaceAll('%', '%%')
    .replaceAll('$', () => '$$')}"`;
}


function absoluteServicePath(path: string, field: string): string {
  if (!isAbsolute(path) || /[\u0000-\u001f\u007f-\u009f]/.test(path)) {
    throw new AriavaCliError('ERR_SERVICE_INSTALL', `Systemd service ${field} must be a safe absolute path.`, {
      backend: 'systemd-user', field,
    });
  }
  return resolve(path);
}

export function renderSystemdUserUnit(input: SystemdUserUnitInput): string {
  for (const [field, value] of Object.entries(input)) {
    if (value !== undefined) absoluteServicePath(value, field);
  }
  const configPath = input.configPath ?? ARIAVA_CONFIG_PATH;

  const execStart = [
    input.runtimePath,
    input.ariavaBinPath,
    'internal',
    'bridge-daemon',
    '--config',
    configPath,
  ].map(quoteSystemdArgument).join(' ');

  return `[Unit]
Description=Ariava Local Bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
UMask=0077
ExecStart=${execStart}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`;
}

function loadStateArgs(serviceId: string): string[] {
  return ['--user', 'show', serviceId, '--property=LoadState', '--value'];
}

function serviceNotInstalled(): AriavaCliError {
  return new AriavaCliError(
    'ERR_SERVICE_NOT_INSTALLED',
    'The Ariava systemd user service is not installed. Run `ariava service install` first.',
    { backend: 'systemd-user' },
  );
}

function systemctlFailure(
  code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND',
  args: string[],
  result: CommandResult,
  secrets: readonly string[],
): AriavaCliError {
  const raw = result.stderr.trim() || result.stdout.trim() || `systemctl ${args.at(-1) ?? 'command'} failed`;
  return new AriavaCliError(
    code,
    sanitizeCommandDetail(raw, secrets),
    { backend: 'systemd-user', ...commandFailureData('systemctl', args, { ...result, stderr: result.stderr.trim() }, secrets) },
  );
}

function fileSystemFailure(
  code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND',
  message: string,
  error: unknown,
  secrets: readonly string[],
): AriavaCliError {
  const detail = safeFileSystemDetail(error, secrets);
  return new AriavaCliError(
    code,
    sanitizeCommandDetail(`${message} ${detail}`, secrets),
    { backend: 'systemd-user', operation: message, detail },
  );
}

function safeFileSystemDetail(error: unknown, secrets: readonly string[]): string {
  const raw = error instanceof Error ? error.message : String(error);
  return sanitizeCommandDetail(raw, secrets).replace(/\/[^\s]*/g, '<redacted-path>').slice(0, 2_000);
}

function isOrdinaryAbsentFailure(result: CommandResult, serviceId: string): boolean {
  const detail = `${result.stdout}\n${result.stderr}`.trim().toLowerCase();
  const unit = serviceId.toLowerCase();
  return new Set([
    'inactive',
    'disabled',
    'not-found',
    `unit ${unit} not loaded.`,
    `unit ${unit} could not be found.`,
    `unit ${unit} does not exist.`,
    `failed to stop ${unit}: unit ${unit} not loaded.`,
    `failed to disable unit: unit file ${unit} does not exist.`,
  ]).has(detail);
}

function statusDiagnostic(
  results: CommandResult[],
  serviceId: string,
  secrets: readonly string[],
): string | undefined {
  const unusual = results.find(
    (result) => result.status !== 0 && !isOrdinaryAbsentFailure(result, serviceId),
  );
  if (!unusual) return undefined;
  return sanitizeCommandDetail(unusual.stderr.trim() || unusual.error?.message || 'systemd status probe failed', secrets);
}

function sanitizeJournalText(text: string): string {
  return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '');
}
