import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { isoNow } from '@ariava/shared-utils';
import {
  ARIAVA_LAUNCHD_LABEL,
  ARIAVA_CONFIG_PATH,
  ARIAVA_LAUNCHD_PLIST_PATH,
  ARIAVA_STDERR_LOG_PATH,
  ARIAVA_STDOUT_LOG_PATH,
} from '../paths';
import { SpawnSyncCommandRunner } from './command-runner';
import { AriavaCliError, commandFailureData, sanitizeCommandDetail } from './errors';
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

export interface LaunchdServiceDefinition {
  label: string;
  nodePath: string;
  ariavaBinPath: string;
  configPath: string;
  plistPath: string;
  stdoutPath: string;
  stderrPath: string;
  programArguments: string[];
}

export interface LaunchdFileSystem {
  existsSync(path: string): boolean;
  chmodSync?(path: string, mode: number): unknown;
  mkdirSync(path: string, options: { recursive: true; mode?: number }): unknown;
  readFileSync(path: string, encoding: 'utf8'): string;
  renameSync(oldPath: string, newPath: string): unknown;
  rmSync(path: string, options: { force: true }): unknown;
  writeFileSync(path: string, data: string, options?: { mode?: number }): unknown;
}

export interface LaunchdServiceManagerDependencies {
  support: ServiceSupport;
  runner: CommandRunner;
  uid: number;
  serviceId: string;
  definitionPath: string;
  stdoutLogPath: string;
  stderrLogPath: string;
  fileSystem: LaunchdFileSystem;
  now?: () => string;
}

const defaultSupport: ServiceSupport = {
  platform: 'darwin',
  backend: 'launchd',
  supported: true,
  isWsl: false,
  reason: 'supported',
};

const defaultFileSystem: LaunchdFileSystem = {
  existsSync,
  chmodSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
};

export function createDefaultLaunchdServiceManager(): LaunchdServiceManager {
  return new LaunchdServiceManager({
    support: defaultSupport,
    runner: new SpawnSyncCommandRunner(),
    uid: process.getuid?.() ?? 0,
    serviceId: ARIAVA_LAUNCHD_LABEL,
    definitionPath: ARIAVA_LAUNCHD_PLIST_PATH,
    stdoutLogPath: ARIAVA_STDOUT_LOG_PATH,
    stderrLogPath: ARIAVA_STDERR_LOG_PATH,
    fileSystem: defaultFileSystem,
  });
}

export class LaunchdServiceManager implements ServiceManager {
  readonly backend = 'launchd' as const;
  readonly support: ServiceSupport;

  private readonly runner: CommandRunner;
  private readonly uid: number;
  private readonly serviceId: string;
  private readonly definitionPath: string;
  private readonly stdoutLogPath: string;
  private readonly stderrLogPath: string;
  private readonly fileSystem: LaunchdFileSystem;
  private readonly now: () => string;

  constructor(dependencies: LaunchdServiceManagerDependencies) {
    this.support = dependencies.support;
    this.runner = dependencies.runner;
    this.uid = dependencies.uid;
    this.serviceId = dependencies.serviceId;
    this.definitionPath = dependencies.definitionPath;
    this.stdoutLogPath = dependencies.stdoutLogPath;
    this.stderrLogPath = dependencies.stderrLogPath;
    this.fileSystem = dependencies.fileSystem;
    this.now = dependencies.now ?? isoNow;
  }

  install(input: ServiceInstallInput): AriavaServiceInstallRecord {
    const runtimePath = absoluteServicePath(input.runtimePath, 'runtimePath');
    const ariavaBinPath = absoluteServicePath(input.ariavaBinPath, 'ariavaBinPath');
    const configPath = absoluteServicePath(input.configPath ?? ARIAVA_CONFIG_PATH, 'configPath');
    const definition = buildLaunchdServiceDefinition(runtimePath, ariavaBinPath, configPath, {
      serviceId: this.serviceId,
      definitionPath: this.definitionPath,
      stdoutLogPath: this.stdoutLogPath,
      stderrLogPath: this.stderrLogPath,
    });
    try {
      writeLaunchdServiceDefinition(this.fileSystem, definition);
    } catch (error) {
      throw fileSystemFailure(
        'ERR_SERVICE_INSTALL',
        'Unable to write launchd service definition.',
        error,
        [runtimePath, ariavaBinPath, configPath, this.definitionPath, this.stdoutLogPath, this.stderrLogPath],
      );
    }

    const secrets = [runtimePath, ariavaBinPath, configPath];
    this.runLaunchctl(
      ['bootout', this.serviceTarget(this.serviceId)],
      false,
      'ERR_SERVICE_INSTALL',
      secrets,
    );
    this.runLaunchctl(
      ['bootstrap', this.domainTarget(), this.definitionPath],
      true,
      'ERR_SERVICE_INSTALL',
      secrets,
    );

    return {
      backend: 'launchd',
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

  uninstall(record?: AriavaServiceInstallRecord): void {
    if (record && record.backend !== this.backend) return;
    const serviceId = record?.serviceId ?? this.serviceId;
    const definitionPath = record?.definitionPath ?? this.definitionPath;
    const args = ['bootout', this.serviceTarget(serviceId)];
    const result = this.runner.run('launchctl', args);
    if (result.status !== 0 && !isNotLoadedFailure(result)) {
      throw launchctlFailure(
        'ERR_SERVICE_COMMAND',
        args,
        result,
        record ? [record.runtimePath, record.ariavaBinPath] : [],
      );
    }
    try {
      removeLaunchdServiceDefinition(this.fileSystem, definitionPath);
    } catch (error) {
      throw fileSystemFailure(
        'ERR_SERVICE_COMMAND',
        'Unable to remove launchd service definition.',
        error,
        [definitionPath, ...(record ? [record.runtimePath, record.ariavaBinPath] : [])],
      );
    }
  }

  start(record?: AriavaServiceInstallRecord): void {
    if (record && record.backend !== this.backend) return;
    this.runLaunchctl(
      ['bootstrap', this.domainTarget(), record?.definitionPath ?? this.definitionPath],
      true,
      'ERR_SERVICE_COMMAND',
      record ? [record.runtimePath, record.ariavaBinPath] : [],
    );
  }

  stop(record?: AriavaServiceInstallRecord): void {
    if (record && record.backend !== this.backend) return;
    this.runLaunchctl(
      ['bootout', this.serviceTarget(record?.serviceId ?? this.serviceId)],
      true,
      'ERR_SERVICE_COMMAND',
      record ? [record.runtimePath, record.ariavaBinPath] : [],
    );
  }

  restart(record?: AriavaServiceInstallRecord): void {
    if (record && record.backend !== this.backend) return;
    this.runLaunchctl(
      ['kickstart', '-k', this.serviceTarget(record?.serviceId ?? this.serviceId)],
      true,
      'ERR_SERVICE_COMMAND',
      record ? [record.runtimePath, record.ariavaBinPath] : [],
    );
  }

  status(
    record: AriavaServiceInstallRecord | undefined,
    currentRuntimePath: string,
    currentAriavaBinPath: string,
  ): ServiceStatus {
    if (!record || record.backend !== this.backend) {
      return {
        backend: this.backend,
        support: this.support,
        definitionPath: this.definitionPath,
        serviceId: this.serviceId,
        installed: false,
        enabled: false,
        loaded: false,
        processRunning: false,
        logBackend: 'files',
        stdoutLogPath: this.stdoutLogPath,
        stderrLogPath: this.stderrLogPath,
        ...(record
          ? { detail: `metadata backend ${record.backend} does not match launchd` }
          : {}),
      };
    }

    const definitionPath = record.definitionPath;
    const serviceId = record.serviceId;
    let plist: string;
    try {
      plist = this.fileSystem.readFileSync(definitionPath, 'utf8');
    } catch (error) {
      return {
        backend: this.backend,
        support: this.support,
        definitionPath,
        serviceId,
        installed: false,
        enabled: false,
        loaded: false,
        processRunning: false,
        runtimePath: record.runtimePath,
        ariavaBinPath: record.ariavaBinPath,
        runtimePathMatchesCurrent: resolve(record.runtimePath) === resolve(currentRuntimePath),
        ariavaBinPathMatchesCurrent: resolve(record.ariavaBinPath) === resolve(currentAriavaBinPath),
        logBackend: 'files',
        stdoutLogPath: this.stdoutLogPath,
        stderrLogPath: this.stderrLogPath,
        detail: fileSystemDetail(
          'unable to read launchd definition',
          error,
          [definitionPath, record.runtimePath, record.ariavaBinPath],
        ),
      };
    }
    const installed = true;
    const enabled = plistHasRunAtLoad(plist);
    const printResult = this.runner.run('launchctl', ['print', this.serviceTarget(serviceId)]);
    const loaded = printResult.status === 0;

    return {
      backend: this.backend,
      support: this.support,
      definitionPath,
      serviceId,
      installed,
      enabled,
      loaded,
      processRunning: loaded && /\bpid\s*=\s*\d+\b/.test(printResult.stdout),
      runtimePath: record.runtimePath,
      ariavaBinPath: record.ariavaBinPath,
      runtimePathMatchesCurrent: resolve(record.runtimePath) === resolve(currentRuntimePath),
      ariavaBinPathMatchesCurrent: resolve(record.ariavaBinPath) === resolve(currentAriavaBinPath),
      logBackend: 'files',
      stdoutLogPath: this.stdoutLogPath,
      stderrLogPath: this.stderrLogPath,
    };
  }

  logsAvailable(): boolean {
    try {
      return this.fileSystem.existsSync(this.stdoutLogPath)
        && this.fileSystem.existsSync(this.stderrLogPath);
    } catch {
      return false;
    }
  }

  logs(record?: AriavaServiceInstallRecord): ServiceLogs {
    if (record && record.backend !== this.backend) {
      return { backend: this.backend, source: 'files', text: '', stdoutPath: this.stdoutLogPath, stderrPath: this.stderrLogPath };
    }
    let stdout: string;
    let stderr: string;
    try {
      stdout = this.fileSystem.readFileSync(this.stdoutLogPath, 'utf8');
      stderr = this.fileSystem.readFileSync(this.stderrLogPath, 'utf8');
    } catch (error) {
      throw fileSystemFailure(
        'ERR_LOGS_UNAVAILABLE',
        'Unable to read launchd service logs.',
        error,
        [this.stdoutLogPath, this.stderrLogPath],
      );
    }
    return {
      backend: this.backend,
      source: 'files',
      text: `${stdout}${stderr}`,
      stdoutPath: this.stdoutLogPath,
      stderrPath: this.stderrLogPath,
    };
  }

  private domainTarget(): string {
    return `gui/${this.uid}`;
  }

  private serviceTarget(serviceId: string): string {
    return `${this.domainTarget()}/${serviceId}`;
  }

  private runLaunchctl(
    args: string[],
    strict: boolean,
    code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND',
    secrets: readonly string[] = [],
  ): CommandResult {
    return runLaunchctlCommand(this.runner, args, strict, code, secrets);
  }

}

export function buildLaunchdServiceDefinition(
  nodePath: string,
  ariavaBinPath: string,
  configPathOrOverrides: string | {
    serviceId?: string; definitionPath?: string; stdoutLogPath?: string; stderrLogPath?: string;
  } = ARIAVA_CONFIG_PATH,
  overrides: { serviceId?: string; definitionPath?: string; stdoutLogPath?: string; stderrLogPath?: string } = {},
): LaunchdServiceDefinition {
  const absoluteNodePath = absoluteServicePath(nodePath, 'runtimePath');
  const absoluteAriavaBinPath = absoluteServicePath(ariavaBinPath, 'ariavaBinPath');
  const resolvedOverrides = typeof configPathOrOverrides === 'string' ? overrides : configPathOrOverrides;
  const absoluteConfigPath = absoluteServicePath(
    typeof configPathOrOverrides === 'string' ? configPathOrOverrides : ARIAVA_CONFIG_PATH,
    'configPath',
  );
  return {
    label: resolvedOverrides.serviceId ?? ARIAVA_LAUNCHD_LABEL,
    nodePath: absoluteNodePath,
    ariavaBinPath: absoluteAriavaBinPath,
    configPath: absoluteConfigPath,
    plistPath: resolvedOverrides.definitionPath ?? ARIAVA_LAUNCHD_PLIST_PATH,
    stdoutPath: resolvedOverrides.stdoutLogPath ?? ARIAVA_STDOUT_LOG_PATH,
    stderrPath: resolvedOverrides.stderrLogPath ?? ARIAVA_STDERR_LOG_PATH,
    programArguments: [absoluteNodePath, absoluteAriavaBinPath, 'internal', 'bridge-daemon', '--config', absoluteConfigPath],
  };
}

export function writeLaunchdServiceDefinition(
  fileSystem: LaunchdFileSystem,
  definition: LaunchdServiceDefinition,
): void {
  fileSystem.mkdirSync(dirname(definition.plistPath), { recursive: true, mode: 0o700 });
  fileSystem.mkdirSync(dirname(definition.stdoutPath), { recursive: true, mode: 0o700 });
  fileSystem.mkdirSync(dirname(definition.stderrPath), { recursive: true, mode: 0o700 });
  const tempPath = `${definition.plistPath}.${process.pid}.tmp`;
  fileSystem.writeFileSync(tempPath, renderLaunchdPlist(definition), { mode: 0o600 });
  fileSystem.chmodSync?.(tempPath, 0o600);
  fileSystem.renameSync(tempPath, definition.plistPath);
}

export function removeLaunchdServiceDefinition(
  fileSystem: LaunchdFileSystem,
  definitionPath: string,
): void {
  fileSystem.rmSync(definitionPath, { force: true });
}

export function runLaunchctlCommand(
  runner: CommandRunner,
  args: string[],
  strict: boolean,
  code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND',
  secrets: readonly string[] = [],
): CommandResult {
  const result = runner.run('launchctl', args);
  if (strict && result.status !== 0) throw launchctlFailure(code, args, result, secrets);
  return result;
}

function launchctlFailure(
  code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND',
  args: string[],
  result: CommandResult,
  secrets: readonly string[],
): AriavaCliError {
  const fallback = `launchctl ${args[0] ?? 'command'} failed`;
  const rawMessage = result.stderr.trim() || result.stdout.trim() || fallback;
  return new AriavaCliError(
    code,
    sanitizeCommandDetail(rawMessage, secrets),
    { backend: 'launchd', ...commandFailureData('launchctl', args, result, secrets) },
  );
}

function fileSystemFailure(
  code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND' | 'ERR_LOGS_UNAVAILABLE',
  message: string,
  error: unknown,
  secrets: readonly string[],
): AriavaCliError {
  const detail = sanitizeFileSystemDetail(errorDetail(error), secrets);
  return new AriavaCliError(
    code,
    sanitizeCommandDetail(`${message} ${detail}`),
    {
      backend: 'launchd',
      operation: message,
      detail,
    },
  );
}

function fileSystemDetail(
  message: string,
  error: unknown,
  secrets: readonly string[],
): string {
  return sanitizeCommandDetail(`${message}: ${sanitizeFileSystemDetail(errorDetail(error), secrets)}`);
}

function errorDetail(error: unknown): string {
  if (error instanceof Error) {
    const code = 'code' in error && typeof error.code === 'string' ? `${error.code}: ` : '';
    return `${code}${error.message}`;
  }
  return String(error);
}

function sanitizeFileSystemDetail(detail: string, secrets: readonly string[]): string {
  return sanitizeCommandDetail(detail, secrets)
    .replace(/\/[^\s]*/g, '<redacted-path>')
    .slice(0, 2_000);
}

export function renderLaunchdPlist(definition: LaunchdServiceDefinition): string {
  const escapedArgs = definition.programArguments.map((arg) => `      <string>${escapeXml(arg)}</string>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>${escapeXml(definition.label)}</string>
    <key>ProgramArguments</key>
    <array>
${escapedArgs}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${escapeXml(definition.stdoutPath)}</string>
    <key>StandardErrorPath</key>
    <string>${escapeXml(definition.stderrPath)}</string>
  </dict>
</plist>
`;
}

function absoluteServicePath(path: string, field: string): string {
  if (!path.startsWith('/') || /[\u0000-\u001f\u007f-\u009f]/.test(path)) {
    throw new AriavaCliError('ERR_SERVICE_INSTALL', `Launchd service ${field} must be a safe absolute path.`, { backend: 'launchd', field });
  }
  return resolve(path);
}

export function parseProgramArgumentsFromPlist(plistPath: string): string[] {
  if (!existsSync(plistPath)) return [];
  const plist = readFileSync(plistPath, 'utf8');
  const match = plist.match(/<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/);
  if (!match) return [];
  return [...match[1].matchAll(/<string>(.*?)<\/string>/g)].map((entry) => decodeXml(entry[1] ?? ''));
}

function plistHasRunAtLoad(plist: string): boolean {
  return /<key>RunAtLoad<\/key>\s*<true\s*\/>/.test(plist);
}

function isNotLoadedFailure(result: CommandResult): boolean {
  if (result.status !== 3 && result.status !== 113) return false;
  const detail = `${result.stdout}\n${result.stderr}`.trim().toLowerCase();
  if (/permission|not permitted|denied|policy|unauthorized|failed|error/.test(detail)) return false;
  return /^(could not find service|no such process|service not found)[.!\s]*$/.test(detail);
}

function escapeXml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function decodeXml(value: string): string {
  return value
    .replaceAll('&apos;', "'")
    .replaceAll('&quot;', '"')
    .replaceAll('&gt;', '>')
    .replaceAll('&lt;', '<')
    .replaceAll('&amp;', '&');
}
