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
  sleep?: (milliseconds: number) => void;
  unloadTimeoutMs?: number;
  bootstrapRetryLimit?: number;
  bootstrapRetryDelayMs?: number;
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

const DEFAULT_UNLOAD_TIMEOUT_MS = 5_000;
const DEFAULT_BOOTSTRAP_RETRY_LIMIT = 8;
const DEFAULT_BOOTSTRAP_RETRY_DELAY_MS = 50;

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
  private readonly sleep: (milliseconds: number) => void;
  private readonly unloadTimeoutMs: number;
  private readonly bootstrapRetryLimit: number;
  private readonly bootstrapRetryDelayMs: number;

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
    this.sleep = dependencies.sleep ?? sleepSync;
    this.unloadTimeoutMs = dependencies.unloadTimeoutMs ?? DEFAULT_UNLOAD_TIMEOUT_MS;
    this.bootstrapRetryLimit = dependencies.bootstrapRetryLimit ?? DEFAULT_BOOTSTRAP_RETRY_LIMIT;
    this.bootstrapRetryDelayMs = dependencies.bootstrapRetryDelayMs ?? DEFAULT_BOOTSTRAP_RETRY_DELAY_MS;
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
    this.unloadService(this.serviceId, 'ERR_SERVICE_INSTALL', secrets);
    this.bootstrapDefinition(this.serviceId, this.definitionPath, 'ERR_SERVICE_INSTALL', secrets);

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
    const secrets = record ? [record.runtimePath, record.ariavaBinPath] : [];
    const definitionPath = record?.definitionPath ?? this.definitionPath;
    const serviceId = record?.serviceId ?? this.serviceId;
    // start must tolerate a half-unloaded or still-loaded agent: unload first,
    // wait for launchd to drop the job, then bootstrap with transient retries.
    this.unloadService(serviceId, 'ERR_SERVICE_COMMAND', secrets);
    this.bootstrapDefinition(serviceId, definitionPath, 'ERR_SERVICE_COMMAND', secrets);
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

  private unloadService(
    serviceId: string,
    code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND',
    secrets: readonly string[],
  ): void {
    this.runLaunchctl(['bootout', this.serviceTarget(serviceId)], false, code, secrets);
    this.waitUntilServiceAbsent(serviceId);
  }

  private waitUntilServiceAbsent(serviceId: string): void {
    const deadline = Date.now() + this.unloadTimeoutMs;
    while (this.isServicePresent(serviceId)) {
      if (Date.now() >= deadline) return;
      this.sleep(this.bootstrapRetryDelayMs);
    }
  }

  private isServicePresent(serviceId: string): boolean {
    const result = this.runner.run('launchctl', ['print', this.serviceTarget(serviceId)]);
    return result.status === 0;
  }

  private bootstrapDefinition(
    serviceId: string,
    definitionPath: string,
    code: 'ERR_SERVICE_INSTALL' | 'ERR_SERVICE_COMMAND',
    secrets: readonly string[],
  ): void {
    const args = ['bootstrap', this.domainTarget(), definitionPath];
    let lastResult: CommandResult | undefined;
    for (let attempt = 1; attempt <= this.bootstrapRetryLimit; attempt += 1) {
      lastResult = this.runner.run('launchctl', args);
      if (lastResult.status === 0) return;
      if (!isTransientBootstrapFailure(lastResult) || attempt === this.bootstrapRetryLimit) {
        throw launchctlFailure(code, args, lastResult, secrets);
      }
      // launchd can still be removing the previous job, or the domain can still
      // be in bootstrap mode. Force another unload and back off before retrying.
      this.runLaunchctl(['bootout', this.serviceTarget(serviceId)], false, code, secrets);
      this.waitUntilServiceAbsent(serviceId);
      this.sleep(this.bootstrapRetryDelayMs * attempt);
    }
    throw launchctlFailure(code, args, lastResult ?? { status: 1, stdout: '', stderr: '' }, secrets);
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

export function isTransientBootstrapFailure(result: CommandResult): boolean {
  // macOS launchd returns EIO (5) while a previous bootout is still tearing down
  // the job, and EINPROGRESS (37) while the gui domain is already bootstrapping.
  if (result.status === 5 || result.status === 37) return true;
  const detail = `${result.stdout}\n${result.stderr}`.toLowerCase();
  return /input\/output error|operation already in progress|bootstrap failed:\s*(5|37)\b/.test(detail);
}

function sleepSync(milliseconds: number): void {
  if (milliseconds <= 0) return;
  const shared = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(shared, 0, 0, milliseconds);
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
