import type { HostPrivateKeyStorage } from '../../identity/types';

export type ServiceBackend = 'launchd' | 'systemd-user';
export type LogBackend = 'files' | 'journald' | 'unavailable';

export type ServiceSupportReason =
  | 'supported'
  | 'unsupported-platform'
  | 'systemctl-not-found'
  | 'systemd-user-manager-unavailable'
  | 'service-directory-unwritable';

export interface ServiceSupport {
  platform: NodeJS.Platform;
  backend?: ServiceBackend;
  supported: boolean;
  isWsl: boolean;
  reason: ServiceSupportReason;
  message?: string;
  detail?: string;
  definitionPath?: string;
}

export interface AriavaServiceInstallRecord {
  backend: ServiceBackend;
  installedAt: string;
  runtimePath: string;
  runtimeName?: 'node';
  runtimeVersion?: string;
  ariavaBinPath: string;
  configPath?: string;
  identityReference?: HostPrivateKeyStorage;
  definitionPath: string;
  serviceId: string;
}

export interface ServiceInstallInput {
  runtimePath: string;
  runtimeName?: 'node';
  runtimeVersion?: string;
  ariavaBinPath: string;
  configPath?: string;
  identityReference?: HostPrivateKeyStorage;
  installedAt?: string;
}

export interface ServiceStatus {
  backend?: ServiceBackend;
  support: ServiceSupport;
  definitionPath?: string;
  serviceId?: string;
  installed: boolean;
  enabled: boolean;
  loaded: boolean;
  processRunning: boolean;
  runtimePath?: string;
  runtimeName?: 'node';
  runtimeVersion?: string;
  recordedRuntimeVersion?: string;
  runtimeVersionMatchesRecorded?: boolean;
  ariavaBinPath?: string;
  runtimeNameIsNode?: boolean;
  runtimeVersionSupported?: boolean;
  runtimePathMatchesCurrent?: boolean;
  ariavaBinPathMatchesCurrent?: boolean;
  runtimeCryptoSelfTestPassed?: boolean;
  logBackend: LogBackend;
  stdoutLogPath?: string;
  stderrLogPath?: string;
  detail?: string;
}

export interface ServiceLogs {
  backend?: ServiceBackend;
  source: 'files' | 'journald';
  text: string;
  stdoutPath?: string;
  stderrPath?: string;
}

export interface ServiceManager {
  readonly backend?: ServiceBackend;
  readonly support: ServiceSupport;
  install(input: ServiceInstallInput): AriavaServiceInstallRecord;
  uninstall(record?: AriavaServiceInstallRecord): void;
  start(record?: AriavaServiceInstallRecord): void;
  stop(record?: AriavaServiceInstallRecord): void;
  restart(record?: AriavaServiceInstallRecord): void;
  status(
    record: AriavaServiceInstallRecord | undefined,
    currentRuntimePath: string,
    currentAriavaBinPath: string,
  ): ServiceStatus;
  logsAvailable(): boolean;
  logs(record?: AriavaServiceInstallRecord): ServiceLogs;
}

export interface CommandResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error & { code?: string };
}

export interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

export interface CommandRunner {
  run(command: string, args: string[], options?: RunOptions): CommandResult;
}

export interface PlatformProbeDependencies {
  platform: NodeJS.Platform;
  homeDir: string;
  runner: CommandRunner;
  readText(path: string): string | undefined;
  pathExists(path: string): boolean;
  assertWritable(path: string): void;
}
