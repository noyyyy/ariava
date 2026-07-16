import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  ARIAVA_LAUNCHD_LABEL,
  ARIAVA_SYSTEMD_SERVICE_ID,
} from '../paths';
import { SpawnSyncCommandRunner } from './command-runner';
import { AriavaCliError } from './errors';
import {
  LaunchdServiceManager,
  type LaunchdFileSystem,
} from './launchd';
import {
  createPlatformProbeDependencies,
  detectServiceSupport,
  supportError,
} from './platform';
import {
  SystemdUserServiceManager,
  type SystemdUserFileSystem,
} from './systemd-user';
import { removeOwnerControlledFile, writeOwnerControlledFile } from '../secure-files';
import type {
  AriavaServiceInstallRecord,
  CommandRunner,
  ServiceInstallInput,
  ServiceLogs,
  ServiceManager,
  ServiceStatus,
  ServiceSupport,
} from './types';

export interface ServiceManagerFileSystem extends LaunchdFileSystem, SystemdUserFileSystem {}

export interface ServiceManagerPaths {
  launchdServiceId: string;
  launchdDefinitionPath: string;
  stdoutLogPath: string;
  stderrLogPath: string;
  systemdServiceId: string;
  systemdDefinitionPath: string;
}

export interface CreateServiceManagerOptions {
  platform?: NodeJS.Platform;
  homeDir?: string;
  runner?: CommandRunner;
  support?: ServiceSupport;
  fileSystem?: Partial<ServiceManagerFileSystem>;
  uid?: number;
  paths?: Partial<ServiceManagerPaths>;
  readText?: (path: string) => string | undefined;
  pathExists?: (path: string) => boolean;
  assertWritable?: (path: string) => void;
}

const defaultFileSystem: ServiceManagerFileSystem = {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeAtomicSync(path, data, controlledRoot) {
    writeOwnerControlledFile(path, Buffer.from(data), controlledRoot);
  },
  removeAtomicSync(path, controlledRoot) {
    removeOwnerControlledFile(path, controlledRoot);
  },
};

export function createServiceManager(options: CreateServiceManagerOptions = {}): ServiceManager {
  const defaults = createPlatformProbeDependencies();
  const platform = options.platform ?? options.support?.platform ?? defaults.platform;
  const homeDir = options.homeDir ?? defaults.homeDir ?? homedir();
  const runner = options.runner ?? new SpawnSyncCommandRunner();
  const fileSystem = { ...defaultFileSystem, ...options.fileSystem };
  const support = options.support ?? detectServiceSupport({
    platform,
    homeDir,
    runner,
    readText: options.readText ?? defaults.readText,
    pathExists: options.pathExists ?? defaults.pathExists,
    assertWritable: options.assertWritable ?? defaults.assertWritable,
  });
  const paths = resolveManagerPaths(homeDir, options.paths, support);

  if (support.supported && support.backend === 'launchd') {
    return new LaunchdServiceManager({
      support,
      runner,
      uid: options.uid ?? process.getuid?.() ?? 0,
      serviceId: paths.launchdServiceId,
      definitionPath: paths.launchdDefinitionPath,
      stdoutLogPath: paths.stdoutLogPath,
      stderrLogPath: paths.stderrLogPath,
      fileSystem,
    });
  }

  if (support.supported && support.backend === 'systemd-user') {
    return new SystemdUserServiceManager({
      support,
      runner,
      homeDir,
      serviceId: paths.systemdServiceId,
      definitionPath: paths.systemdDefinitionPath,
      fileSystem,
    });
  }

  return new UnsupportedServiceManager(support);
}

class UnsupportedServiceManager implements ServiceManager {
  readonly backend;

  constructor(readonly support: ServiceSupport) {
    this.backend = support.backend;
  }

  install(_input: ServiceInstallInput): AriavaServiceInstallRecord {
    throw supportError(this.support);
  }

  uninstall(_record?: AriavaServiceInstallRecord): void {
    throw supportError(this.support);
  }

  start(_record?: AriavaServiceInstallRecord): void {
    throw supportError(this.support);
  }

  stop(_record?: AriavaServiceInstallRecord): void {
    throw supportError(this.support);
  }

  restart(_record?: AriavaServiceInstallRecord): void {
    throw supportError(this.support);
  }

  status(
    _record: AriavaServiceInstallRecord | undefined,
    _currentRuntimePath: string,
    _currentAriavaBinPath: string,
  ): ServiceStatus {
    return {
      ...(this.backend ? { backend: this.backend } : {}),
      support: this.support,
      installed: false,
      enabled: false,
      loaded: false,
      processRunning: false,
      logBackend: 'unavailable',
      ...(this.support.message ? { detail: this.support.message } : {}),
    };
  }

  logsAvailable(): boolean {
    return false;
  }

  logs(_record?: AriavaServiceInstallRecord): ServiceLogs {
    const error = supportError(this.support);
    throw new AriavaCliError('ERR_LOGS_UNAVAILABLE', error.message, {
      ...error.data,
      supportErrorCode: error.code,
    });
  }
}

function resolveManagerPaths(
  homeDir: string,
  overrides: Partial<ServiceManagerPaths> | undefined,
  support: ServiceSupport,
): ServiceManagerPaths {
  const configRoot = join(homeDir, '.config', 'ariava');
  return {
    launchdServiceId: overrides?.launchdServiceId ?? ARIAVA_LAUNCHD_LABEL,
    launchdDefinitionPath: overrides?.launchdDefinitionPath
      ?? join(homeDir, 'Library', 'LaunchAgents', `${ARIAVA_LAUNCHD_LABEL}.plist`),
    stdoutLogPath: overrides?.stdoutLogPath ?? join(configRoot, 'logs', 'bridge.stdout.log'),
    stderrLogPath: overrides?.stderrLogPath ?? join(configRoot, 'logs', 'bridge.stderr.log'),
    systemdServiceId: overrides?.systemdServiceId ?? ARIAVA_SYSTEMD_SERVICE_ID,
    systemdDefinitionPath: overrides?.systemdDefinitionPath
      ?? support.definitionPath
      ?? join(homeDir, '.config', 'systemd', 'user', ARIAVA_SYSTEMD_SERVICE_ID),
  };
}
