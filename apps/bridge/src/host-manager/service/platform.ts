import { accessSync, constants, existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { SpawnSyncCommandRunner } from './command-runner';
import { AriavaCliError, sanitizeCommandDetail } from './errors';
import type { PlatformProbeDependencies, ServiceSupport } from './types';

const PROC_OS_RELEASE_PATH = '/proc/sys/kernel/osrelease';
const PROC_VERSION_PATH = '/proc/version';
const WSL_CONFIG = '[boot]\nsystemd=true';
const WSL_SHUTDOWN_COMMAND = 'wsl.exe --shutdown';

export function detectWsl(readText: (path: string) => string | undefined): boolean {
  const osRelease = readText(PROC_OS_RELEASE_PATH);
  const releaseText = osRelease ?? readText(PROC_VERSION_PATH);
  return releaseText !== undefined && /microsoft|wsl/i.test(releaseText);
}

export function parseSystemdManagerEnvironment(stdout: string): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const line of stdout.split(/\r?\n/)) {
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    environment[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return environment;
}

export function resolveSystemdUserDefinitionPath(
  homeDir: string,
  managerEnvironment: Record<string, string>,
  serviceId = 'ariava.service',
): string {
  const managerHome = managerEnvironment.HOME;
  if (managerHome && (!isAbsolute(managerHome) || resolve(managerHome) !== resolve(homeDir))) {
    throw new Error('systemd user manager HOME does not match the current user home');
  }
  const xdgConfigHome = managerEnvironment.XDG_CONFIG_HOME;
  if (xdgConfigHome && !isAbsolute(xdgConfigHome)) {
    throw new Error('systemd user manager XDG_CONFIG_HOME must be absolute');
  }
  const configHome = xdgConfigHome ? resolve(xdgConfigHome) : join(resolve(homeDir), '.config');
  return join(configHome, 'systemd', 'user', serviceId);
}

function linuxSupport(
  deps: PlatformProbeDependencies,
  isWsl: boolean,
  values: Omit<ServiceSupport, 'platform' | 'backend' | 'isWsl'>,
): ServiceSupport {
  return {
    platform: deps.platform,
    backend: 'systemd-user',
    isWsl,
    ...values,
  };
}

function nearestExistingPath(path: string, pathExists: (path: string) => boolean): string {
  let candidate = path;
  while (!pathExists(candidate)) {
    const parent = dirname(candidate);
    if (parent === candidate) {
      return candidate;
    }
    candidate = parent;
  }
  return candidate;
}

function commandResultDetail(result: { stderr: string; error?: Error }): string | undefined {
  const detail = result.stderr.trim() || result.error?.message.trim();
  return detail ? sanitizeCommandDetail(detail) : undefined;
}

function systemdUnavailableMessage(isWsl: boolean): string {
  if (!isWsl) {
    return 'Ariava requires an available systemd user manager. Check that your logged-in systemd user manager is running, then retry `ariava init`.';
  }

  return `Ariava requires systemd user services on WSL. Add the following to /etc/wsl.conf:\n\n${WSL_CONFIG}\n\nThen run \`${WSL_SHUTDOWN_COMMAND}\` from Windows PowerShell, reopen the distribution, and retry \`ariava init\`.`;
}

export function detectServiceSupport(deps: PlatformProbeDependencies): ServiceSupport {
  if (deps.platform === 'darwin') {
    return {
      platform: 'darwin',
      backend: 'launchd',
      supported: true,
      isWsl: false,
      reason: 'supported',
    };
  }

  if (deps.platform !== 'linux') {
    return {
      platform: deps.platform,
      supported: false,
      isWsl: false,
      reason: 'unsupported-platform',
      message: `Ariava service management is not supported on ${deps.platform}.`,
    };
  }

  const isWsl = detectWsl(deps.readText);
  const version = deps.runner.run('systemctl', ['--version']);
  const versionDetail = commandResultDetail(version);
  if (version.error?.code === 'ENOENT') {
    return linuxSupport(deps, isWsl, {
      supported: false,
      reason: 'systemctl-not-found',
      message: 'Ariava requires systemctl for systemd user service management.',
      ...(versionDetail ? { detail: versionDetail } : {}),
    });
  }
  if (version.status !== 0) {
    return linuxSupport(deps, isWsl, {
      supported: false,
      reason: 'systemd-user-manager-unavailable',
      message: systemdUnavailableMessage(isWsl),
      ...(versionDetail ? { detail: versionDetail } : {}),
    });
  }

  const userManager = deps.runner.run('systemctl', ['--user', 'show-environment']);
  if (userManager.status !== 0) {
    const userManagerDetail = commandResultDetail(userManager);
    return linuxSupport(deps, isWsl, {
      supported: false,
      reason: 'systemd-user-manager-unavailable',
      message: systemdUnavailableMessage(isWsl),
      ...(userManagerDetail ? { detail: userManagerDetail } : {}),
    });
  }

  let definitionPath: string;
  try {
    definitionPath = resolveSystemdUserDefinitionPath(
      deps.homeDir,
      parseSystemdManagerEnvironment(userManager.stdout),
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return linuxSupport(deps, isWsl, {
      supported: false,
      reason: 'service-directory-unwritable',
      message: 'Ariava cannot resolve a safe systemd user service directory from the user manager environment.',
      detail,
    });
  }
  const serviceDirectory = dirname(definitionPath);
  const writablePath = nearestExistingPath(serviceDirectory, deps.pathExists);
  try {
    deps.assertWritable(writablePath);
  } catch (error) {
    const detail = error instanceof Error ? error.message.trim() : String(error).trim();
    return linuxSupport(deps, isWsl, {
      supported: false,
      reason: 'service-directory-unwritable',
      message: `Ariava cannot install its systemd user service because ${writablePath} is not writable.`,
      ...(detail ? { detail } : {}),
    });
  }

  return linuxSupport(deps, isWsl, {
    supported: true,
    reason: 'supported',
    definitionPath,
  });
}

export function supportError(support: ServiceSupport): AriavaCliError {
  if (support.supported || support.reason === 'supported') {
    throw new Error('supportError requires an unsupported service result');
  }

  const data: Record<string, unknown> = {
    platform: support.platform,
    isWsl: support.isWsl,
    ...(support.backend ? { backend: support.backend } : {}),
    reason: support.reason,
  };

  if (support.isWsl && support.reason === 'systemd-user-manager-unavailable') {
    data.instructions = {
      wslConfig: WSL_CONFIG,
      windowsCommand: WSL_SHUTDOWN_COMMAND,
    };
  }

  switch (support.reason) {
    case 'unsupported-platform':
      return new AriavaCliError('ERR_UNSUPPORTED_PLATFORM', support.message ?? 'Unsupported platform.', data);
    case 'systemctl-not-found':
      return new AriavaCliError('ERR_SYSTEMCTL_NOT_FOUND', support.message ?? 'systemctl was not found.', data);
    case 'systemd-user-manager-unavailable':
      return new AriavaCliError(
        'ERR_SYSTEMD_USER_UNAVAILABLE',
        support.message ?? 'The systemd user manager is unavailable.',
        data,
      );
    case 'service-directory-unwritable':
      return new AriavaCliError(
        'ERR_SERVICE_INSTALL',
        support.message ?? 'The service installation directory is not writable.',
        data,
      );
  }
}

function readTextDefensively(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

export function createPlatformProbeDependencies(): PlatformProbeDependencies {
  return {
    platform: process.platform,
    homeDir: homedir(),
    runner: new SpawnSyncCommandRunner(),
    readText: readTextDefensively,
    pathExists: existsSync,
    assertWritable(path: string) {
      const absolute = resolve(path);
      const stats = lstatSync(absolute);
      if (!stats.isDirectory() || stats.isSymbolicLink() || realpathSync(absolute) !== absolute) {
        throw new Error(`${absolute} is not a safe directory`);
      }
      const uid = process.getuid?.();
      if (uid !== undefined && stats.uid !== uid) {
        throw new Error(`${absolute} is not owned by the current user`);
      }
      if ((stats.mode & 0o022) !== 0) {
        throw new Error(`${absolute} is group/world writable`);
      }
      accessSync(absolute, constants.W_OK | constants.X_OK);
    },
  };
}
