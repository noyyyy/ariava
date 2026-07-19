import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  AriavaCliError,
  resolveAriavaConfig,
  type AriavaServiceInstallRecord,
  type ServiceManager,
  type ServiceStatus,
  type ServiceSupport,
} from '../../src/host-manager';
import { runPublicCli } from '../../src/public-cli-app';

const scenario = process.env.ARIAVA_TEST_SCENARIO ?? 'linux-supported';
const managerCallsPath = process.env.ARIAVA_TEST_MANAGER_CALLS_PATH
  ?? join(process.env.HOME ?? '', '.config', 'ariava', 'manager-calls.json');
const installPath = join(process.env.HOME ?? '', '.config', 'ariava', 'install.json');

function supportForScenario(): ServiceSupport {
  switch (scenario) {
    case 'unsupported':
      return { platform: 'win32', supported: false, isWsl: false, reason: 'unsupported-platform' };
    case 'missing-systemctl':
      return { platform: 'linux', backend: 'systemd-user', supported: false, isWsl: false, reason: 'systemctl-not-found' };
    case 'native-user-manager-unavailable':
      return { platform: 'linux', backend: 'systemd-user', supported: false, isWsl: false, reason: 'systemd-user-manager-unavailable' };
    case 'wsl-unavailable':
      return {
        platform: 'linux',
        backend: 'systemd-user',
        supported: false,
        isWsl: true,
        reason: 'systemd-user-manager-unavailable',
        message: 'Ariava requires an available systemd user manager on WSL.',
      };
    case 'directory-unwritable':
      return { platform: 'linux', backend: 'systemd-user', supported: false, isWsl: false, reason: 'service-directory-unwritable' };
    case 'launchd-supported':
      return { platform: 'darwin', backend: 'launchd', supported: true, isWsl: false, reason: 'supported' };
    case 'wsl-supported':
      return { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: true, reason: 'supported' };
    default:
      return { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' };
  }
}

function recordCall(call: Record<string, unknown>): void {
  const calls = existsSync(managerCallsPath)
    ? JSON.parse(readFileSync(managerCallsPath, 'utf8')) as Array<Record<string, unknown>>
    : [];
  mkdirSync(join(managerCallsPath, '..'), { recursive: true });
  writeFileSync(managerCallsPath, JSON.stringify([...calls, call]));
}

function createFakeManager(): ServiceManager {
  const support = supportForScenario();
  const backend = support.backend;
  const record: AriavaServiceInstallRecord = backend === 'launchd'
    ? {
        backend,
        installedAt: '2026-07-15T00:00:00.000Z',
        runtimePath: '/fixture/node',
        ariavaBinPath: '/fixture/ariava',
        definitionPath: '/fixture/home/Library/LaunchAgents/io.noyx.ariava.bridge.plist',
        serviceId: 'io.noyx.ariava.bridge',
        configPath: join(process.env.HOME ?? '', '.config', 'ariava', 'config.json'),
        identityReference: { type: 'macos-keychain', service: 'io.noyx.ariava.host-identity', account: 'host_fixture' },
      }
    : {
        backend: 'systemd-user',
        installedAt: '2026-07-15T00:00:00.000Z',
        runtimePath: '/fixture/node',
        ariavaBinPath: '/fixture/ariava',
        definitionPath: '/fixture/home/.config/systemd/user/ariava.service',
        serviceId: 'ariava.service',
        configPath: join(process.env.HOME ?? '', '.config', 'ariava', 'config.json'),
        identityReference: { type: 'linux-json', path: join(process.env.HOME ?? '', '.config', 'ariava', 'host-identity.json') },
      };
  const status = (stored?: AriavaServiceInstallRecord): ServiceStatus => {
    recordCall({ operation: 'status' });
    const matches = Boolean(stored && stored.backend === backend)
      && scenario !== 'service-not-installed';
    return {
      ...(backend ? { backend } : {}),
      support,
      definitionPath: record.definitionPath,
      serviceId: record.serviceId,
      installed: matches,
      enabled: matches,
      loaded: matches,
      processRunning: matches,
      runtimePath: stored?.runtimePath,
      ariavaBinPath: stored?.ariavaBinPath,
      runtimePathMatchesCurrent: stored ? stored.runtimePath === '/fixture/node' : undefined,
      ariavaBinPathMatchesCurrent: stored ? stored.ariavaBinPath === '/fixture/ariava' : undefined,
      logBackend: support.supported ? backend === 'launchd' ? 'files' : 'journald' : 'unavailable',
      ...(backend === 'launchd' ? { stdoutLogPath: '/fixture/stdout.log', stderrLogPath: '/fixture/stderr.log' } : {}),
      detail: stored && stored.backend !== backend ? `metadata backend ${stored.backend} does not match ${backend}` : undefined,
    };
  };
  return {
    backend,
    support,
    install(input) {
      const { runtimeName: _runtimeName, runtimeVersion: _runtimeVersion, ...legacyObservableInput } = input;
      recordCall({ operation: 'install', ...legacyObservableInput });
      if (scenario === 'install-failure') {
        throw new AriavaCliError('ERR_SERVICE_INSTALL', 'fixture install failed', { command: 'fixture install' });
      }
      return { ...record, runtimeName: input.runtimeName, runtimeVersion: input.runtimeVersion };
    },
    uninstall() {
      recordCall({ operation: 'uninstall' });
      if (scenario === 'uninstall-failure') {
        throw new AriavaCliError('ERR_SERVICE_COMMAND', 'fixture uninstall failed');
      }
    },
    start() { recordCall({ operation: 'start' }); },
    stop() { recordCall({ operation: 'stop' }); },
    restart() {
      const metadataPersisted = existsSync(installPath)
        && (JSON.parse(readFileSync(installPath, 'utf8')).service?.runtimePath === '/fixture/node');
      recordCall({ operation: 'restart', metadataPersisted });
      if (scenario === 'restart-failure') {
        throw new AriavaCliError('ERR_SERVICE_COMMAND', 'restart failed for /fixture/node');
      }
    },
    status,
    logsAvailable() {
      return support.supported && scenario !== 'missing-journal';
    },
    logs() {
      recordCall({ operation: 'logs' });
      if (scenario === 'logs-unavailable') {
        throw new AriavaCliError('ERR_LOGS_UNAVAILABLE', 'fixture logs unavailable');
      }
      return backend === 'launchd'
        ? { backend, source: 'files', stdoutPath: '/fixture/stdout.log', stderrPath: '/fixture/stderr.log', text: 'stdout\nstderr' }
        : { backend, source: 'journald', text: 'journal line\nnext' };
    },
  };
}

const exitCode = await runPublicCli(process.argv.slice(2), {
  createServiceManager: createFakeManager,
  realpath: (path) => path,
  spawn: (command, args, options) => {
    recordCall({ operation: 'spawn', command, args, reentry: Boolean(options && 'env' in options && options.env?.ARIAVA_UPGRADE_SELF_DONE === '1') });
    return { status: 0, stdout: '', stderr: '' } as ReturnType<typeof import('node:child_process').spawnSync>;
  },
  resolveAriavaConfig: () => {
    const resolved = resolveAriavaConfig();
    return resolved.identity ? resolved : {
      ...resolved,
      identity: {
        identityVersion: 2, hostId: 'host_fixture', keyId: 'key_fixture', algorithm: 'Ed25519',
        publicKey: 'fixture', publicKeyFingerprint: 'fixture', createdAt: '2026-07-15T00:00:00.000Z',
        privateKeyStorage: supportForScenario().platform === 'darwin'
          ? { type: 'macos-keychain', service: 'io.noyx.ariava.host-identity', account: 'host_fixture' }
          : { type: 'linux-json', path: resolved.identityPath },
      },
    };
  },
  currentRuntimePath: () => '/fixture/node',
  currentAriavaBinPath: () => '/fixture/ariava',
  stdout: process.stdout,
  stderr: process.stderr,
  commandExists: () => false,
  inspectRuntime: () => ({
    runtimeName: 'node', runtimeVersion: 'v22.0.0', runtimePath: '/fixture/node',
    runtimeNameIsNode: true, runtimeVersionSupported: true,
  }),
  probeRuntimePath: (runtimePath) => ({
    runtimeName: 'node', runtimeVersion: 'v22.0.0', runtimePath,
    runtimeNameIsNode: true, runtimeVersionSupported: true,
  }),
  cryptoSelfTest: () => true,
});
process.exitCode = exitCode;
