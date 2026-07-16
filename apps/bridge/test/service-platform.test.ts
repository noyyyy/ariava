import { describe, expect, mock, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const spawnSyncCalls: Array<{
  command: string;
  args: string[];
  options: Record<string, unknown>;
}> = [];
const spawnSyncResults: Array<Record<string, unknown>> = [];

mock.module('node:child_process', () => ({
  spawnSync(command: string, args: string[], options: Record<string, unknown>) {
    spawnSyncCalls.push({ command, args, options });
    return spawnSyncResults.shift() ?? {};
  },
}));

const {
  ARIAVA_CLI_ERROR_CODES,
  AriavaCliError,
  LaunchdServiceManager,
  SpawnSyncCommandRunner,
  SystemdUserServiceManager,
  commandFailureData,
  createPlatformProbeDependencies,
  createServiceManager,
  detectServiceSupport,
  detectWsl,
  sanitizeCommandDetail,
  supportError,
} = await import('../src/host-manager/service/index');

const managerFileSystem = {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
};

const {
  ARIAVA_SYSTEMD_SERVICE_ID,
  ARIAVA_SYSTEMD_UNIT_PATH,
  ARIAVA_SYSTEMD_USER_DIR,
} = await import('../src/host-manager/paths');

describe('neutral service command boundary', () => {
  test('runs commands without a shell and preserves the requested working directory and environment', () => {
    spawnSyncResults.push({ status: 0, stdout: 'ready\n', stderr: '' });
    const env = { PATH: '/usr/bin', LC_ALL: 'C' };

    const result = new SpawnSyncCommandRunner().run(
      'systemctl',
      ['--user', 'status', 'ariava.service'],
      { cwd: '/tmp/ariava', env },
    );

    expect(spawnSyncCalls.pop()).toEqual({
      command: 'systemctl',
      args: ['--user', 'status', 'ariava.service'],
      options: { encoding: 'utf8', shell: false, cwd: '/tmp/ariava', env },
    });
    expect(result).toEqual({ status: 0, stdout: 'ready\n', stderr: '' });
  });

  test('preserves ENOENT and normalizes absent command result fields', () => {
    const error = Object.assign(new Error('spawn systemctl ENOENT'), { code: 'ENOENT' });
    spawnSyncResults.push({ error });

    const result = new SpawnSyncCommandRunner().run('systemctl', ['--version']);

    expect(result).toEqual({ status: null, stdout: '', stderr: '', error });
  });

  test('returns non-zero command results instead of throwing', () => {
    spawnSyncResults.push({ status: 3, stdout: '', stderr: 'inactive\n' });

    expect(new SpawnSyncCommandRunner().run('systemctl', ['--user', 'is-active', 'ariava.service'])).toEqual({
      status: 3,
      stdout: '',
      stderr: 'inactive\n',
    });
  });
});

describe('stable Ariava CLI errors', () => {
  test('exposes all eight stable service error codes', () => {
    expect(ARIAVA_CLI_ERROR_CODES).toEqual([
      'ERR_UNSUPPORTED_PLATFORM',
      'ERR_SYSTEMCTL_NOT_FOUND',
      'ERR_SYSTEMD_USER_UNAVAILABLE',
      'ERR_SERVICE_NOT_INSTALLED',
      'ERR_SERVICE_INSTALL',
      'ERR_SERVICE_COMMAND',
      'ERR_SERVICE_METADATA',
      'ERR_LOGS_UNAVAILABLE',
    ]);
  });

  test('carries stable code and structured data', () => {
    const error = new AriavaCliError('ERR_SERVICE_COMMAND', 'restart failed', { backend: 'systemd-user' });

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('AriavaCliError');
    expect(error.message).toBe('restart failed');
    expect(error.code).toBe('ERR_SERVICE_COMMAND');
    expect(error.data).toEqual({ backend: 'systemd-user' });
  });

  test('redacts supplied secrets and truncates command details to 2,000 characters', () => {
    const secret = 'top-secret-token';
    const sanitized = sanitizeCommandDetail(`${secret}:${'x'.repeat(2_100)}:${secret}`, [secret]);

    expect(sanitized).not.toContain(secret);
    expect(sanitized).toStartWith('<redacted>:');
    expect(sanitized.length).toBe(2_000);
  });

  test('redacts overlapping secrets longest-first', () => {
    expect(sanitizeCommandDetail('token=abcdef', ['abc', '', 'abcdef'])).toBe('token=<redacted>');
  });

  test('builds sanitized command failure data without environment details', () => {
    const data = commandFailureData(
      'systemctl',
      ['--user', 'show', 'secret-value'],
      { status: 1, stdout: 'ignored', stderr: `failure for secret-value ${'y'.repeat(2_100)}` },
      ['secret-value'],
    );

    expect(data).toEqual({
      command: 'systemctl --user show <redacted>',
      exitCode: 1,
      stderr: `failure for <redacted> ${'y'.repeat(2_100)}`.slice(0, 2_000),
    });
    expect(data.stderr).not.toContain('secret-value');
    expect(data.stderr.length).toBe(2_000);
    expect(data).not.toHaveProperty('env');
  });
});

type FakeCommandResult = {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error & { code?: string };
};

function createPlatformProbe(options: {
  platform?: NodeJS.Platform;
  homeDir?: string;
  commandResults?: FakeCommandResult[];
  procFiles?: Record<string, string | undefined>;
  existingPaths?: string[];
  writableError?: Error;
} = {}) {
  const calls: string[] = [];
  const commandResults = [...(options.commandResults ?? [])];
  const procFiles = options.procFiles ?? {};
  const existingPaths = new Set(options.existingPaths ?? ['/home/test/.config/systemd/user']);
  return {
    calls,
    deps: {
      platform: options.platform ?? 'linux',
      homeDir: options.homeDir ?? '/home/test',
      runner: {
        run(command: string, args: string[]) {
          calls.push(`${command} ${args.join(' ')}`);
          return commandResults.shift() ?? { status: 0, stdout: '', stderr: '' };
        },
      },
      readText(path: string) {
        calls.push(`read ${path}`);
        return procFiles[path];
      },
      pathExists(path: string) {
        calls.push(`exists ${path}`);
        return existingPaths.has(path);
      },
      assertWritable(path: string) {
        calls.push(`writable ${path}`);
        if (options.writableError) {
          throw options.writableError;
        }
      },
    },
  };
}

describe('platform service support detection', () => {
  test('selects launchd on darwin without invoking service commands', () => {
    const probe = createPlatformProbe({ platform: 'darwin' });

    expect(detectServiceSupport(probe.deps)).toEqual({
      platform: 'darwin',
      backend: 'launchd',
      supported: true,
      isWsl: false,
      reason: 'supported',
    });
    expect(probe.calls).toEqual([]);
  });

  test('checks systemctl and the user manager in order on Linux', () => {
    const probe = createPlatformProbe({
      commandResults: [
        { status: 0, stdout: 'systemd 256\n', stderr: '' },
        { status: 0, stdout: 'HOME=/home/test\nXDG_CONFIG_HOME=/home/test/.manager-config\n', stderr: '' },
      ],
    });

    expect(detectServiceSupport(probe.deps)).toMatchObject({
      backend: 'systemd-user',
      supported: true,
      reason: 'supported',
    });
    expect(detectServiceSupport(createPlatformProbe({ commandResults: [
      { status: 0, stdout: '', stderr: '' },
      { status: 0, stdout: 'HOME=/home/test\nXDG_CONFIG_HOME=/home/test/.manager-config\n', stderr: '' },
    ], existingPaths: ['/home/test/.manager-config'] }).deps).definitionPath)
      .toBe('/home/test/.manager-config/systemd/user/ariava.service');
    expect(probe.calls.filter((call) => call.startsWith('systemctl'))).toEqual([
      'systemctl --version',
      'systemctl --user show-environment',
    ]);
  });

  test('rejects mismatched or relative persisted manager environment paths', () => {
    for (const environment of ['HOME=/other/user', 'HOME=/home/test\nXDG_CONFIG_HOME=relative']) {
      const probe = createPlatformProbe({ commandResults: [
        { status: 0, stdout: '', stderr: '' },
        { status: 0, stdout: environment, stderr: '' },
      ] });
      expect(detectServiceSupport(probe.deps)).toMatchObject({ supported: false, reason: 'service-directory-unwritable' });
    }
  });

  test('maps a missing systemctl executable to systemctl-not-found', () => {
    const error = Object.assign(new Error('spawn systemctl ENOENT'), { code: 'ENOENT' });
    const probe = createPlatformProbe({
      commandResults: [{ status: null, stdout: '', stderr: '', error }],
    });

    const support = detectServiceSupport(probe.deps);

    expect(support).toMatchObject({
      supported: false,
      reason: 'systemctl-not-found',
      backend: 'systemd-user',
    });
    expect(probe.calls.filter((call) => call.startsWith('systemctl'))).toEqual(['systemctl --version']);
    expect(supportError(support).code).toBe('ERR_SYSTEMCTL_NOT_FOUND');
  });

  test('does not report unusable systemctl executions as a missing executable', () => {
    const cases: Array<{ name: string; result: FakeCommandResult; detail: string }> = [
      {
        name: 'permission failure',
        result: {
          status: null,
          stdout: '',
          stderr: '',
          error: Object.assign(new Error(`spawn systemctl EACCES ${'x'.repeat(2_100)}`), { code: 'EACCES' }),
        },
        detail: `spawn systemctl EACCES ${'x'.repeat(2_100)}`.slice(0, 2_000),
      },
      {
        name: 'signal termination',
        result: { status: null, stdout: '', stderr: '  systemctl terminated by signal  ' },
        detail: 'systemctl terminated by signal',
      },
      {
        name: 'ordinary nonzero exit',
        result: { status: 1, stdout: '', stderr: '  systemctl version probe failed  ' },
        detail: 'systemctl version probe failed',
      },
    ];

    for (const { name, result, detail } of cases) {
      const probe = createPlatformProbe({ commandResults: [result] });
      const support = detectServiceSupport(probe.deps);

      expect(support, name).toMatchObject({
        supported: false,
        reason: 'systemd-user-manager-unavailable',
        detail,
      });
      expect(supportError(support).code, name).toBe('ERR_SYSTEMD_USER_UNAVAILABLE');
      expect(probe.calls.filter((call) => call.startsWith('systemctl')), name).toEqual([
        'systemctl --version',
      ]);
    }
  });

  test('reports unavailable user manager with trimmed stderr detail', () => {
    const probe = createPlatformProbe({
      commandResults: [
        { status: 0, stdout: 'systemd 256', stderr: '' },
        { status: 1, stdout: '', stderr: '  Failed to connect to bus: No medium found  \n' },
      ],
    });

    const support = detectServiceSupport(probe.deps);

    expect(support).toMatchObject({
      supported: false,
      reason: 'systemd-user-manager-unavailable',
      detail: 'Failed to connect to bus: No medium found',
    });
    expect(support.message).toContain('logged-in systemd user manager');
    expect(support.message).not.toContain('/etc/wsl.conf');
    expect(supportError(support)).toMatchObject({ code: 'ERR_SYSTEMD_USER_UNAVAILABLE' });
  });

  test('uses a bounded error message when the user-manager probe cannot spawn', () => {
    const error = Object.assign(new Error(`spawn systemctl EACCES ${'z'.repeat(2_100)}`), { code: 'EACCES' });
    const probe = createPlatformProbe({
      commandResults: [
        { status: 0, stdout: 'systemd 256', stderr: '' },
        { status: null, stdout: '', stderr: '', error },
      ],
    });

    const support = detectServiceSupport(probe.deps);

    expect(support).toMatchObject({
      supported: false,
      reason: 'systemd-user-manager-unavailable',
    });
    expect(support.detail).toBe(`spawn systemctl EACCES ${'z'.repeat(2_100)}`.slice(0, 2_000));
  });

  test('checks the service directory when it exists', () => {
    const probe = createPlatformProbe();

    expect(detectServiceSupport(probe.deps).supported).toBe(true);
    expect(probe.calls).toContain('writable /home/test/.config/systemd/user');
  });

  test('checks the nearest existing parent without creating directories', () => {
    const probe = createPlatformProbe({ existingPaths: ['/home/test/.config'] });

    expect(detectServiceSupport(probe.deps).supported).toBe(true);
    expect(probe.calls.filter((call) => call.startsWith('writable'))).toEqual([
      'writable /home/test/.config',
    ]);
    expect(probe.calls.every((call) => !call.startsWith('mkdir'))).toBe(true);
  });

  test('maps an unwritable service directory to service-directory-unwritable', () => {
    const probe = createPlatformProbe({ writableError: new Error('EACCES') });

    const support = detectServiceSupport(probe.deps);

    expect(support).toMatchObject({
      supported: false,
      reason: 'service-directory-unwritable',
      detail: 'EACCES',
    });
    expect(supportError(support).code).toBe('ERR_SERVICE_INSTALL');
  });

  test('rejects a nearest existing path that is a regular file', () => {
    const homeDir = mkdtempSync(join(tmpdir(), 'ariava-platform-file-'));
    const configDir = join(homeDir, '.config');
    mkdirSync(configDir);
    writeFileSync(join(configDir, 'systemd'), 'not a directory');

    try {
      const production = createPlatformProbeDependencies();
      const support = detectServiceSupport({
        ...production,
        platform: 'linux',
        homeDir,
        runner: createPlatformProbe().deps.runner,
        readText: () => undefined,
      });

      expect(support).toMatchObject({
        supported: false,
        reason: 'service-directory-unwritable',
      });
      expect(support.detail).toContain('not a safe directory');
    } finally {
      rmSync(homeDir, { recursive: true, force: true });
    }
  });

  test('rejects a writable directory without execute/search permission', () => {
    const homeDir = mkdtempSync(join(tmpdir(), 'ariava-platform-search-'));
    const serviceDir = join(homeDir, '.config', 'systemd', 'user');
    mkdirSync(serviceDir, { recursive: true });
    chmodSync(serviceDir, 0o200);

    try {
      const production = createPlatformProbeDependencies();
      const support = detectServiceSupport({
        ...production,
        platform: 'linux',
        homeDir,
        runner: createPlatformProbe().deps.runner,
        readText: () => undefined,
      });

      expect(support).toMatchObject({
        supported: false,
        reason: 'service-directory-unwritable',
      });
    } finally {
      chmodSync(serviceDir, 0o700);
      rmSync(homeDir, { recursive: true, force: true });
    }
  });

  test('detects WSL from osrelease first and falls back to proc version', () => {
    expect(detectWsl((path: string) => ({
      '/proc/sys/kernel/osrelease': '6.6.87.2-MICROSOFT-standard-WSL2',
      '/proc/version': 'ordinary linux',
    })[path])).toBe(true);

    const reads: string[] = [];
    expect(detectWsl((path: string) => {
      reads.push(path);
      return path === '/proc/version' ? 'Linux version under wSl' : undefined;
    })).toBe(true);
    expect(reads).toEqual(['/proc/sys/kernel/osrelease', '/proc/version']);
  });

  test('provides exact WSL enablement guidance when the user manager is unavailable', () => {
    const probe = createPlatformProbe({
      procFiles: { '/proc/sys/kernel/osrelease': 'microsoft-standard-WSL2' },
      commandResults: [
        { status: 0, stdout: 'systemd 256', stderr: '' },
        { status: 1, stdout: '', stderr: 'bus unavailable' },
      ],
    });

    const support = detectServiceSupport(probe.deps);
    const error = supportError(support);

    expect(support.message).toContain('/etc/wsl.conf');
    expect(support.message).toContain('[boot]\nsystemd=true');
    expect(support.message).toContain('wsl.exe --shutdown');
    expect(support.message).toContain('retry `ariava init`');
    expect(error.data).toEqual({
      platform: 'linux',
      isWsl: true,
      backend: 'systemd-user',
      reason: 'systemd-user-manager-unavailable',
      instructions: {
        wslConfig: '[boot]\nsystemd=true',
        windowsCommand: 'wsl.exe --shutdown',
      },
    });
  });

  test('rejects unsupported platforms without invoking service commands', () => {
    for (const platform of ['win32', 'freebsd', 'openbsd'] as NodeJS.Platform[]) {
      const probe = createPlatformProbe({ platform });
      const support = detectServiceSupport(probe.deps);

      expect(support).toMatchObject({
        platform,
        supported: false,
        reason: 'unsupported-platform',
        isWsl: false,
      });
      expect(probe.calls).toEqual([]);
      expect(supportError(support).code).toBe('ERR_UNSUPPORTED_PLATFORM');
    }
  });

  test('defines stable systemd user service paths', () => {
    expect(ARIAVA_SYSTEMD_SERVICE_ID).toBe('ariava.service');
    expect(ARIAVA_SYSTEMD_UNIT_PATH).toBe(`${ARIAVA_SYSTEMD_USER_DIR}/ariava.service`);
  });
});

describe('service manager selection', () => {
  test('creates launchd on Darwin with injected dependencies', () => {
    const runner = { run: () => ({ status: 0, stdout: '', stderr: '' }) };
    const manager = createServiceManager({
      platform: 'darwin',
      homeDir: '/Users/test',
      runner,
      uid: 501,
      fileSystem: managerFileSystem,
    });

    expect(manager).toBeInstanceOf(LaunchdServiceManager);
    expect(manager.backend).toBe('launchd');
    expect(manager.support).toMatchObject({ supported: true, reason: 'supported' });
  });

  test('detects Linux support once and passes it into systemd-user', () => {
    const probe = createPlatformProbe({
      commandResults: [
        { status: 0, stdout: 'systemd 256', stderr: '' },
        { status: 0, stdout: 'HOME=/home/test', stderr: '' },
      ],
    });
    const manager = createServiceManager({
      platform: 'linux',
      homeDir: '/home/test',
      runner: probe.deps.runner,
      readText: probe.deps.readText,
      pathExists: probe.deps.pathExists,
      assertWritable: probe.deps.assertWritable,
      fileSystem: managerFileSystem,
    });

    expect(manager).toBeInstanceOf(SystemdUserServiceManager);
    expect(manager.backend).toBe('systemd-user');
    expect(manager.support).toMatchObject({ supported: true, reason: 'supported' });
    expect(probe.calls.filter((call) => call.startsWith('systemctl'))).toEqual([
      'systemctl --version',
      'systemctl --user show-environment',
    ]);
  });

  test('uses the exact injected support result without probing again', () => {
    const injectedSupport = {
      platform: 'linux' as const,
      backend: 'systemd-user' as const,
      supported: true,
      isWsl: false,
      reason: 'supported' as const,
    };
    const calls: string[] = [];
    const manager = createServiceManager({
      support: injectedSupport,
      runner: {
        run(command: string, args: string[]) {
          calls.push(`${command} ${args.join(' ')}`);
          return { status: 0, stdout: '', stderr: '' };
        },
      },
      fileSystem: managerFileSystem,
    });

    expect(manager).toBeInstanceOf(SystemdUserServiceManager);
    expect(manager.support).toBe(injectedSupport);
    expect(calls).toEqual([]);
  });

  test('returns neutral diagnostics on unsupported platforms and stable errors for operations', () => {
    const manager = createServiceManager({
      platform: 'win32',
      homeDir: 'C:\\Users\\test',
      runner: { run: () => { throw new Error('must not run'); } },
      fileSystem: managerFileSystem,
    });

    expect(manager.backend).toBeUndefined();
    expect(manager.status(undefined, 'C:\\node.exe', 'C:\\ariava.exe')).toEqual({
      support: manager.support,
      installed: false,
      enabled: false,
      loaded: false,
      processRunning: false,
      logBackend: 'unavailable',
      detail: 'Ariava service management is not supported on win32.',
    });

    for (const operation of [
      () => manager.install({ runtimePath: 'C:\\node.exe', ariavaBinPath: 'C:\\ariava.exe' }),
      () => manager.uninstall(),
      () => manager.start(),
      () => manager.stop(),
      () => manager.restart(),
    ]) {
      expect(operation).toThrow(AriavaCliError);
      try {
        operation();
      } catch (error) {
        expect((error as AriavaCliError).code).toBe('ERR_UNSUPPORTED_PLATFORM');
      }
    }

    expect(() => manager.logs()).toThrow(AriavaCliError);
    try {
      manager.logs();
    } catch (error) {
      expect((error as AriavaCliError).code).toBe('ERR_LOGS_UNAVAILABLE');
      expect((error as AriavaCliError).data).toMatchObject({
        platform: 'win32',
        reason: 'unsupported-platform',
      });
    }
  });
});
