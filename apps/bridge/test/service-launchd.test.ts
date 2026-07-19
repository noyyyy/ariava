import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AriavaCliError,
  LaunchdServiceManager,
  buildLaunchdServiceDefinition,
  parseProgramArgumentsFromPlist,
  renderLaunchdPlist,
  type CommandResult,
  type CommandRunner,
  type LaunchdFileSystem,
  type ServiceSupport,
} from '../src/host-manager/service/index';

const roots: string[] = [];
const support: ServiceSupport = {
  platform: 'darwin',
  backend: 'launchd',
  supported: true,
  isWsl: false,
  reason: 'supported',
};

class FakeRunner implements CommandRunner {
  readonly calls: Array<{ command: string; args: string[] }> = [];
  readonly results: CommandResult[] = [];

  run(command: string, args: string[]): CommandResult {
    this.calls.push({ command, args });
    return this.results.shift() ?? { status: 0, stdout: '', stderr: '' };
  }
}

function fixture(fileSystemOverrides: Partial<LaunchdFileSystem> = {}) {
  const root = join(tmpdir(), `ariava-service-launchd-${Date.now()}-${Math.random()}`);
  roots.push(root);
  const definitionPath = join(root, 'LaunchAgents', 'io.test.ariava.plist');
  const stdoutLogPath = join(root, 'logs', 'stdout.log');
  const stderrLogPath = join(root, 'logs', 'stderr.log');
  const runner = new FakeRunner();
  const manager = new LaunchdServiceManager({
    support,
    runner,
    uid: 501,
    serviceId: 'io.test.ariava',
    definitionPath,
    stdoutLogPath,
    stderrLogPath,
    fileSystem: { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync, ...fileSystemOverrides },
    now: () => '2026-07-15T12:00:00.000Z',
  });
  return { root, definitionPath, stdoutLogPath, stderrLogPath, runner, manager };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('launchd plist compatibility', () => {
  test('retains XML escaping and parsed program arguments', () => {
    const definition = buildLaunchdServiceDefinition('/opt/A & B/node', '/Applications/Ariava <dev>/ariava', '/tmp/config & identity.json', {
      serviceId: 'io.test."ariava"',
      definitionPath: '/tmp/ariava.plist',
      stdoutLogPath: "/tmp/out's.log",
      stderrLogPath: '/tmp/error.log',
    });

    const plist = renderLaunchdPlist(definition);
    expect(plist).toContain('io.test.&quot;ariava&quot;');
    expect(plist).toContain('/opt/A &amp; B/node');
    expect(plist).toContain('/Applications/Ariava &lt;dev&gt;/ariava');
    expect(plist).toContain('/tmp/out&apos;s.log');

    const { definitionPath } = fixture();
    mkdirSync(join(definitionPath, '..'), { recursive: true });
    writeFileSync(definitionPath, plist);
    expect(parseProgramArgumentsFromPlist(definitionPath)).toEqual([
      '/opt/A & B/node',
      '/Applications/Ariava <dev>/ariava',
      'internal',
      'bridge-daemon',
      '--config',
      '/tmp/config & identity.json',
    ]);
  });
});

describe('LaunchdServiceManager', () => {
  test('installs an idempotent neutral launchd service record', () => {
    const { manager, runner, definitionPath, stdoutLogPath, stderrLogPath } = fixture();

    const input = {
      runtimePath: '/opt/node/bin/node', ariavaBinPath: '/opt/ariava/bin/ariava',
      configPath: '/tmp/ariava-config.json',
      identityReference: { type: 'macos-keychain' as const, service: 'io.noyx.ariava.host-identity' as const, account: 'host_test' },
    };
    const record = manager.install(input);
    const reinstalledRecord = manager.install(input);

    expect(record).toEqual({
      backend: 'launchd',
      installedAt: '2026-07-15T12:00:00.000Z',
      runtimePath: '/opt/node/bin/node',
      ariavaBinPath: '/opt/ariava/bin/ariava',
      configPath: '/tmp/ariava-config.json',
      identityReference: input.identityReference,
      definitionPath,
      serviceId: 'io.test.ariava',
    });
    expect(reinstalledRecord).toEqual(record);
    expect(runner.calls).toEqual([
      { command: 'launchctl', args: ['bootout', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['bootstrap', 'gui/501', definitionPath] },
      { command: 'launchctl', args: ['bootout', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['bootstrap', 'gui/501', definitionPath] },
    ]);
    const plist = readFileSync(definitionPath, 'utf8');
    expect(parseProgramArgumentsFromPlist(definitionPath)).toEqual([
      '/opt/node/bin/node',
      '/opt/ariava/bin/ariava',
      'internal',
      'bridge-daemon',
      '--config',
      '/tmp/ariava-config.json',
    ]);
    expect(plist).toContain('<key>RunAtLoad</key>\n    <true/>');
    expect(plist).toContain('<key>KeepAlive</key>\n    <true/>');
    expect(plist).not.toContain('<key>WorkingDirectory</key>');
    expect(plist).toContain(`<string>${stdoutLogPath}</string>`);
    expect(plist).toContain(`<string>${stderrLogPath}</string>`);
  });

  test('uses the expected launchctl lifecycle commands', () => {
    const { manager, runner, definitionPath } = fixture();
    const record = {
      backend: 'launchd' as const,
      installedAt: '2026-07-15T00:00:00Z',
      runtimePath: '/usr/bin/node',
      ariavaBinPath: '/usr/bin/ariava',
      definitionPath,
      serviceId: 'io.test.ariava',
    };
    mkdirSync(join(definitionPath, '..'), { recursive: true });
    writeFileSync(definitionPath, 'definition');

    manager.start(record);
    manager.stop(record);
    manager.restart(record);
    manager.uninstall(record);

    expect(runner.calls).toEqual([
      { command: 'launchctl', args: ['bootstrap', 'gui/501', definitionPath] },
      { command: 'launchctl', args: ['bootout', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['kickstart', '-k', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['bootout', 'gui/501/io.test.ariava'] },
    ]);
    expect(existsSync(definitionPath)).toBe(false);
  });

  test('uninstall only tolerates recognized absent-service failures', () => {
    for (const absent of [
      { status: 3, stdout: '', stderr: 'Could not find service' },
      { status: 113, stdout: '', stderr: 'No such process' },
    ]) {
      const current = fixture();
      mkdirSync(join(current.definitionPath, '..'), { recursive: true });
      writeFileSync(current.definitionPath, 'definition');
      current.runner.results.push(absent);
      current.manager.uninstall();
      expect(existsSync(current.definitionPath)).toBe(false);
    }

    for (const failure of [
      { status: 1, stdout: '', stderr: 'Service is not loaded: Operation not permitted' },
      { status: 5, stdout: '', stderr: 'Could not find service' },
    ]) {
      const current = fixture();
      mkdirSync(join(current.definitionPath, '..'), { recursive: true });
      writeFileSync(current.definitionPath, 'definition');
      current.runner.results.push(failure);
      expect(() => current.manager.uninstall()).toThrow(AriavaCliError);
      expect(existsSync(current.definitionPath)).toBe(true);
    }
  });

  test('wraps install write and uninstall remove filesystem failures', () => {
    const installPath = '/secret/install-definition.plist';
    const install = fixture({
      writeFileSync() {
        throw Object.assign(new Error(`EACCES ${installPath} ${'x'.repeat(3_000)}`), { code: 'EACCES' });
      },
    });
    let installError: unknown;
    try {
      install.manager.install({ runtimePath: '/usr/bin/node', ariavaBinPath: '/usr/bin/ariava' });
    } catch (error) {
      installError = error;
    }
    expect(installError).toBeInstanceOf(AriavaCliError);
    expect((installError as AriavaCliError).code).toBe('ERR_SERVICE_INSTALL');
    expect((installError as AriavaCliError).message.length).toBe(2_000);
    expect(JSON.stringify((installError as AriavaCliError).data)).not.toContain(installPath);
    expect(install.runner.calls).toEqual([]);

    const removePath = '/secret/remove-definition.plist';
    const uninstall = fixture({
      rmSync() {
        throw Object.assign(new Error(`EACCES ${removePath} ${'y'.repeat(3_000)}`), { code: 'EACCES' });
      },
    });
    uninstall.runner.results.push({ status: 3, stdout: '', stderr: 'Could not find service' });
    let uninstallError: unknown;
    try {
      uninstall.manager.uninstall();
    } catch (error) {
      uninstallError = error;
    }
    expect(uninstallError).toBeInstanceOf(AriavaCliError);
    expect((uninstallError as AriavaCliError).code).toBe('ERR_SERVICE_COMMAND');
    expect((uninstallError as AriavaCliError).message.length).toBe(2_000);
    expect(JSON.stringify((uninstallError as AriavaCliError).data)).not.toContain(removePath);
  });

  test('maps launchctl print and plist state to neutral status', () => {
    const { manager, runner, definitionPath, stdoutLogPath, stderrLogPath } = fixture();
    const record = manager.install({ runtimePath: '/usr/bin/node', ariavaBinPath: '/usr/bin/ariava' });
    runner.calls.length = 0;
    runner.results.push(
      { status: 0, stdout: 'v22.1.0\n', stderr: '' },
      { status: 0, stdout: 'state = running\npid = 123\n', stderr: '' },
    );

    const status = manager.status(record, '/usr/bin/node', '/usr/bin/ariava');

    expect(status).toEqual({
      backend: 'launchd',
      support,
      definitionPath,
      serviceId: 'io.test.ariava',
      installed: true,
      enabled: true,
      loaded: true,
      processRunning: true,
      runtimePath: '/usr/bin/node',
      runtimeVersion: 'v22.1.0',
      runtimeName: 'node',
      runtimeNameIsNode: true,
      runtimeVersionSupported: true,
      ariavaBinPath: '/usr/bin/ariava',
      runtimePathMatchesCurrent: true,
      ariavaBinPathMatchesCurrent: true,
      logBackend: 'files',
      stdoutLogPath,
      stderrLogPath,
    });
    expect(runner.calls).toEqual([
      { command: '/usr/bin/node', args: ['--version'] },
      { command: 'launchctl', args: ['print', 'gui/501/io.test.ariava'] },
    ]);
    expect(status).not.toHaveProperty('launchdLoaded');
    expect(status).not.toHaveProperty('plistPath');
  });

  test('probes the recorded runtime and detects an in-place downgrade while legacy records remain readable', () => {
    const current = fixture();
    const installed = current.manager.install({
      runtimePath: '/usr/bin/node', ariavaBinPath: '/usr/bin/ariava', runtimeName: 'node', runtimeVersion: 'v22.1.0',
    });
    current.runner.calls.length = 0;
    current.runner.results.push(
      { status: 0, stdout: 'v21.9.0\n', stderr: '' },
      { status: 0, stdout: 'state = running\npid = 123\n', stderr: '' },
    );
    expect(current.manager.status(installed, '/usr/bin/node', '/usr/bin/ariava')).toMatchObject({
      runtimeVersion: 'v21.9.0', recordedRuntimeVersion: 'v22.1.0', runtimeNameIsNode: true,
      runtimeVersionSupported: false, runtimeVersionMatchesRecorded: false,
    });
    expect(current.runner.calls[0]).toEqual({ command: '/usr/bin/node', args: ['--version'] });

    const legacy = { ...installed, runtimeName: undefined, runtimeVersion: undefined };
    current.runner.results.push(
      { status: 0, stdout: 'v22.2.0\n', stderr: '' },
      { status: 0, stdout: 'state = running\npid = 123\n', stderr: '' },
    );
    expect(current.manager.status(legacy, '/usr/bin/node', '/usr/bin/ariava')).toMatchObject({
      runtimeVersion: 'v22.2.0', runtimeNameIsNode: true, runtimeVersionSupported: true,
    });
    expect(current.manager.status).toBeFunction();
  });

  test('returns safe false status when the recorded plist cannot be read', () => {
    const current = fixture({
      readFileSync() {
        throw Object.assign(new Error(`EACCES /secret/status.plist ${'z'.repeat(3_000)}`), { code: 'EACCES' });
      },
    });
    const record = {
      backend: 'launchd' as const,
      installedAt: '2026-07-15T00:00:00Z',
      runtimePath: '/usr/bin/node',
      ariavaBinPath: '/usr/bin/ariava',
      definitionPath: current.definitionPath,
      serviceId: 'io.test.ariava',
    };
    mkdirSync(join(current.definitionPath, '..'), { recursive: true });
    writeFileSync(current.definitionPath, 'definition');

    const status = current.manager.status(record, '/usr/bin/node', '/usr/bin/ariava');

    expect(status.installed).toBe(false);
    expect(status.enabled).toBe(false);
    expect(status.loaded).toBe(false);
    expect(status.processRunning).toBe(false);
    expect(status.detail).toContain('unable to read launchd definition');
    expect(status.detail?.length).toBeLessThanOrEqual(2_000);
    expect(status.detail).not.toContain('/secret/status.plist');
    expect(current.runner.calls).toEqual([{ command: '/usr/bin/node', args: ['--version'] }]);
  });

  test('does not treat an unrecorded stale default plist as installed or inspect launchctl', () => {
    const { manager, runner, definitionPath } = fixture();
    mkdirSync(join(definitionPath, '..'), { recursive: true });
    writeFileSync(definitionPath, renderLaunchdPlist(buildLaunchdServiceDefinition('/usr/bin/node', '/usr/bin/ariava', {
      serviceId: 'io.test.ariava',
      definitionPath,
    })));

    const status = manager.status(undefined, '/usr/bin/node', '/usr/bin/ariava');

    expect(status.installed).toBe(false);
    expect(status.enabled).toBe(false);
    expect(status.loaded).toBe(false);
    expect(status.processRunning).toBe(false);
    expect(runner.calls).toEqual([]);
  });

  test('does not inspect or delete a foreign backend definition', () => {
    const { manager, runner, definitionPath } = fixture();
    const foreignPath = join(tmpdir(), `foreign-${Date.now()}.service`);
    roots.push(foreignPath);
    writeFileSync(foreignPath, 'foreign');
    const foreign = {
      backend: 'systemd-user' as const,
      installedAt: '2026-07-15T00:00:00Z',
      runtimePath: '/usr/bin/node',
      ariavaBinPath: '/usr/bin/ariava',
      definitionPath: foreignPath,
      serviceId: 'ariava.service',
    };

    const status = manager.status(foreign, '/usr/bin/node', '/usr/bin/ariava');
    manager.uninstall(foreign);

    expect(status.installed).toBe(false);
    expect(status.definitionPath).toBe(definitionPath);
    expect(status.serviceId).toBe('io.test.ariava');
    expect(status.runtimePath).toBeUndefined();
    expect(status.detail).toBe('metadata backend systemd-user does not match launchd');
    expect(runner.calls).toEqual([]);
    expect(existsSync(foreignPath)).toBe(true);
  });

  test('turns strict command failures into stable bounded and redacted errors', () => {
    const install = fixture();
    const runtimePath = '/secret/runtime-token/node';
    const ariavaBinPath = '/secret/bin-token/ariava';
    install.runner.results.push(
      { status: 0, stdout: '', stderr: '' },
      {
        status: 1,
        stdout: '',
        stderr: `bootstrap failed ${runtimePath} ${ariavaBinPath} ${'x'.repeat(3_000)}`,
      },
    );
    let installError: unknown;
    try {
      install.manager.install({ runtimePath, ariavaBinPath });
    } catch (error) {
      installError = error;
    }
    expect(installError).toBeInstanceOf(AriavaCliError);
    const typedInstallError = installError as AriavaCliError;
    expect(typedInstallError.code).toBe('ERR_SERVICE_INSTALL');
    expect(typedInstallError.message.length).toBe(2_000);
    expect(typedInstallError.message).not.toContain(runtimePath);
    expect(typedInstallError.message).not.toContain(ariavaBinPath);
    expect(String(typedInstallError.data.stderr).length).toBe(2_000);
    expect(JSON.stringify(typedInstallError.data)).not.toContain(runtimePath);
    expect(JSON.stringify(typedInstallError.data)).not.toContain(ariavaBinPath);

    const lifecycle = fixture();
    const record = {
      backend: 'launchd' as const,
      installedAt: '2026-07-15T00:00:00Z',
      runtimePath,
      ariavaBinPath,
      definitionPath: lifecycle.definitionPath,
      serviceId: 'io.test.ariava',
    };
    lifecycle.runner.results.push({
      status: 1,
      stdout: '',
      stderr: `restart failed ${runtimePath} ${ariavaBinPath} ${'y'.repeat(3_000)}`,
    });
    let lifecycleError: unknown;
    try {
      lifecycle.manager.restart(record);
    } catch (error) {
      lifecycleError = error;
    }
    expect(lifecycleError).toBeInstanceOf(AriavaCliError);
    const typedLifecycleError = lifecycleError as AriavaCliError;
    expect(typedLifecycleError.code).toBe('ERR_SERVICE_COMMAND');
    expect(typedLifecycleError.message.length).toBe(2_000);
    expect(typedLifecycleError.message).not.toContain(runtimePath);
    expect(typedLifecycleError.message).not.toContain(ariavaBinPath);
    expect(String(typedLifecycleError.data.stderr).length).toBe(2_000);
    expect(JSON.stringify(typedLifecycleError.data)).not.toContain(runtimePath);
    expect(JSON.stringify(typedLifecycleError.data)).not.toContain(ariavaBinPath);
  });

  test('reports file log availability without reading log contents', () => {
    const available = fixture();
    mkdirSync(join(available.stdoutLogPath, '..'), { recursive: true });
    writeFileSync(available.stdoutLogPath, 'out');
    writeFileSync(available.stderrLogPath, 'err');
    expect(available.manager.logsAvailable()).toBe(true);

    const missing = fixture();
    expect(missing.manager.logsAvailable()).toBe(false);
  });

  test('reads file-backed logs using the neutral logs contract', () => {
    const { manager, stdoutLogPath, stderrLogPath } = fixture();
    mkdirSync(join(stdoutLogPath, '..'), { recursive: true });
    writeFileSync(stdoutLogPath, 'out line\n');
    writeFileSync(stderrLogPath, 'error line\n');

    expect(manager.logs()).toEqual({
      backend: 'launchd',
      source: 'files',
      text: 'out line\nerror line\n',
      stdoutPath: stdoutLogPath,
      stderrPath: stderrLogPath,
    });
  });

  test('wraps missing, unreadable, and disappearing log files', () => {
    const missing = fixture();
    expect(() => missing.manager.logs()).toThrow(AriavaCliError);
    try {
      missing.manager.logs();
    } catch (error) {
      expect((error as AriavaCliError).code).toBe('ERR_LOGS_UNAVAILABLE');
    }

    const unreadablePath = '/secret/unreadable.log';
    const unreadable = fixture({
      readFileSync() {
        throw Object.assign(new Error(`EACCES ${unreadablePath} ${'q'.repeat(3_000)}`), { code: 'EACCES' });
      },
    });
    mkdirSync(join(unreadable.stdoutLogPath, '..'), { recursive: true });
    writeFileSync(unreadable.stdoutLogPath, 'exists');
    let logsError: unknown;
    try {
      unreadable.manager.logs();
    } catch (error) {
      logsError = error;
    }
    expect(logsError).toBeInstanceOf(AriavaCliError);
    expect((logsError as AriavaCliError).code).toBe('ERR_LOGS_UNAVAILABLE');
    expect((logsError as AriavaCliError).message.length).toBe(2_000);
    expect(JSON.stringify((logsError as AriavaCliError).data)).not.toContain(unreadablePath);
  });
});
