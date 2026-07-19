import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  AriavaCliError,
  SystemdUserServiceManager,
  quoteSystemdArgument,
  renderSystemdUserUnit,
  type CommandResult,
  type CommandRunner,
  type ServiceSupport,
  type SystemdUserFileSystem,
} from '../src/host-manager/service/index';
import { removeOwnerControlledFile, writeOwnerControlledFile } from '../src/host-manager/secure-files';

describe('systemd user unit renderer', () => {
  test('quotes each argument and escapes spaces, quotes, backslashes, percent, and environment expansion', () => {
    expect(quoteSystemdArgument('/opt/$RUNTIME/${VERSION}/Ariava Runtime/"node"\\100%')).toBe(
      '"/opt/$$RUNTIME/$${VERSION}/Ariava Runtime/\\"node\\"\\\\100%%"',
    );

    const unit = renderSystemdUserUnit({
      runtimePath: '/opt/$RUNTIME/Ariava Runtime/"node"\\100%',
      ariavaBinPath: '/home/${USER}/test user/bin/ariava\\cli%',
      configPath: '/home/${USER}/.config/ariava/config $v%.json',
      homeDir: '/home/$USER/${WORKSPACE}/"work"\\100%',
    });

    expect(unit).toContain(
      'ExecStart="/opt/$$RUNTIME/Ariava Runtime/\\"node\\"\\\\100%%" "/home/$${USER}/test user/bin/ariava\\\\cli%%" "internal" "bridge-daemon" "--config" "/home/$${USER}/.config/ariava/config $$v%%.json"',
    );
    expect(unit).not.toContain('WorkingDirectory=');
  });

  test('renders the exact semantic systemd user unit', () => {
    expect(renderSystemdUserUnit({
      runtimePath: '/usr/bin/node',
      ariavaBinPath: '/home/user/.local/bin/ariava',
      configPath: '/home/user/.config/ariava/config.json',
      homeDir: '/home/user',
    })).toBe(`[Unit]
Description=Ariava Local Bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
UMask=0077
ExecStart="/usr/bin/node" "/home/user/.local/bin/ariava" "internal" "bridge-daemon" "--config" "/home/user/.config/ariava/config.json"
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`);
  });

  test('preserves valid Unicode characters in the config path', () => {
    const unit = renderSystemdUserUnit({
      runtimePath: '/usr/bin/node',
      ariavaBinPath: '/home/user/bin/ariava',
      configPath: '/home/测试/config.json',
      homeDir: '/home/测试',
    });

    expect(unit).toContain('"/home/测试/config.json"');
  });

  test.each([
    ['runtimePath', 'node'],
    ['ariavaBinPath', 'bin/ariava'],
    ['configPath', 'home/user/config.json'],
    ['homeDir', 'home/user'],
  ] as const)('rejects a relative %s with ERR_SERVICE_INSTALL', (field, value) => {
    const input = {
      runtimePath: '/usr/bin/node',
      ariavaBinPath: '/home/user/bin/ariava',
      homeDir: '/home/user',
      [field]: value,
    };

    expect(() => renderSystemdUserUnit(input)).toThrow(AriavaCliError);
    try {
      renderSystemdUserUnit(input);
      throw new Error('expected renderSystemdUserUnit to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(AriavaCliError);
      expect((error as AriavaCliError).code).toBe('ERR_SERVICE_INSTALL');
    }
  });

  test.each([
    ['NUL', '/home/user\0bad'],
    ['newline', '/home/user\nbad'],
    ['carriage return', '/home/user\rbad'],
  ])('rejects %s in quoted values with ERR_SERVICE_INSTALL', (_name, value) => {
    expect(() => quoteSystemdArgument(value)).toThrow(AriavaCliError);
    try {
      quoteSystemdArgument(value);
      throw new Error('expected quoteSystemdArgument to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(AriavaCliError);
      expect((error as AriavaCliError).code).toBe('ERR_SERVICE_INSTALL');
    }
  });

  test('does not serialize credentials, environment directives, logs, or unsupported lifecycle fallbacks', () => {
    const credentials = {
      ARIAVA_HOST_AUTH_TOKEN: 'host-token-fixture',
      ARIAVA_AGENT_ADAPTER_SECRET: 'adapter-secret-fixture',
      ARIAVA_RELAY_TOKEN: 'relay-token-fixture',
    };
    const previous = Object.fromEntries(
      Object.keys(credentials).map((key) => [key, process.env[key]]),
    );

    try {
      Object.assign(process.env, credentials);
      const unit = renderSystemdUserUnit({
        runtimePath: '/usr/bin/node',
        ariavaBinPath: '/home/user/bin/ariava',
        homeDir: '/home/user',
      });

      for (const credential of Object.values(credentials)) {
        expect(unit).not.toContain(credential);
      }
      for (const forbidden of [
        'Environment=',
        'StandardOutput=append:',
        'sudo',
        'loginctl',
        'sh -c',
        'shell',
        'PIDFile',
        'detached',
        'profile',
        'Task Scheduler',
      ]) {
        expect(unit.toLowerCase()).not.toContain(forbidden.toLowerCase());
      }
    } finally {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  });
});

const roots: string[] = [];
const support: ServiceSupport = { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' };

class FakeRunner implements CommandRunner {
  readonly calls: Array<{ command: string; args: string[] }> = [];
  readonly options: Array<{ cwd?: string; env?: NodeJS.ProcessEnv } | undefined> = [];
  readonly results: CommandResult[] = [];
  run(command: string, args: string[], options?: { cwd?: string; env?: NodeJS.ProcessEnv }): CommandResult {
    this.calls.push({ command, args });
    this.options.push(options);
    return this.results.shift() ?? { status: 0, stdout: '', stderr: '' };
  }
}

function fixture(overrides: Partial<SystemdUserFileSystem> = {}, serviceSupport = support) {
  const root = join(tmpdir(), `ariava-systemd-${Date.now()}-${Math.random()}`);
  roots.push(root);
  const homeDir = join(root, 'home');
  const definitionPath = join(homeDir, '.config', 'systemd', 'user', 'ariava.service');
  const runner = new FakeRunner();
  const fileSystem: SystemdUserFileSystem = {
    existsSync,
    rmSync,
    writeAtomicSync(path, data, controlledRoot) {
      writeOwnerControlledFile(path, Buffer.from(data), controlledRoot);
    },
    removeAtomicSync(path, controlledRoot) {
      removeOwnerControlledFile(path, controlledRoot);
    },
    ...overrides,
  };
  const manager = new SystemdUserServiceManager({
    support: serviceSupport, runner, homeDir, serviceId: 'ariava.service', definitionPath, fileSystem,
    now: () => '2026-07-15T12:00:00.000Z',
  });
  return { root, homeDir, definitionPath, tempPath: `${definitionPath}.fixed.tmp`, runner, manager };
}

function record(definitionPath: string) {
  return { backend: 'systemd-user' as const, installedAt: '2026-07-15T12:00:00.000Z', runtimePath: '/usr/bin/node', ariavaBinPath: '/usr/bin/ariava', definitionPath, serviceId: 'ariava.service' };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('SystemdUserServiceManager', () => {
  test('installs atomically, enables after reload, and repeats idempotently', () => {
    const current = fixture();
    const input = { runtimePath: '/usr/bin/node', ariavaBinPath: '/usr/bin/ariava' };
    expect(current.manager.install(input)).toEqual(record(current.definitionPath));
    expect(current.manager.install(input)).toEqual(record(current.definitionPath));
    expect(readFileSync(current.definitionPath, 'utf8')).toBe(renderSystemdUserUnit({ ...input, homeDir: current.homeDir }));
    expect(existsSync(current.tempPath)).toBe(false);
    expect(current.runner.calls).toEqual([
      { command: 'systemctl', args: ['--user', 'daemon-reload'] },
      { command: 'systemctl', args: ['--user', 'enable', '--now', 'ariava.service'] },
      { command: 'systemctl', args: ['--user', 'daemon-reload'] },
      { command: 'systemctl', args: ['--user', 'enable', '--now', 'ariava.service'] },
    ]);
  });

  test('forces the C locale for every systemctl call while preserving the parent environment', () => {
    const current = fixture();
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    const installed = record(current.definitionPath);
    current.manager.install({ runtimePath: '/usr/bin/node', ariavaBinPath: '/usr/bin/ariava' });
    current.manager.start(installed);
    current.manager.stop(installed);
    current.manager.restart(installed);
    current.runner.results.push(
      { status: 0, stdout: 'v22.1.0\n', stderr: '' },
      { status: 0, stdout: 'enabled\n', stderr: '' },
      { status: 0, stdout: 'active\n', stderr: '' },
      { status: 0, stdout: 'loaded\n', stderr: '' },
    );
    current.manager.status(installed, '/usr/bin/node', '/usr/bin/ariava');

    const uninstall = fixture();
    mkdirSync(dirname(uninstall.definitionPath), { recursive: true });
    writeFileSync(uninstall.definitionPath, 'unit');
    uninstall.runner.results.push(
      { status: 0, stdout: 'loaded\n', stderr: '' },
      { status: 0, stdout: '', stderr: '' },
      { status: 0, stdout: '', stderr: '' },
    );
    uninstall.manager.uninstall(record(uninstall.definitionPath));

    const systemctlOptions = [current, uninstall].flatMap(({ runner }) => runner.calls
      .map((call, index) => ({ call, options: runner.options[index] }))
      .filter(({ call }) => call.command === 'systemctl')
      .map(({ options }) => options));
    expect(systemctlOptions.length).toBe(11);
    for (const options of systemctlOptions) {
      expect(options?.env).toMatchObject({ ...process.env, LC_ALL: 'C' });
    }
  });

  test('rejects unsupported and relative installs before filesystem work', () => {
    let writes = 0;
    const fs = { writeAtomicSync() { writes += 1; } };
    const unavailable = fixture(fs, { ...support, supported: false, reason: 'systemd-user-manager-unavailable', message: 'unavailable' });
    expect(() => unavailable.manager.install({ runtimePath: '/usr/bin/node', ariavaBinPath: '/usr/bin/ariava' })).toThrow(AriavaCliError);
    const relative = fixture(fs);
    expect(() => relative.manager.install({ runtimePath: 'node', ariavaBinPath: '/usr/bin/ariava' })).toThrow(AriavaCliError);
    expect(writes).toBe(0);
  });

  test.each([
    [[{ status: 1, stdout: '', stderr: ' reload /secret/token/node denied \n' }], 'daemon-reload'],
    [[{ status: 0, stdout: '', stderr: '' }, { status: 5, stdout: '', stderr: ' enable /secret/token/node denied \n' }], 'enable'],
  ] as const)('keeps the diagnostic unit and reports bounded redacted command failure', (results, _name) => {
    const current = fixture();
    current.runner.results.push(...results);
    let thrown: unknown;
    try { current.manager.install({ runtimePath: '/secret/token/node', ariavaBinPath: '/usr/bin/ariava' }); } catch (error) { thrown = error; }
    expect(thrown).toBeInstanceOf(AriavaCliError);
    const typed = thrown as AriavaCliError;
    expect(typed.code).toBe('ERR_SERVICE_INSTALL');
    expect(typed.message).not.toContain('token');
    expect(typed.message.length).toBeLessThanOrEqual(2_000);
    expect(typed.data.command).toContain('systemctl --user');
    expect(typed.data.exitCode).toBe(results.at(-1)?.status);
    expect(existsSync(current.definitionPath)).toBe(true);
  });

  test('wraps atomic filesystem failure before systemctl', () => {
    const current = fixture({
      writeAtomicSync(path) { throw new Error(`EIO ${path}`); },
    });
    let thrown: unknown;
    try { current.manager.install({ runtimePath: '/usr/bin/node', ariavaBinPath: '/usr/bin/ariava' }); } catch (error) { thrown = error; }
    expect((thrown as AriavaCliError).code).toBe('ERR_SERVICE_INSTALL');
    expect((thrown as AriavaCliError).message).not.toContain(current.root);
    expect(current.runner.calls).toEqual([]);
  });

  test('preserves a pre-existing unit when atomic reinstall fails', () => {
    const current = fixture({
      writeAtomicSync() { throw new Error('write failed'); },
    });
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'old unit');
    expect(() => current.manager.install({ runtimePath: '/new/node', ariavaBinPath: '/new/ariava' })).toThrow(AriavaCliError);
    expect(readFileSync(current.definitionPath, 'utf8')).toBe('old unit');
    expect(current.runner.calls).toEqual([]);
  });

  test('uses exact lifecycle commands and requires matching install for start/restart', () => {
    const current = fixture();
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    current.manager.start(record(current.definitionPath));
    current.manager.stop(record(current.definitionPath));
    current.manager.restart(record(current.definitionPath));
    expect(current.runner.calls).toEqual([
      { command: 'systemctl', args: ['--user', 'start', 'ariava.service'] },
      { command: 'systemctl', args: ['--user', 'stop', 'ariava.service'] },
      { command: 'systemctl', args: ['--user', 'restart', 'ariava.service'] },
    ]);
    for (const method of ['start', 'restart'] as const) {
      const absent = fixture();
      expect(() => absent.manager[method]()).toThrow(AriavaCliError);
      try { absent.manager[method](); } catch (error) { expect((error as AriavaCliError).code).toBe('ERR_SERVICE_NOT_INSTALLED'); }
    }
  });

  test('keeps stop and uninstall idempotent and uses exact uninstall order', () => {
    const absentStop = fixture();
    absentStop.manager.stop();
    expect(absentStop.runner.calls).toEqual([]);

    const current = fixture();
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    current.runner.results.push({ status: 0, stdout: 'loaded\n', stderr: '' }, { status: 0, stdout: '', stderr: '' }, { status: 0, stdout: '', stderr: '' });
    current.manager.uninstall(record(current.definitionPath));
    expect(current.runner.calls).toEqual([
      { command: 'systemctl', args: ['--user', 'show', 'ariava.service', '--property=LoadState', '--value'] },
      { command: 'systemctl', args: ['--user', 'disable', '--now', 'ariava.service'] },
      { command: 'systemctl', args: ['--user', 'daemon-reload'] },
    ]);
    expect(existsSync(current.definitionPath)).toBe(false);

    const absent = fixture();
    absent.runner.results.push({ status: 1, stdout: 'not-found\n', stderr: '' });
    absent.manager.uninstall();
    expect(absent.runner.calls).toHaveLength(1);
  });

  test('surfaces genuine uninstall bus errors without removing the unit', () => {
    const current = fixture();
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    current.runner.results.push({ status: 0, stdout: 'loaded\n', stderr: '' }, { status: 1, stdout: '', stderr: 'Failed to connect to bus: Permission denied' });
    expect(() => current.manager.uninstall(record(current.definitionPath))).toThrow(AriavaCliError);
    expect(existsSync(current.definitionPath)).toBe(true);
  });

  test('treats the canonical C-locale failed-to-stop absent unit message as idempotent', () => {
    const current = fixture();
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    current.runner.results.push({
      status: 5,
      stdout: '',
      stderr: 'Failed to stop ariava.service: Unit ariava.service not loaded.',
    });

    expect(() => current.manager.stop(record(current.definitionPath))).not.toThrow();
  });

  test.each([
    'La unidad está inactive por un error localizado.',
    'Unit ariava.service permission denied and does not exist.',
  ])('does not swallow localized or contradictory lifecycle failure: %s', (stderr) => {
    const current = fixture();
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    current.runner.results.push({ status: 1, stdout: '', stderr });

    expect(() => current.manager.stop(record(current.definitionPath))).toThrow(AriavaCliError);
  });

  test('leaves the unit and skips daemon-reload when removal fails after disable', () => {
    const current = fixture({
      removeAtomicSync(path) { throw new Error(`EACCES ${path}`); },
    });
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    current.runner.results.push(
      { status: 0, stdout: 'loaded\n', stderr: '' },
      { status: 0, stdout: '', stderr: '' },
    );

    let thrown: unknown;
    try { current.manager.uninstall(record(current.definitionPath)); } catch (error) { thrown = error; }
    expect((thrown as AriavaCliError).code).toBe('ERR_SERVICE_COMMAND');
    expect(existsSync(current.definitionPath)).toBe(true);
    expect(current.runner.calls).toEqual([
      { command: 'systemctl', args: ['--user', 'show', 'ariava.service', '--property=LoadState', '--value'] },
      { command: 'systemctl', args: ['--user', 'disable', '--now', 'ariava.service'] },
    ]);
  });

  test('surfaces daemon-reload failure after removal and permits a safe retry', () => {
    const current = fixture();
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    current.runner.results.push(
      { status: 0, stdout: 'loaded\n', stderr: '' },
      { status: 0, stdout: '', stderr: '' },
      { status: 1, stdout: '', stderr: 'Failed to reload user manager.' },
    );

    let thrown: unknown;
    try { current.manager.uninstall(record(current.definitionPath)); } catch (error) { thrown = error; }
    expect((thrown as AriavaCliError).code).toBe('ERR_SERVICE_COMMAND');
    expect((thrown as AriavaCliError).data).toMatchObject({
      command: 'systemctl --user daemon-reload',
      exitCode: 1,
    });
    expect(existsSync(current.definitionPath)).toBe(false);

    current.runner.results.push({ status: 0, stdout: 'loaded\n', stderr: '' }, { status: 1, stdout: '', stderr: 'Unit ariava.service does not exist.' }, { status: 0, stdout: '', stderr: '' });
    expect(() => current.manager.uninstall(record(current.definitionPath))).not.toThrow();
    expect(current.runner.calls.slice(-3)).toEqual([
      { command: 'systemctl', args: ['--user', 'show', 'ariava.service', '--property=LoadState', '--value'] },
      { command: 'systemctl', args: ['--user', 'disable', '--now', 'ariava.service'] },
      { command: 'systemctl', args: ['--user', 'daemon-reload'] },
    ]);
  });

  test('maps exact status values and requires a matching record and unit for installed', () => {
    const current = fixture();
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    current.runner.results.push({ status: 0, stdout: 'v22.1.0\n', stderr: '' }, { status: 0, stdout: 'enabled\n', stderr: '' }, { status: 0, stdout: 'active\n', stderr: '' }, { status: 0, stdout: 'loaded\n', stderr: '' });
    expect(current.manager.status(record(current.definitionPath), '/usr/bin/node', '/usr/bin/ariava')).toMatchObject({ installed: true, enabled: true, loaded: true, processRunning: true, logBackend: 'journald' });
    expect(current.runner.calls).toEqual([
      { command: '/usr/bin/node', args: ['--version'] },
      { command: 'systemctl', args: ['--user', 'is-enabled', 'ariava.service'] },
      { command: 'systemctl', args: ['--user', 'is-active', 'ariava.service'] },
      { command: 'systemctl', args: ['--user', 'show', 'ariava.service', '--property=LoadState', '--value'] },
    ]);

    const ordinary = fixture();
    mkdirSync(dirname(ordinary.definitionPath), { recursive: true });
    writeFileSync(ordinary.definitionPath, 'unit');
    ordinary.runner.results.push({ status: 0, stdout: 'v22.1.0\n', stderr: '' }, { status: 1, stdout: 'disabled\n', stderr: '' }, { status: 3, stdout: 'inactive\n', stderr: '' }, { status: 1, stdout: 'not-found\n', stderr: '' });
    expect(ordinary.manager.status(record(ordinary.definitionPath), '/usr/bin/node', '/usr/bin/ariava')).toMatchObject({ enabled: false, loaded: false, processRunning: false });
  });

  test('probes the recorded runtime version and detects an in-place downgrade', () => {
    const current = fixture();
    mkdirSync(dirname(current.definitionPath), { recursive: true });
    writeFileSync(current.definitionPath, 'unit');
    const installed = { ...record(current.definitionPath), runtimeName: 'node' as const, runtimeVersion: 'v22.1.0' };
    current.runner.results.push(
      { status: 0, stdout: 'v21.9.0\n', stderr: '' },
      { status: 0, stdout: 'enabled\n', stderr: '' },
      { status: 0, stdout: 'active\n', stderr: '' },
      { status: 0, stdout: 'loaded\n', stderr: '' },
    );
    expect(current.manager.status(installed, '/usr/bin/node', '/usr/bin/ariava')).toMatchObject({
      runtimeVersion: 'v21.9.0', recordedRuntimeVersion: 'v22.1.0', runtimeVersionSupported: false,
      runtimeVersionMatchesRecorded: false,
    });
    expect(current.runner.calls[0]).toEqual({ command: '/usr/bin/node', args: ['--version'] });
  });

  test('keeps a foreign backend safe while reinstall returns replacement metadata', () => {
    const current = fixture();
    const foreignPath = join(current.root, 'foreign.plist');
    mkdirSync(dirname(foreignPath), { recursive: true });
    writeFileSync(foreignPath, 'foreign');
    const foreign = { ...record(foreignPath), backend: 'launchd' as const, serviceId: 'io.test.ariava' };
    expect(current.manager.status(foreign, '/usr/bin/node', '/usr/bin/ariava')).toMatchObject({ installed: false, detail: 'metadata backend launchd does not match systemd-user' });
    current.manager.uninstall(foreign);
    expect(current.runner.calls).toEqual([]);
    expect(current.manager.install({ runtimePath: '/usr/bin/node', ariavaBinPath: '/usr/bin/ariava' }).backend).toBe('systemd-user');
    expect(existsSync(foreignPath)).toBe(true);
  });

  test('probes journald availability without reading logs', () => {
    const current = fixture();
    current.runner.results.push({ status: 0, stdout: 'systemd 256', stderr: '' });
    expect(current.manager.logsAvailable()).toBe(true);
    expect(current.runner.calls).toEqual([{ command: 'journalctl', args: ['--version'] }]);

    current.runner.results.push({
      status: null, stdout: '', stderr: '',
      error: Object.assign(new Error('ENOENT'), { code: 'ENOENT' }),
    });
    expect(current.manager.logsAvailable()).toBe(false);
    expect(current.manager.support).toBe(support);
    expect(current.runner.calls.at(-1)).toEqual({ command: 'journalctl', args: ['--version'] });
  });

  test('reads sanitized journald output with the exact command', () => {
    const current = fixture();
    current.runner.results.push({ status: 0, stdout: 'one\0\n\ttwo\u0007\u001b[31m\u0085three\u009b32m\n', stderr: '' });
    expect(current.manager.logs()).toEqual({ backend: 'systemd-user', source: 'journald', text: 'one\n\ttwo[31mthree32m\n' });
    expect(current.runner.calls).toEqual([{ command: 'journalctl', args: ['--user', '--unit', 'ariava.service', '--no-pager', '-n', '200'] }]);
  });

  test.each([
    { status: null, stdout: '', stderr: '', error: Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) },
    { status: 1, stdout: '', stderr: `failed /secret/token/node ${'x'.repeat(3_000)}` },
  ])('reports unavailable logs without changing service support', (result) => {
    const current = fixture();
    current.runner.results.push(result);
    let thrown: unknown;
    try { current.manager.logs({ ...record('/tmp/unit'), runtimePath: '/secret/token/node' }); } catch (error) { thrown = error; }
    expect((thrown as AriavaCliError).code).toBe('ERR_LOGS_UNAVAILABLE');
    expect((thrown as AriavaCliError).message.length).toBeLessThanOrEqual(2_000);
    expect(JSON.stringify((thrown as AriavaCliError).data)).not.toContain('/secret/token/node');
    expect(current.manager.support).toBe(support);
    current.runner.results.push(result);
    expect(current.manager.logsAvailable()).toBe(false);
    expect(current.manager.support.supported).toBe(true);
  });
});
