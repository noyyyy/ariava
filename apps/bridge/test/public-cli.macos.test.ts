import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIsolatedPublicCliEnvironment } from './fixtures/isolated-public-cli-env';

if (process.platform !== 'darwin') {
  throw new Error(`public-cli.macos.test.ts requires Darwin, received ${process.platform}`);
}

const publicCoreRoot = join(import.meta.dir, '..', '..', '..');
const roots: string[] = [];
const bunPath = process.execPath;
const cliPath = join(publicCoreRoot, 'apps', 'bridge', 'src', 'public-cli.ts');

function isolatedEnv(home: string, overrides: Record<string, string | undefined> = {}) {
  return createIsolatedPublicCliEnvironment(home, overrides).env;
}

function secureDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

function secureJsonFixture(path: string, value: unknown): void {
  secureDirectory(join(path, '..'));
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
  chmodSync(path, 0o600);
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('public ariava CLI on macOS', () => {
  test('isolates launchctl when the uninstall subprocess purges its temporary home', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'ariava-cli-parent-'));
    const home = join(parent, 'home-$UNDEFINED');
    roots.push(parent);
    const env = isolatedEnv(home);
    const launchctlPath = join(home, '.ariava-test-bin', 'launchctl');
    const launchctlLogPath = join(home, 'launchctl-calls.log');

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'uninstall', '--purge', '--json'],
      cwd: process.cwd(),
      env,
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stderr] = await Promise.all([proc.exited, new Response(proc.stderr).text()]);
    expect(exitCode, stderr).toBe(0);
    expect(existsSync(launchctlPath)).toBe(true);
    expect(readFileSync(launchctlLogPath, 'utf8')).toContain('bootout');
  });

  test('renders top-level human status with neutral loaded wording and ignores adversarial ambient XDG state', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'ariava-cli-status-'));
    const home = join(parent, 'home');
    const adversarialXdgRoot = join(parent, 'ambient-xdg');
    roots.push(parent);
    secureDirectory(home);
    secureJsonFixture(join(adversarialXdgRoot, 'ariava', 'install.json'), {
      service: {
        backend: 'systemd-user',
        installedAt: '2026-07-15T00:00:00Z',
        runtimePath: '/ambient/runtime',
        ariavaBinPath: '/ambient/ariava',
        definitionPath: '/ambient/ariava.service',
        serviceId: 'ariava.service',
      },
    });

    const configRoot = join(home, '.config', 'ariava');
    const plistPath = join(home, 'Library', 'LaunchAgents', 'io.noyx.ariava.bridge.plist');
    mkdirSync(join(plistPath, '..'), { recursive: true });
    secureDirectory(configRoot);
    const env = isolatedEnv(home, { XDG_CONFIG_HOME: adversarialXdgRoot });
    const launchctlPath = join(home, '.ariava-test-bin', 'launchctl');
    writeFileSync(launchctlPath, '#!/bin/sh\nprintf "pid = 123\\n"\n');
    chmodSync(launchctlPath, 0o755);
    writeFileSync(plistPath, `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>io.noyx.ariava.bridge</string>
<key>ProgramArguments</key><array><string>${bunPath}</string><string>${cliPath}</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`);
    secureJsonFixture(join(configRoot, 'install.json'), {
      service: {
        backend: 'launchd',
        installedAt: '2026-07-15T00:00:00Z',
        runtimePath: bunPath,
        ariavaBinPath: cliPath,
        definitionPath: plistPath,
        serviceId: 'io.noyx.ariava.bridge',
      },
    });

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'status'],
      cwd: process.cwd(),
      env,
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stdout, stderr] = await Promise.all([
      proc.exited,
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    expect(exitCode, stderr).toBe(0);
    expect(stdout).toContain('Service loaded: yes');
    expect(stdout).not.toContain('Launchd loaded');
    expect(env.XDG_CONFIG_HOME).toBe(join(home, '.config'));
  });

  test('service status shows relay base url and log paths in text output', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'service', 'status'],
      cwd: process.cwd(),
      env: isolatedEnv(home, { ARIAVA_RELAY_BASE_URL: 'https://relay.example.test' }),
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Relay base URL: https://relay.example.test');
    expect(stdout).toContain(`Log dir: ${join(home, '.config', 'ariava', 'logs')}`);
    expect(stdout).toContain(`Stdout log: ${join(home, '.config', 'ariava', 'logs', 'bridge.stdout.log')}`);
    expect(stdout).toContain(`Stderr log: ${join(home, '.config', 'ariava', 'logs', 'bridge.stderr.log')}`);
  });

  test('service status returns relay base url and log paths in json output', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'service', 'status', '--json'],
      cwd: process.cwd(),
      env: isolatedEnv(home, { ARIAVA_RELAY_BASE_URL: 'https://relay.example.test' }),
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
    expect(exitCode).toBe(0);
    const body = JSON.parse(stdout);
    expect(body.ok).toBe(true);
    expect(body.data.relayBaseUrl).toBe('https://relay.example.test');
    expect(body.data.logDir).toBe(join(home, '.config', 'ariava', 'logs'));
    expect(body.data.stdoutLogPath).toBe(join(home, '.config', 'ariava', 'logs', 'bridge.stdout.log'));
    expect(body.data.stderrLogPath).toBe(join(home, '.config', 'ariava', 'logs', 'bridge.stderr.log'));
  });

  test('preserves foreign systemd metadata and reports mismatch safely', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-foreign-service-'));
    roots.push(home);
    const configRoot = join(home, '.config', 'ariava');
    const installPath = join(configRoot, 'install.json');
    const unitPath = join(home, '.config', 'systemd', 'user', 'ariava.service');
    mkdirSync(join(home, '.config', 'systemd', 'user'), { recursive: true });
    writeFileSync(unitPath, '[Service]\nExecStart=/usr/bin/true\n');
    const foreignService = {
      backend: 'systemd-user',
      installedAt: '2026-07-15T00:00:00Z',
      runtimePath: '/usr/bin/node',
      ariavaBinPath: '/usr/bin/ariava',
      definitionPath: unitPath,
      serviceId: 'ariava.service',
    };
    secureJsonFixture(installPath, { service: foreignService });

    const run = async (...args: string[]) => {
      const proc = Bun.spawn({
        cmd: [bunPath, cliPath, ...args, '--json'],
        cwd: process.cwd(),
        env: isolatedEnv(home, { ARIAVA_UPGRADE_SELF_DONE: '1', ARIAVA_UPGRADE_SKIP_LAUNCHCTL: '1' }),
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stdout, stderr] = await Promise.all([
        proc.exited,
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]);
      return { exitCode, stdout: stdout ? JSON.parse(stdout) : undefined, stderr: stderr ? JSON.parse(stderr) : undefined };
    };

    const status = await run('service', 'status');
    expect(status.exitCode).toBe(0);
    expect(status.stdout.data.installed).toBe(false);
    expect(status.stdout.data.detail).toContain('metadata backend systemd-user does not match launchd');
    expect(JSON.stringify(status.stdout.data)).not.toMatch(/plistPath|nodePath|launchdLoaded/);
    expect(existsSync(unitPath)).toBe(true);

    for (const command of ['start', 'restart']) {
      const result = await run('service', command);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.code).toBe('ERR_SERVICE_NOT_INSTALLED');
    }
    expect((await run('service', 'stop')).exitCode).toBe(0);
    expect((await run('service', 'uninstall')).exitCode).toBe(0);
    expect(existsSync(unitPath)).toBe(true);
    expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toEqual(foreignService);

    const upgrade = await run('upgrade');
    expect(upgrade.exitCode).toBe(0);
    expect(upgrade.stdout.data.service).toEqual({
      updated: false,
      restarted: false,
      installed: false,
      reason: 'backend-mismatch',
    });
    expect(existsSync(unitPath)).toBe(true);
    expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toEqual(foreignService);

    expect((await run('uninstall')).exitCode).toBe(0);
    expect(existsSync(unitPath)).toBe(true);
    expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toEqual(foreignService);
  });
});
