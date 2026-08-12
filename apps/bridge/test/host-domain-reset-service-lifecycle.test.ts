import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefaultHostDomainResetLifecycle } from '../src/cli/lifecycle/default';
import {
  LaunchdServiceManager,
  type CommandResult,
  type CommandRunner,
} from '../src/host-manager/service';

const roots: string[] = [];

const oldReference = { type: 'linux-json' as const, path: '/home/test/.config/ariava/old-identity.json' };

class ResetLaunchdRunner implements CommandRunner {
  readonly calls: Array<{ command: string; args: string[] }> = [];
  loaded = true;
  running = true;

  run(command: string, args: string[]): CommandResult {
    this.calls.push({ command, args });
    if (command === '/usr/bin/node') return { status: 0, stdout: 'v22.0.0\n', stderr: '' };
    if (args[0] === 'bootout') {
      this.loaded = false;
      this.running = false;
      return { status: 0, stdout: '', stderr: '' };
    }
    if (args[0] === 'bootstrap') {
      this.loaded = true;
      return { status: 0, stdout: '', stderr: '' };
    }
    if (args[0] === 'kickstart') {
      this.running = true;
      return { status: 0, stdout: '', stderr: '' };
    }
    if (args[0] === 'print') {
      if (!this.loaded) return { status: 3, stdout: '', stderr: 'Could not find service' };
      return { status: 0, stdout: this.running ? 'state = running\npid = 123\n' : 'state = waiting\n', stderr: '' };
    }
    throw new Error(`Unexpected command: ${command} ${args.join(' ')}`);
  }
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('default Host-domain reset service lifecycle', () => {
  test.each([
    { enabled: false, processRunning: false },
    { enabled: true, processRunning: false },
    { enabled: false, processRunning: true },
    { enabled: true, processRunning: true },
  ])('fails before reset when stale metadata is not installed ($enabled/$processRunning)', ({ enabled, processRunning }) => {
    let metadataWrites = 0;
    const record = {
      backend: 'systemd-user' as const,
      installedAt: '2026-08-11T00:00:00.000Z',
      runtimePath: '/usr/bin/node',
      ariavaBinPath: '/usr/bin/ariava',
      configPath: '/home/test/.config/ariava/config.json',
      identityReference: oldReference,
      definitionPath: '/home/test/.config/systemd/user/ariava.service',
      serviceId: 'ariava.service',
    };
    const lifecycle = createDefaultHostDomainResetLifecycle({
      createServiceManager: () => ({
        backend: 'systemd-user',
        support: { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' },
        status: () => ({
          backend: 'systemd-user', support: { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' },
          installed: false, enabled, loaded: processRunning, processRunning, logBackend: 'journald',
        }),
      }),
      loadInstallMetadataDetailed: () => ({
        metadata: { service: record },
        diagnostics: { serviceMetadataValid: true, installerMetadataValid: true, documentMetadataValid: true },
      }),
      currentRuntimePath: () => '/usr/bin/node',
      currentAriavaBinPath: () => '/usr/bin/ariava',
      realpath: (path: string) => path,
      mergeInstallMetadata: () => { metadataWrites += 1; return {}; },
    } as never);

    expect(() => lifecycle.prepare({})).toThrow(/metadata|installed|repair/i);
    expect(metadataWrites).toBe(0);
  });

  test('restores a previously running disabled launchd service without enabling its plist', () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-reset-launchd-'));
    roots.push(root);
    const definitionPath = join(root, 'LaunchAgents', 'io.test.ariava.plist');
    const runner = new ResetLaunchdRunner();
    const manager = new LaunchdServiceManager({
      support: { platform: 'darwin', backend: 'launchd', supported: true, isWsl: false, reason: 'supported' },
      runner,
      uid: 501,
      serviceId: 'io.test.ariava',
      definitionPath,
      stdoutLogPath: join(root, 'logs', 'stdout.log'),
      stderrLogPath: join(root, 'logs', 'stderr.log'),
      fileSystem: { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync },
      now: () => '2026-08-11T00:00:00.000Z',
      sleep: () => {},
      unloadTimeoutMs: 0,
      bootstrapRetryDelayMs: 0,
    });
    const record = {
      backend: 'launchd' as const,
      installedAt: '2026-08-11T00:00:00.000Z',
      runtimePath: '/usr/bin/node',
      runtimeName: 'node' as const,
      runtimeVersion: 'v22.0.0',
      ariavaBinPath: '/usr/bin/ariava',
      configPath: join(root, 'config.json'),
      identityReference: {
        type: 'macos-keychain' as const,
        service: 'io.noyx.ariava.host-identity' as const,
        account: 'host_old',
      },
      definitionPath,
      serviceId: 'io.test.ariava',
    };
    manager.install({ ...record }, { enabled: false, start: false });
    runner.calls.length = 0;
    runner.loaded = true;
    runner.running = true;
    let currentRecord = record;
    const replacementReference = {
      type: 'macos-keychain' as const,
      service: 'io.noyx.ariava.host-identity' as const,
      account: 'host_new',
    };
    const lifecycle = createDefaultHostDomainResetLifecycle({
      createServiceManager: () => manager,
      loadInstallMetadataDetailed: () => ({
        metadata: { service: currentRecord },
        diagnostics: { serviceMetadataValid: true, installerMetadataValid: true, documentMetadataValid: true },
      }),
      currentRuntimePath: () => '/usr/bin/node',
      currentAriavaBinPath: () => '/usr/bin/ariava',
      realpath: (path: string) => path,
      resolveAriavaConfig: () => ({
        configPath: join(root, 'config.json'),
        identityPath: join(root, 'identity.json'),
        identity: { privateKeyStorage: replacementReference },
      }),
      probeRuntimePath: () => ({
        runtimeName: 'node', runtimeVersion: 'v22.0.0', runtimeNameIsNode: true, runtimeVersionSupported: true,
      }),
      mergeInstallMetadata: ({ service }) => {
        currentRecord = service!;
        return { service: currentRecord };
      },
    } as never);

    const snapshot = lifecycle.prepare({});
    lifecycle.stopAndConfirm(snapshot);
    lifecycle.synchronizeMetadata(snapshot, replacementReference);
    const processRunning = lifecycle.restoreAndConfirm(snapshot, replacementReference);

    expect(snapshot).toEqual({ managed: true, installed: true, enabled: false, wasRunning: true, backend: 'launchd' });
    expect(processRunning).toBe(true);
    expect(readFileSync(definitionPath, 'utf8')).toContain('<key>RunAtLoad</key>\n    <false/>');
    expect(readFileSync(definitionPath, 'utf8')).toContain('<key>KeepAlive</key>\n    <false/>');
    expect(runner.calls).toEqual([
      { command: '/usr/bin/node', args: ['--version'] },
      { command: 'launchctl', args: ['print', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['bootout', 'gui/501/io.test.ariava'] },
      { command: '/usr/bin/node', args: ['--version'] },
      { command: 'launchctl', args: ['print', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['bootout', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['print', 'gui/501/io.test.ariava'] },
      { command: '/usr/bin/node', args: ['--version'] },
      { command: 'launchctl', args: ['print', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['bootout', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['print', 'gui/501/io.test.ariava'] },
      { command: 'launchctl', args: ['bootstrap', 'gui/501', definitionPath] },
      { command: 'launchctl', args: ['kickstart', 'gui/501/io.test.ariava'] },
      { command: '/usr/bin/node', args: ['--version'] },
      { command: 'launchctl', args: ['print', 'gui/501/io.test.ariava'] },
    ]);
  });
});
