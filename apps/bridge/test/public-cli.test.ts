import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { AriavaCliError, type OnboardingDetection, type OnboardingResult, type ServiceManager } from '../src/host-manager';
import { HostIdentityError } from '../src/identity';
import { RelayClientError } from '../src/relay-client';
import { formatHumanCliFailure, normalizeCliFailure, runPublicCli } from '../src/public-cli-app';
import { createIsolatedPublicCliEnvironment } from './fixtures/isolated-public-cli-env';
import { createProfileCliHarness } from './fixtures/profile-cli-harness';

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
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function captureStream() {
  let output = '';
  return {
    stream: { write(chunk: unknown) { output += String(chunk); return true; } } as NodeJS.WritableStream,
    read: () => output,
  };
}

describe('public ariava CLI', () => {
  describe('Unix-style default error rendering', () => {
    test('unknown top-level command without --json prints ariava: text on stderr', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const exitCode = await runPublicCli(['definitely-unknown'], { stdout: stdout.stream, stderr: stderr.stream });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      const text = stderr.read();
      expect(text.startsWith('ariava: Unknown command: definitely-unknown')).toBe(true);
      expect(text).toContain(`Run 'ariava help' for usage.`);
      expect(text).not.toContain('{"ok":false');
      expect(() => JSON.parse(text.trim())).toThrow();
    });


    test('unknown top-level command with --json keeps ERR_CLI envelope on stderr', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const exitCode = await runPublicCli(['definitely-unknown', '--json'], { stdout: stdout.stream, stderr: stderr.stream });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      expect(JSON.parse(stderr.read())).toEqual({
        ok: false,
        code: 'ERR_CLI',
        message: 'Unknown command: definitely-unknown',
        data: {},
      });
    });


    test('AriavaCliError with advice renders Next: line in human mode', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const support = {
        platform: 'linux' as const,
        backend: 'systemd-user' as const,
        supported: true,
        isWsl: false,
        reason: 'supported' as const,
      };
      const installedManager: ServiceManager = {
        backend: 'systemd-user',
        support,
        install() { throw new Error('install should not run'); },
        uninstall() { throw new Error('uninstall should not run'); },
        start() { throw new Error('start should not run'); },
        stop() { throw new Error('stop should not run'); },
        restart() { throw new Error('restart should not run'); },
        status() {
          return {
            support,
            installed: false,
            enabled: false,
            loaded: false,
            processRunning: false,
            logBackend: 'unavailable',
          };
        },
        logsAvailable() { return false; },
        logs() { return { source: 'files' as const, text: '' }; },
      };
      const exitCode = await runPublicCli(['service', 'start'], {
        stdout: stdout.stream,
        stderr: stderr.stream,
        createServiceManager: () => installedManager,
        loadInstallMetadata: () => ({}),
      });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      const text = stderr.read();
      expect(text.startsWith('ariava: Ariava service is not installed.')).toBe(true);
      expect(text).toContain('Next: ariava service install');
      expect(text).not.toContain('{"ok":false');
      expect(text).not.toContain('"advice"');
    });


    test('Host identity errors render human text and preserve identity codes in JSON', async () => {
      const humanStdout = captureStream();
      const humanStderr = captureStream();
      const store = {
        load: async () => null,
        hasEvidence: () => false,
        create: async () => { throw new Error('unused'); },
        rotate: async () => { throw new Error('unused'); },
        commitRotation: async () => { throw new Error('unused'); },
        abortRotation: async () => { throw new Error('unused'); },
        reset: async () => { throw new Error('unused'); },
      } as any;
      const manager = {
        backend: 'systemd-user' as const,
        support: {
          platform: 'linux' as const,
          backend: 'systemd-user' as const,
          supported: true,
          isWsl: false,
          reason: 'supported' as const,
        },
        install() { throw new Error('unused'); },
        uninstall() {},
        start() {},
        stop() {},
        restart() {},
        status() {
          return {
            support: this.support,
            installed: false,
            enabled: false,
            loaded: false,
            processRunning: false,
            logBackend: 'unavailable' as const,
          };
        },
        logsAvailable() { return false; },
        logs() { return { source: 'files' as const, text: '' }; },
      };
      const harness = createProfileCliHarness();
      roots.push(harness.root);
      const profile = harness.profiles.default;
      const profileRoot = profile.resources.root;
      const userConfig = {
        relayBaseUrl: profile.defaultRelayBaseUrl,
        hostName: profile.defaultHostName('test-host'),
        agentAdapterPort: profile.resources.agentAdapterPort,
        agentAdapterConfigPath: profile.resources.agentAdapterConfigPath,
        agentAdapterSecret: 'test-secret',
        statePath: profile.resources.statePath,
        identityPath: profile.resources.identityMetadataPath,
      };
      const deps = {
        createServiceManager: () => manager,
        createHostIdentityStore: () => store,
        createProfile: () => profile,
        loadUserConfig: () => userConfig,
        resolveAriavaConfig: () => ({
          ...userConfig,
          configPath: profile.resources.configPath,
          installPath: join(profileRoot, 'install.json'),
          logDir: join(profileRoot, 'logs'),
          stdoutLogPath: join(profileRoot, 'logs', 'bridge.stdout.log'),
          stderrLogPath: join(profileRoot, 'logs', 'bridge.stderr.log'),
          tmpDir: join(profileRoot, 'tmp'),
          environmentOverrides: [],
        }),
      };


      const humanCode = await runPublicCli(['pair', 'ABCDEF'], {
        stdout: humanStdout.stream,
        stderr: humanStderr.stream,
        ...deps,
      });
      expect(humanCode).toBe(1);
      expect(humanStdout.read()).toBe('');
      expect(humanStderr.read()).toBe('ariava: Host identity is not initialized; run `ariava init`.\n');


      const jsonStdout = captureStream();
      const jsonStderr = captureStream();
      const jsonCode = await runPublicCli(['pair', 'ABCDEF', '--json'], {
        stdout: jsonStdout.stream,
        stderr: jsonStderr.stream,
        ...deps,
      });
      expect(jsonCode).toBe(1);
      expect(jsonStdout.read()).toBe('');
      expect(JSON.parse(jsonStderr.read())).toEqual({
        ok: false,
        code: 'ERR_IDENTITY_NOT_INITIALIZED',
        message: 'Host identity is not initialized; run `ariava init`.',
        data: {},
      });
    });


    test('locked macOS Keychain errors guide the native interactive unlock instead of Host reset', () => {
      const nativeUnlockCommand = 'security unlock-keychain "$HOME/Library/Keychains/login.keychain-db"';
      const failure = normalizeCliFailure(new HostIdentityError(
        'ERR_IDENTITY_KEYCHAIN_LOCKED',
        'macOS login Keychain is locked or unavailable in this session.',
      ));
      expect(failure).toEqual({
        ok: false,
        code: 'ERR_IDENTITY_KEYCHAIN_LOCKED',
        message: 'macOS login Keychain is locked or unavailable in this session.',
        data: {
          retryable: true,
          remediation: {
            message: 'Unlock the macOS login Keychain in this terminal, then retry the Ariava command.',
            command: nativeUnlockCommand,
          },
        },
      });
      const text = formatHumanCliFailure(failure);
      expect(text).toContain(`Next: ${nativeUnlockCommand}`);
      expect(text).not.toContain('ariava keychain unlock');
      expect(text).not.toContain('ariava host reset --confirm');
      expect(text).not.toContain(' -p ');
    });


    test('generic and relay failures normalize to stable codes', () => {
      expect(normalizeCliFailure(new Error('boom'))).toEqual({
        ok: false,
        code: 'ERR_CLI',
        message: 'boom',
        data: {},
      });
      expect(normalizeCliFailure(new RelayClientError(503, 'relay unavailable'))).toEqual({
        ok: false,
        code: 'ERR_RELAY',
        message: 'relay unavailable',
        data: { status: 503 },
      });
      expect(normalizeCliFailure(new HostIdentityError('ERR_IDENTITY_MISSING', 'missing'))).toEqual({
        ok: false,
        code: 'ERR_IDENTITY_MISSING',
        message: 'missing',
        data: {},
      });
    });


    test('generic error without --json prints ariava: message only', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const exitCode = await runPublicCli(['install', 'not-pi'], {
        stdout: stdout.stream,
        stderr: stderr.stream,
      });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      expect(stderr.read()).toBe('ariava: Usage: ariava install pi\n');
      expect(stderr.read()).not.toContain('Error');
    });


    test('generic error with --json keeps ERR_CLI envelope', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const exitCode = await runPublicCli(['install', 'not-pi', '--json'], {
        stdout: stdout.stream,
        stderr: stderr.stream,
      });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      expect(JSON.parse(stderr.read())).toEqual({
        ok: false,
        code: 'ERR_CLI',
        message: 'Usage: ariava install pi',
        data: {},
      });
    });


    test('WSL multi-line instructions format as plain text without JSON data dumps', () => {
      const failure = normalizeCliFailure(new AriavaCliError(
        'ERR_SYSTEMD_USER_UNAVAILABLE',
        'Ariava requires an available systemd user manager on WSL.',
        {
          platform: 'linux',
          isWsl: true,
          backend: 'systemd-user',
          reason: 'systemd-user-manager-unavailable',
          instructions: { wslConfig: '[boot]\nsystemd=true', windowsCommand: 'wsl.exe --shutdown' },
        },
      ));
      const text = formatHumanCliFailure(failure);
      expect(text.startsWith('ariava: Ariava requires an available systemd user manager on WSL.')).toBe(true);
      expect(text).toContain('/etc/wsl.conf');
      expect(text).toContain('[boot]\nsystemd=true');
      expect(text).toContain('wsl.exe --shutdown');
      expect(text).not.toContain('"instructions"');
      expect(text).not.toContain('JSON');
      expect(() => JSON.parse(text.trim())).toThrow();

      // When the message already embeds the WSL guidance (production supportError shape),
      // do not duplicate the structured instructions block.
      const embedded = normalizeCliFailure(new AriavaCliError(
        'ERR_SYSTEMD_USER_UNAVAILABLE',
        'Ariava requires systemd user services on WSL. Add the following to /etc/wsl.conf:\n\n[boot]\nsystemd=true\n\nThen run `wsl.exe --shutdown` from Windows PowerShell, reopen the distribution, and retry `ariava init`.',
        {
          platform: 'linux',
          isWsl: true,
          backend: 'systemd-user',
          reason: 'systemd-user-manager-unavailable',
          instructions: { wslConfig: '[boot]\nsystemd=true', windowsCommand: 'wsl.exe --shutdown' },
        },
      ));
      const embeddedText = formatHumanCliFailure(embedded);
      expect(embeddedText).toBe(`ariava: ${embedded.message}\n`);
      expect(embeddedText).toContain('/etc/wsl.conf');
      expect(embeddedText).toContain('wsl.exe --shutdown');
      expect(embeddedText.split('wsl.exe --shutdown').length - 1).toBe(1);
    });


    test('setup normalizes locked Keychain failures with unlock remediation', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const exitCode = await runPublicCli(['setup', '--no-extensions'], {
        stdout: stdout.stream,
        stderr: stderr.stream,
      }, {
        terminal: { stdout: stdout.stream, stderr: stderr.stream, interactive: false, color: false },
        detect: () => ({
          platform: 'darwin', architecture: 'arm64', nodeVersion: '22.0.0', npm: { present: true }, pi: { present: true },
          serviceSupport: { platform: 'darwin', backend: 'launchd', supported: true, isWsl: false, reason: 'supported' },
          interactive: false, machineOutput: false, configPath: '/isolated/config.json', config: {}, installMetadata: {},
          currentCli: { executablePath: '/isolated/bin/ariava' },
        }),
        run: async () => {
          throw new HostIdentityError(
            'ERR_IDENTITY_KEYCHAIN_LOCKED',
            'macOS login Keychain is locked or unavailable in this session.',
          );
        },
      });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      expect(stderr.read()).toContain('Next: security unlock-keychain "$HOME/Library/Keychains/login.keychain-db"');
      expect(stderr.read()).not.toContain('ariava keychain unlock');
      expect(stderr.read()).not.toContain('ariava host reset --confirm');
    });


    test('setup human errors use ariava: prefix and remediation lines', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const exitCode = await runPublicCli(['setup', '--no-extensions'], {
        stdout: stdout.stream,
        stderr: stderr.stream,
      }, {
        terminal: { stdout: stdout.stream, stderr: stderr.stream, interactive: false, color: false },
        detect: () => ({
          platform: 'linux', architecture: 'arm64', nodeVersion: '22.0.0', npm: { present: true }, pi: { present: true },
          serviceSupport: { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' },
          interactive: false, machineOutput: false, configPath: '/isolated/config.json', config: {}, installMetadata: {},
          currentCli: { executablePath: '/isolated/bin/ariava' },
        }),
        run: async () => {
          throw new AriavaCliError('ERR_STABLE_CLI_INSTALL', 'npm global prefix is not writable.', {
            step: 'stable-cli', retryable: true,
            remediation: { message: 'Configure a user-writable npm prefix.', command: 'npm config set prefix ~/.local' },
          });
        },
      });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      const text = stderr.read();
      expect(text.startsWith('ariava: npm global prefix is not writable.')).toBe(true);
      expect(text).toContain('Configure a user-writable npm prefix.');
      expect(text).toContain('Next: npm config set prefix ~/.local');
      expect(text).not.toContain('Onboarding stopped:');
    });
  });

  describe('--version option', () => {
    const expectedVersion = JSON.parse(readFileSync(join(publicCoreRoot, 'package.json'), 'utf8')).version as string;

    test('prints package SemVer only on stdout without config side effects', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-version-home-'));
      roots.push(home);
      const stdout = captureStream();
      const stderr = captureStream();
      const previousHome = process.env.HOME;
      process.env.HOME = home;
      try {
        const exitCode = await runPublicCli(['--version'], { stdout: stdout.stream, stderr: stderr.stream });
        expect(exitCode).toBe(0);
        expect(stdout.read()).toBe(`${expectedVersion}\n`);
        expect(stderr.read()).toBe('');
        expect(existsSync(join(home, '.config', 'ariava'))).toBe(false);
      } finally {
        if (previousHome === undefined) delete process.env.HOME;
        else process.env.HOME = previousHome;
      }
    });

    test('accepts --version --json and --json --version success envelopes', async () => {
      const expectedEnvelope = {
        ok: true,
        code: 'ok',
        message: 'Ariava CLI version.',
        data: { version: expectedVersion },
      };

      for (const args of [['--version', '--json'], ['--json', '--version']] as const) {
        const stdout = captureStream();
        const stderr = captureStream();
        const exitCode = await runPublicCli([...args], { stdout: stdout.stream, stderr: stderr.stream });
        expect(exitCode).toBe(0);
        expect(JSON.parse(stdout.read())).toEqual(expectedEnvelope);
        expect(stderr.read()).toBe('');
      }
    });

    test('rejects extra arguments under human and JSON contracts', async () => {
      const humanStdout = captureStream();
      const humanStderr = captureStream();
      const humanCode = await runPublicCli(['--version', 'extra'], {
        stdout: humanStdout.stream,
        stderr: humanStderr.stream,
      });
      expect(humanCode).toBe(1);
      expect(humanStdout.read()).toBe('');
      const humanText = humanStderr.read();
      expect(humanText.startsWith('ariava:')).toBe(true);
      expect(humanText).toMatch(/version|extra|Usage/i);
      expect(humanText).not.toContain('{"ok":false');

      const jsonStdout = captureStream();
      const jsonStderr = captureStream();
      const jsonCode = await runPublicCli(['--version', 'extra', '--json'], {
        stdout: jsonStdout.stream,
        stderr: jsonStderr.stream,
      });
      expect(jsonCode).toBe(1);
      expect(jsonStdout.read()).toBe('');
      const envelope = JSON.parse(jsonStderr.read());
      expect(envelope).toMatchObject({ ok: false, code: 'ERR_CLI' });
      expect(String(envelope.message)).toMatch(/version|extra|Usage/i);
    });

    test('does not treat version as a subcommand alias', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const exitCode = await runPublicCli(['version'], { stdout: stdout.stream, stderr: stderr.stream });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      const text = stderr.read();
      expect(text.startsWith('ariava: Unknown command: version')).toBe(true);
      expect(text).toContain(`Run 'ariava help' for usage.`);
    });

    test('help documents --version and command catalog omits version subcommand', async () => {
      const humanStdout = captureStream();
      const humanStderr = captureStream();
      const humanCode = await runPublicCli(['help'], { stdout: humanStdout.stream, stderr: humanStderr.stream });
      expect(humanCode).toBe(0);
      expect(humanStderr.read()).toBe('');
      expect(humanStdout.read()).toContain('--version                       Show the current Ariava CLI version');

      const jsonStdout = captureStream();
      const jsonStderr = captureStream();
      const jsonCode = await runPublicCli(['--help', '--json'], { stdout: jsonStdout.stream, stderr: jsonStderr.stream });
      expect(jsonCode).toBe(0);
      expect(jsonStderr.read()).toBe('');
      const json = JSON.parse(jsonStdout.read());
      expect(json.data.commands).not.toContain('ariava version');
      expect(json.data.commands.some((entry: string) => entry.includes('ariava version'))).toBe(false);
    });

    test('works from an unrelated cwd with isolated HOME via spawn', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-version-spawn-home-'));
      const cwd = mkdtempSync(join(tmpdir(), 'ariava-cli-version-cwd-'));
      roots.push(home, cwd);
      const proc = Bun.spawn({
        cmd: [bunPath, cliPath, '--version'],
        cwd,
        env: isolatedEnv(home),
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stdout, stderr] = await Promise.all([
        proc.exited,
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]);
      expect(exitCode, stderr).toBe(0);
      expect(stdout).toBe(`${expectedVersion}\n`);
      expect(stderr).toBe('');
      expect(existsSync(join(home, '.config', 'ariava'))).toBe(false);
    });
  });
  test('renders structured top-level help while preserving the JSON command catalog', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-help-'));
    roots.push(home);
    const run = async (...args: string[]) => {
      const proc = Bun.spawn({
        cmd: [bunPath, cliPath, ...args],
        cwd: process.cwd(),
        env: isolatedEnv(home),
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stdout, stderr] = await Promise.all([
        proc.exited,
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]);
      expect(exitCode, stderr).toBe(0);
      return stdout;
    };

    const human = await run('help');
    expect(human).toContain('Ariava — Apple Watch-first collaboration for coding agents');
    expect(human).toContain('Usage:\n  ariava <command> [options]');
    expect(human).toContain('Get started:');
    expect(human).toContain('Status and diagnostics:');
    expect(human).toContain('Watch pairing:');
    expect(human).toContain('Global options:');
    expect(human).toContain('npx --yes ariava@latest setup');

    const json = JSON.parse(await run('--help', '--json'));
    expect(json).toMatchObject({ ok: true, code: 'ok', message: 'Ariava CLI' });
    expect(json.data.commands).toEqual([
      'ariava setup [--extension pi ... | --no-extensions] [--resume] [--json] [--yes] [--relay-base-url <URL>]',
      'ariava init',
      'ariava status [pi]',
      'ariava pair <PAIRING_CODE> [--codes-match]',
      'ariava watches list',
      'ariava watches remove <WATCH_DEVICE_ID>',
      'ariava identity status',
      'ariava host rotate-key',
      'ariava host reset --confirm',
      'ariava doctor',
      'ariava logs',
      'ariava upgrade [pi]',
      'ariava uninstall [--purge] [--remove-pi]',
      'ariava config path|show|get|set',
      'ariava config agent-secret ensure|rotate',
      'ariava service install|reinstall|status|start|stop|restart|uninstall',
      'ariava install pi',
      'ariava remove pi',
      'ariava dev install pi [--from <path>]',
      'ariava dev upgrade pi [--from <path>]',
      'ariava dev bridge use [--from <path>]',
      'ariava dev status',
    ]);
  });

  test('renders a concise human status card with only product-facing fields', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-status-home-'));
    roots.push(home);

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'status'],
      cwd: process.cwd(),
      env: isolatedEnv(home),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [exitCode, stdout, stderr] = await Promise.all([proc.exited, new Response(proc.stdout).text(), new Response(proc.stderr).text()]);

    expect(exitCode, stderr).toBe(0);
    expect(stderr).toBe('');
    expect(stdout).toMatch(/^Ariava\n\n  Version\s{2,}\S/);
    expect(stdout).toMatch(/\n  Bridge\s{2,}offline\n/);
    expect(stdout).toMatch(/\n  Host\s{2,}\S/);
    expect(stdout).toMatch(/\n  Identity\s{2,}not-initialized\n/);
    expect(stdout).toMatch(/\n  Relay\s{2,}https:\/\/ariava-relay\.noyx\.io\n/);
    expect(stdout).toMatch(/\n  Agent\s{2,}Pi · not installed\n/);
    expect(stdout).not.toMatch(/Config complete|Service backend|Service supported|Process running|Bridge source|pi extension:/);
  });

  test('reports the package version in status and upgrade output', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);
    const expectedVersion = JSON.parse(readFileSync(join(publicCoreRoot, 'package.json'), 'utf8')).version;

    const run = async (...args: string[]) => {
      const proc = Bun.spawn({
        cmd: [bunPath, cliPath, ...args, '--json'],
        cwd: process.cwd(),
        env: isolatedEnv(home, { ARIAVA_UPGRADE_SELF_DONE: '1', ARIAVA_UPGRADE_SKIP_LAUNCHCTL: '1' }),
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stdout, stderr] = await Promise.all([proc.exited, new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
      expect(exitCode, stderr).toBe(0);
      return JSON.parse(stdout);
    };

    const status = await run('status');
    expect(status.data.cliVersion).toBe(expectedVersion);

    const upgrade = await run('upgrade');
    expect(upgrade.data.cliVersion).toBe(expectedVersion);
    expect(upgrade.data.piExtension.record.version).toBe(expectedVersion);
  });


  test('config path returns stable json envelope', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'config', 'path', '--json'],
      cwd: process.cwd(),
      env: isolatedEnv(home),
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
    expect(exitCode).toBe(0);
    expect(JSON.parse(stdout)).toEqual({
      ok: true,
      code: 'ok',
      message: 'Resolved Ariava config path.',
      data: { configPath: join(home, '.config', 'ariava', 'config.json') },
    });
  });

  test('status pi returns structured json', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'status', 'pi', '--json'],
      cwd: process.cwd(),
      env: isolatedEnv(home),
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
    expect(exitCode).toBe(0);
    const body = JSON.parse(stdout);
    expect(body.ok).toBe(true);
    expect(body.data.installPath).toBe(join(home, '.pi', 'agent', 'extensions', 'ariava-pi'));
    expect(body.data.managed).toBe(false);
  });

  test('install pi delegates to Pi package management and persists the npm package', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    const workdir = mkdtempSync(join(tmpdir(), 'ariava-random-cwd-'));
    roots.push(home, workdir);
    const isolated = createIsolatedPublicCliEnvironment(home);

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'install', 'pi', '--json'],
      cwd: workdir,
      env: isolated.env,
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stdout, stderr] = await Promise.all([proc.exited, new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
    expect(exitCode, stderr).toBe(0);
    const body = JSON.parse(stdout);
    expect(body.ok).toBe(true);
    expect(body.data.managedPath).toBe(join(home, '.pi', 'agent', 'npm', 'node_modules', '@ariava', 'pi-extension'));
    const expectedVersion = JSON.parse(readFileSync(join(publicCoreRoot, 'package.json'), 'utf8')).version;
    const exactSource = `npm:@ariava/pi-extension@${expectedVersion}`;
    expect(body.data.source).toMatchObject({ kind: 'npm-package', package: exactSource });
    expect(readFileSync(isolated.piLogPath, 'utf8')).toContain(`install ${exactSource}`);
    expect(JSON.parse(readFileSync(join(home, '.pi', 'agent', 'settings.json'), 'utf8')).packages).toContain(exactSource);
  });


  test('dev status returns source metadata envelope', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'dev', 'status', '--json'],
      cwd: process.cwd(),
      env: isolatedEnv(home),
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
    expect(exitCode).toBe(0);
    const body = JSON.parse(stdout);
    expect(body.ok).toBe(true);
    expect(body.data.bridgeSource.kind).toBe('release-bundle');
    expect(body.data.piSource.kind).toBe('release-bundle');
  });

  test('uninstall with purge removes config root after fake manager success', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);
    const configRoot = join(home, '.config', 'ariava');
    secureJsonFixture(join(configRoot, 'config.json'), {});
    const harnessPath = join(publicCoreRoot, 'apps', 'bridge', 'test', 'fixtures', 'public-cli-harness.ts');
    const proc = Bun.spawn({
      cmd: [bunPath, harnessPath, 'uninstall', '--purge', '--json'],
      cwd: process.cwd(),
      env: isolatedEnv(home, { ARIAVA_TEST_SCENARIO: 'linux-supported' }),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      proc.exited,
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    expect(exitCode, stderr).toBe(0);
    const body = JSON.parse(stdout);
    expect(body.ok).toBe(true);
    expect(body.data.purge).toBe(true);
    expect(existsSync(configRoot)).toBe(false);
  });

  test('init persists the canonical production relay and stable agent adapter secret without printing it', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);

    const harnessPath = join(publicCoreRoot, 'apps', 'bridge', 'test', 'fixtures', 'public-cli-harness.ts');
    const proc = Bun.spawn({
      cmd: [bunPath, harnessPath, 'init', '--json'],
      cwd: process.cwd(),
      env: isolatedEnv(home, { ARIAVA_TEST_SCENARIO: 'linux-supported' }),
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
    expect(exitCode).toBe(0);
    const body = JSON.parse(stdout);
    expect(body.ok).toBe(true);
    expect(body.data.config.agentAdapterSecret).toBeUndefined();

    const config = JSON.parse(readFileSync(join(home, '.config', 'ariava', 'config.json'), 'utf8'));
    expect(config.agentAdapterSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(config.relayBaseUrl).toBe('https://ariava-relay.noyx.io');
    expect(stdout).not.toContain(config.agentAdapterSecret);
  });

  test('config agent-secret ensure creates once and rotate replaces it', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);

    const run = async (...args: string[]) => {
      const proc = Bun.spawn({
        cmd: [bunPath, cliPath, ...args, '--json'],
        cwd: process.cwd(),
        env: isolatedEnv(home),
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
      expect(exitCode).toBe(0);
      return JSON.parse(stdout);
    };

    const ensured = await run('config', 'agent-secret', 'ensure');
    expect(ensured.data.generated).toBe(true);
    expect(ensured.data.rotated).toBe(false);
    const first = JSON.parse(readFileSync(join(home, '.config', 'ariava', 'config.json'), 'utf8')).agentAdapterSecret;
    expect(first).toMatch(/^[0-9a-f]{64}$/);

    const ensuredAgain = await run('config', 'agent-secret', 'ensure');
    expect(ensuredAgain.data.generated).toBe(false);
    expect(ensuredAgain.data.rotated).toBe(false);
    const second = JSON.parse(readFileSync(join(home, '.config', 'ariava', 'config.json'), 'utf8')).agentAdapterSecret;
    expect(second).toBe(first);

    const rotated = await run('config', 'agent-secret', 'rotate');
    expect(rotated.data.generated).toBe(true);
    expect(rotated.data.rotated).toBe(true);
    const third = JSON.parse(readFileSync(join(home, '.config', 'ariava', 'config.json'), 'utf8')).agentAdapterSecret;
    expect(third).toMatch(/^[0-9a-f]{64}$/);
    expect(third).not.toBe(first);

  });

  test('upgrade performs local reconciliation after self-upgrade has already run', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-cli-home-'));
    roots.push(home);

    const proc = Bun.spawn({
      cmd: [bunPath, cliPath, 'upgrade', '--json'],
      cwd: process.cwd(),
      env: isolatedEnv(home, { ARIAVA_UPGRADE_SELF_DONE: '1', ARIAVA_UPGRADE_SKIP_LAUNCHCTL: '1' }),
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const [exitCode, stdout, stderr] = await Promise.all([proc.exited, new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
    expect(exitCode, stderr).toBe(0);
    const body = JSON.parse(stdout);
    expect(body.ok).toBe(true);
    expect(body.message).toBe('Ariava upgraded.');
    expect(body.data.config.updated).toBe(true);
    expect(body.data.piExtension.updated).toBe(true);
    expect(body.data.service.updated).toBe(false);
    expect(body.data.selfUpgrade.skipped).toBe(true);

    const config = JSON.parse(readFileSync(join(home, '.config', 'ariava', 'config.json'), 'utf8'));
    expect(config.agentAdapterSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(stdout).not.toContain(config.agentAdapterSecret);

    expect(body.data.piExtension.record.managedPath).toBe(join(home, '.pi', 'agent', 'npm', 'node_modules', '@ariava', 'pi-extension'));
  });


  describe('guided onboarding CLI integration', () => {
    function captureStream() {
      let output = '';
      return {
        stream: { write(chunk: unknown) { output += String(chunk); return true; } } as NodeJS.WritableStream,
        read: () => output,
      };
    }

    function detection(piPresent = true): OnboardingDetection {
      return {
        platform: 'linux', architecture: 'arm64', nodeVersion: '22.0.0', npm: { present: true }, pi: { present: piPresent },
        serviceSupport: { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' },
        interactive: false, machineOutput: true, configPath: '/isolated/config.json', config: {}, installMetadata: {},
        currentCli: { executablePath: '/isolated/bin/ariava' },
      };
    }

    function result(target: 'host-ready' | 'adapter-installed', readiness: OnboardingResult['readiness'], nextActions: OnboardingResult['nextActions'] = []): OnboardingResult {
      const adapterSelected = target === 'adapter-installed';
      const failed = readiness === 'failed';
      let readinessStatus: OnboardingResult['steps'][number]['status'] = 'ready';
      if (readiness === 'reload-pending') readinessStatus = 'reload-pending';
      else if (failed) readinessStatus = 'failed';
      return {
        target, readiness, nextActions,
        steps: [
          { id: 'preflight', status: 'ready' },
          { id: 'stable-cli', status: 'reused' },
          { id: 'relay-config', status: 'ready' },
          { id: 'host-init', status: 'ready' },
          { id: 'bridge-service', status: 'ready' },
          { id: 'adapter-detect', status: adapterSelected ? 'ready' : 'skipped' },
          { id: 'adapter-install', status: adapterSelected ? 'installed' : 'skipped' },
          { id: 'strict-readiness', status: readinessStatus },
          { id: 'completion', status: failed ? 'failed' : 'ready' },
        ],
      };
    }

    test('non-TTY Bridge-only onboarding returns JSON success without host mutations', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      let received: Parameters<NonNullable<Parameters<typeof runPublicCli>[2]['run']>>[0] | undefined;
      const exitCode = await runPublicCli(['setup', '--no-extensions', '--json'], { stdout: stdout.stream, stderr: stderr.stream }, {
        terminal: { stdout: stdout.stream, stderr: stderr.stream, interactive: false, color: false },
        detect: () => detection(),
        run: async (input) => { received = input; return result('host-ready', 'host-ready'); },
      });
      expect(exitCode).toBe(0);
      expect(received).toMatchObject({ target: 'host-ready', publicArgs: ['--no-extensions'], resumed: false });
      expect(JSON.parse(stdout.read())).toMatchObject({ ok: true, code: 'ok', data: { target: 'host-ready', readiness: 'host-ready' } });
      expect(stderr.read()).toBe('');
    });

    test('Pi onboarding returns reload-pending JSON and required next actions', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const nextActions = [
        { id: 'reload-pi', command: '/reload' },
        { id: 'pair-watch', command: 'ariava pair <PAIRING_CODE>' },
      ];
      const exitCode = await runPublicCli(['setup', '--extension', 'pi', '--json'], { stdout: stdout.stream, stderr: stderr.stream }, {
        terminal: { stdout: stdout.stream, stderr: stderr.stream, interactive: false, color: false },
        detect: () => detection(),
        run: async (input) => {
          expect(input.target).toBe('adapter-installed');
          return result('adapter-installed', 'reload-pending', nextActions);
        },
      });
      expect(exitCode).toBe(0);
      expect(JSON.parse(stdout.read())).toMatchObject({ ok: true, data: { readiness: 'reload-pending', nextActions } });
      expect(stderr.read()).toBe('');
    });

    test('interactive Pi selection is persisted into publicArgs for stable re-entry', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      let received: Parameters<NonNullable<Parameters<typeof runPublicCli>[2]['run']>>[0] | undefined;
      const exitCode = await runPublicCli(['setup'], { stdout: stdout.stream, stderr: stderr.stream }, {
        terminal: { stdout: stdout.stream, stderr: stderr.stream, interactive: true, color: false },
        prompt: {
          multiselect: async () => ['pi'],
        },
        detect: () => detection(true),
        run: async (input) => {
          received = input;
          return result('adapter-installed', 'reload-pending', [
            { id: 'reload-pi', command: '/reload' },
            { id: 'pair-watch', command: 'ariava pair <PAIRING_CODE>' },
          ]);
        },
      });
      expect(exitCode).toBe(0);
      expect(received).toMatchObject({
        target: 'adapter-installed',
        publicArgs: ['--extension', 'pi'],
      });
      expect(stderr.read()).toBe('');
    });

    test('public --resume is accepted without internal bootstrap markers', async () => {
      const stdout = captureStream();
      let received: Parameters<NonNullable<Parameters<typeof runPublicCli>[2]['run']>>[0] | undefined;
      const exitCode = await runPublicCli(['setup', '--no-extensions', '--resume', '--json'], { stdout: stdout.stream }, {
        terminal: { stdout: stdout.stream, stderr: captureStream().stream, interactive: false, color: false },
        detect: () => detection(),
        run: async (input) => { received = input; return result('host-ready', 'host-ready'); },
      });
      expect(exitCode).toBe(0);
      expect(received).toMatchObject({ resumed: true, bootstrapVersion: undefined, publicArgs: ['--no-extensions'] });
    });

    test('SIGINT abort produces failed JSON, nonzero exit, and closes the onboarding prompt', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      let closeCalls = 0;
      const exitCodePromise = runPublicCli(['setup', '--no-extensions', '--json'], { stdout: stdout.stream, stderr: stderr.stream }, {
        terminal: { stdout: stdout.stream, stderr: stderr.stream, interactive: false, color: false },
        prompt: { choose: async () => 'bridge-only', close: () => { closeCalls += 1; } },
        detect: () => detection(),
        run: (input) => new Promise((resolve) => {
          input.signal?.addEventListener('abort', () => resolve(result('host-ready', 'failed', [{ id: 'retry-onboarding', command: 'ariava setup --resume' }])), { once: true });
          queueMicrotask(() => process.emit('SIGINT'));
        }),
      });
      const exitCode = await exitCodePromise;
      expect(exitCode).toBe(1);
      expect(closeCalls).toBeGreaterThan(0);
      expect(JSON.parse(stdout.read())).toMatchObject({ ok: false, data: { readiness: 'failed', nextActions: [{ id: 'retry-onboarding', command: 'ariava setup --resume' }] } });
      expect(stderr.read()).toBe('');
    });

    test('onboarding errors preserve structured remediation in JSON', async () => {
      const stdout = captureStream();
      const stderr = captureStream();
      const exitCode = await runPublicCli(['setup', '--no-extensions', '--json'], { stdout: stdout.stream, stderr: stderr.stream }, {
        terminal: { stdout: stdout.stream, stderr: stderr.stream, interactive: false, color: false },
        detect: () => detection(),
        run: async () => {
          throw new AriavaCliError('ERR_STABLE_CLI_INSTALL', 'npm global prefix is not writable.', {
            step: 'stable-cli', retryable: true,
            remediation: { message: 'Configure a user-writable npm prefix.', command: 'npm config set prefix ~/.local' },
          });
        },
      });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      expect(JSON.parse(stderr.read())).toEqual({
        ok: false, code: 'ERR_STABLE_CLI_INSTALL', message: 'npm global prefix is not writable.',
        data: { step: 'stable-cli', retryable: true, remediation: { message: 'Configure a user-writable npm prefix.', command: 'npm config set prefix ~/.local' } },
      });
    });
  });

  describe('injectable cross-platform service commands', () => {
    const harnessPath = join(publicCoreRoot, 'apps', 'bridge', 'test', 'fixtures', 'public-cli-harness.ts');

    async function runHarness(home: string, scenario: string, ...args: string[]) {
      return runHarnessWithEnv(home, scenario, {}, ...args);
    }

    async function runHarnessWithEnv(
      home: string,
      scenario: string,
      environment: Record<string, string>,
      ...args: string[]
    ) {
      const isolated = createIsolatedPublicCliEnvironment(home);
      const env: Record<string, string> = {
        ...(isolated.env as Record<string, string>),
        HOME: home,
        ARIAVA_TEST_SCENARIO: scenario,
        ARIAVA_TEST_MANAGER_CALLS_PATH: retainedManagerCallsPath(home),
        ARIAVA_RELAY_BASE_URL: '',
        ARIAVA_HOST_ID: '',
        ARIAVA_HOST_NAME: '',
        ARIAVA_AGENT_ADAPTER_PORT: '',
      };
      for (const name of ['TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL']) {
        const value = process.env[name];
        if (value !== undefined) env[name] = value;
      }
      Object.assign(env, environment);
      const proc = Bun.spawn({
        cmd: [bunPath, harnessPath, ...args, '--json'],
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
      return {
        exitCode,
        stdout: stdout ? JSON.parse(stdout) : undefined,
        stderr: stderr ? JSON.parse(stderr) : undefined,
      };
    }

    function writeInstall(home: string, value: unknown): string {
      const path = join(home, '.config', 'ariava', 'install.json');
      secureJsonFixture(path, value);
      return path;
    }

    function retainedManagerCallsPath(home: string): string {
      const path = `${home}.manager-calls.json`;
      if (!roots.includes(path)) roots.push(path);
      return path;
    }

    function managerCalls(home: string): Array<Record<string, unknown>> {
      const path = retainedManagerCallsPath(home);
      return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : [];
    }

    type HarnessResult = Awaited<ReturnType<typeof runHarnessWithEnv>>;

    function expectStdoutSuccess(result: HarnessResult): void {
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toMatchObject({ ok: true });
      expect(result.stderr).toBeUndefined();
    }

    function expectStdoutFailure(result: HarnessResult, code: string): void {
      expect(result.exitCode).toBe(1);
      expect(result.stdout).toMatchObject({ ok: false, code });
      expect(result.stderr).toBeUndefined();
    }

    function expectStderrFailure(result: HarnessResult, code: string): void {
      expect(result.exitCode).toBe(1);
      expect(result.stdout).toBeUndefined();
      expect(result.stderr).toMatchObject({ ok: false, code });
    }

    test('supported Linux init writes config without installing a service', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-linux-init-'));
      roots.push(home);
      const result = await runHarness(home, 'linux-supported', 'init');
      expectStdoutSuccess(result);
      expect(existsSync(join(home, '.config', 'ariava', 'config.json'))).toBe(true);
      expect(existsSync(join(home, '.config', 'ariava', 'install.json'))).toBe(false);
    });

    test('production status preserves the exact JSON baseline and ignores dev Bridge evidence', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-status-baseline-'));
      roots.push(home);
      const devRoot = join(home, '.config', 'ariava-dev');
      secureJsonFixture(join(devRoot, 'bridge-state.json'), { sourceBridge: 'ready' });
      secureJsonFixture(join(devRoot, 'agent-adapter.json'), {
        url: 'http://127.0.0.1:7273',
        secret: 'dev-only-secret',
      });
      const cliVersion = JSON.parse(readFileSync(join(publicCoreRoot, 'package.json'), 'utf8')).version;

      const status = await runHarness(home, 'linux-supported', 'status');

      expect(status).toEqual({
        exitCode: 0,
        stderr: undefined,
        stdout: {
          ok: true,
          code: 'ok',
          message: 'Ariava host status.',
          data: {
            cliVersion,
            configComplete: false,
            bridgeHealth: 'offline',
            hostId: 'host_fixture',
            hostName: hostname(),
            relayBaseUrl: 'https://ariava-relay.noyx.io',
            service: {
              backend: 'systemd-user',
              supported: true,
              supportReason: 'supported',
              installed: false,
              enabled: false,
              loaded: false,
              processRunning: false,
              runtimeCryptoSelfTestPassed: true,
            },
            piExtension: {
              installed: false,
              installPath: join(home, '.pi', 'agent', 'extensions', 'ariava-pi'),
              expectedManagedPath: join(home, '.pi', 'agent', 'npm', 'node_modules', '@ariava', 'pi-extension'),
              managed: false,
              managedMetadataPath: join(home, '.pi', 'agent', 'extensions', 'ariava-pi', '.ariava-managed.json'),
              expectedSource: `npm:@ariava/pi-extension@${cliVersion}`,
              sourceOwnership: 'absent',
              mismatchReasons: [],
              bundledVersion: cliVersion,
            },
            environmentOverrides: [],
            identity: {
              status: 'not-initialized',
              storageType: 'linux-json',
              storageReference: { type: 'linux-json', path: join(home, '.config', 'ariava', 'host-identity.json') },
              path: join(home, '.config', 'ariava', 'host-identity.json'),
              ownerIntegrity: false,
              permissionIntegrity: false,
              metadataIntegrity: false,
              pendingRotation: false,
            },
          },
        },
      });
      expect(JSON.stringify(status)).not.toContain('dev-only-secret');
    });

    test.each([
      ['Linux', 'linux-supported'],
      ['WSL', 'wsl-supported'],
    ])('supported %s completes the public service lifecycle contract', async (_name, scenario) => {
      const home = mkdtempSync(join(tmpdir(), `ariava-cli-${scenario}-lifecycle-`));
      roots.push(home);
      const init = await runHarness(home, scenario, 'init');
      expect(init).toMatchObject({ exitCode: 0, stdout: { ok: true }, stderr: undefined });
      const install = await runHarness(home, scenario, 'service', 'install');
      expect(install).toMatchObject({ exitCode: 0, stdout: { ok: true }, stderr: undefined });
      expect(install.stdout.data.backend).toBe('systemd-user');
      const status = await runHarness(home, scenario, 'service', 'status');
      expect(status).toMatchObject({
        exitCode: 0, stderr: undefined,
        stdout: { ok: true, data: { backend: 'systemd-user', installed: true, enabled: true, loaded: true, processRunning: true } },
      });
      for (const command of ['start', 'stop', 'restart'] as const) {
        const result = await runHarness(home, scenario, 'service', command);
        expect(result).toMatchObject({ exitCode: 0, stdout: { ok: true }, stderr: undefined });
      }
      const logs = await runHarness(home, scenario, 'logs');
      expect(logs).toEqual({
        exitCode: 0, stderr: undefined,
        stdout: { ok: true, code: 'ok', message: 'Ariava service logs.', data: { backend: 'systemd-user', source: 'journald', text: 'journal line\nnext' } },
      });
      const uninstall = await runHarness(home, scenario, 'uninstall');
      expect(uninstall).toMatchObject({ exitCode: 0, stdout: { ok: true }, stderr: undefined });
      expect(managerCalls(home).map((call) => call.operation)).toEqual([
        'install', 'status', 'status', 'start', 'status', 'stop', 'status', 'restart', 'logs', 'uninstall',
      ]);
    });

    test('unavailable WSL init returns exact stable guidance before config writes', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-wsl-init-'));
      roots.push(home);
      const result = await runHarness(home, 'wsl-unavailable', 'init');
      expect(result.exitCode).toBe(1);
      expect(result.stdout).toBeUndefined();
      expect(result.stderr).toEqual({
        ok: false,
        code: 'ERR_SYSTEMD_USER_UNAVAILABLE',
        message: 'Ariava requires an available systemd user manager on WSL.',
        data: {
          platform: 'linux',
          isWsl: true,
          backend: 'systemd-user',
          reason: 'systemd-user-manager-unavailable',
          instructions: { wslConfig: '[boot]\nsystemd=true', windowsCommand: 'wsl.exe --shutdown' },
        },
      });
      expect(existsSync(join(home, '.config', 'ariava', 'config.json'))).toBe(false);
    });

    test('unavailable WSL blocks every setup/write entrypoint before filesystem writes', async () => {
      for (const args of [['init'], ['service', 'install'], ['service', 'reinstall'], ['service', 'start']]) {
        const home = mkdtempSync(join(tmpdir(), 'ariava-cli-wsl-blocked-'));
        roots.push(home);
        const result = await runHarness(home, 'wsl-unavailable', ...args);
        expectStderrFailure(result, 'ERR_SYSTEMD_USER_UNAVAILABLE');
        expect(result.stderr.data.instructions).toEqual({ wslConfig: '[boot]\nsystemd=true', windowsCommand: 'wsl.exe --shutdown' });
        expect(existsSync(join(home, '.config', 'ariava'))).toBe(false);
        expect(managerCalls(home)).toEqual([]);
      }
    });

    test('native Linux unavailable omits WSL-only remediation', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-native-unavailable-'));
      roots.push(home);
      const result = await runHarness(home, 'native-user-manager-unavailable', 'service', 'install');
      expectStderrFailure(result, 'ERR_SYSTEMD_USER_UNAVAILABLE');
      expect(result.stderr.data).not.toHaveProperty('instructions');
      expect(JSON.stringify(result.stderr)).not.toMatch(/wsl\.exe|\[boot\]|systemd=true/i);
      expect(existsSync(join(home, '.config', 'ariava'))).toBe(false);
    });

    test('missing systemctl returns its stable error on stderr without writes', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-systemctl-missing-'));
      roots.push(home);
      const result = await runHarness(home, 'missing-systemctl', 'service', 'install');
      expectStderrFailure(result, 'ERR_SYSTEMCTL_NOT_FOUND');
      expect(existsSync(join(home, '.config', 'ariava'))).toBe(false);
    });

    test('unsupported status is nonthrowing and doctor is structured', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-unsupported-'));
      roots.push(home);
      const status = await runHarness(home, 'unsupported', 'status');
      expectStdoutSuccess(status);
      expect(status.stdout.data.service).toMatchObject({ supported: false, supportReason: 'unsupported-platform' });
      const doctor = await runHarness(home, 'unsupported', 'doctor');
      expectStdoutFailure(doctor, 'ERR_DOCTOR');
      expect(doctor.stdout.data).toMatchObject({
        platform: 'win32',
        isWsl: false,
        serviceSupported: false,
        serviceSupportReason: 'unsupported-platform',
      });
    });

    test('unhealthy human doctor stays on stdout with exit 1', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-doctor-human-'));
      roots.push(home);
      const isolated = createIsolatedPublicCliEnvironment(home);
      const proc = Bun.spawn({
        cmd: [bunPath, harnessPath, 'doctor'],
        cwd: process.cwd(),
        env: {
          ...isolated.env,
          HOME: home,
          ARIAVA_TEST_SCENARIO: 'linux-supported',
          ARIAVA_TEST_MANAGER_CALLS_PATH: retainedManagerCallsPath(home),
        },
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stdout, stderr] = await Promise.all([
        proc.exited,
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]);
      expect(exitCode).toBe(1);
      expect(stdout).toContain('configComplete: false');
      expect(stderr).toBe('');
    });

    test('unsupported platform rejects all service writes with structured stable errors', async () => {
      for (const command of ['install', 'reinstall', 'start', 'stop', 'restart', 'uninstall'] as const) {
        const home = mkdtempSync(join(tmpdir(), 'ariava-cli-unsupported-write-'));
        roots.push(home);
        const result = await runHarness(home, 'unsupported', 'service', command);
        expectStderrFailure(result, 'ERR_UNSUPPORTED_PLATFORM');
        expect(existsSync(join(home, '.config', 'ariava'))).toBe(false);
      }
    });

    test('doctor reports exact neutral fields without real command probes', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-doctor-'));
      roots.push(home);
      const doctor = await runHarness(home, 'linux-supported', 'doctor');
      expectStdoutFailure(doctor, 'ERR_DOCTOR');
      expect(doctor.stdout).toEqual({
        ok: false,
        code: 'ERR_DOCTOR',
        message: 'Ariava doctor found issues.',
        data: {
          platform: 'linux',
          isWsl: false,
          serviceBackend: 'systemd-user',
          serviceSupported: true,
          serviceSupportReason: 'supported',
          nodeFound: true,
          runtimeNameIsNode: true,
          runtimeVersionSupported: true,
          runtimePathMatchesCurrent: true,
          serviceRuntimeNameIsNode: null,
          serviceRuntimeVersionSupported: null,
          serviceRuntimeVersionMatchesRecorded: null,
          runtimeCryptoSelfTestPassed: true,
          piFound: false,
          configComplete: false,
          serviceInstalled: false,
          serviceEnabled: false,
          serviceLoaded: false,
          serviceRunning: false,
          servicePathCurrent: true,
          serviceRuntimeCurrent: true,
          serviceMetadataValid: true,
          installerMetadataValid: true,
          documentMetadataValid: true,
          logsAvailable: true,
          statePathParentExists: false,
          relayConfigured: true,
          identity: {
            status: 'not-initialized', storageType: 'linux-json',
            storageReference: { type: 'linux-json', path: join(home, '.config', 'ariava', 'host-identity.json') },
            path: join(home, '.config', 'ariava', 'host-identity.json'),
            ownerIntegrity: false, permissionIntegrity: false, metadataIntegrity: false, pendingRotation: false,
          } as any,
          identityReady: false,
          agentAdapterConfigPath: join(home, '.config', 'ariava', 'agent-adapter.json'),
          agentAdapterConfigPresent: false,
          piExtensionManaged: false,
          piExtensionInstalled: false,
          piExtensionNeedsUpgrade: false,
          environmentOverrides: [],
          bridgeSource: { kind: 'release-bundle' },
        },
      });
    });

    test('doctor ignores ambient Ariava configuration variables under the controlled harness environment', async () => {
      const ambient = {
        ARIAVA_RELAY_BASE_URL: process.env.ARIAVA_RELAY_BASE_URL,
        ARIAVA_HOST_ID: process.env.ARIAVA_HOST_ID,
        ARIAVA_HOST_NAME: process.env.ARIAVA_HOST_NAME,
        ARIAVA_AGENT_ADAPTER_PORT: process.env.ARIAVA_AGENT_ADAPTER_PORT,
      };
      Object.assign(process.env, {
        ARIAVA_RELAY_BASE_URL: 'https://ambient.invalid',
        ARIAVA_HOST_ID: 'ambient-host',
        ARIAVA_HOST_NAME: 'Ambient Host',
        ARIAVA_AGENT_ADAPTER_PORT: '9000',
      });
      try {
        const home = mkdtempSync(join(tmpdir(), 'ariava-cli-doctor-isolated-'));
        roots.push(home);
        const doctor = await runHarness(home, 'linux-supported', 'doctor');
        expectStdoutFailure(doctor, 'ERR_DOCTOR');
        expect(doctor.stdout.data.environmentOverrides).toEqual([]);
        expect(doctor.stdout.data.configComplete).toBe(false);
      } finally {
        for (const [name, value] of Object.entries(ambient)) {
          if (value === undefined) delete process.env[name];
          else process.env[name] = value;
        }
      }
    });

    test('missing journal capability is a doctor warning without changing service support', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-doctor-journal-'));
      roots.push(home);
      const doctor = await runHarness(home, 'missing-journal', 'doctor');
      expectStdoutFailure(doctor, 'ERR_DOCTOR');
      expect(doctor.stdout.data.logsAvailable).toBe(false);
      expect(doctor.stdout.data.serviceSupported).toBe(true);
      expect(doctor.stdout.data.serviceSupportReason).toBe('supported');
    });

    test('unavailable WSL doctor includes exact support instructions', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-doctor-wsl-'));
      roots.push(home);
      const doctor = await runHarness(home, 'wsl-unavailable', 'doctor');
      expectStdoutFailure(doctor, 'ERR_DOCTOR');
      expect(doctor.stdout.data).toEqual({
        platform: 'linux',
        isWsl: true,
        serviceBackend: 'systemd-user',
        serviceSupported: false,
        serviceSupportReason: 'systemd-user-manager-unavailable',
        serviceSupportInstructions: {
          wslConfig: '[boot]\nsystemd=true',
          windowsCommand: 'wsl.exe --shutdown',
        },
        nodeFound: true,
        runtimeNameIsNode: true,
        runtimeVersionSupported: true,
        runtimePathMatchesCurrent: true,
        serviceRuntimeNameIsNode: null,
        serviceRuntimeVersionSupported: null,
        serviceRuntimeVersionMatchesRecorded: null,
        runtimeCryptoSelfTestPassed: true,
        piFound: false,
        configComplete: false,
        serviceInstalled: false,
        serviceEnabled: false,
        serviceLoaded: false,
        serviceRunning: false,
        servicePathCurrent: true,
        serviceRuntimeCurrent: true,
        serviceMetadataValid: true,
        installerMetadataValid: true,
        documentMetadataValid: true,
        logsAvailable: false,
        statePathParentExists: false,
        relayConfigured: true,
        identity: {
          status: 'not-initialized', storageType: 'linux-json',
          storageReference: { type: 'linux-json', path: join(home, '.config', 'ariava', 'host-identity.json') },
          path: join(home, '.config', 'ariava', 'host-identity.json'),
          ownerIntegrity: false, permissionIntegrity: false, metadataIntegrity: false, pendingRotation: false,
        } as any,
        identityReady: false,
        agentAdapterConfigPath: join(home, '.config', 'ariava', 'agent-adapter.json'),
        agentAdapterConfigPresent: false,
        piExtensionManaged: false,
        piExtensionInstalled: false,
        piExtensionNeedsUpgrade: false,
        environmentOverrides: [],
        bridgeSource: { kind: 'release-bundle' },
      });
    });

    test('doctor fails runtime drift and recommends service reinstall', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-doctor-runtime-drift-'));
      roots.push(home);
      await runHarness(home, 'linux-supported', 'service', 'install');
      const doctor = await runHarness(home, 'service-runtime-downgrade', 'doctor');
      expectStdoutFailure(doctor, 'ERR_DOCTOR');
      expect(doctor.stdout.data).toMatchObject({
        serviceInstalled: true,
        serviceRuntimeNameIsNode: true,
        serviceRuntimeVersionSupported: false,
        serviceRuntimeVersionMatchesRecorded: false,
        serviceRuntimeCurrent: false,
        serviceReinstallRecommendation: 'Run `ariava service reinstall`.',
      });
    });

    test('service install persists neutral metadata only after success', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-service-install-'));
      roots.push(home);
      const successful = await runHarness(home, 'linux-supported', 'service', 'install');
      expectStdoutSuccess(successful);
      expect(successful.stdout.data).toEqual({
        backend: 'systemd-user',
        installedAt: '2026-07-15T00:00:00.000Z',
        runtimePath: '/fixture/node',
        runtimeName: 'node',
        runtimeVersion: 'v22.0.0',
        ariavaBinPath: '/fixture/ariava',
        configPath: join(home, '.config', 'ariava', 'config.json'),
        identityReference: { type: 'linux-json', path: join(home, '.config', 'ariava', 'host-identity.json') },
        definitionPath: '/fixture/home/.config/systemd/user/ariava.service',
        serviceId: 'ariava.service',
      });
      const stored = JSON.parse(readFileSync(join(home, '.config', 'ariava', 'install.json'), 'utf8'));
      expect(stored.service).toEqual(successful.stdout.data);
      expect(JSON.stringify(successful.stdout.data)).not.toMatch(/plistPath|nodePath|launchdLoaded/);
    });

    test('neutral install and host/service status never expose legacy launchd keys', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-neutral-contract-'));
      roots.push(home);
      const install = await runHarness(home, 'linux-supported', 'service', 'install');
      expectStdoutSuccess(install);
      for (const args of [['status'], ['service', 'status']] as const) {
        const result = await runHarness(home, 'linux-supported', ...args);
        expect(result).toMatchObject({ exitCode: 0, stdout: { ok: true }, stderr: undefined });
        if (args.length === 1) expect(result.stdout.data.service.runtimeCryptoSelfTestPassed).toBe(true);
        const serialized = JSON.stringify(result.stdout.data);
        expect(serialized).not.toMatch(/launchdLoaded|plistPath|nodePath/);
        expect(result.stdout.data).not.toHaveProperty('label');
      }
    });

    test('install failure preserves an old valid record', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-service-failure-'));
      roots.push(home);
      const installPath = join(home, '.config', 'ariava', 'install.json');
      const old = { backend: 'systemd-user', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava', definitionPath: '/old/unit', serviceId: 'ariava.service' };
      secureJsonFixture(installPath, { service: old });
      const result = await runHarness(home, 'install-failure', 'service', 'reinstall');
      expectStderrFailure(result, 'ERR_SERVICE_INSTALL');
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toEqual(old);
    });

    test('service status is neutral and lifecycle not-installed errors are stable', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-service-status-'));
      roots.push(home);
      const status = await runHarness(home, 'linux-supported', 'service', 'status');
      expectStdoutSuccess(status);
      expect(status.stdout.data).toMatchObject({
        backend: 'systemd-user',
        installed: false, enabled: false, loaded: false, processRunning: false,
        logBackend: 'journald',
      });
      expect(JSON.stringify(status.stdout.data)).not.toMatch(/plistPath|nodePath|launchdLoaded|stdoutLogPath|stderrLogPath/);
      for (const command of ['start', 'restart']) {
        const result = await runHarness(home, 'linux-supported', 'service', command);
        expectStderrFailure(result, 'ERR_SERVICE_NOT_INSTALLED');
        expect(result.stderr.data.advice).toBe('ariava service install');
      }
      expectStdoutSuccess(await runHarness(home, 'linux-supported', 'service', 'stop'));
      expectStdoutSuccess(await runHarness(home, 'linux-supported', 'service', 'uninstall'));
    });

    test('all support failures retain stable service codes', async () => {
      const cases = [
        ['unsupported', 'ERR_UNSUPPORTED_PLATFORM'],
        ['missing-systemctl', 'ERR_SYSTEMCTL_NOT_FOUND'],
        ['native-user-manager-unavailable', 'ERR_SYSTEMD_USER_UNAVAILABLE'],
        ['directory-unwritable', 'ERR_SERVICE_INSTALL'],
      ];
      for (const [scenario, code] of cases) {
        const home = mkdtempSync(join(tmpdir(), `ariava-cli-support-${scenario}-`));
        roots.push(home);
        const result = await runHarness(home, scenario, 'service', 'install');
        expectStderrFailure(result, code);
      }
    });

    test('repeated service install and uninstall are idempotent', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-idempotent-'));
      roots.push(home);
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const install = await runHarness(home, 'linux-supported', 'service', 'install');
        expectStdoutSuccess(install);
      }
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const uninstall = await runHarness(home, 'linux-supported', 'service', 'uninstall');
        expectStdoutSuccess(uninstall);
      }
      expect(managerCalls(home).map((call) => call.operation)).toEqual(['install', 'install', 'uninstall', 'uninstall']);
    });

    test('unknown commands retain the generic ERR_CLI envelope on stderr', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-unknown-'));
      roots.push(home);
      const result = await runHarness(home, 'linux-supported', 'definitely-unknown');
      expect(result).toEqual({
        exitCode: 1, stdout: undefined,
        stderr: { ok: false, code: 'ERR_CLI', message: 'Unknown command: definitely-unknown', data: {} },
      });
    });

    test('full upgrade performs package-manager self-upgrade and re-entry without reconciliation', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-upgrade-full-'));
      roots.push(home);
      const result = await runHarnessWithEnv(home, 'linux-supported', { ARIAVA_UPGRADE_PACKAGE_MANAGER: 'npm' }, 'upgrade');
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBeUndefined();
      expect(managerCalls(home)).toEqual([
        { operation: 'spawn', command: 'npm', args: ['install', '-g', 'ariava@latest'], reentry: false },
        { operation: 'spawn', command: '/fixture/ariava', args: ['upgrade', '--json'], reentry: true },
      ]);
    });

    test('upgrade does not install when no matching service is installed', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-upgrade-not-installed-'));
      roots.push(home);
      const result = await runHarnessWithEnv(home, 'linux-supported', { ARIAVA_UPGRADE_SELF_DONE: '1' }, 'upgrade');
      expectStdoutSuccess(result);
      expect(result.stdout.data.service).toEqual({
        updated: false, restarted: false, installed: false, reason: 'not-installed',
      });
      expect(managerCalls(home)).toEqual([{ operation: 'status' }]);
    });

    test('upgrade does not rewrite matching metadata when the backend reports not installed', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-upgrade-record-not-installed-'));
      roots.push(home);
      const old = {
        backend: 'systemd-user', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava',
        definitionPath: '/fixture/home/.config/systemd/user/ariava.service', serviceId: 'ariava.service',
      };
      const installPath = writeInstall(home, { service: old });
      const result = await runHarnessWithEnv(home, 'service-not-installed', { ARIAVA_UPGRADE_SELF_DONE: '1' }, 'upgrade');
      expectStdoutSuccess(result);
      expect(result.stdout.data.service).toEqual({
        updated: false, restarted: false, installed: false, reason: 'not-installed',
      });
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toEqual(old);
      expect(managerCalls(home)).toEqual([{ operation: 'status' }, { operation: 'status' }]);
    });

    test('upgrade install failure keeps old metadata and returns the stable install error', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-upgrade-install-failure-'));
      roots.push(home);
      const old = {
        backend: 'systemd-user', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava',
        definitionPath: '/fixture/home/.config/systemd/user/ariava.service', serviceId: 'ariava.service',
      };
      const installPath = writeInstall(home, { service: old });
      const result = await runHarnessWithEnv(home, 'install-failure', { ARIAVA_UPGRADE_SELF_DONE: '1' }, 'upgrade');
      expectStderrFailure(result, 'ERR_SERVICE_INSTALL');
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toEqual(old);
      expect(managerCalls(home)).toEqual([
        { operation: 'status' },
        { operation: 'install', runtimePath: '/fixture/node', ariavaBinPath: '/fixture/ariava',
          configPath: join(home, '.config', 'ariava', 'config.json'),
          identityReference: { type: 'linux-json', path: join(home, '.config', 'ariava', 'host-identity.json') } },
      ]);
    });

    test('upgrade backend mismatch preserves foreign metadata without lifecycle operations', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-upgrade-mismatch-'));
      roots.push(home);
      const foreign = {
        backend: 'launchd', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava',
        definitionPath: '/foreign/plist', serviceId: 'io.noyx.ariava.bridge',
      };
      const installPath = writeInstall(home, { service: foreign });
      const result = await runHarnessWithEnv(home, 'linux-supported', { ARIAVA_UPGRADE_SELF_DONE: '1' }, 'upgrade');
      expectStdoutSuccess(result);
      expect(result.stdout.data.service).toEqual({
        updated: false, restarted: false, installed: false, reason: 'backend-mismatch',
      });
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toEqual(foreign);
      const calls = managerCalls(home);
      expect(calls).toEqual([{ operation: 'status' }]);
      expect(calls.filter((call) => ['install', 'restart', 'uninstall'].includes(String(call.operation)))).toEqual([]);
    });

    test('upgrade rewrites an installed systemd service, persists its record, then restarts', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-upgrade-systemd-'));
      roots.push(home);
      const installPath = writeInstall(home, { service: {
        backend: 'systemd-user', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava',
        definitionPath: '/fixture/home/.config/systemd/user/ariava.service', serviceId: 'ariava.service',
      } });
      const result = await runHarnessWithEnv(home, 'linux-supported', { ARIAVA_UPGRADE_SELF_DONE: '1' }, 'upgrade');
      expectStdoutSuccess(result);
      expect(result.stdout.data.service).toEqual({ updated: true, restarted: true, installed: true });
      expect(managerCalls(home)).toEqual([
        { operation: 'status' },
        { operation: 'install', runtimePath: '/fixture/node', ariavaBinPath: '/fixture/ariava',
          configPath: join(home, '.config', 'ariava', 'config.json'),
          identityReference: { type: 'linux-json', path: join(home, '.config', 'ariava', 'host-identity.json') } },
        { operation: 'restart', metadataPersisted: true },
        { operation: 'status' },
      ]);
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toMatchObject({
        backend: 'systemd-user', runtimePath: '/fixture/node', ariavaBinPath: '/fixture/ariava',
      });
    });

    test('upgrade normalizes legacy launchd metadata and rewrites current absolute paths', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-upgrade-launchd-'));
      roots.push(home);
      const installPath = writeInstall(home, { service: {
        installedAt: 'old', nodePath: '/old/node', ariavaBinPath: '/old/ariava',
        plistPath: '/fixture/home/Library/LaunchAgents/io.noyx.ariava.bridge.plist', label: 'io.noyx.ariava.bridge',
      } });
      const result = await runHarnessWithEnv(home, 'launchd-supported', { ARIAVA_UPGRADE_SELF_DONE: '1' }, 'upgrade');
      expectStdoutSuccess(result);
      expect(result.stdout.data.service).toEqual({ updated: true, restarted: true, installed: true });
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toMatchObject({
        backend: 'launchd', runtimePath: '/fixture/node', ariavaBinPath: '/fixture/ariava',
      });
      expect(managerCalls(home).map((call) => call.operation)).toEqual(['status', 'install', 'restart', 'status']);
    });

    test('upgrade restart compatibility variables use neutral precedence and stay private', async () => {
      const cases = [
        [{ ARIAVA_UPGRADE_SKIP_SERVICE_RESTART: '1' }, true],
        [{ ARIAVA_UPGRADE_SKIP_LAUNCHCTL: '1' }, true],
        [{ ARIAVA_UPGRADE_SKIP_SERVICE_RESTART: '0', ARIAVA_UPGRADE_SKIP_LAUNCHCTL: '1' }, false],
        [{ ARIAVA_UPGRADE_SKIP_SERVICE_RESTART: '1', ARIAVA_UPGRADE_SKIP_LAUNCHCTL: '0' }, true],
      ] as const;
      for (const [environment, skipped] of cases) {
        const home = mkdtempSync(join(tmpdir(), 'ariava-cli-upgrade-skip-'));
        roots.push(home);
        writeInstall(home, { service: {
          backend: 'systemd-user', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava',
          definitionPath: '/fixture/home/.config/systemd/user/ariava.service', serviceId: 'ariava.service',
        } });
        const result = await runHarnessWithEnv(home, 'linux-supported', { ARIAVA_UPGRADE_SELF_DONE: '1', ...environment }, 'upgrade');
        expectStdoutSuccess(result);
        expect(result.stdout.data.service.reason).toBe(skipped ? 'service-restart-skipped' : undefined);
        expect(managerCalls(home).some((call) => call.operation === 'restart')).toBe(!skipped);
        expect(JSON.stringify(result.stdout)).not.toContain('ARIAVA_UPGRADE_SKIP_');
      }
    });

    test('upgrade preserves the new record and sanitizes a restart-only failure', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-upgrade-restart-failure-'));
      roots.push(home);
      const installPath = writeInstall(home, { service: {
        backend: 'systemd-user', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava',
        definitionPath: '/fixture/home/.config/systemd/user/ariava.service', serviceId: 'ariava.service',
      } });
      const result = await runHarnessWithEnv(home, 'restart-failure', { ARIAVA_UPGRADE_SELF_DONE: '1' }, 'upgrade');
      expectStdoutSuccess(result);
      expect(result.stdout.data.service).toMatchObject({ updated: true, restarted: false, installed: true, reason: 'restart-failed' });
      expect(result.stdout.data.service.detail).toBe('restart failed for <redacted>');
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service.runtimePath).toBe('/fixture/node');
      expect(managerCalls(home).find((call) => call.operation === 'restart')).toMatchObject({ metadataPersisted: true });
    });

    test('top-level uninstall performs adapter removal before metadata and pi cleanup', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-uninstall-order-'));
      roots.push(home);
      const managedPi = join(home, '.pi', 'agent', 'extensions', 'ariava-pi');
      mkdirSync(managedPi, { recursive: true });
      writeFileSync(join(managedPi, 'marker'), 'installed');
      const metadata = {
        service: { backend: 'systemd-user', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava', definitionPath: '/fixture/home/.config/systemd/user/ariava.service', serviceId: 'ariava.service' },
        piExtension: { installedAt: 'old', version: '1', managedPath: managedPi, source: { kind: 'release-bundle', updatedAt: 'old' } },
        piSource: { kind: 'release-bundle', updatedAt: 'old' },
      };
      const installPath = writeInstall(home, metadata);
      const failed = await runHarness(home, 'uninstall-failure', 'uninstall', '--purge');
      expectStderrFailure(failed, 'ERR_SERVICE_COMMAND');
      expect(JSON.parse(readFileSync(installPath, 'utf8'))).toEqual(metadata);
      expect(existsSync(managedPi)).toBe(true);

      const succeeded = await runHarness(home, 'linux-supported', 'uninstall', '--remove-pi');
      expectStdoutSuccess(succeeded);
      expect(succeeded.stdout.data).toEqual({ purge: false, removedPi: true });
      expect(managerCalls(home).at(-1)?.operation).toBe('uninstall');
      expect(existsSync(managedPi)).toBe(false);
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toBeUndefined();
    });

    test('top-level uninstall invokes the adapter even without service metadata', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-uninstall-absent-'));
      roots.push(home);
      const result = await runHarness(home, 'linux-supported', 'uninstall');
      expectStdoutSuccess(result);
      expect(managerCalls(home)).toEqual([{ operation: 'uninstall' }]);
    });

    test('explicit service reinstall replaces foreign metadata through the current adapter', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-reinstall-mismatch-'));
      roots.push(home);
      const installPath = writeInstall(home, { service: {
        backend: 'launchd', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava', definitionPath: '/foreign/plist', serviceId: 'io.noyx.ariava.bridge',
      } });
      const result = await runHarness(home, 'linux-supported', 'service', 'reinstall');
      expectStdoutSuccess(result);
      expect(managerCalls(home)).toEqual([{
        operation: 'install', runtimePath: '/fixture/node', ariavaBinPath: '/fixture/ariava',
        configPath: join(home, '.config', 'ariava', 'config.json'),
        identityReference: { type: 'linux-json', path: join(home, '.config', 'ariava', 'host-identity.json') },
      }]);
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service.backend).toBe('systemd-user');
    });

    test('top-level uninstall retains foreign metadata unless purge explicitly removes config', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-uninstall-mismatch-'));
      roots.push(home);
      const foreign = { backend: 'launchd', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava', definitionPath: '/foreign/plist', serviceId: 'io.noyx.ariava.bridge' };
      const installPath = writeInstall(home, { service: foreign });
      const retained = await runHarness(home, 'linux-supported', 'uninstall');
      expectStdoutSuccess(retained);
      expect(retained.stdout.data).toMatchObject({ backendMismatch: true });
      expect(managerCalls(home)).toEqual([]);
      expect(JSON.parse(readFileSync(installPath, 'utf8')).service).toEqual(foreign);

      const purged = await runHarness(home, 'linux-supported', 'uninstall', '--purge');
      expectStdoutSuccess(purged);
      expect(managerCalls(home)).toEqual([]);
      expect(existsSync(join(home, '.config', 'ariava'))).toBe(false);
    });

    test('manager calls remain observable after a successful config purge', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-uninstall-purge-call-log-'));
      roots.push(home);
      writeInstall(home, { service: {
        backend: 'systemd-user', installedAt: 'old', runtimePath: '/old/node', ariavaBinPath: '/old/ariava',
        definitionPath: '/fixture/home/.config/systemd/user/ariava.service', serviceId: 'ariava.service',
      } });
      const result = await runHarness(home, 'linux-supported', 'uninstall', '--purge');
      expectStdoutSuccess(result);
      expect(existsSync(join(home, '.config', 'ariava'))).toBe(false);
      expect(managerCalls(home)).toEqual([{ operation: 'uninstall' }]);
    });

    test('logs route through manager with stable backend contracts and escaped JSON', async () => {
      const linuxHome = mkdtempSync(join(tmpdir(), 'ariava-cli-logs-linux-'));
      const macHome = mkdtempSync(join(tmpdir(), 'ariava-cli-logs-mac-'));
      roots.push(linuxHome, macHome);
      const linux = await runHarness(linuxHome, 'linux-supported', 'logs');
      expectStdoutSuccess(linux);
      expect(linux.stdout.data).toEqual({ backend: 'systemd-user', source: 'journald', text: 'journal line\nnext' });
      expect(managerCalls(linuxHome)).toEqual([{ operation: 'logs' }]);
      const mac = await runHarness(macHome, 'launchd-supported', 'logs');
      expectStdoutSuccess(mac);
      expect(mac.stdout.data).toEqual({
        backend: 'launchd', source: 'files', stdoutPath: '/fixture/stdout.log', stderrPath: '/fixture/stderr.log', text: 'stdout\nstderr',
      });
    });

    test('logs retain stable unavailable and support errors', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-logs-errors-'));
      roots.push(home);
      const missing = await runHarness(home, 'logs-unavailable', 'logs');
      expectStderrFailure(missing, 'ERR_LOGS_UNAVAILABLE');
      const unsupported = await runHarness(home, 'unsupported', 'logs');
      expectStderrFailure(unsupported, 'ERR_UNSUPPORTED_PLATFORM');
    });

    test('invalid service metadata makes doctor unhealthy without data loss', async () => {
      const home = mkdtempSync(join(tmpdir(), 'ariava-cli-invalid-metadata-'));
      roots.push(home);
      const installPath = join(home, '.config', 'ariava', 'install.json');
      secureJsonFixture(installPath, {
        service: { backend: 'systemd-user' },
        bridgeSource: { kind: 'dev-repo', path: '/repo', updatedAt: 'now' },
        piSource: { kind: 'explicit-path', path: '/pi-source', updatedAt: 'now' },
        piExtension: {
          installedAt: 'now', version: '1.2.3', managedPath: '/managed/pi',
          source: { kind: 'explicit-path', path: '/pi-source', updatedAt: 'now' },
        },
      });
      const result = await runHarness(home, 'linux-supported', 'doctor');
      expectStdoutFailure(result, 'ERR_DOCTOR');
      expect(result.stdout.data.serviceMetadataValid).toBe(false);
      const retained = JSON.parse(readFileSync(installPath, 'utf8'));
      expect(retained.bridgeSource.kind).toBe('dev-repo');
      expect(retained.piSource).toMatchObject({ kind: 'explicit-path', path: '/pi-source' });
      expect(retained.piExtension).toMatchObject({ version: '1.2.3', managedPath: '/managed/pi' });
    });

    test('service lifecycle and upgrade fail closed on corrupt metadata without overwriting it', async () => {
      for (const argv of [
        ['service', 'install'],
        ['service', 'reinstall'],
        ['service', 'uninstall'],
        ['upgrade'],
      ]) {
        const home = mkdtempSync(join(tmpdir(), 'ariava-cli-corrupt-metadata-'));
        roots.push(home);
        const installPath = join(home, '.config', 'ariava', 'install.json');
        const raw = JSON.stringify({ service: { backend: 'systemd-user' }, bridgeSource: { kind: 'dev-repo', path: '/repo', updatedAt: 'now' } });
        secureJsonFixture(installPath, JSON.parse(raw));
        const persistedBefore = readFileSync(installPath, 'utf8');
        const result = argv[0] === 'upgrade'
          ? await runHarnessWithEnv(home, 'linux-supported', { ARIAVA_UPGRADE_SELF_DONE: '1' }, ...argv)
          : await runHarness(home, 'linux-supported', ...argv);
        expectStderrFailure(result, 'ERR_SERVICE_METADATA');
        expect(readFileSync(installPath, 'utf8')).toBe(persistedBefore);
        expect(managerCalls(home)).toEqual([]);
      }
    });
  });

});

describe('default lifecycle adapter structure', () => {
  test('keeps public-cli-app as a compatibility wrapper over the default adapter', () => {
    const wrapper = readFileSync(join(publicCoreRoot, 'apps', 'bridge', 'src', 'public-cli-app.ts'), 'utf8');
    const adapter = readFileSync(join(publicCoreRoot, 'apps', 'bridge', 'src', 'cli', 'lifecycle', 'default.ts'), 'utf8');

    expect(wrapper).toContain('runAriavaCli(argv, createDefaultCliApplicationContext(overrides, onboardingOverrides))');
    expect(wrapper).not.toContain('runDefaultCli');
    expect(wrapper).not.toContain('dispatchPublicCli');
    expect(wrapper).not.toContain('switch (command)');
    expect(adapter).toContain('createDefaultLifecycleAdapter');
    expect(adapter).toContain('runSetup');
    expect(adapter).toContain('runService');
    expect(adapter).toContain('runInternal');
  });
});
