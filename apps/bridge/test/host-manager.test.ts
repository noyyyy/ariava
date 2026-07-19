import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildHostManagerStatus,
  buildLaunchdServiceDefinition,
  getPiExtensionStatus,
  LaunchdServiceManager,
  resolveDevPiSource,
  installPiExtension,
  loadInstallMetadata,
  loadInstallMetadataDetailed,
  loadUserConfig,
  parseProgramArgumentsFromPlist,
  renderLaunchdPlist,
  saveInstallMetadata,
  saveUserConfig,
  isConfigComplete,
  resolveAriavaConfig,
  type ServiceStatus,
} from '../src/host-manager';
import type { BridgeConfig } from '../src/types';
import type { ResolvedAriavaConfig } from '../src/host-manager/config';
import type { PiExtensionStatus } from '../src/host-manager/pi-extension';
import type { HostServiceStatusInput } from '../src/host-manager/status';

const roots: string[] = [];
let homeOverride = '';

beforeEach(() => {
  homeOverride = join(tmpdir(), `ariava-test-home-${Date.now()}-${Math.random()}`);
  process.env.HOME = homeOverride;
  process.env.PI_CODING_AGENT_DIR = join(homeOverride, '.pi', 'agent');
  mkdirSync(homeOverride, { recursive: true });
  roots.push(homeOverride);
});

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe('host-manager helpers', () => {
  test('persists user config and install metadata', () => {
    const root = join(tmpdir(), `ariava-host-manager-${Date.now()}`);
    roots.push(root);
    const configPath = join(root, 'config.json');
    const installPath = join(root, 'install.json');

    saveUserConfig({ relayBaseUrl: 'http://127.0.0.1:8787', hostId: 'host-1' }, configPath);
    saveInstallMetadata({ bridgeSource: { kind: 'release-bundle', updatedAt: '2026-07-07T00:00:00Z' } }, installPath);

    expect(loadUserConfig(configPath)).toEqual({ relayBaseUrl: 'http://127.0.0.1:8787', hostId: 'host-1' });
    expect(loadInstallMetadata(installPath)).toEqual({ bridgeSource: { kind: 'release-bundle', updatedAt: '2026-07-07T00:00:00Z' } });
  });

  test('atomically preserves prior config when public identity metadata promotion fails', () => {
    const root = join(tmpdir(), `ariava-config-atomic-${Date.now()}`); roots.push(root);
    const configPath = join(root, 'config.json');
    const original = { relayBaseUrl: 'https://relay.test', identity: { keyId: 'old-key' } } as any;
    saveUserConfig(original, configPath);
    chmodSync(root, 0o500);
    try {
      expect(() => saveUserConfig({ ...original, identity: { keyId: 'new-key' } } as any, configPath)).toThrow();
    } finally {
      chmodSync(root, 0o700);
    }
    expect(loadUserConfig(configPath)).toEqual(original);
  });

  test('fails closed on dangling config and install metadata symlinks', () => {
    const root = join(tmpdir(), `ariava-host-manager-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const configPath = join(root, 'config.json');
    const installPath = join(root, 'install.json');
    symlinkSync(join(root, 'missing-config.json'), configPath);
    symlinkSync(join(root, 'missing-install.json'), installPath);
    expect(() => loadUserConfig(configPath)).toThrow();
    expect(() => loadInstallMetadata(installPath)).toThrow();
  });

  test('uses the canonical production relay when no override is configured', () => {
    const root = join(tmpdir(), `ariava-host-manager-${Date.now()}`);
    roots.push(root);
    const configPath = join(root, 'config.json');

    const resolved = resolveAriavaConfig({}, configPath);

    expect(resolved.relayBaseUrl).toBe('https://ariava-relay.noyx.io');
  });

  test('resolves persisted and environment agent adapter secrets', () => {
    const root = join(tmpdir(), `ariava-host-manager-${Date.now()}`);
    roots.push(root);
    const configPath = join(root, 'config.json');

    saveUserConfig({ agentAdapterSecret: 'persisted-secret' }, configPath);
    const fromConfig = resolveAriavaConfig({}, configPath);
    expect(fromConfig.agentAdapterSecret).toBe('persisted-secret');
    const previousRelay = process.env.ARIAVA_RELAY_BASE_URL;
    const previousIdentity = process.env.ARIAVA_HOST_IDENTITY_PATH;
    process.env.ARIAVA_RELAY_BASE_URL = 'https://transient.invalid';
    process.env.ARIAVA_HOST_IDENTITY_PATH = '/tmp/transient-identity.json';
    try {
      saveUserConfig({ relayBaseUrl: 'https://persisted.example', identityPath: '/tmp/persisted-identity.json' }, configPath);
      const persisted = resolveAriavaConfig({}, configPath, false);
      expect(persisted.relayBaseUrl).toBe('https://persisted.example');
      expect(persisted.identityPath).toBe('/tmp/persisted-identity.json');
      expect(persisted.environmentOverrides).toEqual([]);
    } finally {
      if (previousRelay === undefined) delete process.env.ARIAVA_RELAY_BASE_URL; else process.env.ARIAVA_RELAY_BASE_URL = previousRelay;
      if (previousIdentity === undefined) delete process.env.ARIAVA_HOST_IDENTITY_PATH; else process.env.ARIAVA_HOST_IDENTITY_PATH = previousIdentity;
    }

    process.env.ARIAVA_AGENT_ADAPTER_SECRET = 'env-secret';
    const fromEnv = resolveAriavaConfig({}, configPath);
    expect(fromEnv.agentAdapterSecret).toBe('env-secret');
    expect(fromEnv.environmentOverrides).toContain('ARIAVA_AGENT_ADAPTER_SECRET');
    delete process.env.ARIAVA_AGENT_ADAPTER_SECRET;
  });

  test('treats host config as complete without a relay token', () => {
    expect(isConfigComplete({
      relayBaseUrl: 'https://relay.example.test',
      hostName: 'Mac mini',
      identity: {
        identityVersion: 2, hostId: `host_${'A'.repeat(43)}`, keyId: `key_${'B'.repeat(43)}`,
        algorithm: 'Ed25519', publicKey: 'C'.repeat(43), publicKeyFingerprint: 'D'.repeat(43),
        createdAt: '2026-07-15T00:00:00.000Z',
        privateKeyStorage: { type: 'linux-json', path: join(homeOverride, '.config', 'ariava', 'host-identity.json') },
      },
      agentAdapterPort: 7272,
      agentAdapterConfigPath: join(homeOverride, '.config', 'ariava', 'agent-adapter.json'),
      statePath: join(homeOverride, '.config', 'ariava', 'state', 'bridge-state.json'),
      identityPath: join(homeOverride, '.config', 'ariava', 'host-identity.json'),
      configPath: join(homeOverride, '.config', 'ariava', 'config.json'),
      installPath: join(homeOverride, '.config', 'ariava', 'install.json'),
      logDir: join(homeOverride, '.config', 'ariava', 'logs'),
      stdoutLogPath: join(homeOverride, '.config', 'ariava', 'logs', 'bridge.stdout.log'),
      stderrLogPath: join(homeOverride, '.config', 'ariava', 'logs', 'bridge.stderr.log'),
      tmpDir: join(homeOverride, '.config', 'ariava', 'tmp'),
      environmentOverrides: [],
    })).toBe(true);
  });

  test('renders launchd plist with absolute program arguments', () => {
    const definition = buildLaunchdServiceDefinition('/opt/homebrew/bin/node', '/usr/local/bin/ariava');
    const plist = renderLaunchdPlist(definition);
    expect(plist).toContain('<string>/opt/homebrew/bin/node</string>');
    expect(plist).toContain('<string>/usr/local/bin/ariava</string>');
  });

  test('writes a launchd plist that can be parsed back', () => {
    const root = join(tmpdir(), `ariava-launchd-${Date.now()}`);
    roots.push(root);
    const definition = buildLaunchdServiceDefinition(
      '/opt/homebrew/bin/node',
      '/usr/local/bin/ariava',
      join(root, 'config.json'),
      { definitionPath: join(root, 'io.noyx.ariava.bridge.plist'), stdoutLogPath: join(root, 'bridge.stdout.log'), stderrLogPath: join(root, 'bridge.stderr.log') },
    );
    mkdirSync(join(definition.plistPath, '..'), { recursive: true });
    writeFileSync(definition.plistPath, renderLaunchdPlist(definition));
    expect(parseProgramArgumentsFromPlist(definition.plistPath)).toEqual([
      '/opt/homebrew/bin/node', '/usr/local/bin/ariava', 'internal', 'bridge-daemon',
      '--config', join(root, 'config.json'),
    ]);
  });

  test('launchd adapter ignores a foreign systemd record and its existing unit', () => {
    const root = join(tmpdir(), `ariava-foreign-systemd-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { recursive: true });
    const unitPath = join(root, 'ariava.service');
    writeFileSync(unitPath, '[Service]\nExecStart=/usr/bin/true\n');
    const foreignService = {
      backend: 'systemd-user' as const, installedAt: '2026-07-15T00:00:00Z', runtimePath: '/usr/bin/node',
      ariavaBinPath: '/usr/bin/ariava', definitionPath: unitPath, serviceId: 'ariava.service',
    };
    const manager = new LaunchdServiceManager({
      support: { platform: 'darwin', backend: 'launchd', supported: true, isWsl: false, reason: 'supported' },
      runner: { run: () => ({ status: 1, stdout: '', stderr: '' }) },
      uid: 501, serviceId: 'io.noyx.ariava.bridge', definitionPath: join(root, 'bridge.plist'),
      stdoutLogPath: join(root, 'stdout.log'), stderrLogPath: join(root, 'stderr.log'),
      fileSystem: { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync },
    });
    const status = manager.status(foreignService, '/usr/bin/node', '/usr/bin/ariava');
    expect(status).toMatchObject({ installed: false, detail: 'metadata backend systemd-user does not match launchd' });
    expect(status.runtimePath).toBeUndefined();
    expect(existsSync(unitPath)).toBe(true);
  });

  test('invalid service metadata diagnostics retain unrelated source metadata', () => {
    const root = join(tmpdir(), `ariava-invalid-metadata-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const installPath = join(root, 'install.json');
    const bridgeSource = { kind: 'dev-repo', path: '/repo', updatedAt: 'now' };
    const piSource = { kind: 'explicit-path', path: '/pi', updatedAt: 'now' };
    const piExtension = { installedAt: 'now', version: '1.2.3', managedPath: '/managed/pi', source: piSource };
    writeFileSync(installPath, JSON.stringify({ service: { backend: 'systemd-user' }, bridgeSource, piSource, piExtension }), { mode: 0o600 });

    const result = loadInstallMetadataDetailed(installPath);

    expect(result.diagnostics).toEqual({ serviceMetadataValid: false, serviceMetadataIssue: 'invalid-service-record' });
    expect(result.metadata).toEqual({ bridgeSource, piSource, piExtension });
    expect(JSON.parse(readFileSync(installPath, 'utf8'))).toMatchObject({ bridgeSource, piSource, piExtension });
  });

  test('installs managed pi extension metadata from a source directory', async () => {
    const root = join(tmpdir(), `ariava-pi-source-${Date.now()}`);
    roots.push(root);
    const source = join(root, 'source');
    const nested = join(source, 'src');
    mkdirSync(nested, { recursive: true });
    await Bun.write(join(nested, 'index.ts'), 'export default {}');
    await Bun.write(join(source, 'package.json'), JSON.stringify({ name: '@ariava/pi-extension', version: '0.1.2' }));

    const installPath = join(root, 'isolated-pi', 'extensions', 'ariava-pi');
    const record = installPiExtension({
      sourcePath: source,
      sourceKind: 'release-bundle',
      version: '0.1.2',
      force: true,
      installDependencies: false,
      installPath,
    });
    const status = getPiExtensionStatus('0.1.2', {
      settingsPath: join(root, 'isolated-pi', 'settings.json'),
      packagePath: installPath,
      legacyInstallPath: installPath,
      legacyMetadataPath: join(installPath, '.ariava-managed.json'),
    });

    expect(record.version).toBe('0.1.2');
    expect(record.managedPath).toBe(installPath);
    expect(JSON.parse(readFileSync(join(installPath, '.ariava-managed.json'), 'utf8')).version).toBe('0.1.2');
    expect(status.managed).toBe(true);
  });

  test('resolves default dev pi source to the built bundle', () => {
    const repoRoot = '/tmp/ariava-repo';
    expect(resolveDevPiSource(undefined, repoRoot)).toBe(join(repoRoot, 'extensions', 'pi', 'bundle'));
    expect(resolveDevPiSource('/tmp/custom-extension', repoRoot)).toBe('/tmp/custom-extension');
  });
});

describe('portable host-manager status', () => {
  test('serializes exactly the neutral service status core', () => {
    const statePath = join(homeOverride, 'missing-state.json');
    const config = {
      relayBaseUrl: 'https://relay.example.test',
      ownerUserId: 'owner-1',
      hostId: 'host-1',
      hostName: 'Linux host',
      agentAdapterPort: 7272,
      agentAdapterConfigPath: join(homeOverride, 'agent-adapter.json'),
      statePath,
      configPath: join(homeOverride, 'config.json'),
      installPath: join(homeOverride, 'install.json'),
      logDir: join(homeOverride, 'logs'),
      stdoutLogPath: join(homeOverride, 'logs', 'stdout.log'),
      stderrLogPath: join(homeOverride, 'logs', 'stderr.log'),
      tmpDir: join(homeOverride, 'tmp'),
      environmentOverrides: [],
    } satisfies ResolvedAriavaConfig;
    const bridgeConfig = {
      hostId: 'host-1',
      hostName: 'Linux host',
      ownerUserId: 'owner-1',
      relayBaseUrl: 'https://relay.example.test',
      statePath,
      identityPath: join(homeOverride, 'host-identity.json'),
      configPath: config.configPath,
      pollIntervalMs: 1000,
      bridgeVersion: '0.1.4',
      agentAdapter: { port: 7272, secret: 'secret', configPath: config.agentAdapterConfigPath },
    } satisfies BridgeConfig;
    const serviceStatus = {
      backend: 'systemd-user',
      support: {
        supported: true,
        reason: 'supported',
      },
      installed: true,
      enabled: true,
      loaded: true,
      processRunning: true,
      runtimePathMatchesCurrent: true,
      ariavaBinPathMatchesCurrent: false,
    } satisfies HostServiceStatusInput;
    const piStatus = {
      installed: true,
      installPath: '/home/test/.pi/ariava-pi',
      managed: true,
      managedMetadataPath: '/home/test/.pi/ariava-pi/.ariava-managed.json',
    } satisfies PiExtensionStatus;

    const status = buildHostManagerStatus({
      config,
      bridgeConfig,
      installMetadata: {},
      serviceStatus,
      piStatus,
      cliVersion: '0.1.4',
    });

    expect(status.service).toEqual({
      backend: 'systemd-user',
      supported: true,
      supportReason: 'supported',
      installed: true,
      enabled: true,
      loaded: true,
      processRunning: true,
      runtimePathMatchesCurrent: true,
      ariavaBinPathMatchesCurrent: false,
    });
    const serialized = JSON.parse(JSON.stringify(status));
    expect(serialized.service).not.toHaveProperty('launchdLoaded');
    expect(serialized.service).not.toHaveProperty('plistPath');
    expect(serialized.service).not.toHaveProperty('nodePath');
    expect(serialized.service).not.toHaveProperty('label');
  });

  test('accepts a neutral service status at the host status boundary', () => {
    const statePath = join(homeOverride, 'missing-state.json');
    const config = resolveAriavaConfig({
      relayBaseUrl: 'https://relay.example.test', ownerUserId: 'owner-1', hostId: 'host-1', hostName: 'Mac host', statePath,
    }, join(homeOverride, 'config.json'));
    const bridgeConfig = {
      hostId: config.hostId, hostName: config.hostName, ownerUserId: config.ownerUserId, relayBaseUrl: config.relayBaseUrl,
      statePath, identityPath: config.identityPath, configPath: config.configPath, pollIntervalMs: 1000, bridgeVersion: '0.1.4',
      agentAdapter: { port: 7272, secret: 'secret', configPath: config.agentAdapterConfigPath },
    } satisfies BridgeConfig;
    const portableInput: ServiceStatus = {
      backend: 'launchd',
      support: { platform: 'darwin', backend: 'launchd', supported: true, isWsl: false, reason: 'supported' },
      installed: false, enabled: false, loaded: false, processRunning: false, logBackend: 'files',
    };
    const status = buildHostManagerStatus({
      config, bridgeConfig, installMetadata: {}, serviceStatus: portableInput,
      piStatus: { installed: false, installPath: '/tmp/ariava-pi', managed: false, managedMetadataPath: '/tmp/ariava-pi/.ariava-managed.json' },
      cliVersion: '0.1.4',
    });
    expect(status.service).toEqual({
      backend: 'launchd', supported: true, supportReason: 'supported', installed: false, enabled: false, loaded: false, processRunning: false,
    });
  });
});
