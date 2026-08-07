import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runPublicCli } from '../src/public-cli-app';
import { HostIdentityError, LinuxJsonHostIdentityStore, publicIdentityMetadata } from '../src/identity';
import type { ServiceManager } from '../src/host-manager';
import { createDefaultProfile } from '../src/cli/profiles/default';

const roots: string[] = [];
const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  roots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true }));
});

function manager(): ServiceManager {
  const support = { platform: 'linux' as const, backend: 'systemd-user' as const, supported: true, isWsl: false, reason: 'supported' as const };
  return { backend: 'systemd-user', support, install() { throw new Error('unused'); }, uninstall() {}, start() {}, stop() {}, restart() {},
    status: () => ({ backend: 'systemd-user', support, installed: false, enabled: false, loaded: false, processRunning: false, logBackend: 'journald' }),
    logsAvailable: () => true, logs: () => ({ backend: 'systemd-user', source: 'journald', text: '' }) };
}

function withProfileHome<T>(home: string, run: () => T): T {
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = home;
  try {
    return run();
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousXdg;
  }
}

describe('identity-safe public CLI', () => {
  test('init creates once, reuses identity, and rejects managed config fields', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-identity-cli-')); roots.push(root);
    const configPath = join(root, 'config.json'); const identityPath = join(root, 'identity.json');
    let config: any = { identityPath }; const out: string[] = []; const err: string[] = [];
    const deps = {
      createServiceManager: manager, stdout: { write: (x: string) => { out.push(x); return true; } } as any,
      stderr: { write: (x: string) => { err.push(x); return true; } } as any,
      loadUserConfig: () => config, saveUserConfig: (next: any) => { config = next; mkdirSync(root, { recursive: true }); writeFileSync(configPath, JSON.stringify(next)); },
      resolveAriavaConfig: () => ({ ...config, relayBaseUrl: 'https://relay.test', hostName: 'Linux', agentAdapterPort: 7272,
        agentAdapterConfigPath: join(root, 'adapter.json'), statePath: join(root, 'state.json'), identityPath, configPath,
        installPath: join(root, 'install.json'), logDir: root, stdoutLogPath: '', stderrLogPath: '', tmpDir: root, environmentOverrides: [] }),
      createHostIdentityStore: (path: string) => new LinuxJsonHostIdentityStore(path), commandExists: () => false,
      createProfile: () => withProfileHome(root, createDefaultProfile),
      currentRuntimePath: () => process.execPath, currentAriavaBinPath: () => process.execPath, pathExists: () => false,
      removePath: () => {}, loadInstallMetadata: () => ({}), loadInstallMetadataDetailed: () => ({ metadata: {}, diagnostics: { serviceMetadataValid: true } }),
      mergeInstallMetadata: () => ({}), saveInstallMetadata: () => {},
    } as any;
    expect(await runPublicCli(['init', '--json'], deps), err.join('')).toBe(0);
    const first = config.identity.hostId;
    expect(await runPublicCli(['init', '--json'], deps)).toBe(0);
    expect(config.identity.hostId).toBe(first);
    expect(await runPublicCli(['config', 'set', 'hostId', 'manual', '--json'], deps)).toBe(1);
    expect(JSON.parse(err.at(-1)!).code).toBe('ERR_IDENTITY_MANAGED_CONFIG');
    expect(readFileSync(identityPath, 'utf8')).not.toContain('signer');
  });

  test('unconfirmed production reset fails before config, identity, Relay, or service effects', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-unconfirmed-reset-')); roots.push(root);
    const output: string[] = [];
    const errors: string[] = [];
    const deps = cliDeps(root, join(root, 'identity.json'), () => { throw new Error('config read'); }, () => { throw new Error('config write'); }, output, errors);
    let identityCalls = 0;
    let serviceCalls = 0;
    let relayCalls = 0;
    deps.createHostIdentityStore = () => { identityCalls += 1; throw new Error('identity access'); };
    deps.createServiceManager = () => { serviceCalls += 1; throw new Error('service access'); };
    globalThis.fetch = (async () => { relayCalls += 1; throw new Error('relay access'); }) as typeof fetch;

    expect(await runPublicCli(['host', 'reset', '--json'], deps)).toBe(1);
    expect(JSON.parse(errors[0]!)).toMatchObject({ code: 'ERR_CONFIRMATION_REQUIRED' });
    expect(identityCalls).toBe(0);
    expect(serviceCalls).toBe(0);
    expect(relayCalls).toBe(0);
    expect(output).toEqual([]);
  });

  test('identity status delegates to the shared default inspection operation', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-identity-status-')); roots.push(root);
    const identityPath = join(root, 'identity.json');
    const store = new LinuxJsonHostIdentityStore(identityPath);
    const identity = await store.createFirstRun();
    const config: any = { identity: publicIdentityMetadata(identity), identityPath };
    const output: string[] = [];
    const errors: string[] = [];
    const deps = cliDeps(root, identityPath, () => config, () => {}, output, errors);
    deps.createProfile = () => withProfileHome(root, createDefaultProfile);

    expect(await runPublicCli(['identity', 'status', '--json'], deps)).toBe(0);
    expect(JSON.parse(output[0]!)).toMatchObject({
      ok: true,
      data: { status: 'ready', path: identityPath, hostId: identity.hostId },
    });
  });

  test.each([false, true])('production pair cancellation preserves stable %s JSON output and redacts pair failures', async (json) => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-pair-cancel-')); roots.push(home);
    const profile = withProfileHome(home, createDefaultProfile);
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    const identityPath = profile.resources.identityMetadataPath;
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const secret = 'adapter-secret-sensitive';
    const account = 'keychain-account-sensitive';
    const selectedIdentity = {
      ...identity,
      privateKeyStorage: { type: 'macos-keychain' as const, service: 'test.service', account },
    };
    const config: any = {
      identity: publicIdentityMetadata(identity),
      identityPath,
      agentAdapterSecret: secret,
      hostName: 'Linux host',
    };
    const output: string[] = [];
    const errors: string[] = [];
    const deps = cliDeps(home, identityPath, () => config, () => {}, output, errors);
    deps.createProfile = () => profile;
    deps.createHostIdentityStore = () => ({ load: async () => selectedIdentity } as any);
    deps.createPairDependencies = () => ({
      bridgeVersion: '1.0.0',
      normalizePairingCode: (value: string) => value.toUpperCase(),
      enroll: async () => {},
      createRelay: () => ({}),
      pairWatch: async () => pairResponse(identity.hostId),
      createKeyring: () => ({}),
      createHostBinding: async () => ({}),
      activate: async (input: any) => {
        input.write('Safety Code:  123-456');
        return 'cancelled';
      },
    });

    expect(await runPublicCli(['pair', 'peyx7k', ...(json ? ['--json'] : [])], deps)).toBe(1);
    const rendered = errors.join('');
    if (json) {
      expect(JSON.parse(rendered)).toEqual({
        ok: false,
        code: 'ERR_PAIR_CANCELLED',
        message: 'Safety Code confirmation cancelled.',
        data: {},
      });
      expect(output).toEqual([]);
    } else {
      expect(rendered).toBe('ariava: Safety Code confirmation cancelled.\n');
      expect(output.join('')).toContain(
        `Pairing code accepted for watch watch_${'C'.repeat(43)} with host Linux host (${identity.hostId}). Pairing completes after Safety Code confirmation.\n`,
      );
    }
    expect(rendered).not.toContain('peyx7k');
    expect(rendered).not.toContain('PEYX7K');
    expect(rendered).not.toContain('123-456');
    expect(rendered).not.toContain(secret);
    expect(rendered).not.toContain(account);
  });

  test('generic pair failures redact pairing, Safety Code, Adapter, and Keychain account material', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-pair-redact-')); roots.push(home);
    const profile = withProfileHome(home, createDefaultProfile);
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    const identityPath = profile.resources.identityMetadataPath;
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const secret = 'adapter-secret-sensitive';
    const account = 'keychain-account-sensitive';
    const selectedIdentity = {
      ...identity,
      privateKeyStorage: { type: 'macos-keychain' as const, service: 'test.service', account },
    };
    const config: any = { identity: publicIdentityMetadata(identity), identityPath, agentAdapterSecret: secret };
    const output: string[] = [];
    const errors: string[] = [];
    const deps = cliDeps(home, identityPath, () => config, () => {}, output, errors);
    deps.createProfile = () => profile;
    deps.createHostIdentityStore = () => ({ load: async () => selectedIdentity } as any);
    deps.createPairDependencies = () => ({
      bridgeVersion: '1.0.0',
      normalizePairingCode: (value: string) => value.toUpperCase(),
      enroll: async () => {
        throw new Error(`pair PEYX7K Safety Code: 123-456 privateKey: PRIVATE-KEY-MATERIAL secret ${secret} account ${account}`);
      },
      createRelay: () => ({}),
      pairWatch: async () => pairResponse(identity.hostId),
      createKeyring: () => ({}),
      createHostBinding: async () => ({}),
      activate: async () => 'activated',
    });

    expect(await runPublicCli(['pair', 'peyx7k', '--json'], deps)).toBe(1);
    const rendered = errors.join('');
    expect(JSON.parse(rendered)).toMatchObject({ code: 'ERR_CLI' });
    expect(rendered).not.toContain('PEYX7K');
    expect(rendered).not.toContain('123-456');
    expect(rendered).not.toContain('PRIVATE-KEY-MATERIAL');
    expect(rendered).not.toContain(secret);
    expect(rendered).not.toContain(account);
  });

  test.each([
    [['pair', 'peyx7k'], '/v2/bridge/pair-watch'],
    [['watches', 'list'], '/v2/bridge/watches'],
    [['watches', 'remove', `watch_${'C'.repeat(43)}`], `/v2/bridge/watches/watch_${'C'.repeat(43)}`],
  ] as const)('public %s ensures metadata/enrollment before link API', async (argv, finalPath) => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-link-cli-')); roots.push(root);
    const profile = withProfileHome(root, createDefaultProfile);
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    const identityPath = profile.resources.identityMetadataPath;
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    let config: any = { identity: publicIdentityMetadata(identity), identityPath, hostName: 'Linux host' };
    const paths: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const path = new URL(request.url).pathname; paths.push(path);
      if (path === '/v2/bridge/enroll') return Response.json({ host: hostProjection(identity.hostId) });
      if (path === '/v2/bridge/watches') return Response.json({ watches: [] });
      if (path === '/v2/bridge/pair-watch') {
        expect(await request.json()).toEqual({ pairingCode: 'PEYX7K' });
        const now = new Date().toISOString();
        const watchDeviceId = `watch_${'C'.repeat(43)}`;
        return Response.json({
          host: hostProjection(identity.hostId),
          watchDevice: {
            watchDeviceId,
            selectedHostIds: [identity.hostId],
            registeredAt: now,
            lastSeenAt: now,
            pairingStatus: 'paired',
          },
          link: {
            hostId: identity.hostId,
            watchDeviceId,
            pairedAt: now,
            generation: 1,
            updatedAt: now,
          },
          alreadyPaired: false,
        });
      }
      return Response.json({ ok: true });
    }) as typeof fetch;
    const output: string[] = []; const errors: string[] = [];
    const deps = cliDeps(root, identityPath, () => config, (next) => { config = next; }, output, errors);
    deps.createProfile = () => profile;
    const code = await runPublicCli([...argv, '--json'], deps);
    expect(code, errors.join('')).toBe(0);
    expect(paths).toEqual(['/v2/bridge/enroll', finalPath]);
  });

  test('rejects invalid pair codes before identity loading, enrollment, or Relay requests', async () => {
    for (const pairingCode of ['ABCDEFGH', 'ABCD-EFGH', ' PEYX7K', 'PEYX7K ']) {
      const root = mkdtempSync(join(tmpdir(), 'ariava-invalid-pair-cli-')); roots.push(root);
      const output: string[] = []; const errors: string[] = [];
      let storeCalls = 0; let fetchCalls = 0;
      globalThis.fetch = (async () => { fetchCalls += 1; return Response.json({ ok: true }); }) as typeof fetch;
      const deps = cliDeps(root, join(root, 'identity.json'), () => ({}), () => {}, output, errors);
      deps.createHostIdentityStore = () => { storeCalls += 1; throw new Error('identity should not load'); };

      expect(await runPublicCli(['pair', pairingCode, '--json'], deps)).toBe(1);
      expect(JSON.parse(errors[0]!).message).toContain('exactly 6 Crockford symbols');
      expect(storeCalls).toBe(0);
      expect(fetchCalls).toBe(0);
    }
  });

  test('rejects invalid pair codes before identity loading, enrollment, or Relay requests', async () => {
    for (const pairingCode of ['ABCDEFGH', 'ABCD-EFGH', ' PEYX7K', 'PEYX7K ']) {
      const root = mkdtempSync(join(tmpdir(), 'ariava-invalid-pair-cli-')); roots.push(root);
      const output: string[] = []; const errors: string[] = [];
      let storeCalls = 0; let fetchCalls = 0;
      globalThis.fetch = (async () => { fetchCalls += 1; return Response.json({ ok: true }); }) as typeof fetch;
      const deps = cliDeps(root, join(root, 'identity.json'), () => ({}), () => {}, output, errors);
      deps.createHostIdentityStore = () => { storeCalls += 1; throw new Error('identity should not load'); };

      expect(await runPublicCli(['pair', pairingCode, '--json'], deps)).toBe(1);
      expect(JSON.parse(errors[0]!).message).toContain('exactly 6 Crockford symbols');
      expect(storeCalls).toBe(0);
      expect(fetchCalls).toBe(0);
    }
  });

  test('preserves typed HostIdentityError code in CLI errors', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-typed-error-')); roots.push(root);
    const output: string[] = []; const errors: string[] = [];
    const deps = cliDeps(root, join(root, 'identity.json'), () => ({}), () => {}, output, errors);
    deps.createHostIdentityStore = () => ({ load: async () => { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'unsafe identity permissions'); } } as any);
    expect(await runPublicCli(['watches', 'list', '--json'], deps)).toBe(1);
    expect(JSON.parse(errors[0]!)).toMatchObject({ code: 'ERR_IDENTITY_PERMISSIONS', message: 'unsafe identity permissions' });
  });

  test('doctor treats pending rotation as warning and non-ready', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-doctor-pending-')); roots.push(root);
    const identityPath = join(root, 'identity.json');
    const store = new LinuxJsonHostIdentityStore(identityPath);
    const identity = await store.createFirstRun();
    const { generateHostRotationIdentity } = await import('../src/identity');
    const next = await generateHostRotationIdentity(identity.hostId, identity.privateKeyStorage);
    await store.stageRotation({ operationId: 'op_pending', issuedAt: new Date().toISOString(), identity: next.identity });
    const config: any = { identity: publicIdentityMetadata(identity), hostName: 'Linux host' };
    const output: string[] = []; const errors: string[] = [];
    const deps = cliDeps(root, identityPath, () => config, () => {}, output, errors);
    const profile = withProfileHome(root, createDefaultProfile);
    deps.createProfile = () => profile;
    deps.resolveAriavaConfig = () => ({
      ...config,
      relayBaseUrl: 'https://relay.test',
      hostName: 'Linux host',
      agentAdapterPort: profile.resources.agentAdapterPort,
      agentAdapterConfigPath: profile.resources.agentAdapterConfigPath,
      statePath: profile.resources.statePath,
      identityPath,
      configPath: profile.resources.configPath,
      installPath: join(profile.resources.root, 'install.json'),
      logDir: join(profile.resources.root, 'logs'),
      stdoutLogPath: join(profile.resources.root, 'logs', 'bridge.stdout.log'),
      stderrLogPath: join(profile.resources.root, 'logs', 'bridge.stderr.log'),
      tmpDir: join(profile.resources.root, 'tmp'),
      environmentOverrides: [],
    });
    expect(await runPublicCli(['doctor', '--json'], deps)).toBe(1);
    const result = JSON.parse(output[0]!);
    expect(result).toMatchObject({ ok: false, code: 'ERR_DOCTOR', data: {
      identityReady: false,
      identityWarning: 'Host key rotation is pending; recover it before normal operation.',
      identity: { status: 'rotation-pending', pendingRotation: true, pendingOperationId: 'op_pending' },
    } });
  });

  test('corrupt explicit reset enrolls the new identity and reports zero links with warning', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ariava-reset-enroll-')); roots.push(home);
    const profile = withProfileHome(home, createDefaultProfile);
    const root = profile.resources.root;
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const identityPath = profile.resources.identityMetadataPath;
    const original = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    await Bun.write(identityPath, '{bad json');
    let config: any = { identity: publicIdentityMetadata(original), identityPath, hostName: 'Linux host' };
    const paths: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init); paths.push(new URL(request.url).pathname);
      const body = await request.json() as any;
      expect(body.hostId).not.toBe(original.hostId);
      return Response.json({ host: hostProjection(body.hostId) });
    }) as typeof fetch;
    const output: string[] = []; const errors: string[] = [];
    const deps = cliDeps(root, identityPath, () => config, (next) => { config = next; }, output, errors);
    deps.createProfile = () => profile;
    const code = await runPublicCli(['host', 'reset', '--confirm', '--json'], deps);
    expect(code, errors.join('')).toBe(0);
    expect(paths).toEqual(['/v2/bridge/enroll']);
    expect(JSON.parse(output[0]!).data).toMatchObject({ hostId: config.identity.hostId, links: [], revokedOldIdentity: false });
    expect(JSON.parse(output[0]!).data.warning).toContain('ERR_IDENTITY_INVALID');
  });
});

function pairResponse(hostId: string) {
  const now = new Date().toISOString();
  const watchDeviceId = `watch_${'C'.repeat(43)}`;
  return {
    host: hostProjection(hostId),
    watchDevice: {
      watchDeviceId,
      selectedHostIds: [hostId],
      registeredAt: now,
      lastSeenAt: now,
      pairingStatus: 'paired' as const,
    },
    link: { hostId, watchDeviceId, pairedAt: now, generation: 1, updatedAt: now },
    alreadyPaired: false,
  };
}

function hostProjection(hostId: string) {
  return { hostId, hostName: 'Linux host', platform: 'linux', bridgeVersion: '1.0.0', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' };
}

function cliDeps(root: string, identityPath: string, loadConfig: () => any, saveConfig: (next: any) => void, out: string[], err: string[]) {
  return {
    createServiceManager: manager,
    stdout: { write: (x: string) => { out.push(x); return true; } } as any,
    stderr: { write: (x: string) => { err.push(x); return true; } } as any,
    loadUserConfig: loadConfig, saveUserConfig: saveConfig,
    resolveAriavaConfig: () => ({ ...loadConfig(), relayBaseUrl: 'https://relay.test', hostName: 'Linux host', agentAdapterPort: 7272,
      agentAdapterConfigPath: join(root, 'adapter.json'), statePath: join(root, 'state.json'), identityPath, configPath: join(root, 'config.json'),
      installPath: join(root, 'install.json'), logDir: root, stdoutLogPath: '', stderrLogPath: '', tmpDir: root, environmentOverrides: [] }),
    createHostIdentityStore: (path: string) => new LinuxJsonHostIdentityStore(path), commandExists: () => false,
    currentRuntimePath: () => process.execPath, currentAriavaBinPath: () => process.execPath, pathExists: () => false, removePath: () => {},
    loadInstallMetadata: () => ({}), loadInstallMetadataDetailed: () => ({ metadata: {}, diagnostics: { serviceMetadataValid: true } }),
    mergeInstallMetadata: () => ({}), saveInstallMetadata: () => {},
  } as any;
}
