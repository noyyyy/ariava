import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runPublicCli } from '../src/public-cli-app';
import { HostIdentityError, LinuxJsonHostIdentityStore, publicIdentityMetadata } from '../src/identity';
import type { ServiceManager } from '../src/host-manager';

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

describe('identity-safe public CLI', () => {
  test('init creates once, reuses identity, and rejects managed config fields', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-identity-cli-')); roots.push(root);
    const configPath = join(root, 'config.json'); const identityPath = join(root, 'identity.json');
    let config: any = {}; const out: string[] = []; const err: string[] = [];
    const deps = {
      createServiceManager: manager, stdout: { write: (x: string) => { out.push(x); return true; } } as any,
      stderr: { write: (x: string) => { err.push(x); return true; } } as any,
      loadUserConfig: () => config, saveUserConfig: (next: any) => { config = next; mkdirSync(root, { recursive: true }); Bun.write(configPath, JSON.stringify(next)); },
      resolveAriavaConfig: () => ({ ...config, relayBaseUrl: 'https://relay.test', hostName: 'Linux', agentAdapterPort: 7272,
        agentAdapterConfigPath: join(root, 'adapter.json'), statePath: join(root, 'state.json'), identityPath, configPath,
        installPath: join(root, 'install.json'), logDir: root, stdoutLogPath: '', stderrLogPath: '', tmpDir: root, environmentOverrides: [] }),
      createHostIdentityStore: (path: string) => new LinuxJsonHostIdentityStore(path), commandExists: () => false,
      currentRuntimePath: () => process.execPath, currentAriavaBinPath: () => process.execPath, pathExists: () => false,
      removePath: () => {}, loadInstallMetadata: () => ({}), loadInstallMetadataDetailed: () => ({ metadata: {}, diagnostics: { serviceMetadataValid: true } }),
      mergeInstallMetadata: () => ({}), saveInstallMetadata: () => {},
    } as any;
    expect(await runPublicCli(['init', '--json'], deps)).toBe(0);
    const first = config.identity.hostId;
    expect(await runPublicCli(['init', '--json'], deps)).toBe(0);
    expect(config.identity.hostId).toBe(first);
    expect(await runPublicCli(['config', 'set', 'hostId', 'manual', '--json'], deps)).toBe(1);
    expect(JSON.parse(err.at(-1)!).code).toBe('ERR_IDENTITY_MANAGED_CONFIG');
    expect(readFileSync(identityPath, 'utf8')).not.toContain('signer');
  });

  test.each([
    [['pair', 'ABCDEFGH'], '/v2/bridge/pair-watch'],
    [['watches', 'list'], '/v2/bridge/watches'],
    [['watches', 'remove', `watch_${'C'.repeat(43)}`], `/v2/bridge/watches/watch_${'C'.repeat(43)}`],
  ] as const)('public %s ensures metadata/enrollment before link API', async (argv, finalPath) => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-link-cli-')); roots.push(root);
    const identityPath = join(root, 'identity.json');
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    let config: any = { identity: publicIdentityMetadata(identity), hostName: 'Linux host' };
    const paths: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const request = new Request(input);
      const path = new URL(request.url).pathname; paths.push(path);
      if (path === '/v2/bridge/registration') return new Response('missing', { status: 404 });
      if (path === '/v2/bridge/enroll') return Response.json({ host: hostProjection(identity.hostId) });
      if (path === '/v2/bridge/watches') return Response.json({ watches: [] });
      if (path === '/v2/bridge/pair-watch') return Response.json({
        host: hostProjection(identity.hostId),
        watchDevice: { watchDeviceId: `watch_${'C'.repeat(43)}` },
      });
      return Response.json({ ok: true });
    }) as typeof fetch;
    const output: string[] = []; const errors: string[] = [];
    const code = await runPublicCli([...argv, '--json'], cliDeps(root, identityPath, () => config, (next) => { config = next; }, output, errors));
    expect(code, errors.join('')).toBe(0);
    expect(paths).toEqual(['/v2/bridge/registration', '/v2/bridge/enroll', finalPath]);
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
    expect(await runPublicCli(['doctor', '--json'], deps)).toBe(1);
    const result = JSON.parse(output[0]!);
    expect(result).toMatchObject({ ok: false, code: 'ERR_DOCTOR', data: {
      identityReady: false,
      identityWarning: 'Host key rotation is pending; recover it before normal operation.',
      identity: { status: 'rotation-pending', pendingRotation: true, pendingOperationId: 'op_pending' },
    } });
  });

  test('corrupt explicit reset enrolls the new identity and reports zero links with warning', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-reset-enroll-')); roots.push(root);
    const identityPath = join(root, 'identity.json');
    const original = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    await Bun.write(identityPath, '{bad json');
    let config: any = { identity: publicIdentityMetadata(original), hostName: 'Linux host' };
    const paths: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init); paths.push(new URL(request.url).pathname);
      const body = await request.json() as any;
      expect(body.hostId).not.toBe(original.hostId);
      return Response.json({ host: hostProjection(body.hostId) });
    }) as typeof fetch;
    const output: string[] = []; const errors: string[] = [];
    const code = await runPublicCli(['host', 'reset', '--confirm', '--json'], cliDeps(root, identityPath, () => config, (next) => { config = next; }, output, errors));
    expect(code, errors.join('')).toBe(0);
    expect(paths).toEqual(['/v2/bridge/enroll']);
    expect(JSON.parse(output[0]!).data).toMatchObject({ hostId: config.identity.hostId, links: [], revokedOldIdentity: false });
    expect(JSON.parse(output[0]!).data.warning).toContain('ERR_IDENTITY_INVALID');
  });
});

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
