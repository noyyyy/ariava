import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { LinuxJsonHostIdentityStore } from '../src/identity/linux-json-store';
import { readSecureJson, writeSecureJson } from '../src/host-manager/secure-files';

if (process.platform !== 'linux') {
  throw new Error(`host-runtime.linux.test.ts requires Linux, received ${process.platform}`);
}

const publicCoreRoot = join(import.meta.dir, '..', '..', '..');
const bunPath = process.execPath;
const roots: string[] = [];

function temporaryRoot(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(root, 0o700);
  roots.push(root);
  return root;
}

function isolatedRuntime(home: string, cwd: string): { env: Record<string, string>; cwd: string } {
  const xdgConfigHome = join(home, 'xdg-config');
  const npmPrefix = join(home, 'npm-prefix');
  const bin = join(npmPrefix, 'bin');
  mkdirSync(cwd, { recursive: true, mode: 0o700 });
  mkdirSync(bin, { recursive: true, mode: 0o700 });
  return {
    cwd,
    env: {
      HOME: home,
      XDG_CONFIG_HOME: xdgConfigHome,
      XDG_RUNTIME_DIR: join(home, 'xdg-runtime'),
      npm_config_prefix: npmPrefix,
      NPM_CONFIG_PREFIX: npmPrefix,
      NPM_CONFIG_USERCONFIG: join(home, 'npm-config', 'user.npmrc'),
      NPM_CONFIG_GLOBALCONFIG: join(home, 'npm-config', 'global.npmrc'),
      PI_CODING_AGENT_DIR: join(home, '.pi', 'agent'),
      PATH: `${bin}${delimiter}${process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin'}`,
      BUN_RUNTIME_TRANSPILER_CACHE_PATH: '',
    },
  };
}

async function spawnText(cmd: string[], options: { cwd: string; env: Record<string, string> }) {
  const proc = Bun.spawn({ cmd, cwd: options.cwd, env: options.env, stdout: 'pipe', stderr: 'pipe' });
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('Linux host runtime smoke', () => {
  test('uses native owner, mode, symlink, and atomic secure-file behavior', () => {
    const home = temporaryRoot('ariava-linux-files-');
    const path = join(home, 'state', 'runtime.json');
    writeSecureJson(path, { generation: 1 });

    const directoryStats = lstatSync(join(path, '..'));
    const fileStats = lstatSync(path);
    expect(directoryStats.mode & 0o777).toBe(0o700);
    expect(fileStats.mode & 0o777).toBe(0o600);
    if (process.getuid) {
      expect(directoryStats.uid).toBe(process.getuid());
      expect(fileStats.uid).toBe(process.getuid());
    }

    writeSecureJson(path, { generation: 2 });
    expect(readSecureJson(path)).toEqual({ generation: 2 });
    expect(readFileSync(path, 'utf8')).toEndWith('\n');

    const link = join(home, 'runtime-link.json');
    symlinkSync(path, link);
    expect(() => readSecureJson(link)).toThrow();
  });

  test('persists and reloads Linux JSON identity material in the disposable home', async () => {
    const home = temporaryRoot('ariava-linux-identity-');
    const identityPath = join(home, 'xdg-config', 'ariava', 'host-identity.json');
    const store = new LinuxJsonHostIdentityStore(identityPath);
    const created = await store.createFirstRun();

    const stats = lstatSync(identityPath);
    expect(stats.mode & 0o777).toBe(0o600);
    if (process.getuid) expect(stats.uid).toBe(process.getuid());
    expect(await store.load()).toMatchObject({
      hostId: created.hostId,
      keyId: created.keyId,
      privateKeyStorage: { type: 'linux-json', path: identityPath },
    });
    expect(await store.inspect()).toMatchObject({
      status: 'ready',
      storageType: 'linux-json',
      ownerIntegrity: true,
      permissionIntegrity: true,
      metadataIntegrity: true,
    });
  });

  test('resolves Linux host paths and imports the CLI from an unrelated disposable cwd', async () => {
    const home = temporaryRoot('ariava-linux-paths-');
    const runtime = isolatedRuntime(home, join(home, 'unrelated-cwd'));
    const pathsUrl = pathToFileURL(join(publicCoreRoot, 'apps', 'bridge', 'src', 'host-manager', 'paths.ts')).href;
    const paths = await spawnText([
      bunPath,
      '-e',
      `const paths = await import(${JSON.stringify(pathsUrl)}); console.log(JSON.stringify({ configRoot: paths.ARIAVA_CONFIG_ROOT, identityPath: paths.ARIAVA_HOST_IDENTITY_PATH, unitPath: paths.ARIAVA_SYSTEMD_UNIT_PATH, piPath: paths.ARIAVA_PI_EXTENSION_DIR, npmPrefix: process.env.npm_config_prefix }));`,
    ], runtime);
    expect(paths.exitCode, paths.stderr).toBe(0);
    expect(JSON.parse(paths.stdout)).toEqual({
      configRoot: join(home, 'xdg-config', 'ariava'),
      identityPath: join(home, 'xdg-config', 'ariava', 'host-identity.json'),
      unitPath: join(home, '.config', 'systemd', 'user', 'ariava.service'),
      piPath: join(home, '.pi', 'agent', 'extensions', 'ariava-pi'),
      npmPrefix: join(home, 'npm-prefix'),
    });

    const cli = await spawnText([
      bunPath,
      join(publicCoreRoot, 'apps', 'bridge', 'src', 'public-cli.ts'),
      'help',
      '--json',
    ], runtime);
    expect(cli.exitCode, cli.stderr).toBe(0);
    expect(JSON.parse(cli.stdout)).toMatchObject({ ok: true, code: 'ok', message: 'Ariava CLI' });
    expect(existsSync(join(home, '.config', 'systemd', 'user'))).toBe(false);
  });

  test('reports the actual read-only systemctl capability probe without requiring a user bus', async () => {
    const home = temporaryRoot('ariava-linux-systemctl-');
    const runtime = isolatedRuntime(home, join(home, 'probe-cwd'));
    const serviceUrl = pathToFileURL(join(publicCoreRoot, 'apps', 'bridge', 'src', 'host-manager', 'service', 'index.ts')).href;
    const probe = await spawnText([
      bunPath,
      '-e',
      `const service = await import(${JSON.stringify(serviceUrl)}); const result = service.detectServiceSupport(service.createPlatformProbeDependencies()); console.log(JSON.stringify(result));`,
    ], runtime);
    expect(probe.exitCode, probe.stderr).toBe(0);
    const result = JSON.parse(probe.stdout);
    expect(result).toMatchObject({ platform: 'linux', backend: 'systemd-user', isWsl: expect.any(Boolean) });
    expect(['supported', 'systemctl-not-found', 'systemd-user-manager-unavailable', 'service-directory-unwritable'])
      .toContain(result.reason);
    expect(existsSync(join(home, '.config', 'systemd', 'user', 'ariava.service'))).toBe(false);
  });
});
