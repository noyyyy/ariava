import { describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { AGENT_ADAPTER_PROTOCOL_HEADER, AGENT_ADAPTER_PROTOCOL_VERSION } from '../packages/protocol/src/agent-adapter';
import { AGENT_ADAPTER_OWNER_HEADERS } from '../extensions/pi/src/adapter';

const repositoryRoot = join(import.meta.dir, '..');
const installScript = join(repositoryRoot, 'scripts', 'install-pi-extension.sh');
const bundleRoot = join(repositoryRoot, 'extensions', 'pi', 'bundle');

function isolatedEnvironment(home: string, binDir: string): Record<string, string> {
  const npmConfigRoot = join(home, 'npm-config');
  const npmPrefix = join(home, 'npm-prefix');
  mkdirSync(npmConfigRoot, { recursive: true, mode: 0o700 });
  mkdirSync(npmPrefix, { recursive: true, mode: 0o700 });
  const env: Record<string, string> = {
    HOME: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    XDG_RUNTIME_DIR: join(home, '.runtime'),
    PI_CODING_AGENT_DIR: join(home, '.pi', 'agent'),
    npm_config_prefix: npmPrefix,
    NPM_CONFIG_PREFIX: npmPrefix,
    NPM_CONFIG_USERCONFIG: join(npmConfigRoot, 'user.npmrc'),
    NPM_CONFIG_GLOBALCONFIG: join(npmConfigRoot, 'global.npmrc'),
    PATH: `${binDir}${delimiter}/usr/local/bin${delimiter}/usr/bin${delimiter}/bin`,
    BUN_RUNTIME_TRANSPILER_CACHE_PATH: '',
  };
  return env;
}

function writeFakePi(binDir: string, installRoot: string, logPath: string): void {
  mkdirSync(binDir, { recursive: true, mode: 0o700 });
  const piPath = join(binDir, 'pi');
  writeFileSync(piPath, `#!/bin/sh
set -eu
[ "$#" -eq 2 ]
[ "$1" = "install" ]
[ "$HOME" = "${dirname(dirname(dirname(dirname(installRoot))))}" ]
[ "$PI_CODING_AGENT_DIR" = "$HOME/.pi/agent" ]
[ "$NPM_CONFIG_USERCONFIG" = "$HOME/npm-config/user.npmrc" ]
[ "$NPM_CONFIG_GLOBALCONFIG" = "$HOME/npm-config/global.npmrc" ]
[ "$npm_config_prefix" = "$HOME/npm-prefix" ]
[ -z "\${NODE_AUTH_TOKEN:-}" ]
[ -z "\${NPM_TOKEN:-}" ]
source="$2"
mkdir -p "${installRoot}" "$PI_CODING_AGENT_DIR"
rm -rf "${installRoot}"/* "${installRoot}"/.[!.]* "${installRoot}"/..?* 2>/dev/null || true
cp -R "$source"/. "${installRoot}"/
printf '{"packages":["%s"]}\n' "$source" > "$PI_CODING_AGENT_DIR/settings.json"
printf '%s\n' "$source" > "${logPath}"
`);
  chmodSync(piPath, 0o755);
}

const loadSmokeSource = String.raw`
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const [entryPath, discoveryPath, expectedHome] = process.argv.slice(2);
if (process.env.HOME !== expectedHome) throw new Error('HOME isolation failed');
if (process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH !== discoveryPath) throw new Error('discovery selection failed');
if (!discoveryPath.startsWith(expectedHome + '/')) throw new Error('discovery path escaped temporary home');

const requests = [];
const secret = 'temporary-loopback-secret';
const agentAdapterProtocolHeader = ${JSON.stringify(AGENT_ADAPTER_PROTOCOL_HEADER)};
const agentAdapterProtocolVersion = ${AGENT_ADAPTER_PROTOCOL_VERSION};
const ownerLease = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';
const driverInstanceHeader = ${JSON.stringify(AGENT_ADAPTER_OWNER_HEADERS.driverInstance)};
const ownerLeaseHeader = ${JSON.stringify(AGENT_ADAPTER_OWNER_HEADERS.ownerLease)};
const server = Bun.serve({
  hostname: '127.0.0.1',
  port: 0,
  async fetch(request) {
    const url = new URL(request.url);
    const protocolVersion = request.headers.get(agentAdapterProtocolHeader);
    requests.push({
      method: request.method,
      path: url.pathname,
      authorization: request.headers.get('authorization'),
      protocolVersion,
      driverInstanceId: request.headers.get(driverInstanceHeader),
      ownerLease: request.headers.get(ownerLeaseHeader),
    });
    if (request.headers.get('authorization') !== 'Bearer ' + secret) return new Response('Unauthorized', { status: 401 });
    if (protocolVersion !== String(agentAdapterProtocolVersion)) return new Response('Upgrade Required', { status: 426 });
    if (request.method === 'POST' && url.pathname === '/v2/agent/sessions') {
      const session = await request.json();
      return Response.json({ hostId: 'host-smoke', sessionId: session.sessionId, ownerLease }, { status: 201 });
    }
    const ownerRoute = url.pathname.startsWith('/v2/agent/sessions/');
    if (ownerRoute && (request.headers.get(driverInstanceHeader) === null || request.headers.get(ownerLeaseHeader) !== ownerLease)) {
      return Response.json({ error: { code: 'STALE_OWNER', retryable: false } }, { status: 409 });
    }
    if (request.method === 'GET' && url.pathname.endsWith('/commands')) return new Response(null, { status: 204 });
    if (request.method === 'DELETE' && ownerRoute) return Response.json({ ok: true });
    return new Response('Not found', { status: 404 });
  },
});

mkdirSync(new URL('.', pathToFileURL(discoveryPath)), { recursive: true, mode: 0o700 });
writeFileSync(discoveryPath, JSON.stringify({
  url: server.url.toString().replace(/\/$/, ''),
  secret,
  hostId: 'host-smoke',
  profileId: 'production',
  provider: 'pi',
  protocolVersion: agentAdapterProtocolVersion,
}), { mode: 0o600 });
chmodSync(discoveryPath, 0o600);

const extensionModule = await import(pathToFileURL(entryPath).href);
if (typeof extensionModule.default !== 'function') throw new Error('installed extension default export is not loadable');
const handlers = new Map();
const pi = { on(name, handler) { handlers.set(name, handler); } };
const context = {
  cwd: expectedHome + '/project',
  hasUI: false,
  sessionManager: {
    getSessionId: () => 'smoke-session',
    getLeafId: () => 'smoke-leaf',
    buildSessionContext: () => ({ messages: [] }),
  },
  isIdle: () => true,
  hasPendingMessages: () => false,
};
extensionModule.default(pi);
await handlers.get('session_start')({}, context);
for (let attempt = 0; attempt < 100 && !requests.some((request) => request.method === 'POST' && request.path === '/v2/agent/sessions'); attempt += 1) {
  await Bun.sleep(20);
}
if (!requests.some((request) => request.method === 'POST' && request.path === '/v2/agent/sessions')) {
  throw new Error('installed extension did not resolve discovery and register with the loopback adapter');
}
await handlers.get('session_shutdown')({ reason: 'quit' }, context);
await Bun.sleep(20);
server.stop(true);
console.log(JSON.stringify({ loaded: true, registered: true, discoveryPath, requests }));
`;

describe('pi extension disposable-home install and discovery smoke', () => {
  test('installs the generated bundle with a fake Pi package contract and loads loopback discovery', async () => {
    expect(existsSync(join(bundleRoot, 'index.js')), 'run bun run build:pi-bundle before the shared test lane').toBe(true);
    expect(existsSync(join(bundleRoot, 'package.json')), 'run bun run build:pi-bundle before the shared test lane').toBe(true);

    const root = mkdtempSync(join(tmpdir(), 'ariava-pi-install-smoke-'));
    const home = join(root, 'home');
    const workdir = join(root, 'unrelated-cwd');
    const binDir = join(root, 'bin');
    const installRoot = join(home, '.pi', 'agent', 'extensions', 'ariava-pi');
    const piLogPath = join(root, 'pi-install.log');
    const childPath = join(root, 'load-installed-extension.mjs');
    const discoveryPath = join(home, '.config', 'ariava', 'agent-adapter.json');
    mkdirSync(home, { recursive: true, mode: 0o700 });
    mkdirSync(workdir, { recursive: true, mode: 0o700 });
    writeFakePi(binDir, installRoot, piLogPath);
    writeFileSync(childPath, loadSmokeSource);
    const env = isolatedEnvironment(home, binDir);

    try {
      const installed = Bun.spawn({
        cmd: ['/bin/bash', installScript],
        cwd: workdir,
        env,
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [installExit, installStdout, installStderr] = await Promise.all([
        installed.exited,
        new Response(installed.stdout).text(),
        new Response(installed.stderr).text(),
      ]);
      expect(installExit, `${installStdout}\n${installStderr}`).toBe(0);
      expect(readFileSync(piLogPath, 'utf8').trim()).toBe(bundleRoot);
      expect(JSON.parse(readFileSync(join(home, '.pi', 'agent', 'settings.json'), 'utf8')).packages).toEqual([bundleRoot]);
      expect(JSON.parse(readFileSync(join(installRoot, 'package.json'), 'utf8')).name).toBe('@ariava/pi-extension');
      expect(readFileSync(join(installRoot, 'index.js'), 'utf8').length).toBeGreaterThan(0);

      const loaded = Bun.spawn({
        cmd: [process.execPath, childPath, join(installRoot, 'index.js'), discoveryPath, home],
        cwd: workdir,
        env: { ...env, ARIAVA_AGENT_ADAPTER_CONFIG_PATH: discoveryPath },
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [loadExit, loadStdout, loadStderr] = await Promise.all([
        loaded.exited,
        new Response(loaded.stdout).text(),
        new Response(loaded.stderr).text(),
      ]);
      expect(loadExit, loadStderr).toBe(0);
      const result = JSON.parse(loadStdout.trim().split('\n').at(-1)!);
      expect(result).toMatchObject({ loaded: true, registered: true, discoveryPath });
      expect(result.requests).toContainEqual({
        method: 'POST',
        path: '/v2/agent/sessions',
        authorization: 'Bearer temporary-loopback-secret',
        protocolVersion: String(AGENT_ADAPTER_PROTOCOL_VERSION),
        driverInstanceId: null,
        ownerLease: null,
      });
      expect(discoveryPath).toStartWith(home);
      expect(installRoot).toStartWith(home);
      expect(home).not.toBe(homedir());
      for (const sensitiveName of ['NODE_AUTH_TOKEN', 'NPM_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'AWS_ACCESS_KEY_ID']) {
        expect(env).not.toHaveProperty(sensitiveName);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);
});
