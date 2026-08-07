import * as childProcess from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, expect, mock, test } from 'bun:test';
import type { DevProfileDependencies } from '../src/dev-profile-app';

interface ChildAction {
  command: string;
  args: string[];
}

let activeActions: ChildAction[] | undefined;
mock.module('node:child_process', () => ({
  ...childProcess,
  spawn: recordUnsupportedChildAction('spawn'),
  exec: recordUnsupportedChildAction('exec'),
  execFile: recordUnsupportedChildAction('execFile'),
  execSync: recordUnsupportedChildAction('execSync'),
  execFileSync: recordUnsupportedChildAction('execFileSync'),
  fork: recordUnsupportedChildAction('fork'),
  spawnSync(command: string, args: string[] = []) {
    recordChildAction(command, args);
    return { status: 0, stdout: '', stderr: '' };
  },
}));

function recordChildAction(command: string, args: string[]): void {
  if (!activeActions) throw new Error(`Unexpected child action outside recorder: ${command}`);
  activeActions.push({ command, args });
}

function recordUnsupportedChildAction(api: string): (...args: unknown[]) => never {
  return (...args) => {
    const command = typeof args[0] === 'string' ? args[0] : `<${api}>`;
    const commandArgs = Array.isArray(args[1]) ? args[1].map(String) : [];
    recordChildAction(command, commandArgs);
    throw new Error(`Dev lifecycle used unsupported child-process API ${api}`);
  };
}

const { writeAgentAdapterConfig } = await import('../src/agent-adapter/config');
const { createDefaultDevProfileDependencies, runDevProfileCommand } = await import('../src/dev-profile-app');
const { resolveAriavaDevProfilePaths } = await import('../src/host-manager/dev-profile');
const { createDevProfile } = await import('../src/cli/profiles/dev');

const root = resolve(import.meta.dir, '../../..');

describe('Node-backed dev setup', () => {
  test('builds a Node dev-profile entrypoint and runs setup through it', () => {
    const manifest = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
      bin: Record<string, string>;
    };
    const buildScript = readFileSync(resolve(root, 'scripts/build-bridge.mjs'), 'utf8');

    expect(manifest.scripts['dev:cli']).toBe('node ./scripts/build-bridge.mjs && node ./apps/bridge/dist/dev-profile-cli.js');
    expect(manifest.scripts['dev:setup']).toBe('node ./scripts/build-bridge.mjs && node ./apps/bridge/dist/dev-profile-cli.js setup');
    expect(Object.keys(manifest.scripts).filter((name) => name.startsWith('dev:'))).toEqual(['dev:cli', 'dev:setup']);
    expect(manifest.scripts['build:protocol']).toBeUndefined();
    expect(manifest.scripts['build:shared-utils']).toBeUndefined();
    expect(manifest.scripts['build:bridge']).toBeUndefined();
    expect(buildScript).toContain("resolve(bridgeRoot, 'src', 'dev-profile-cli.ts')");
    expect(manifest.bin).toEqual({ ariava: 'apps/bridge/dist/public-cli.js' });
    expect(buildScript).toContain("resolve(bridgeRoot, 'src', 'public-cli.ts')");
  });

  test('records the exact child actions allowed for each dev lifecycle command', async () => {
    const cases = [
      { command: 'setup', argv: ['setup', '--no-extensions'], expected: [] },
      { command: 'init', argv: ['init'], expected: [] },
      { command: 'bridge', argv: ['bridge'], expected: [] },
      { command: 'status', argv: ['status'], expected: [] },
      { command: 'pair', argv: ['pair', 'PEYX7K'], expected: [] },
      {
        command: 'pi',
        argv: ['pi'],
        expected: [{ command: 'pi', args: ['--no-extensions', '-e', '/source/extensions/pi/index.ts'] }],
      },
    ];

    for (const row of cases) {
      const actions: ChildAction[] = [];
      const harness = createActionHarness();
      activeActions = actions;
      try {
        await prepareActionCase(row.command, harness.dependencies);
        actions.splice(0);
        expect(await runDevProfileCommand(row.argv, harness.dependencies)).toBe(0);
        expect(actions).toEqual(row.expected);
      } finally {
        activeActions = undefined;
        rmSync(harness.root, { recursive: true, force: true });
      }
    }
  });

  test('keeps the canonical dev lifecycle graph outside production lifecycle modules', () => {
    const sourceRoot = resolve(root, 'apps/bridge/src');
    const graph = inspectRelativeImportGraph({
      sourceRoot,
      entryPath: resolve(sourceRoot, 'dev-profile-cli.ts'),
      safeModules: SAFE_DEV_LIFECYCLE_MODULES,
      forbiddenModules: FORBIDDEN_PRODUCTION_LIFECYCLE_MODULES,
    });

    expect(graph.forbiddenModules).toEqual([]);
    expect(graph.unsafeModules).toEqual([]);
    expect(graph.modules).toEqual([...SAFE_DEV_LIFECYCLE_MODULES].sort());
  });

  test('keeps the built dev entrypoint outside production lifecycle implementations', () => {
    const artifact = readFileSync(resolve(root, 'apps/bridge/dist/dev-profile-cli.js'), 'utf8');
    for (const forbidden of [
      'SpawnSyncCommandRunner',
      'installPiPackage',
      'upgradePiPackage',
      'removePiPackage',
      'launchctl',
      'systemctl',
    ]) {
      expect(artifact).not.toContain(forbidden);
    }
    expect(artifact).toContain('deps.spawn("pi", ["--no-extensions", "-e", deps.sourcePiExtensionPath, ...args]');
  });

  test('keeps both executable entrypoints as direct unified-app wrappers', () => {
    const sourceRoot = resolve(root, 'apps/bridge/src');
    const entrypoints = [
      { file: 'public-cli.ts', contextFactory: 'createDefaultCliApplicationContext' },
      { file: 'dev-profile-cli.ts', contextFactory: 'createDevCliApplicationContext' },
    ];

    for (const entrypoint of entrypoints) {
      const source = readFileSync(resolve(sourceRoot, entrypoint.file), 'utf8');
      expect(source).toContain("import { runAriavaCli } from './cli/app';");
      expect(source).toContain(entrypoint.contextFactory);
      expect(source).toContain(`runAriavaCli(process.argv.slice(2), ${entrypoint.contextFactory}())`);
      expect(source).not.toContain('console.error');
    }
  });

  test('keeps dev-profile-app as compatibility-only glue', () => {
    const source = readFileSync(resolve(root, 'apps/bridge/src/dev-profile-app.ts'), 'utf8');
    expect(source).not.toContain('dispatchDevProfileCommand');
    expect(source).not.toContain('runDevSetup');
    expect(source).not.toContain('runDevBridge');
    expect(source).not.toContain('runDevPi');
    expect(source).not.toContain('runSharedHostCommand');
    expect(source).not.toContain('switch (');
  });
  test.each([
    {
      name: 'direct import',
      files: { 'entry.ts': "import './host-manager/service/manager';", 'host-manager/service/manager.ts': '' },
    },
    {
      name: 'index alias',
      files: {
        'entry.ts': "import { createServiceManager as harmless } from './host-manager/index'; void harmless;",
        'host-manager/index.ts': "export { createServiceManager } from './service/manager';",
        'host-manager/service/manager.ts': '',
      },
    },
    {
      name: 'wrapper indirection',
      files: {
        'entry.ts': "import './renamed-helper';",
        'renamed-helper.ts': "export * from './host-manager/service/manager';",
        'host-manager/service/manager.ts': '',
      },
    },
  ])('detects forbidden lifecycle modules through $name', ({ files }) => {
    const fixture = createImportGraphFixture(files);
    try {
      const graph = inspectRelativeImportGraph({
        sourceRoot: fixture.root,
        entryPath: resolve(fixture.root, 'entry.ts'),
        safeModules: Object.keys(files),
        forbiddenModules: ['host-manager/service/manager.ts'],
      });

      expect(graph.forbiddenModules).toEqual(['host-manager/service/manager.ts']);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });
});

function createActionHarness(): { root: string; dependencies: DevProfileDependencies } {
  const harnessRoot = mkdtempSync(join(tmpdir(), 'ariava-dev-actions-'));
  return {
    root: harnessRoot,
    dependencies: {
      ...createDefaultDevProfileDependencies(),
      paths: resolveAriavaDevProfilePaths(harnessRoot),
      profile: withHome(harnessRoot, createDevProfile),
      platform: 'linux',
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      stdin: new PassThrough(),
      sourcePiExtensionPath: '/source/extensions/pi/index.ts',
      interactive: false,
      environment: { HOME: harnessRoot, PATH: '/usr/bin' },
      hostName: () => 'test-host',
      generateSecret: () => 'dev-secret',
      waitForShutdown: async () => {},
    },
  };
}

async function prepareActionCase(command: string, dependencies: DevProfileDependencies): Promise<void> {
  if (command === 'setup' || command === 'bridge') dependencies.createBridge = stoppedBridge;
  if (command === 'bridge' || command === 'status' || command === 'pair') {
    await runDevProfileCommand(['init'], dependencies);
  }
  if (command === 'pair') dependencies.createPairDependencies = () => fakePairDependencies(dependencies);
  if (command === 'pi') {
    mkdirSync(dependencies.paths.root, { recursive: true, mode: 0o700 });
    writeAgentAdapterConfig(dependencies.paths.agentAdapterConfigPath, {
      url: 'http://127.0.0.1:7273',
      secret: 'dev-secret',
    });
    dependencies.pathExists = (path) => path === dependencies.paths.agentAdapterConfigPath
      || path === dependencies.sourcePiExtensionPath;
  }
}

function stoppedBridge() {
  let finish!: () => void;
  const runPromise = new Promise<void>((resolveRun) => { finish = resolveRun; });
  return {
    start: async () => {},
    runForever: () => runPromise,
    stop: () => finish(),
  };
}

function fakePairDependencies(dependencies: DevProfileDependencies): ReturnType<DevProfileDependencies['createPairDependencies']> {
  return {
    bridgeVersion: '0.0.0-test',
    normalizePairingCode: (value) => value.toUpperCase(),
    enroll: async () => {},
    createRelay: () => ({} as never),
    pairWatch: async () => {
      const identity = await dependencies.createIdentityStore(
        dependencies.paths.identityPath,
        dependencies.platform,
        'dev',
      ).load();
      const now = new Date().toISOString();
      const watchDeviceId = `watch_${'C'.repeat(43)}`;
      return {
        host: {
          hostId: identity!.hostId,
          hostName: 'test-host (Dev)',
          platform: 'linux',
          bridgeVersion: '0.0.0-test',
          registeredAt: now,
          lastSeenAt: now,
          bridgeStatus: 'online',
        },
        watchDevice: {
          watchDeviceId,
          selectedHostIds: [identity!.hostId],
          registeredAt: now,
          lastSeenAt: now,
          pairingStatus: 'paired',
        },
        link: { hostId: identity!.hostId, watchDeviceId, pairedAt: now, generation: 1, updatedAt: now },
        alreadyPaired: false,
      };
    },
    createKeyring: () => ({} as never),
    createHostBinding: async () => ({} as never),
    activate: async () => 'activated',
  };
}

function withHome<T>(home: string, run: () => T): T {
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = home;
  delete process.env.XDG_CONFIG_HOME;
  try {
    return run();
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousXdg;
  }
}

interface ImportGraphOptions {
  sourceRoot: string;
  entryPath: string;
  safeModules: readonly string[];
  forbiddenModules: readonly string[];
}

interface ImportGraphInspection {
  modules: string[];
  forbiddenModules: string[];
  unsafeModules: string[];
}

const SAFE_DEV_LIFECYCLE_MODULES = [
  'agent-adapter/client.ts',
  'agent-adapter/config.ts',
  'agent-adapter/registry.ts',
  'agent-adapter/server.ts',
  'cli/app.ts',
  'cli/catalog.ts',
  'cli/context.ts',
  'cli/commands/doctor.ts',
  'cli/commands/config.ts',
  'cli/commands/identity.ts',
  'cli/commands/index.ts',
  'cli/commands/pair.ts',
  'cli/commands/status.ts',
  'cli/commands/watches.ts',
  'cli/failure.ts',
  'cli/operations/identity.ts',
  'cli/operations/initialize.ts',
  'cli/operations/pair.ts',
  'cli/operations/watches.ts',
  'cli/output.ts',
  'cli/profile.ts',
  'cli/probes/profile.ts',
  'cli/profiles/dev.ts',
  'cli/lifecycle/dev.ts',
  'command-router.ts',
  'daemon.ts',
  'dev-profile-cli.ts',
  'drivers/pi.ts',
  'e2e/command-execution.ts',
  'e2e/envelope.ts',
  'e2e/host-safety-code-activation.ts',
  'e2e/link-keyring.ts',
  'e2e/local-spool.ts',
  'e2e/node-crypto-self-test.ts',
  'e2e/node-crypto.ts',
  'e2e/notification-preview.ts',
  'e2e/upload-orchestrator.ts',
  'host-manager/config.ts',
  'host-manager/dev-profile.ts',
  'host-manager/output.ts',
  'host-manager/paths.ts',
  'host-manager/secure-files.ts',
  'host-manager/status.ts',
  'host-manager/service/errors.ts',
  'host-manager/service/migration.ts',
  'host-platform.ts',
  'identity/errors.ts',
  'identity/host-encryption-key.ts',
  'identity/host-identity.ts',
  'identity/index.ts',
  'identity/linux-encryption-key-store.ts',
  'identity/linux-json-store.ts',
  'identity/macos-encryption-key-store.ts',
  'identity/macos-keychain-store.ts',
  'identity/manager.ts',
  'identity/request-signer.ts',
  'identity/runtime-store.ts',
  'identity/types.ts',
  'relay-client.ts',
  'runtime/node-runtime.ts',
  'state-store.ts',
  'ui/onboarding-renderer.ts',
] as const;

const FORBIDDEN_PRODUCTION_LIFECYCLE_MODULES = [
  'public-cli-app.ts',
  'cli/lifecycle/default.ts',
  'host-manager/onboarding/bootstrap.ts',
  'host-manager/onboarding/catalog.ts',
  'host-manager/onboarding/detector.ts',
  'host-manager/onboarding/index.ts',
  'host-manager/onboarding/lock.ts',
  'host-manager/onboarding/orchestrator.ts',
  'host-manager/onboarding/readiness.ts',
  'host-manager/onboarding/types.ts',
  'host-manager/pi-extension.ts',
  'host-manager/service/command-runner.ts',
  'host-manager/service/index.ts',
  'host-manager/service/launchd.ts',
  'host-manager/service/manager.ts',
  'host-manager/service/platform.ts',
  'host-manager/service/runtime-probe.ts',
  'host-manager/service/systemd-user.ts',
  'host-manager/service/types.ts',
] as const;

function inspectRelativeImportGraph(options: ImportGraphOptions): ImportGraphInspection {
  const sourceRoot = realpathSync(options.sourceRoot);
  const safeModules = new Set(options.safeModules);
  const forbiddenModules = new Set(options.forbiddenModules);
  const visited = new Set<string>();
  const queued = [realpathSync(options.entryPath)];
  while (queued.length > 0) {
    const modulePath = queued.shift()!;
    const moduleName = moduleNameWithin(sourceRoot, modulePath);
    if (visited.has(moduleName)) continue;
    visited.add(moduleName);

    const source = readFileSync(modulePath, 'utf8').replace(/^#![^\n]*(?:\n|$)/u, '');
    for (const { path: specifier } of new Bun.Transpiler({ loader: 'ts' }).scanImports(source)) {
      if (!specifier.startsWith('.')) continue;
      const importedPath = resolveRelativeTsModule(modulePath, specifier);
      if (importedPath) queued.push(importedPath);
    }
  }

  const modules = [...visited].sort();
  return {
    modules,
    forbiddenModules: modules.filter((moduleName) => forbiddenModules.has(moduleName)),
    unsafeModules: modules.filter((moduleName) => !safeModules.has(moduleName)),
  };
}

function resolveRelativeTsModule(importerPath: string, specifier: string): string | undefined {
  if (/\.[^/]+$/u.test(specifier) && !/\.(?:ts|tsx|js|mjs)$/u.test(specifier)) return undefined;
  const basePath = resolve(dirname(importerPath), specifier.replace(/\.(?:js|mjs)$/u, ''));
  const candidates = /\.(?:ts|tsx)$/u.test(basePath)
    ? [basePath]
    : [`${basePath}.ts`, `${basePath}.tsx`, resolve(basePath, 'index.ts'), resolve(basePath, 'index.tsx')];
  const match = candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
  if (!match) throw new Error(`Unable to resolve relative TypeScript import ${specifier} from ${importerPath}`);
  return realpathSync(match);
}

function moduleNameWithin(sourceRoot: string, modulePath: string): string {
  const moduleName = relative(sourceRoot, modulePath);
  if (isAbsolute(moduleName) || moduleName === '..' || moduleName.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
    throw new Error(`Relative TypeScript import escapes source root: ${modulePath}`);
  }
  return moduleName.replaceAll('\\', '/');
}

function createImportGraphFixture(files: Record<string, string>): { root: string } {
  const fixtureRoot = mkdtempSync(join(tmpdir(), 'ariava-import-graph-'));
  for (const [name, source] of Object.entries(files)) {
    const path = resolve(fixtureRoot, name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, source);
  }
  return { root: fixtureRoot };
}
