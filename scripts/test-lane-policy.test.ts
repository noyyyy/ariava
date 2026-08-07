import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveBunExecutable } from './bun-executable.mjs';
import { runHostVerification } from './verify-host.mjs';
import {
  REVIEWED_TEST_ROOTS,
  classifyTestFile,
  collectTestInventory,
  collectTestLane,
  runTestLane,
} from './run-test-lane.mjs';

const roots: string[] = [];
const repositoryRoot = join(import.meta.dir, '..');
const packageJson = JSON.parse(readFileSync(join(repositoryRoot, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>;
};

function fixture(files: string[]): string {
  const root = mkdtempSync(join(tmpdir(), 'ariava-test-lanes-'));
  roots.push(root);
  for (const reviewedRoot of REVIEWED_TEST_ROOTS) mkdirSync(join(root, reviewedRoot), { recursive: true });
  for (const path of files) {
    const absolute = join(root, path);
    mkdirSync(join(absolute, '..'), { recursive: true });
    writeFileSync(absolute, '// fixture\n');
  }
  return root;
}

function scriptClosure(entrypoint: string): Array<{ name: string; command: string }> {
  const visited = new Set<string>();
  const closure: Array<{ name: string; command: string }> = [];
  const visit = (name: string) => {
    if (visited.has(name)) return;
    visited.add(name);
    const command = packageJson.scripts[name];
    if (!command) return;
    closure.push({ name, command });
    for (const match of command.matchAll(/\bbun run ([a-z][a-z0-9:-]*)\b/giu)) visit(match[1]!);
  };
  visit(entrypoint);
  return closure;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('Public Core test lane collection policy', () => {
  test('classifies approved suffixes and rejects alternative Bun test names deterministically', () => {
    expect(classifyTestFile('scripts/example.test.ts')).toBe('shared');
    expect(classifyTestFile('apps/bridge/test/example.macos.test.ts')).toBe('macos');
    expect(classifyTestFile('apps/bridge/test/example.linux.test.ts')).toBe('linux');
    expect(classifyTestFile('scripts/example.integration.test.ts')).toBe('integration');
    expect(classifyTestFile('scripts/example.integration.test.mjs')).toBe('integration');
    expect(classifyTestFile('scripts/example.test.js')).toBe('unclassified');
    expect(classifyTestFile('scripts/example.spec.ts')).toBe('unclassified');
    expect(classifyTestFile('scripts/example_test.ts')).toBe('unclassified');
    expect(classifyTestFile('scripts/example_test_case.ts')).toBe('unclassified');
    expect(classifyTestFile('scripts/example_spec.ts')).toBe('unclassified');
    expect(classifyTestFile('scripts/example_spec_case.ts')).toBe('unclassified');
    expect(classifyTestFile('scripts/helper.ts')).toBeUndefined();
  });

  test('each ordinary lane includes only its owned suffix class', () => {
    const root = fixture([
      'scripts/shared.test.ts',
      'packages/protocol/test/protocol.macos.test.ts',
      'packages/shared-utils/test/utils.linux.test.ts',
      'apps/bridge/test/real.integration.test.ts',
    ]);

    expect(collectTestLane('shared', { repositoryRoot: root })).toEqual(['scripts/shared.test.ts']);
    expect(collectTestLane('macos', { repositoryRoot: root })).toEqual(['packages/protocol/test/protocol.macos.test.ts']);
    expect(collectTestLane('linux', { repositoryRoot: root })).toEqual(['packages/shared-utils/test/utils.linux.test.ts']);
    expect(collectTestInventory({ repositoryRoot: root }).filter((entry) => entry.classification === 'integration'))
      .toEqual([{ path: 'apps/bridge/test/real.integration.test.ts', classification: 'integration' }]);
  });

  test('platform and integration tests cannot leak into shared collection', () => {
    const root = fixture([
      'apps/bridge/test/zeta.test.ts',
      'apps/bridge/test/alpha.macos.test.ts',
      'apps/bridge/test/beta.linux.test.ts',
      'apps/bridge/test/gamma.integration.test.ts',
    ]);
    expect(collectTestLane('shared', { repositoryRoot: root })).toEqual(['apps/bridge/test/zeta.test.ts']);
  });

  test('empty lanes and new unclassified test files fail closed', () => {
    const emptyRoot = fixture(['scripts/only.test.ts']);
    expect(() => collectTestLane('macos', { repositoryRoot: emptyRoot })).toThrow('collected no files');

    const unclassifiedRoot = fixture(['scripts/valid.test.ts', 'scripts/new-contract.test.js']);
    expect(() => collectTestLane('shared', { repositoryRoot: unclassifiedRoot })).toThrow('Unclassified test files');
  });

  test('alternative Bun test naming fixtures fail closed under every reviewed root', () => {
    const alternatives = [
      'scripts/example.spec.ts',
      'packages/protocol/test/example_test.ts',
      'packages/shared-utils/test/example_test_case.ts',
      'apps/bridge/test/example_spec.ts',
      'apps/bridge/test/example_spec_case.ts',
    ];
    for (const alternative of alternatives) {
      const root = fixture(['scripts/valid.test.ts', alternative]);
      expect(collectTestInventory({ repositoryRoot: root })).toContainEqual({
        path: alternative,
        classification: 'unclassified',
      });
      expect(() => collectTestLane('shared', { repositoryRoot: root }), alternative)
        .toThrow('Unclassified test files');
    }
  });

  test('the reviewed repository inventory is classified and shared files contain no host skip wrappers', () => {
    const inventory = collectTestInventory({ repositoryRoot });
    expect(inventory.length).toBeGreaterThan(0);
    expect(inventory.filter((entry) => entry.classification === 'unclassified')).toEqual([]);
    const prohibitedHostSkip = 'skipIf(process.' + 'platform';
    for (const entry of inventory.filter((candidate) => candidate.classification === 'shared')) {
      expect(readFileSync(join(repositoryRoot, entry.path), 'utf8'), entry.path)
        .not.toContain(prohibitedHostSkip);
    }
  });

  test('package scripts preserve the shared release closure and additive host gates', () => {
    expect(packageJson.scripts.test).toBe(
      'bun run build && bun run ./scripts/run-test-lane.mjs shared && bun run --cwd extensions/pi test',
    );
    expect(packageJson.scripts['test:shared']).toBeUndefined();
    expect(packageJson.scripts['test:macos']).toBe('bun run ./scripts/run-test-lane.mjs macos');
    expect(packageJson.scripts['test:linux']).toBe('bun run ./scripts/run-test-lane.mjs linux');
    expect(packageJson.scripts.verify).toBe(
      'bun run test && bun run --cwd extensions/pi typecheck && bun run package:assert',
    );
    expect(packageJson.scripts['verify:shared']).toBeUndefined();
    expect(packageJson.scripts['verify:macos']).toBe('bun run verify && bun run test:macos');
    expect(packageJson.scripts['verify:linux']).toBe('bun run verify && bun run test:linux');
    expect(packageJson.scripts['verify:host']).toBe('bun run ./scripts/verify-host.mjs');

    const closure = scriptClosure('verify');
    const closureNames = closure.map((entry) => entry.name);
    const closureCommands = closure.map((entry) => entry.command).join('\n');
    expect(closureNames).toContain('build');
    expect(closureNames).toContain('build:pi-bundle');
    expect(closureCommands).toContain('bun run ./scripts/build-public-package.mjs protocol');
    expect(closureCommands).toContain('bun run ./scripts/build-public-package.mjs shared-utils');
    expect(closureCommands).toContain('node ./scripts/build-bridge.mjs');
    for (const removedBuildScript of ['build:protocol', 'build:shared-utils', 'build:bridge']) {
      expect(packageJson.scripts[removedBuildScript]).toBeUndefined();
    }
    expect(closureCommands).toContain('bun run --cwd extensions/pi test');
    expect(closureCommands).toContain('bun run --cwd extensions/pi typecheck');
    expect(closureNames).toContain('package:assert');

    const sharedLane = collectTestLane('shared', { repositoryRoot });
    for (const releaseCriticalTest of [
      'scripts/assert-npm-package.test.ts',
      'scripts/npm-tarball-install.test.ts',
      'scripts/pi-extension-install-smoke.test.ts',
      'scripts/public-package-consumers.test.ts',
    ]) {
      expect(sharedLane, releaseCriticalTest).toContain(releaseCriticalTest);
    }
  });

  test('local host verification is Darwin-only dispatch and never starts Docker or OrbStack', () => {
    const source = readFileSync(join(repositoryRoot, 'scripts', 'verify-host.mjs'), 'utf8');
    expect(source).toContain("process.platform");
    expect(source).toContain("['run', 'verify:macos']");
    expect(source).toContain('shell: false');
    expect(source).not.toContain('process.execPath');
    expect(source).not.toMatch(/docker|orbstack|verify:linux/iu);
  });

  test('Bun executable resolution and launchers honor explicit overrides with argument arrays', () => {
    expect(resolveBunExecutable({ env: {} })).toBe('bun');
    expect(resolveBunExecutable({ env: { ARIAVA_BUN_EXECUTABLE: '/fake/env-bun' } })).toBe('/fake/env-bun');
    expect(resolveBunExecutable({ bunPath: '/fake/explicit-bun', env: { ARIAVA_BUN_EXECUTABLE: '/fake/env-bun' } }))
      .toBe('/fake/explicit-bun');

    const laneRoot = fixture(['scripts/shared.test.ts']);
    const laneLaunches: Array<{ command: string; args: string[]; options: Record<string, unknown> }> = [];
    const laneStatus = runTestLane('shared', {
      repositoryRoot: laneRoot,
      reviewedRoots: ['scripts'],
      env: {
        ARIAVA_BUN_EXECUTABLE: '/fake/lane-bun',
        HOME: '/Users/real-user',
        XDG_CONFIG_HOME: '/Users/real-user/.config',
        ARIAVA_HOST_IDENTITY_PATH: '/Users/real-user/.config/ariava/host-identity.json',
        ARIAVA_AGENT_ADAPTER_CONFIG_PATH: '/Users/real-user/.config/ariava/agent-adapter.json',
        ARIAVA_STATE_PATH: '/Users/real-user/.config/ariava/state/bridge-state.json',
      },
      stdio: 'pipe',
      spawnSync: (command: string, args: string[], options: Record<string, unknown>) => {
        laneLaunches.push({ command, args, options });
        return { status: 0 };
      },
    });
    expect(laneStatus).toBe(0);
    expect(laneLaunches).toHaveLength(1);
    expect(laneLaunches[0]).toMatchObject({
      command: '/fake/lane-bun',
      args: ['test', './scripts/shared.test.ts'],
      options: { cwd: laneRoot, shell: false, stdio: 'pipe' },
    });
    const laneEnvironment = laneLaunches[0]!.options.env as NodeJS.ProcessEnv;
    expect(laneEnvironment.HOME).toStartWith(join(tmpdir(), 'ariava-test-lane-'));
    expect(laneEnvironment.XDG_CONFIG_HOME).toBe(join(laneEnvironment.HOME!, '.config'));
    expect(laneEnvironment.PI_CODING_AGENT_DIR).toBe(join(laneEnvironment.HOME!, '.pi', 'agent'));
    expect(laneEnvironment.ARIAVA_HOST_IDENTITY_PATH).toBeUndefined();
    expect(laneEnvironment.ARIAVA_AGENT_ADAPTER_CONFIG_PATH).toBeUndefined();
    expect(laneEnvironment.ARIAVA_STATE_PATH).toBeUndefined();

    const hostLaunches: Array<{ command: string; args: string[]; options: Record<string, unknown> }> = [];
    const hostStatus = runHostVerification({
      platform: 'darwin',
      repositoryRoot: laneRoot,
      env: { ARIAVA_BUN_EXECUTABLE: '/fake/host-bun' },
      stdio: 'pipe',
      spawnSync: (command: string, args: string[], options: Record<string, unknown>) => {
        hostLaunches.push({ command, args, options });
        return { status: 0 };
      },
    });
    expect(hostStatus).toBe(0);
    expect(hostLaunches).toEqual([{
      command: '/fake/host-bun',
      args: ['run', 'verify:macos'],
      options: expect.objectContaining({ cwd: laneRoot, shell: false, stdio: 'pipe' }),
    }]);
  });

  test('collector uses reviewed roots, sorted argument arrays, and no shell execution', () => {
    const source = readFileSync(join(repositoryRoot, 'scripts', 'run-test-lane.mjs'), 'utf8');
    for (const root of REVIEWED_TEST_ROOTS) expect(source).toContain(`'${root}'`);
    expect(source).toContain("spawn(bunPath, ['test', ...group.map");
    expect(source).toContain('shell: false');
    expect(source).not.toContain('process.execPath');
    expect(source).not.toMatch(/execSync|\bshell:\s*true/u);
  });
});
