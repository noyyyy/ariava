import { afterEach, describe, expect, test } from 'bun:test';
import { detectPackageManager } from '../src/public-cli-app';
import { detectPackageManager as detectPackageManagerFromDefault } from '../src/cli/lifecycle/default';

const priorForced = process.env.ARIAVA_UPGRADE_PACKAGE_MANAGER;
afterEach(() => {
  if (priorForced === undefined) delete process.env.ARIAVA_UPGRADE_PACKAGE_MANAGER;
  else process.env.ARIAVA_UPGRADE_PACKAGE_MANAGER = priorForced;
});

function detect(shim: string, realPath: string, metadata = {}) {
  return detectPackageManager({ currentAriavaBinPath: () => shim, realpath: () => realPath }, metadata);
}

describe('package manager detection', () => {
  test('compatibility exports preserve the same detection behavior', () => {
    const cases = [
      { shim: '/usr/local/bin/ariava', realPath: '/usr/local/lib/node_modules/ariava/apps/bridge/dist/public-cli.js', metadata: {} },
      { shim: '/usr/local/bin/ariava', realPath: '/usr/local/lib/node_modules/.pnpm/ariava@0.1.4/node_modules/ariava/apps/bridge/dist/public-cli.js', metadata: {} },
      { shim: '/home/test/.bun/bin/ariava', realPath: '/home/test/.bun/install/global/node_modules/ariava/apps/bridge/dist/public-cli.js', metadata: {} },
      { shim: '/opt/homebrew/bin/ariava', realPath: '/opt/homebrew/Cellar/ariava/0.1.4/libexec/apps/bridge/dist/public-cli.js', metadata: {} },
      { shim: '/fake/pnpm/bin/ariava', realPath: '/opt/custom/ariava/public-cli.js', metadata: {} },
      {
        shim: '/new/bin/ariava',
        realPath: '/new/layout/public-cli.js',
        metadata: { installer: { manager: 'pnpm' as const, ariavaBinRealPath: '/old/path', recordedAt: '2026-07-15T00:00:00.000Z' } },
      },
      {
        shim: '/new/bin/ariava',
        realPath: '/new/layout/public-cli.js',
        metadata: { installer: { manager: 'npm' as const, ariavaBinRealPath: 'relative/path', recordedAt: '2026-07-15T00:00:00.000Z' } },
      },
    ];
    for (const { shim, realPath, metadata } of cases) {
      const dependencies = { currentAriavaBinPath: () => shim, realpath: () => realPath };
      expect(detectPackageManager(dependencies, metadata)).toEqual(
        detectPackageManagerFromDefault(dependencies, metadata),
      );
    }
  });

  test.each([
    ['/usr/local/bin/ariava', '/usr/local/lib/node_modules/ariava/apps/bridge/dist/public-cli.js', 'npm'],
    ['/Users/test/.nvm/versions/node/v22.0.0/bin/ariava', '/Users/test/.nvm/versions/node/v22.0.0/lib/node_modules/ariava/apps/bridge/dist/public-cli.js', 'npm'],
    ['/custom/prefix/bin/ariava', '/custom/prefix/lib/node_modules/ariava/apps/bridge/dist/public-cli.js', 'npm'],
    ['/home/test/.local/share/pnpm/ariava', '/home/test/.local/share/pnpm/global/5/node_modules/ariava/apps/bridge/dist/public-cli.js', 'pnpm'],
    ['/usr/local/bin/ariava', '/usr/local/lib/node_modules/.pnpm/ariava@0.1.4/node_modules/ariava/apps/bridge/dist/public-cli.js', 'pnpm'],
    ['/home/test/.bun/bin/ariava', '/home/test/.bun/install/global/node_modules/ariava/apps/bridge/dist/public-cli.js', 'bun'],
    ['/opt/homebrew/bin/ariava', '/opt/homebrew/Cellar/ariava/0.1.4/libexec/apps/bridge/dist/public-cli.js', 'homebrew'],
  ])('uses realpath for %s', (shim, realPath, manager) => {
    expect(detect(shim, realPath)?.manager).toBe(manager);
  });

  test('does not guess from the unresolved shim substring', () => {
    expect(detect('/fake/pnpm/bin/ariava', '/opt/custom/ariava/public-cli.js')).toBeUndefined();
  });

  test('prefers persisted installer metadata after package paths move', () => {
    expect(detect('/new/bin/ariava', '/new/layout/public-cli.js', {
      installer: { manager: 'pnpm', ariavaBinRealPath: '/old/path', recordedAt: '2026-07-15T00:00:00.000Z' },
    })?.manager).toBe('pnpm');
  });

  test('rejects malformed persisted installer paths instead of trusting the manager', () => {
    expect(detect('/new/bin/ariava', '/new/layout/public-cli.js', {
      installer: { manager: 'npm', ariavaBinRealPath: 'relative/path', recordedAt: '2026-07-15T00:00:00.000Z' },
    })).toBeUndefined();
  });
});
