import { describe, expect, test } from 'bun:test';
import { join } from 'node:path';
import {
  ARIAVA_PI_PACKAGE_NAME,
  buildExactPiPackageSource,
  ensureExactPiPackage,
  inspectPiPackage,
  type PiPackageLifecycleDependencies,
} from '../src/host-manager/pi-extension';
import type { CommandResult } from '../src/host-manager/service/types';

const settingsPath = '/isolated/pi/settings.json';
const packagePath = '/isolated/pi/npm/node_modules/@ariava/pi-extension';
const manifestPath = join(packagePath, 'package.json');

function fixture(input: {
  packages?: unknown[];
  manifest?: { name?: string; version?: string };
  installResult?: CommandResult;
  installedManifest?: { name?: string; version?: string } | null;
} = {}) {
  const files = new Map<string, string>();
  const calls: Array<{ command: string; args: string[] }> = [];
  const initialSettings = { theme: 'dark', packages: input.packages ?? [], customSetting: { preserved: true } };
  files.set(settingsPath, JSON.stringify(initialSettings));
  if (input.manifest) files.set(manifestPath, JSON.stringify(input.manifest));

  const deps: PiPackageLifecycleDependencies = {
    settingsPath,
    packagePath,
    now: () => '2026-07-20T00:00:00.000Z',
    readText: (path) => files.get(path),
    pathExists: (path) => path === packagePath ? files.has(manifestPath) : files.has(path),
    runner: {
      run(command, args) {
        calls.push({ command, args: [...args] });
        if (input.installResult) return input.installResult;
        const source = args[1];
        const settings = JSON.parse(files.get(settingsPath)!) as { packages: unknown[] };
        settings.packages = [
          ...settings.packages.filter((entry) => {
            const value = typeof entry === 'string' ? entry : (entry as { source?: string })?.source;
            return value !== 'npm:@ariava/pi-extension' && !value?.startsWith('npm:@ariava/pi-extension@');
          }),
          source,
        ];
        files.set(settingsPath, JSON.stringify(settings));
        if (input.installedManifest !== null) {
          const version = source.slice(source.lastIndexOf('@') + 1);
          files.set(manifestPath, JSON.stringify(input.installedManifest ?? { name: ARIAVA_PI_PACKAGE_NAME, version }));
        }
        return { status: 0, stdout: '', stderr: '' };
      },
    },
  };
  return { deps, files, calls, initialSettings };
}

describe('exact Pi package lifecycle', () => {
  test('builds an exact scoped npm source including prerelease versions', () => {
    expect(buildExactPiPackageSource('1.2.3-beta.4')).toBe('npm:@ariava/pi-extension@1.2.3-beta.4');
  });

  test('installs the exact source and verifies source, path, manifest name, and version', () => {
    const state = fixture({ packages: ['npm:unrelated@4.0.0'] });
    const result = ensureExactPiPackage('1.2.3', state.deps);

    expect(result.action).toBe('installed');
    expect(state.calls).toEqual([{ command: 'pi', args: ['install', 'npm:@ariava/pi-extension@1.2.3'] }]);
    expect(result.status).toMatchObject({
      registeredSource: 'npm:@ariava/pi-extension@1.2.3',
      expectedManagedPath: packagePath,
      manifestName: '@ariava/pi-extension',
      manifestVersion: '1.2.3',
      sourceOwnership: 'managed-exact',
      mismatchReasons: [],
    });
  });

  test('is a no-op only when exact source, managed path, name, and version all match', () => {
    const state = fixture({
      packages: ['npm:unrelated@4.0.0', { source: 'npm:@ariava/pi-extension@1.2.3', enabled: true }],
      manifest: { name: '@ariava/pi-extension', version: '1.2.3' },
    });
    const before = state.files.get(settingsPath);
    const result = ensureExactPiPackage('1.2.3', state.deps);

    expect(result.action).toBe('reused');
    expect(state.calls).toEqual([]);
    expect(state.files.get(settingsPath)).toBe(before);
  });

  test.each([
    ['older exact', 'npm:@ariava/pi-extension@1.0.0'],
    ['legacy unpinned official', 'npm:@ariava/pi-extension'],
  ])('converges %s registration by reinstalling only Ariava', (_label, source) => {
    const unrelated = { source: 'npm:unrelated@4.0.0', enabled: false, extra: 'keep' };
    const state = fixture({ packages: [unrelated, source], manifest: { name: '@ariava/pi-extension', version: '1.0.0' } });
    const result = ensureExactPiPackage('1.2.3', state.deps);
    const after = JSON.parse(state.files.get(settingsPath)!);

    expect(result.action).toBe('upgraded');
    expect(state.calls).toEqual([{ command: 'pi', args: ['install', 'npm:@ariava/pi-extension@1.2.3'] }]);
    expect(after.theme).toBe('dark');
    expect(after.customSetting).toEqual({ preserved: true });
    expect(after.packages).toEqual([unrelated, 'npm:@ariava/pi-extension@1.2.3']);
  });

  test.each([
    ['duplicate official sources', ['npm:@ariava/pi-extension', 'npm:@ariava/pi-extension@1.0.0']],
    ['local source', ['file:/tmp/@ariava/pi-extension']],
    ['git source', ['git+https://example.test/@ariava/pi-extension.git']],
    ['url source', ['https://example.test/@ariava/pi-extension.tgz']],
  ])('rejects unmanaged ownership: %s', (_label, packages) => {
    const state = fixture({ packages });
    expect(() => ensureExactPiPackage('1.2.3', state.deps)).toThrow(expect.objectContaining({ code: 'ERR_EXTENSION_UNMANAGED' }));
    expect(state.calls).toEqual([]);
  });

  test('classifies wrong manifest name on an exact registration as unmanaged without mutation', () => {
    const state = fixture({
      packages: ['npm:@ariava/pi-extension@1.2.3'],
      manifest: { name: '@foreign/pi-extension', version: '1.2.3' },
    });
    const status = inspectPiPackage('1.2.3', state.deps);
    expect(status.mismatchReasons).toContain('manifest-name-mismatch');
    expect(() => ensureExactPiPackage('1.2.3', state.deps)).toThrow(expect.objectContaining({ code: 'ERR_EXTENSION_UNMANAGED' }));
    expect(state.calls).toEqual([]);
  });

  test.each([
    ['manifest missing', null, 'ERR_EXTENSION_INSTALL', 'manifest-missing'],
    ['manifest name mismatch', { name: '@foreign/pi-extension', version: '1.2.3' }, 'ERR_EXTENSION_UNMANAGED', 'manifest-name-mismatch'],
    ['manifest version mismatch', { name: '@ariava/pi-extension', version: '9.9.9' }, 'ERR_EXTENSION_VERSION_MISMATCH', 'manifest-version-mismatch'],
  ])('fails post-install verification when %s', (_label, installedManifest, code, reason) => {
    const state = fixture({ installedManifest });
    try {
      ensureExactPiPackage('1.2.3', state.deps);
      throw new Error('expected installation verification to fail');
    } catch (error) {
      expect(error).toMatchObject({ code, data: { mismatchReasons: expect.arrayContaining([reason]) } });
    }
    expect(state.calls).toHaveLength(1);
  });

  test('reports missing Pi distinctly and does not manufacture package evidence', () => {
    const state = fixture({ installResult: { status: null, stdout: '', stderr: '', error: Object.assign(new Error('missing'), { code: 'ENOENT' }) } });
    expect(() => ensureExactPiPackage('1.2.3', state.deps)).toThrow(expect.objectContaining({ code: 'ERR_AGENT_RUNTIME_NOT_FOUND' }));
    expect(state.files.has(manifestPath)).toBe(false);
  });

  test('reports registry failure and preserves settings and unrelated packages', () => {
    const state = fixture({
      packages: ['npm:unrelated@4.0.0'],
      installResult: { status: 1, stdout: '', stderr: 'registry unavailable' },
    });
    const before = state.files.get(settingsPath);
    expect(() => ensureExactPiPackage('1.2.3', state.deps)).toThrow(expect.objectContaining({ code: 'ERR_EXTENSION_INSTALL' }));
    expect(state.files.get(settingsPath)).toBe(before);
    expect(state.files.has(manifestPath)).toBe(false);
  });
});
