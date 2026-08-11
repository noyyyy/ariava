import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { resolveCliVersion } from '../src/cli/app';
import { findAriavaPackageAuthority } from '../src/cli/package-authority';

const roots: string[] = [];

function writeManifest(root: string, manifest: unknown): void {
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, 'package.json'), `${JSON.stringify(manifest)}\n`);
}

function artifactUrl(path: string): URL {
  return pathToFileURL(path);
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('Ariava package authority', () => {
  test('resolves the Public Repo manifest from the source lifecycle depth', () => {
    const expectedRoot = resolve(import.meta.dir, '..', '..', '..');
    const authority = findAriavaPackageAuthority(artifactUrl(join(
      expectedRoot,
      'apps',
      'bridge',
      'src',
      'cli',
      'lifecycle',
      'default.ts',
    )));

    expect(authority.packageRoot).toBe(expectedRoot);
    expect(authority.manifest.name).toBe('ariava');
    expect(resolveCliVersion('default', () => authority.manifest)).toBe(
      JSON.parse(readFileSync(join(expectedRoot, 'package.json'), 'utf8')).version,
    );
  });

  test('resolves the packed ariava manifest from bundled public-cli depth', () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), 'ariava-package-authority-'));
    roots.push(fixtureRoot);
    writeManifest(fixtureRoot, { name: 'unrelated-consumer', version: '1.0.0' });
    const packageRoot = join(fixtureRoot, 'node_modules', 'ariava');
    writeManifest(packageRoot, { name: 'ariava', version: '0.2.1' });

    const authority = findAriavaPackageAuthority(artifactUrl(join(
      packageRoot,
      'apps',
      'bridge',
      'dist',
      'public-cli.js',
    )));

    expect(authority.packageRoot).toBe(packageRoot);
    expect(resolveCliVersion('default', () => authority.manifest)).toBe('0.2.1');
  });

  test('does not accept an enclosing unrelated manifest and keeps version fallback policy', () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), 'ariava-package-authority-'));
    roots.push(fixtureRoot);
    writeManifest(fixtureRoot, { name: 'unrelated-consumer', version: '1.0.0' });
    const artifact = artifactUrl(join(fixtureRoot, 'node_modules', 'missing', 'dist', 'public-cli.js'));

    expect(() => findAriavaPackageAuthority(artifact)).toThrow('Unable to locate the ariava package.json');
    expect(() => resolveCliVersion('default', () => findAriavaPackageAuthority(artifact).manifest))
      .toThrow('Unable to read Ariava package version');
    expect(resolveCliVersion('dev', () => findAriavaPackageAuthority(artifact).manifest)).toBe('0.0.0-dev');
  });

  test('subjects the located ariava manifest to strict SemVer validation', () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), 'ariava-package-authority-'));
    roots.push(fixtureRoot);
    const packageRoot = join(fixtureRoot, 'node_modules', 'ariava');
    writeManifest(packageRoot, { name: 'ariava', version: 'v0.2.1' });
    const authority = findAriavaPackageAuthority(artifactUrl(join(packageRoot, 'apps', 'bridge', 'dist', 'public-cli.js')));

    expect(() => resolveCliVersion('default', () => authority.manifest)).toThrow('Invalid Ariava package version');
    expect(resolveCliVersion('dev', () => authority.manifest)).toBe('0.0.0-dev');
  });
});
