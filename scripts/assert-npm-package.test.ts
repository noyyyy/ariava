import { describe, expect, test } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const helper = join(process.cwd(), 'scripts', 'assert-npm-package.mjs');
const required = [
  'package.json', 'apps/bridge/dist/cli.js', 'apps/bridge/dist/public-cli.js',
  'apps/bridge/dist/ui/assets/ariava-success-wide.txt',
  'apps/bridge/dist/ui/assets/ariava-success-compact.txt',
  'packages/protocol/dist/index.js', 'packages/protocol/dist/index.d.ts',
  'packages/protocol/dist/events.js', 'packages/protocol/dist/events.d.ts',
  'packages/protocol/dist/fixtures/ed25519-request-vectors.json',
  'packages/shared-utils/dist/index.js', 'packages/shared-utils/dist/index.d.ts',
  'extensions/pi/bundle/index.js', 'extensions/pi/bundle/package.json',
];

function run(paths: string[]) {
  const root = mkdtempSync(join(tmpdir(), 'ariava-package-assert-'));
  const input = join(root, 'pack.json');
  writeFileSync(input, JSON.stringify([{ files: paths.map((path) => ({ path })) }]));
  const result = Bun.spawnSync({ cmd: [process.execPath, helper, input], stdout: 'pipe', stderr: 'pipe' });
  rmSync(root, { recursive: true, force: true });
  return result;
}

function runTarball(paths: string[]) {
  const root = mkdtempSync(join(tmpdir(), 'ariava-package-tarball-'));
  const packageRoot = join(root, 'package');
  for (const path of paths) {
    const target = join(packageRoot, path);
    mkdirSync(join(target, '..'), { recursive: true });
    writeFileSync(target, 'fixture');
  }
  const tarball = join(root, 'fixture.tgz');
  const packed = spawnSync('/usr/bin/tar', ['-czf', tarball, '-C', root, 'package'], { encoding: 'utf8' });
  if (packed.status !== 0) throw new Error(packed.stderr);
  const result = Bun.spawnSync({ cmd: [process.execPath, helper, tarball], stdout: 'pipe', stderr: 'pipe' });
  rmSync(root, { recursive: true, force: true });
  return result;
}

describe('npm package artifact assertion', () => {
  test('accepts the required Bridge, protocol, shared utils, and pi bundle artifacts', () => {
    const result = run(required);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString()).toContain(`${required.length} required artifacts`);
  });

  test('rejects a missing reviewed asset and private, source, image, or otherwise unexpected artifacts', () => {
    expect(run(required.filter((path) => path !== 'apps/bridge/dist/ui/assets/ariava-success-wide.txt')).exitCode).toBe(1);
    for (const forbidden of [
      'helpers/Identity.swift',
      'apps/relay/dist/worker.js',
      'apps/watchos/Ariava/App/AriavaApp.swift',
      'docs/release.md',
      'screenshots/watch.png',
      'scripts/private-deploy.sh',
      'packages/protocol/src/index.ts',
      'packages/protocol/dist/index.js.map',
      'apps/bridge/dist/ui/assets/ariava.png',
      'apps/bridge/dist/ui/assets/unreviewed.txt',
      'Users/example/private.txt',
      'ariava-private/README.md',
    ]) {
      const result = run([...required, forbidden]);
      expect(result.exitCode, `${forbidden}: ${result.stderr.toString()}`).toBe(1);
    }
  });

  test('asserts actual tarball contents and rejects unexpected private files', () => {
    expect(runTarball(required).exitCode).toBe(0);
    expect(runTarball(required.slice(1)).exitCode).toBe(1);
    expect(runTarball([...required, 'apps/relay/dist/worker.js']).exitCode).toBe(1);
  });
});
