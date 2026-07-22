import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const dist = join(root, 'extensions/pi/dist/index.js');
const bundle = join(root, 'extensions/pi/bundle');
const script = join(root, 'scripts/build-pi-release-bundle.mjs');
const originalDist = existsSync(dist) ? readFileSync(dist) : undefined;

function ensureDist() {
  if (!existsSync(dist)) {
    mkdirSync(join(dist, '..'), { recursive: true });
    writeFileSync(dist, 'export default function ariavaPiExtension() {}\n');
  }
}

beforeAll(() => {
  ensureDist();
});

afterAll(() => {
  if (originalDist === undefined) rmSync(join(root, 'extensions/pi/dist'), { recursive: true, force: true });
  else writeFileSync(dist, originalDist);
  ensureDist();
  const result = Bun.spawnSync({ cmd: [process.execPath, script], stdout: 'pipe', stderr: 'pipe' });
  if (result.exitCode !== 0) throw new Error(result.stderr.toString());
});

async function build(epoch: string) {
  ensureDist();
  const result = Bun.spawnSync({
    cmd: [process.execPath, script],
    env: { ...process.env, SOURCE_DATE_EPOCH: epoch },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  return {
    manifest: readFileSync(join(bundle, 'package.json'), 'utf8'),
    marker: readFileSync(join(bundle, '.ariava-release-bundle.json'), 'utf8'),
  };
}

describe('deterministic pi release bundle metadata', () => {
  test('SOURCE_DATE_EPOCH produces byte-identical metadata for a release commit', async () => {
    const first = await build('1784678400');
    const second = await build('1784678400');
    expect(second).toEqual(first);
    expect(JSON.parse(first.marker).createdAt).toBe('2026-07-22T00:00:00.000Z');
  });

  test('rejects invalid deterministic timestamps', () => {
    ensureDist();
    const result = Bun.spawnSync({
      cmd: [process.execPath, script],
      env: { ...process.env, SOURCE_DATE_EPOCH: '-1' },
      stdout: 'pipe', stderr: 'pipe',
    });
    expect(result.exitCode).toBe(1);
    expect(result.stderr.toString()).toContain('SOURCE_DATE_EPOCH');
  });
});
