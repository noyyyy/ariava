import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, test } from 'bun:test';

const root = resolve(import.meta.dir, '../../..');

describe('Node-backed dev setup', () => {
  test('builds a Node dev-profile entrypoint and runs setup through it', () => {
    const manifest = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    const buildScript = readFileSync(resolve(root, 'scripts/build-bridge.mjs'), 'utf8');

    expect(manifest.scripts['dev:setup']).toBe('npm run build:bridge && node ./apps/bridge/dist/dev-profile-cli.js setup');
    expect(buildScript).toContain("resolve(bridgeRoot, 'src', 'dev-profile-cli.ts')");
  });
});
