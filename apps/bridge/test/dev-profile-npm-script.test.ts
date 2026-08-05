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

    expect(manifest.scripts['dev:cli']).toBe('node ./scripts/build-bridge.mjs && node ./apps/bridge/dist/dev-profile-cli.js');
    expect(manifest.scripts['dev:setup']).toBe('node ./scripts/build-bridge.mjs && node ./apps/bridge/dist/dev-profile-cli.js setup');
    expect(Object.keys(manifest.scripts).filter((name) => name.startsWith('dev:'))).toEqual(['dev:cli', 'dev:setup']);
    expect(manifest.scripts['build:protocol']).toBeUndefined();
    expect(manifest.scripts['build:shared-utils']).toBeUndefined();
    expect(manifest.scripts['build:bridge']).toBeUndefined();
    expect(buildScript).toContain("resolve(bridgeRoot, 'src', 'dev-profile-cli.ts')");
  });
});
