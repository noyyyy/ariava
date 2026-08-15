import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const protocolRoot = resolve(import.meta.dir, '..');
const publicRoot = resolve(protocolRoot, '../..');

describe('public Protocol type contracts', () => {
  test('strictly typechecks current v3 and retired export contracts with the local compiler', () => {
    const result = spawnSync(
      resolve(publicRoot, 'node_modules/.bin/tsc'),
      ['-p', resolve(protocolRoot, 'test/type-tests/tsconfig.json')],
      { cwd: publicRoot, encoding: 'utf8', shell: false },
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });
});
