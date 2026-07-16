import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const script = join(process.cwd(), 'scripts', 'assert-publication-readme.mjs');

function check(readme: string) {
  const root = mkdtempSync(join(tmpdir(), 'ariava-publication-readme-'));
  try {
    writeFileSync(join(root, 'README.md'), readme);
    return Bun.spawnSync({
      cmd: [process.execPath, script, '--root', root],
      stdout: 'pipe',
      stderr: 'pipe',
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe('publication README guard', () => {
  test('rejects the transition private Product README marker', () => {
    const result = check('<!-- ARIAVA_PRIVATE_PRODUCT_README: DO_NOT_PUBLISH -->\n# Ariava\n');
    expect(result.exitCode).toBe(1);
    expect(result.stderr.toString()).toContain('private Product README');
  });

  test('rejects an unmarked README and accepts only a generated Public Core marker', () => {
    expect(check('# Ariava\n').exitCode).toBe(1);
    const result = check('<!-- ARIAVA_PUBLIC_CORE_README: PUBLISHABLE -->\n# Ariava Public Core\n');
    expect(result.exitCode, result.stderr.toString()).toBe(0);
  });
});
