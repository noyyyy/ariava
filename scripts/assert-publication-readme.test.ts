import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = join(dirname(fileURLToPath(import.meta.url)), 'assert-publication-readme.mjs');

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

const requiredPublicationText = [
  ['recommended npx command', 'npx --yes ariava@latest setup'],
  ['canonical Relay', 'https://ariava-relay.noyx.io'],
  ['Pi reload instruction', '/reload'],
  ['explicit pairing', 'ariava pair <PAIRING_CODE>'],
  ['manual init', 'ariava init'],
  ['manual service install', 'ariava service install'],
  ['manual Pi install', 'ariava install pi'],
  ['doctor', 'ariava doctor'],
] as const;
const requiredText = `\n${requiredPublicationText.map(([, text]) => text).join('\n')}\n`;

function publishableReadme(overrides = requiredText): string {
  return `<!-- ARIAVA_PUBLIC_CORE_README: PUBLISHABLE -->\n# Ariava Public Core\n${overrides}`;
}

describe('publication README guard', () => {
  test('rejects the transition private Product README marker', () => {
    const result = check('<!-- ARIAVA_PRIVATE_PRODUCT_README: DO_NOT_PUBLISH -->\n# Ariava\n');
    expect(result.exitCode).toBe(1);
    expect(result.stderr.toString()).toContain('private Product README');
  });

  test('rejects an unmarked README and accepts a marked README with required onboarding text', () => {
    expect(check(`# Ariava\n${requiredText}`).exitCode).toBe(1);
    const result = check(publishableReadme());
    expect(result.exitCode, result.stderr.toString()).toBe(0);
  });

  test.each(requiredPublicationText)('rejects a README missing %s', (_label, required) => {
    const result = check(publishableReadme(requiredText.replace(required, '')));
    expect(result.exitCode).toBe(1);
    expect(result.stderr.toString()).toContain(required);
  });
});
