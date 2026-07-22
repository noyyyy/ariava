#!/usr/bin/env node
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const temporaryDirectory = mkdtempSync(join(tmpdir(), 'ariava-package-assert-'));
const packJson = join(temporaryDirectory, 'pack.json');

try {
  const packed = spawnSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    shell: false,
  });
  if (packed.error) throw packed.error;
  if (packed.status !== 0) {
    process.stderr.write(packed.stderr);
    process.exit(packed.status ?? 1);
  }
  writeFileSync(packJson, packed.stdout);
  const asserted = spawnSync(process.execPath, [resolve(repositoryRoot, 'scripts', 'assert-npm-package.mjs'), packJson], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    shell: false,
    stdio: 'inherit',
  });
  if (asserted.error) throw asserted.error;
  process.exitCode = asserted.status ?? 1;
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
