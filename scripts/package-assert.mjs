#!/usr/bin/env node
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const assertionScript = resolve(repositoryRoot, 'scripts', 'assert-npm-package.mjs');
const temporaryDirectory = mkdtempSync(join(tmpdir(), 'ariava-package-assert-'));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    shell: false,
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  return result;
}

try {
  run('bunx', ['tsc', '-p', resolve(repositoryRoot, 'packages/protocol/tsconfig.contract.json')], { stdio: 'inherit' });
  const dryRun = run('npm', ['pack', '--dry-run', '--json']);
  const packJson = join(temporaryDirectory, 'pack.json');
  writeFileSync(packJson, dryRun.stdout);
  run(process.execPath, [assertionScript, packJson], { stdio: 'inherit' });

  const packed = run('npm', ['pack', '--json', '--pack-destination', temporaryDirectory]);
  let packResult;
  try { packResult = JSON.parse(packed.stdout)?.[0]; }
  catch { throw new Error('npm pack did not return valid JSON'); }
  if (!packResult?.filename) throw new Error('npm pack did not return a tarball filename');
  run(process.execPath, [
    assertionScript, '--protocol-declarations-only', resolve(temporaryDirectory, packResult.filename),
  ], { stdio: 'inherit' });
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
