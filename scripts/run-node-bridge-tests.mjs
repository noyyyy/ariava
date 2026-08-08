#!/usr/bin/env node
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const testRoot = resolve(repositoryRoot, 'apps/bridge/test-node');

export function collectNodeBridgeTests() {
  return readdirSync(testRoot, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.test.mjs'))
    .map((entry) => `./apps/bridge/test-node/${entry.name}`)
    .sort();
}

export function runNodeBridgeTests(options = {}) {
  const spawn = options.spawnSync ?? spawnSync;
  const result = spawn(process.execPath, ['--test', ...collectNodeBridgeTests()], {
    cwd: repositoryRoot,
    env: options.env ?? process.env,
    encoding: 'utf8',
    shell: false,
    stdio: options.stdio ?? 'inherit',
  });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runNodeBridgeTests();
}
