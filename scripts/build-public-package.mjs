#!/usr/bin/env node

import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packageName = process.argv[2];
const entries = packageName === 'protocol'
  ? ['index', 'commands', 'events', 'hosts', 'identity', 'pairing', 'request-signing', 'sessions', 'validation']
  : packageName === 'shared-utils'
    ? ['index']
    : undefined;

if (!entries) {
  console.error('usage: build-public-package.mjs <protocol|shared-utils>');
  process.exit(2);
}

const packageRoot = resolve(root, 'packages', packageName);
const dist = resolve(packageRoot, 'dist');
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

const build = spawnSync('bun', [
  'build',
  ...entries.map((entry) => resolve(packageRoot, 'src', `${entry}.ts`)),
  '--outdir', dist,
  '--root', resolve(packageRoot, 'src'),
  '--target', 'node',
  '--format', 'esm',
  '--external', '@ariava/*',
], { cwd: root, encoding: 'utf8', stdio: 'inherit', shell: false });
if (build.status !== 0) process.exit(build.status ?? 1);

const declarations = spawnSync('bunx', [
  'tsc', '-p', resolve(packageRoot, 'tsconfig.build.json'),
], { cwd: root, encoding: 'utf8', stdio: 'inherit', shell: false });
if (declarations.status !== 0) process.exit(declarations.status ?? 1);

if (packageName === 'protocol') {
  const fixtureDir = resolve(dist, 'fixtures');
  mkdirSync(fixtureDir, { recursive: true });
  cpSync(
    resolve(packageRoot, 'test', 'fixtures', 'ed25519-request-vectors.json'),
    resolve(fixtureDir, 'ed25519-request-vectors.json'),
  );
}
