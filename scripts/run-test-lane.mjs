#!/usr/bin/env bun
import { readdirSync, rmSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolveBunExecutable } from './bun-executable.mjs';
import { createIsolatedTestEnvironment, createIsolatedTestHome } from './test-environment.mjs';

export const TEST_LANES = ['shared', 'macos', 'linux'];
export const REVIEWED_TEST_ROOTS = [
  'scripts',
  'packages/protocol/test',
  'packages/shared-utils/test',
  'apps/bridge/test',
];

const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));

export function classifyTestFile(path) {
  const normalized = path.split(sep).join('/');
  const name = normalized.slice(normalized.lastIndexOf('/') + 1);
  if (/\.integration\.test\.[^.]+$/u.test(name)) return 'integration';
  if (name.endsWith('.macos.test.ts')) return 'macos';
  if (name.endsWith('.linux.test.ts')) return 'linux';
  if (name.endsWith('.test.ts')) return 'shared';
  if (/(?:\.(?:test|spec)\.|_(?:test|spec)(?:_|\.))/u.test(name)) return 'unclassified';
  return undefined;
}

function walk(directory, files) {
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walk(path, files);
    else if (entry.isFile()) files.push(path);
  }
}

export function collectTestInventory(options = {}) {
  const root = resolve(options.repositoryRoot ?? repositoryRoot);
  const reviewedRoots = options.reviewedRoots ?? REVIEWED_TEST_ROOTS;
  const inventory = [];
  for (const reviewedRoot of reviewedRoots) {
    const absoluteRoot = resolve(root, reviewedRoot);
    const files = [];
    walk(absoluteRoot, files);
    for (const absolutePath of files) {
      const path = relative(root, absolutePath).split(sep).join('/');
      const classification = classifyTestFile(path);
      if (classification) inventory.push({ path, classification });
    }
  }
  return inventory.sort((left, right) => left.path.localeCompare(right.path));
}

export function collectTestLane(lane, options = {}) {
  if (!TEST_LANES.includes(lane)) {
    throw new Error(`Unknown test lane ${JSON.stringify(lane)}. Expected one of: ${TEST_LANES.join(', ')}.`);
  }
  const inventory = collectTestInventory(options);
  const unclassified = inventory.filter((entry) => entry.classification === 'unclassified');
  if (unclassified.length > 0) {
    throw new Error(`Unclassified test files under reviewed roots:\n${unclassified.map((entry) => `- ${entry.path}`).join('\n')}`);
  }
  const paths = inventory.filter((entry) => entry.classification === lane).map((entry) => entry.path);
  if (paths.length === 0) throw new Error(`Test lane ${lane} collected no files.`);
  return paths;
}
export function runTestLane(lane, options = {}) {
  const root = resolve(options.repositoryRoot ?? repositoryRoot);
  const reviewedRoots = options.reviewedRoots ?? REVIEWED_TEST_ROOTS;
  const paths = collectTestLane(lane, { ...options, repositoryRoot: root, reviewedRoots });
  const bunPath = resolveBunExecutable({ bunPath: options.bunPath, env: options.env ?? process.env });
  const spawn = options.spawnSync ?? spawnSync;
  const groups = reviewedRoots
    .map((reviewedRoot) => paths.filter((path) => path === reviewedRoot || path.startsWith(`${reviewedRoot}/`)))
    .filter((group) => group.length > 0);
  for (const group of groups) {
    const testHome = createIsolatedTestHome();
    const environment = createIsolatedTestEnvironment(options.env ?? process.env, testHome);
    try {
      const result = spawn(bunPath, ['test', ...group.map((path) => `./${path}`)], {
        cwd: root,
        env: environment,
        encoding: 'utf8',
        shell: false,
        stdio: options.stdio ?? 'inherit',
      });
      if (result.error) throw result.error;
      if (result.status !== 0) return result.status ?? 1;
    } finally {
      rmSync(testHome, { recursive: true, force: true });
    }
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = runTestLane(process.argv[2]);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
