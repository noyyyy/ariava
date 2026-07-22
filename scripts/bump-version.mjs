#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const PUBLIC_VERSION_FILES = [
  'package.json',
  'apps/bridge/package.json',
  'extensions/pi/package.json',
  'extensions/pi/bundle/package.json',
  'packages/protocol/package.json',
  'packages/shared-utils/package.json',
];

const LOCKFILE = 'bun.lock';

function usage() {
  return `Usage: node scripts/bump-version.mjs <patch|minor|major|x.y.z> [--dry-run] [--root <path>]

Prepares a reviewed Ariava release PR. Normal publication happens after merge
from an annotated stable Public Core tag; see docs/release.md.

Examples:
  node scripts/bump-version.mjs patch
  node scripts/bump-version.mjs 0.1.5
  node scripts/bump-version.mjs patch --dry-run
`;
}

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

function parseArgs(argv) {
  let root = process.cwd();
  let dryRun = false;
  let target;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg === '--root') {
      const value = argv[i + 1];
      if (!value) fail('--root requires a path');
      root = resolve(value);
      i += 1;
    } else if (arg === '-h' || arg === '--help') {
      console.log(usage());
      process.exit(0);
    } else if (!target) {
      target = arg;
    } else {
      fail(`unexpected argument: ${arg}`);
    }
  }

  if (!target) fail(usage());
  return { root, dryRun, target };
}

function readJson(root, file) {
  return JSON.parse(readFileSync(resolve(root, file), 'utf8'));
}

function writeJson(root, file, value) {
  writeFileSync(resolve(root, file), `${JSON.stringify(value, null, 2)}\n`);
}

function parseVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) fail(`invalid semver version: ${version}`);
  return match.slice(1).map((part) => Number.parseInt(part, 10));
}

function nextVersion(current, target) {
  const [major, minor, patch] = parseVersion(current);
  if (target === 'patch') return `${major}.${minor}.${patch + 1}`;
  if (target === 'minor') return `${major}.${minor + 1}.0`;
  if (target === 'major') return `${major + 1}.0.0`;
  parseVersion(target);
  return target;
}

function assertVersionsConsistent(root) {
  const versions = PUBLIC_VERSION_FILES.map((file) => ({ file, version: readJson(root, file).version }));
  const expected = versions[0]?.version;
  for (const { file, version } of versions) {
    if (version !== expected) {
      fail(`version mismatch: package.json is ${expected}, but ${file} is ${version}`);
    }
  }
  return expected;
}

function stripJsoncComments(original) {
  let result = '';
  let inString = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let index = 0; index < original.length; index += 1) {
    const char = original[index];
    const next = original[index + 1];

    if (lineComment) {
      if (char === '\n' || char === '\r') {
        lineComment = false;
        result += char;
      } else {
        result += ' ';
      }
      continue;
    }
    if (blockComment) {
      if (char === '*' && next === '/') {
        result += '  ';
        blockComment = false;
        index += 1;
      } else {
        result += char === '\n' || char === '\r' ? char : ' ';
      }
      continue;
    }
    if (inString) {
      result += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      result += char;
    } else if (char === '/' && next === '/') {
      result += '  ';
      lineComment = true;
      index += 1;
    } else if (char === '/' && next === '*') {
      result += '  ';
      blockComment = true;
      index += 1;
    } else {
      result += char;
    }
  }

  if (blockComment) throw new Error('unterminated block comment');
  return result;
}

function stripJsoncTrailingCommas(original) {
  let result = '';
  let inString = false;
  let escaped = false;

  for (let index = 0; index < original.length; index += 1) {
    const char = original[index];
    if (inString) {
      result += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      result += char;
      continue;
    }
    if (char === ',') {
      let lookahead = index + 1;
      while (/\s/u.test(original[lookahead] ?? '')) lookahead += 1;
      if (original[lookahead] === '}' || original[lookahead] === ']') continue;
    }
    result += char;
  }

  return result;
}

function parseLockfile(original) {
  try {
    return JSON.parse(stripJsoncTrailingCommas(stripJsoncComments(original)));
  } catch (error) {
    fail(`${LOCKFILE} is not valid Bun JSONC: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function replaceWorkspaceVersion(original, workspacePath, current, next) {
  const escapedPath = workspacePath.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const workspacePattern = new RegExp(`("${escapedPath}"\\s*:\\s*\\{)([\\s\\S]*?)(\\n\\s*\\}(?:\\s*,)?)`, 'u');
  const match = workspacePattern.exec(original);
  if (!match) fail(`${LOCKFILE} does not contain public workspace ${workspacePath}`);

  const versionPattern = /("version"\s*:\s*")([^"]+)(")/u;
  const versionMatch = versionPattern.exec(match[2]);
  if (!versionMatch) fail(`${LOCKFILE} workspace ${workspacePath} has no version`);
  if (versionMatch[2] !== current) {
    fail(`${LOCKFILE} workspace ${workspacePath} is ${versionMatch[2]}, expected ${current}`);
  }

  const body = match[2].replace(versionPattern, `$1${next}$3`);
  return `${original.slice(0, match.index)}${match[1]}${body}${match[3]}${original.slice(match.index + match[0].length)}`;
}

function bumpLockfile(root, current, next) {
  const path = resolve(root, LOCKFILE);
  const original = readFileSync(path, 'utf8');
  const parsed = parseLockfile(original);
  const workspaceNames = PUBLIC_VERSION_FILES
    .filter((file) => file !== 'package.json' && file !== 'extensions/pi/bundle/package.json')
    .map((file) => file.replace(/\/package\.json$/u, ''));

  for (const workspacePath of workspaceNames) {
    const version = parsed?.workspaces?.[workspacePath]?.version;
    if (version !== current) {
      fail(`${LOCKFILE} workspace ${workspacePath} is ${version ?? 'missing'}, expected ${current}`);
    }
  }

  return workspaceNames.reduce(
    (lockfile, workspacePath) => replaceWorkspaceVersion(lockfile, workspacePath, current, next),
    original,
  );
}

const { root, dryRun, target } = parseArgs(process.argv.slice(2));
const current = assertVersionsConsistent(root);
const next = nextVersion(current, target);

if (next === current) fail(`target version is already current version: ${current}`);

const nextLockfile = bumpLockfile(root, current, next);

if (!dryRun) {
  for (const file of PUBLIC_VERSION_FILES) {
    const json = readJson(root, file);
    json.version = next;
    writeJson(root, file, json);
  }
  writeFileSync(resolve(root, LOCKFILE), nextLockfile);
}

const prefix = dryRun ? 'Dry run: Ariava version would change' : 'Bumped Ariava version:';
console.log(`${prefix} ${current} -> ${next}`);
console.log('Next steps:');
console.log('  bun install --frozen-lockfile');
console.log('  bun run verify');
console.log('  Review and merge the Public Core release change to the default branch.');
console.log(`  Create and push annotated tag v${next} on that merged commit.`);
console.log('  Observe and, if configured, approve publish-npm.yml in npm-production.');
console.log('  Break-glass/manual instructions: docs/release.md');
