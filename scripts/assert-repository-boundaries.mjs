#!/usr/bin/env node

import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { dirname, extname, isAbsolute, relative, resolve, sep, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_MANIFEST = resolve(SCRIPT_DIR, 'public-core-manifest.json');
const TEXT_EXTENSIONS = new Set([
  '', '.cjs', '.css', '.html', '.ini', '.js', '.json', '.jsonc', '.md', '.mjs', '.plist',
  '.rb', '.sh', '.swift', '.toml', '.ts', '.tsx', '.txt', '.yaml', '.yml',
]);

function usage() {
  return `Usage: node scripts/assert-repository-boundaries.mjs --mode <transition|public-candidate> --root <path> [--manifest <path>] [--report-only]\n\n` +
    `Checks fail on violations by default. --report-only is allowed only in transition mode and reports current known violations without failing.\n`;
}

function parseArgs(argv) {
  const options = { mode: undefined, root: undefined, manifest: DEFAULT_MANIFEST, reportOnly: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') return { help: true };
    if (argument === '--report-only') {
      options.reportOnly = true;
      continue;
    }
    if (!['--mode', '--root', '--manifest'].includes(argument)) throw new Error(`Unknown option: ${argument}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${argument}`);
    index += 1;
    if (argument === '--mode') options.mode = value;
    if (argument === '--root') options.root = value;
    if (argument === '--manifest') options.manifest = resolve(value);
  }
  if (!['transition', 'public-candidate'].includes(options.mode)) throw new Error('--mode must be transition or public-candidate');
  if (!options.root) throw new Error('--root is required');
  if (options.reportOnly && options.mode !== 'transition') throw new Error('--report-only is allowed only in transition mode');
  options.root = resolve(options.root);
  return options;
}

function normalizeManifestPath(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${field} contains an invalid path`);
  if (isAbsolute(value) || win32.isAbsolute(value) || value.startsWith('\\\\')) {
    throw new Error(`${field} contains path traversal or an absolute path: ${value}`);
  }
  const normalized = value.replaceAll('\\', '/').replace(/^\.\//u, '').replace(/\/+$/u, '');
  const segments = normalized.split('/');
  if (!normalized || segments.some((segment) => segment === '..' || segment === '')) {
    throw new Error(`${field} contains path traversal or an absolute path: ${value}`);
  }
  return normalized;
}

function normalizeManifest(manifest) {
  const pathLists = [
    'publicSourceRoots', 'publicSourceFiles', 'publicRequiredFiles', 'transitionRequiredRootFiles',
    'generatedCandidateRootFiles', 'generatedCandidatePaths', 'excludedPaths',
  ];
  for (const field of pathLists) {
    if (!Array.isArray(manifest[field])) throw new Error(`Manifest is missing ${field}`);
    manifest[field] = manifest[field].map((value) => normalizeManifestPath(value, field));
  }
  if (!Array.isArray(manifest.generatedPathSegments) || !Array.isArray(manifest.credentialFileNames) || !Array.isArray(manifest.credentialFilePatterns)) {
    throw new Error('Manifest is missing generatedPathSegments, credentialFileNames, or credentialFilePatterns');
  }
  if (!manifest.scriptClassifications || typeof manifest.scriptClassifications !== 'object') {
    throw new Error('Manifest is missing scriptClassifications');
  }
  const allowedClasses = new Set(['public', 'private', 'review-required']);
  const normalizedClassifications = {};
  for (const [path, classification] of Object.entries(manifest.scriptClassifications)) {
    const normalized = normalizeManifestPath(path, 'scriptClassifications');
    if (!normalized.startsWith('scripts/')) throw new Error(`Script classification is outside scripts/: ${path}`);
    if (!allowedClasses.has(classification)) throw new Error(`Invalid script classification for ${path}: ${classification}`);
    normalizedClassifications[normalized] = classification;
  }
  manifest.scriptClassifications = normalizedClassifications;
  return manifest;
}

function hasPathPrefix(path, prefix) {
  return path === prefix || path.startsWith(`${prefix}/`);
}

function isInside(parent, child) {
  const path = relative(parent, child);
  return path === '' || (!path.startsWith(`..${sep}`) && path !== '..' && !isAbsolute(path));
}

async function walk(root, ignoredPrefixes = []) {
  const files = [];
  const symlinks = [];
  async function visit(directory, relativeDirectory = '') {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const relativePath = relativeDirectory ? `${relativeDirectory}/${entry.name}` : entry.name;
      if (ignoredPrefixes.some((prefix) => hasPathPrefix(relativePath, prefix))) continue;
      const absolutePath = resolve(directory, entry.name);
      if (entry.isSymbolicLink()) symlinks.push({ path: relativePath, absolutePath });
      else if (entry.isDirectory()) await visit(absolutePath, relativePath);
      else if (entry.isFile()) files.push({ path: relativePath, absolutePath });
    }
  }
  await visit(root);
  return { files, symlinks };
}

function isTextFile(path) {
  return TEXT_EXTENSIONS.has(extname(path).toLowerCase()) || path.split('/').at(-1) === 'LICENSE';
}

function publicOwned(path, manifest) {
  return manifest.publicSourceRoots.some((prefix) => hasPathPrefix(path, prefix)) ||
    manifest.publicSourceFiles.includes(path) || manifest.scriptClassifications[path] === 'public';
}

function expectedCandidate(path, manifest) {
  const generated = manifest.generatedCandidatePaths.some((prefix) => hasPathPrefix(path, prefix));
  return manifest.publicSourceFiles.includes(path) || manifest.publicRequiredFiles.includes(path) ||
    manifest.scriptClassifications[path] === 'public' || manifest.generatedCandidateRootFiles.includes(path) || generated;
}

function add(violations, code, path, detail) {
  violations.push({ code, path, detail });
}

// Replaces comments with spaces while retaining strings, newlines, and offsets. This avoids
// treating commented examples as imports without attempting to be a full JS/TS parser.
function maskJsComments(source) {
  let result = '';
  let state = 'code';
  let quote = '';
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    if (state === 'line') {
      if (char === '\n') { state = 'code'; result += '\n'; } else result += ' ';
    } else if (state === 'block') {
      if (char === '*' && next === '/') { result += '  '; index += 1; state = 'code'; }
      else result += char === '\n' ? '\n' : ' ';
    } else if (state === 'string') {
      result += char;
      if (char === '\\') { if (next !== undefined) { result += next; index += 1; } }
      else if (char === quote) state = 'code';
    } else if (char === '/' && next === '/') {
      result += '  '; index += 1; state = 'line';
    } else if (char === '/' && next === '*') {
      result += '  '; index += 1; state = 'block';
    } else {
      result += char;
      if (char === '"' || char === "'" || char === '`') { state = 'string'; quote = char; }
    }
  }
  return result;
}

function lineNumberAt(content, offset) {
  let line = 1;
  for (let index = 0; index < offset; index += 1) if (content[index] === '\n') line += 1;
  return line;
}

function addMatches(violations, content, path, regex, code, detail) {
  for (const match of content.matchAll(regex)) add(violations, code, `${path}:${lineNumberAt(content, match.index ?? 0)}`, detail);
}

function isSyntheticPortableHomePath(value) {
  const normalized = value.trimStart().replace(/^["'`(=]+/u, '').replaceAll('\\', '/');
  if (normalized.startsWith('/fixture/home/')) return true;
  if (/^\/home\/(?:test|user|ariava-test|\$\{?USER\}?)(?:\/|$)/u.test(normalized)) return true;
  if (/^\/home\/\$VM_USER(?:\/|$)/u.test(normalized)) return true;
  if (/^\/Users\/(?:test|user|demo)(?:\/|$)/u.test(normalized)) return true;
  if (/^\/home\/(?:测试|\$\$?\{?USER\}?)(?:\/|$)/u.test(normalized)) return true;
  if (normalized.includes(['/', 'home', '/$${USER}/'].join(''))) return true;
  if (/^[A-Za-z]:\/Users\/test(?:\/|$)/u.test(normalized)) return true;
  return false;
}

function isScannerSelfTest(path) {
  return path === 'scripts/assert-repository-boundaries.mjs' || path === 'scripts/assert-repository-boundaries.test.ts';
}

async function inspect({ mode, root, manifest }) {
  const violations = [];
  const rootStat = await lstat(root).catch(() => undefined);
  if (!rootStat?.isDirectory()) throw new Error(`Root is not a directory: ${root}`);
  const rootRealPath = await realpath(root);
  const ignoredPrefixes = mode === 'transition'
    ? [...manifest.excludedPaths.filter((path) => path.startsWith('.') || path === 'node_modules'), 'docs']
    : [
      '.git', 'node_modules', 'apps/bridge/node_modules', 'extensions/pi/node_modules', 'packages/protocol/node_modules', 'packages/shared-utils/node_modules',
    ];
  const { files, symlinks } = await walk(root, ignoredPrefixes);
  const present = new Set([...files.map(({ path }) => path), ...symlinks.map(({ path }) => path)]);

  for (const { path, absolutePath } of symlinks) {
    const target = await realpath(absolutePath).catch(() => undefined);
    if (!target || !isInside(rootRealPath, target)) {
      add(violations, 'SYMLINK_ESCAPE', path, 'symlink is broken or resolves outside the inspected root');
      continue;
    }
    if (publicOwned(path, manifest)) {
      const relativeTarget = relative(rootRealPath, target).split(sep).join('/');
      const excluded = manifest.excludedPaths.find((prefix) => hasPathPrefix(relativeTarget, prefix));
      if (excluded) add(violations, 'SYMLINK_PRIVATE_TARGET', path, `symlink resolves into excluded path ${excluded}`);
    }
  }

  const scripts = [...present].filter((path) => path.startsWith('scripts/') && !path.includes('/node_modules/'));
  for (const path of scripts) {
    if (!manifest.scriptClassifications[path]) add(violations, 'UNCLASSIFIED_SCRIPT', path, 'every scripts/** file must be classified as public, private, or review-required');
  }
  for (const path of Object.keys(manifest.scriptClassifications)) {
    if (mode === 'transition' && !present.has(path)) add(violations, 'MISSING_CLASSIFIED_SCRIPT', path, 'classified script does not exist in the transition tree');
  }

  const publicScripts = Object.entries(manifest.scriptClassifications)
    .filter(([, classification]) => classification === 'public').map(([path]) => path);
  const requiredTransition = [...manifest.publicSourceFiles, ...manifest.publicRequiredFiles, ...manifest.transitionRequiredRootFiles];
  const requiredCandidate = [...manifest.publicSourceFiles, ...manifest.publicRequiredFiles, ...publicScripts, ...manifest.generatedCandidateRootFiles];
  for (const path of mode === 'transition' ? requiredTransition : requiredCandidate) {
    if (!present.has(path)) add(violations, mode === 'transition' ? 'MISSING_TRANSITION_FILE' : 'MISSING_CANDIDATE_FILE', path, 'required manifest file is missing');
  }
  for (const path of manifest.publicSourceRoots) {
    if (![...present].some((candidate) => hasPathPrefix(candidate, path))) add(violations, 'MISSING_PUBLIC_ROOT', path, 'required public source root is empty or missing');
  }

  if (mode === 'public-candidate') {
    for (const path of present) {
      const excluded = manifest.excludedPaths.find((prefix) => hasPathPrefix(path, prefix));
      if (excluded) add(violations, 'PRIVATE_PATH', path, `candidate includes excluded path ${excluded}`);
      const generated = path.split('/').find((segment) => manifest.generatedPathSegments.includes(segment));
      const allowedGenerated = manifest.generatedCandidatePaths.some((prefix) => hasPathPrefix(path, prefix));
      if (generated && !allowedGenerated) add(violations, 'GENERATED_PATH', path, `candidate includes generated/cache segment ${generated} outside the explicit generated allowlist`);
      const basename = path.split('/').at(-1) ?? '';
      if (manifest.credentialFileNames.includes(basename) || manifest.credentialFilePatterns.some((pattern) => new RegExp(pattern, 'u').test(basename))) {
        add(violations, 'CREDENTIAL_FILE', path, 'candidate includes a credential-bearing filename');
      }
      if (path.startsWith('scripts/') && manifest.scriptClassifications[path] !== 'public') add(violations, 'NON_PUBLIC_SCRIPT', path, `candidate script is classified ${manifest.scriptClassifications[path] ?? 'unclassified'}`);
      if (!expectedCandidate(path, manifest)) add(violations, 'UNEXPECTED_CANDIDATE_FILE', path, 'file is not in a public source root, public file allowlist, or generated root allowlist');
    }
  }

  for (const { path, absolutePath } of files) {
    if (!isTextFile(path)) continue;
    const content = await readFile(absolutePath, 'utf8').catch(() => undefined);
    if (content === undefined || content.includes('\u0000')) continue;
    const scanContent = /\.(?:[cm]?[jt]sx?)$/u.test(path) ? maskJsComments(content) : content;
    addMatches(violations, scanContent, path,
      /(?:\bfrom\s*|\bimport\s*(?:\(|)|\brequire\s*\()\s*["'][^"']*(?:\.\.\/)+packages\/(?:protocol|shared-utils)\/src(?:\/|["'])/gu,
      'DEEP_PACKAGE_IMPORT', 'consumer traverses packages/protocol or packages/shared-utils src; use a package export');
    if (publicOwned(path, manifest)) {
      addMatches(violations, scanContent, path,
        /(?:\bfrom\s*|\bimport\s*(?:\(|)|\brequire\s*\()\s*["'](?:\.\.\/)+(?:apps\/)?(?:relay|watchos)(?:\/|["'])/gu,
        'PRIVATE_IMPORT', 'public-owned file imports private Relay/watchOS code');
    }
    if (mode !== 'public-candidate') continue;
    const tool = String.raw`(?:wrangler|xcodebuild|asc)`;
    const executableTool = new RegExp(
      String.raw`(?:\b(?:spawn|spawnSync|exec|execFile|execFileSync)\s*\(\s*(?:\[\s*)?["']${tool}["']|\b(?:cmd|command|args)\s*:\s*\[\s*["']${tool}["']|\[\s*["']${tool}["']\s*(?:,|\]))`,
      'gu',
    );
    addMatches(violations, scanContent, path, executableTool, 'PRIVATE_TOOLING', 'candidate has an executable dependency on private product tooling');

    const lines = scanContent.split(/\r?\n/u);
    lines.forEach((line, index) => {
      const location = `${path}:${index + 1}`;
      if (/(?:https?:\/\/|ssh:\/\/git@|git@)github\.com(?::|\/)noyyyy\/ariava-private(?:\.git)?/iu.test(line)) add(violations, 'PRIVATE_REPOSITORY_URL', location, 'candidate references the private repository URL');
      const unixHome = new RegExp(String.raw`(?:^|["'\x60\s=(])(?:\/(?:Users|home)\/[^/\s"'\x60]+|\/` + 'root' + String.raw`)(?:\/[^\s"'\x60]*)?`, 'u');
      const windowsHome = /(?:^|["'`\s=(])[A-Za-z]:[\\/]Users[\\/][^\s"'`]+/u;
      const homeMatch = line.match(unixHome)?.[0] ?? line.match(windowsHome)?.[0];
      if (homeMatch && !isScannerSelfTest(path) && !isSyntheticPortableHomePath(homeMatch)) add(violations, 'LOCAL_CHECKOUT_PATH', location, 'candidate contains an absolute developer home path');
      const shellTool = new RegExp(String.raw`(?:^|[;&|` + '`' + String.raw`$]\s*|\b(?:run|exec|x)\s+)${tool}(?:\s|$)`, 'u');
      if (shellTool.test(line)) add(violations, 'PRIVATE_TOOLING', location, 'candidate has an executable dependency on private product tooling');
    });
  }

  violations.sort((left, right) => `${left.path}:${left.code}`.localeCompare(`${right.path}:${right.code}`));
  return violations;
}

export async function assertRepositoryBoundaries(options) {
  const manifestSource = await readFile(options.manifest ?? DEFAULT_MANIFEST, 'utf8');
  const manifest = normalizeManifest(JSON.parse(manifestSource));
  return inspect({ ...options, manifest });
}

async function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) { process.stdout.write(usage()); return; }
    const violations = await assertRepositoryBoundaries(options);
    if (violations.length === 0) { console.log(`Repository boundary check passed (${options.mode}): no violations.`); return; }
    const stream = options.reportOnly ? process.stdout : process.stderr;
    stream.write(`Repository boundary check found ${violations.length} violation(s) (${options.mode}):\n`);
    for (const violation of violations) stream.write(`- [${violation.code}] ${violation.path}: ${violation.detail}\n`);
    if (options.reportOnly) stream.write('Transition report-only mode did not fail the command. Run without --report-only for the strict regression gate.\n');
    else process.exitCode = 1;
  } catch (error) {
    console.error(`Repository boundary check failed: ${error instanceof Error ? error.message : String(error)}`);
    console.error(usage());
    process.exitCode = 2;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
