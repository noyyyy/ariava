#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const args = process.argv.slice(2);
let kind = 'root';
let inputPath;
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === '--kind' && ['root', 'pi'].includes(args[index + 1])) {
    kind = args[index + 1];
    index += 1;
  } else if (!inputPath) inputPath = args[index];
  else fail('usage: assert-npm-package.mjs [--kind root|pi] <npm-pack-json-or-tarball>');
}
if (!inputPath) fail('usage: assert-npm-package.mjs [--kind root|pi] <npm-pack-json-or-tarball>');

function fail(message) {
  console.error(`npm package assertion failed: ${message}`);
  process.exit(1);
}

function isValidPublishedSemVer(version) {
  if (typeof version !== 'string') return false;
  const trimmed = version.trim();
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(trimmed)) return false;
  // Published packages must not claim the silent/placeholder 0.0.0 version.
  return trimmed !== '0.0.0';
}

function assertPublishedVersion(version, label = 'package.json.version') {
  if (!isValidPublishedSemVer(version)) {
    fail(`${label} must be a non-placeholder SemVer, got: ${JSON.stringify(version ?? null)}`);
  }
  return typeof version === 'string' ? version.trim() : version;
}

function readTarEntry(tarball, entry) {
  const result = spawnSync('tar', ['-xOf', tarball, `package/${entry}`], { encoding: 'utf8', shell: false });
  if (result.status !== 0) fail(`cannot read ${entry} from tarball`);
  return result.stdout;
}

let filePaths;
let packVersion;
if (inputPath.endsWith('.tgz')) {
  const listed = spawnSync('tar', ['-tzf', inputPath], { encoding: 'utf8', shell: false });
  if (listed.status !== 0) fail('tarball could not be listed');
  filePaths = listed.stdout.split(/\r?\n/u).filter((path) => path && !path.endsWith('/')).map((path) => path.replace(/^package\//u, ''));
} else {
  let payload;
  try { payload = JSON.parse(readFileSync(inputPath, 'utf8')); }
  catch { fail('input must be valid npm pack --json output or a .tgz'); }
  filePaths = (payload?.[0]?.files ?? []).map((entry) => entry.path);
  packVersion = payload?.[0]?.version;
}
const files = new Set(filePaths);

const forbiddenPatterns = [
  /(^|\/)(?:docs|screenshots|scripts|node_modules)(\/|$)/u,
  /(^|\/)(?:notify\.js|ariava\.png)$/u,
  /(^|\/)Formula(\/|$)/u,
  /(^|\/)\.github(\/|$)/u,
  /(^|\/)(?:AGENTS|SECURITY|CONTRIBUTING|CODE_OF_CONDUCT)\.md$/u,
  /(^|\/)(?:bun\.lock|bunfig\.toml|tsconfig[^/]*\.json)$/u,
  /(^|\/)apps\/(relay|watchos)(\/|$)/u,
  /(^|\/)\.env(?:\.|$)/u,
  /ariava-private/iu,
  /(^|\/)(?:Users|home)\//u,
  /(^|\/)src(\/|$)/u,
  /(?<!\.d)\.ts$/iu,
  /\.swift$/iu,
  /\.map$/iu,
  /macos-helper/iu,
  /runtime-image/iu,
  /\.(?:png|jpe?g|gif|webp|heic|svg)$/iu,
];

if (kind === 'pi') {
  const required = ['package.json', 'index.js', '.ariava-release-bundle.json'];
  const missing = required.filter((path) => !files.has(path));
  if (missing.length > 0) fail(`missing ${missing.join(', ')}`);
  const unexpected = [...files].filter((path) => !required.includes(path) || forbiddenPatterns.some((pattern) => pattern.test(path)));
  if (unexpected.length > 0) fail(`unexpected artifact(s): ${unexpected.sort().join(', ')}`);
  if (inputPath.endsWith('.tgz')) {
    let manifest;
    let marker;
    try {
      manifest = JSON.parse(readTarEntry(inputPath, 'package.json'));
      marker = JSON.parse(readTarEntry(inputPath, '.ariava-release-bundle.json'));
    } catch { fail('pi package metadata must be valid JSON'); }
    assertPublishedVersion(manifest.version);
    if (manifest.name !== '@ariava/pi-extension' || manifest.private !== undefined || manifest.type !== 'module'
      || manifest.main !== './index.js' || !manifest.files?.includes('index.js') || !manifest.files?.includes('.ariava-release-bundle.json')
      || !manifest.keywords?.includes('pi-package') || JSON.stringify(manifest.pi?.extensions) !== JSON.stringify(['./index.js'])) {
      fail('pi package public metadata or entrypoint is invalid');
    }
    if (marker.bundleVersion !== manifest.version || marker.entry !== 'index.js' || marker.source !== 'extensions/pi/dist/index.js'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(marker.createdAt ?? '')) {
      fail('pi release bundle marker is invalid');
    }
  } else {
    assertPublishedVersion(packVersion, 'pack metadata version');
  }
  console.log(`npm pi package assertion passed: ${files.size} artifacts allowlisted`);
  process.exit(0);
}

const reviewedBridgeAssets = [
  'apps/bridge/dist/ui/assets/ariava-success-wide.txt',
  'apps/bridge/dist/ui/assets/ariava-success-compact.txt',
];

const required = [
  'package.json',
  'apps/bridge/dist/cli.js',
  'apps/bridge/dist/public-cli.js',
  ...reviewedBridgeAssets,
  'packages/protocol/dist/index.js',
  'packages/protocol/dist/index.d.ts',
  'packages/protocol/dist/events.js',
  'packages/protocol/dist/events.d.ts',
  'packages/protocol/dist/fixtures/ed25519-request-vectors.json',
  'packages/shared-utils/dist/index.js',
  'packages/shared-utils/dist/index.d.ts',
  'extensions/pi/bundle/index.js',
  'extensions/pi/bundle/package.json',
  'extensions/pi/bundle/.ariava-release-bundle.json',
];
const allowedPrefixes = ['apps/bridge/dist/', 'packages/protocol/dist/', 'packages/shared-utils/dist/', 'extensions/pi/bundle/'];
const reviewedBridgeAssetSet = new Set(reviewedBridgeAssets);
const allowedExactFiles = new Set(['package.json', 'README.md', 'LICENSE']);
const missing = required.filter((path) => !files.has(path));
if (missing.length > 0) fail(`missing ${missing.join(', ')}`);
const unexpected = [...files].filter((path) => {
  if (allowedExactFiles.has(path)) return false;
  if (path.startsWith('apps/bridge/dist/ui/assets/') && !reviewedBridgeAssetSet.has(path)) return true;
  if (!allowedPrefixes.some((prefix) => path.startsWith(prefix))) return true;
  return forbiddenPatterns.some((pattern) => pattern.test(path));
});
if (unexpected.length > 0) fail(`unexpected artifact(s): ${unexpected.sort().join(', ')}`);
if (inputPath.endsWith('.tgz')) {
  let manifest;
  try {
    manifest = JSON.parse(readTarEntry(inputPath, 'package.json'));
  } catch { fail('root package.json must be valid JSON'); }
  assertPublishedVersion(manifest.version);
  if (manifest.name !== 'ariava') fail(`root package name must be ariava, got: ${JSON.stringify(manifest.name ?? null)}`);
} else {
  assertPublishedVersion(packVersion, 'pack metadata version');
}
console.log(`npm root package assertion passed: ${required.length} required artifacts present; ${files.size} artifacts allowlisted`);
