#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const forbiddenRuntime = /event-content-v1|session-content-v1|notification-preview-v1|agent\.(?:working|question|blocked)|question_requested|driver_error|host_unavailable|event\.diagnostic_ingested|statusToStateLabel|\bstateLabel\b/gu;

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

function stripRecognizedPriorResetDecoder(source, entry) {
  if (!entry.match(/^apps\/bridge\/dist\/(?:cli|daemon|dev-profile-cli|public-cli|state-store)\.js$/u) || !source.match(forbiddenRuntime)) return source;
  const priorSessionKeys = source.match(/var PRIOR_SESSION_REQUIRED_KEYS = \[\.\.\.SESSION_REQUIRED_KEYS, "stateLabel"\];/u)?.[0];
  const decoder = source.match(/function isRecognizedPriorSession[^]*?function isRecognizedPriorSpoolMigration\(value\) \{[^]*?\}(?=\s*(?:function|$))/u)?.[0];
  if (!priorSessionKeys || !decoder) fail(`cannot isolate recognized-prior reset decoder in ${entry}`);
  return source.replace(priorSessionKeys, '').replace(decoder, '');
}

function assertCanonicalRuntimePackageContents(tarball, entries) {
  for (const entry of entries.filter((path) => /\.(?:js|json)$/u.test(path))) {
    const active = stripRecognizedPriorResetDecoder(readTarEntry(tarball, entry), entry);
    const match = active.match(forbiddenRuntime)?.[0];
    if (match) fail(`runtime package artifact ${entry} contains ${match}`);
  }
}

const runtimeFixturePaths = {
  vectors: 'packages/protocol/dist/fixtures/e2e-v2-vectors.json',
  preview: 'packages/protocol/dist/fixtures/notification-preview-v2-vector.json',
  parity: 'packages/protocol/dist/fixtures/need-human-error-validation-v2.json',
};

function assertRuntimeFixtureContents(tarball) {
  let vectors;
  let preview;
  let parity;
  try {
    vectors = JSON.parse(readTarEntry(tarball, runtimeFixturePaths.vectors));
    preview = JSON.parse(readTarEntry(tarball, runtimeFixturePaths.preview));
    parity = JSON.parse(readTarEntry(tarball, runtimeFixturePaths.parity));
  } catch { fail('runtime v2 and parity fixtures must be valid JSON'); }
  if (vectors.version !== 2 || vectors.event?.contentId === undefined || vectors.session?.contentId === undefined
    || !String(vectors.event?.contentAAD ?? '').trim() || !String(vectors.session?.contentAAD ?? '').trim()) {
    fail('runtime v2 interoperability fixture is invalid');
  }
  if (preview.version !== 2 || preview.preview?.contentId === undefined || !String(preview.preview?.contentAAD ?? '').trim()) {
    fail('notification preview v2 fixture is invalid');
  }
  if (parity.version !== 2 || !Array.isArray(parity.cases) || parity.cases.length === 0) {
    fail('NeedHuman error parity fixture is invalid');
  }
  const runtimeFixtureBytes = JSON.stringify({ vectors, preview });
  for (const legacy of ['event-content-v1', 'session-content-v1', 'notification-preview-v1']) {
    if (runtimeFixtureBytes.includes(legacy)) fail(`runtime fixture contains ${legacy}`);
  }
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
  /packages\/protocol\/dist\/fixtures\/(?:e2e-v1-vectors|notification-preview-v1-vector)\.json$/u,
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
    assertCanonicalRuntimePackageContents(inputPath, filePaths);
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
  'apps/bridge/dist/e2e/node-crypto.js',
  'apps/bridge/dist/e2e/node-crypto-self-test.js',
  'packages/protocol/dist/index.js',
  'packages/protocol/dist/index.d.ts',
  'packages/protocol/dist/events.js',
  'packages/protocol/dist/events.d.ts',
  'packages/protocol/dist/encryption.js',
  'packages/protocol/dist/encryption.d.ts',
  'packages/protocol/dist/fixtures/ed25519-request-vectors.json',
  ...Object.values(runtimeFixturePaths),
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
  assertRuntimeFixtureContents(inputPath);
  assertCanonicalRuntimePackageContents(inputPath, filePaths);
} else {
  assertPublishedVersion(packVersion, 'pack metadata version');
}
console.log(`npm root package assertion passed: ${required.length} required artifacts present; ${files.size} artifacts allowlisted`);
