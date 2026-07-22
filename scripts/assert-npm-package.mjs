#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const [inputPath] = process.argv.slice(2);
if (!inputPath) {
  console.error('usage: assert-npm-package.mjs <npm-pack-json-or-tarball>');
  process.exit(2);
}

let filePaths;
if (inputPath.endsWith('.tgz')) {
  const listed = spawnSync('tar', ['-tzf', inputPath], { encoding: 'utf8', shell: false });
  if (listed.status !== 0) {
    console.error('npm package assertion failed: tarball could not be listed');
    process.exit(1);
  }
  filePaths = listed.stdout.split(/\r?\n/).filter((path) => path && !path.endsWith('/')).map((path) => path.replace(/^package\//, ''));
} else {
  let payload;
  try {
    payload = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    console.error('npm package assertion failed: input must be valid npm pack --json output or a .tgz');
    process.exit(1);
  }
  filePaths = (payload?.[0]?.files ?? []).map((entry) => entry.path);
}
const files = new Set(filePaths);
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
];
const allowedPrefixes = [
  'apps/bridge/dist/',
  'packages/protocol/dist/',
  'packages/shared-utils/dist/',
  'extensions/pi/bundle/',
];
const reviewedBridgeAssetSet = new Set(reviewedBridgeAssets);
const allowedExactFiles = new Set([
  'package.json',
  'README.md',
  'LICENSE',
  'extensions/pi/bundle/.ariava-release-bundle.json',
]);
const forbiddenPatterns = [
  /(^|\/)apps\/(relay|watchos)(\/|$)/u,
  /(^|\/)(?:docs|screenshots|scripts|node_modules)(\/|$)/u,
  /(^|\/)(?:notify\.js|ariava\.png)$/u,
  /(^|\/)Formula(\/|$)/u,
  /(^|\/)\.github(\/|$)/u,
  /(^|\/)(?:AGENTS|SECURITY|CONTRIBUTING|CODE_OF_CONDUCT)\.md$/u,
  /(^|\/)(?:bun\.lock|bunfig\.toml|tsconfig[^/]*\.json)$/u,
  /(^|\/)\.ariava-release-bundle\.json$/u,
  /(^|\/)\.env(?:\.|$)/u,
  /(^|\/)(?:Users|home)\//u,
  /ariava-private/iu,
  /(^|\/)src(\/|$)/u,
  /(?<!\.d)\.ts$/iu,
  /\.swift$/iu,
  /\.map$/iu,
  /macos-helper/iu,
  /runtime-image/iu,
  /\.(?:png|jpe?g|gif|webp|heic|svg)$/iu,
 ];
const missing = required.filter((path) => !files.has(path));
if (missing.length > 0) {
  console.error(`npm package assertion failed: missing ${missing.join(', ')}`);
  process.exit(1);
}
const unexpected = [...files].filter((path) => {
  if (allowedExactFiles.has(path)) return false;
  if (path.startsWith('apps/bridge/dist/ui/assets/') && !reviewedBridgeAssetSet.has(path)) return true;
  if (!allowedPrefixes.some((prefix) => path.startsWith(prefix))) return true;
  return forbiddenPatterns.some((pattern) => pattern.test(path));
});
if (unexpected.length > 0) {
  console.error(`npm package assertion failed: unexpected artifact(s): ${unexpected.sort().join(', ')}`);
  process.exit(1);
}
console.log(`npm package assertion passed: ${required.length} required artifacts present; ${files.size} artifacts allowlisted`);
