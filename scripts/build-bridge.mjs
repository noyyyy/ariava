#!/usr/bin/env node
import { copyFileSync, mkdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, '..');
const bridgeRoot = resolve(repositoryRoot, 'apps', 'bridge');
const outputDirectory = resolve(bridgeRoot, 'dist');
const assetSourceDirectory = resolve(bridgeRoot, 'src', 'ui', 'assets');
const assetOutputDirectory = resolve(outputDirectory, 'ui', 'assets');
const reviewedAssets = ['ariava-success-wide.txt', 'ariava-success-compact.txt'];

// Clear the complete Bridge output so removed entrypoints or assets cannot survive a build.
rmSync(outputDirectory, { recursive: true, force: true });
const built = spawnSync('bun', [
  'build',
  resolve(bridgeRoot, 'src', 'cli.ts'),
  resolve(bridgeRoot, 'src', 'public-cli.ts'),
  resolve(bridgeRoot, 'src', 'e2e', 'node-crypto.ts'),
  resolve(bridgeRoot, 'src', 'e2e', 'node-crypto-self-test.ts'),
  '--outdir', outputDirectory,
  '--target', 'node',
  '--format', 'esm',
], { cwd: repositoryRoot, encoding: 'utf8', shell: false, stdio: 'inherit' });
if (built.error) throw built.error;
if (built.status !== 0) process.exit(built.status ?? 1);

mkdirSync(assetOutputDirectory, { recursive: true, mode: 0o755 });
for (const asset of reviewedAssets) {
  const destination = resolve(assetOutputDirectory, asset);
  copyFileSync(resolve(assetSourceDirectory, asset), destination);
}

console.log(`Bridge build complete; copied ${reviewedAssets.length} reviewed text assets.`);
