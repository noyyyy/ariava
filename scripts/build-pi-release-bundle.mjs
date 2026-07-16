#!/usr/bin/env node
import { mkdirSync, readFileSync, rmSync, writeFileSync, cpSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const repoRoot = resolve(dirname(new URL(import.meta.url).pathname), '..');
const sourceRoot = join(repoRoot, 'extensions', 'pi');
const distPath = join(sourceRoot, 'dist', 'index.js');
const bundleRoot = join(sourceRoot, 'bundle');

if (!existsSync(distPath)) {
  throw new Error(`Missing built pi extension artifact: ${distPath}. Run bun run --cwd extensions/pi build first.`);
}

rmSync(bundleRoot, { recursive: true, force: true });
mkdirSync(bundleRoot, { recursive: true });

cpSync(distPath, join(bundleRoot, 'index.js'));

const sourcePackage = JSON.parse(readFileSync(join(sourceRoot, 'package.json'), 'utf8'));
const version = sourcePackage.version ?? '0.1.2';

writeFileSync(
  join(bundleRoot, 'package.json'),
  `${JSON.stringify(
    {
      name: sourcePackage.name ?? '@ariava/pi-extension',
      version,
      description: sourcePackage.description ?? 'Ariava pi extension for Apple Watch-first agent collaboration.',
      type: 'module',
      main: './index.js',
      files: ['index.js', '.ariava-release-bundle.json'],
      keywords: ['pi-package', 'pi-extension', 'ariava', 'apple-watch', 'coding-agent'],
      homepage: 'https://github.com/noyx/ariava',
      repository: { type: 'git', url: 'git+https://github.com/noyx/ariava.git' },
      pi: {
        extensions: ['./index.js'],
      },
      peerDependencies: {
        '@earendil-works/pi-coding-agent': '*',
      },
    },
    null,
    2,
  )}\n`,
);

writeFileSync(
  join(bundleRoot, '.ariava-release-bundle.json'),
  `${JSON.stringify(
    {
      bundleVersion: version,
      createdAt: new Date().toISOString(),
      entry: 'index.js',
      source: 'extensions/pi/dist/index.js',
    },
    null,
    2,
  )}\n`,
);

console.log(`Built pi release bundle at ${bundleRoot}`);
