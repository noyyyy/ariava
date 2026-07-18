import { describe, expect, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const scriptPath = join(process.cwd(), 'scripts', 'bump-version.mjs');
const publicPackageFiles = [
  'package.json',
  'apps/bridge/package.json',
  'extensions/pi/package.json',
  'extensions/pi/bundle/package.json',
  'packages/protocol/package.json',
  'packages/shared-utils/package.json',
];
const relayPackageFile = 'apps/relay/package.json';

function makeFixture(version = '0.1.4') {
  const root = join(tmpdir(), `ariava-bump-version-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  for (const file of [...publicPackageFiles, relayPackageFile]) {
    mkdirSync(join(root, file, '..'), { recursive: true });
    writeFileSync(join(root, file), JSON.stringify({ name: file === 'package.json' ? 'ariava' : file, version }, null, 2) + '\n');
  }
  writeFileSync(join(root, 'bun.lock'), `{
  // Bun lockfiles are JSONC and retain trailing commas.
  "workspaces": {
    "apps/bridge": {
      "name": "@ariava/bridge",
      "version": "${version}",
      "dependencies": {},
    },
    "apps/relay": { "name": "@ariava/relay", "version": "${version}" },
    "extensions/pi": { "name": "@ariava/pi-extension", "version": "${version}" },
    "packages/protocol": { "name": "@ariava/protocol", "version": "${version}" },
    "packages/shared-utils": { "name": "@ariava/shared-utils", "version": "${version}" },
  },
  "packages": {},
}\n`);
  return root;
}

function readJson(path: string) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function readLockfileWorkspaceVersion(lockfile: string, workspacePath: string): string | undefined {
  const escapedPath = workspacePath.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const workspace = new RegExp(`"${escapedPath}"\\s*:\\s*\\{([\\s\\S]*?)\\n\\s*\\}(?:\\s*,)?`, 'u').exec(lockfile)?.[1];
  return workspace ? /"version"\s*:\s*"([^"]+)"/u.exec(workspace)?.[1] : undefined;
}

describe('bump-version release preparation script', () => {
  test('bumps public publish-time versions without modifying the private Relay version', async () => {
    const root = makeFixture();
    try {
      const proc = Bun.spawn({
        cmd: [process.execPath, scriptPath, 'patch', '--root', root],
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stdout, stderr] = await Promise.all([
        proc.exited,
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]);

      expect(exitCode, stderr).toBe(0);
      expect(stdout).toContain('Bumped Ariava version: 0.1.4 -> 0.1.5');
      expect(stdout).toContain('./scripts/publish-npm-safe.sh --publish');

      for (const file of publicPackageFiles) {
        expect(readJson(join(root, file)).version).toBe('0.1.5');
      }
      expect(readJson(join(root, relayPackageFile)).version).toBe('0.1.4');
      const lockfileText = readFileSync(join(root, 'bun.lock'), 'utf8');
      expect(readLockfileWorkspaceVersion(lockfileText, 'apps/bridge')).toBe('0.1.5');
      expect(readLockfileWorkspaceVersion(lockfileText, 'apps/relay')).toBe('0.1.4');
      expect(readLockfileWorkspaceVersion(lockfileText, 'extensions/pi')).toBe('0.1.5');
      expect(readLockfileWorkspaceVersion(lockfileText, 'packages/protocol')).toBe('0.1.5');
      expect(readLockfileWorkspaceVersion(lockfileText, 'packages/shared-utils')).toBe('0.1.5');
      expect(lockfileText).toContain('// Bun lockfiles are JSONC and retain trailing commas.');
      expect(lockfileText).toContain('"dependencies": {},\n    },');
      expect(lockfileText).toContain('"packages": {},\n}');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('dry-run parses JSONC and reports the next version without editing files', async () => {
    const root = makeFixture('1.2.3');
    try {
      const packageBefore = readFileSync(join(root, 'package.json'), 'utf8');
      const lockBefore = readFileSync(join(root, 'bun.lock'), 'utf8');
      const proc = Bun.spawn({
        cmd: [process.execPath, scriptPath, 'minor', '--root', root, '--dry-run'],
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stdout, stderr] = await Promise.all([
        proc.exited,
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]);

      expect(exitCode, stderr).toBe(0);
      expect(stdout).toContain('Dry run: Ariava version would change 1.2.3 -> 1.3.0');
      expect(readFileSync(join(root, 'package.json'), 'utf8')).toBe(packageBefore);
      expect(readFileSync(join(root, 'bun.lock'), 'utf8')).toBe(lockBefore);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('refuses to bump when package versions are inconsistent', async () => {
    const root = makeFixture('0.1.4');
    try {
      const bridgePackage = join(root, 'apps/bridge/package.json');
      const json = readJson(bridgePackage);
      json.version = '0.1.3';
      writeFileSync(bridgePackage, JSON.stringify(json, null, 2) + '\n');

      const proc = Bun.spawn({
        cmd: [process.execPath, scriptPath, 'patch', '--root', root],
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stderr] = await Promise.all([proc.exited, new Response(proc.stderr).text()]);

      expect(exitCode).toBe(1);
      expect(stderr).toContain('version mismatch');
      expect(readJson(join(root, 'package.json')).version).toBe('0.1.4');
      expect(readJson(bridgePackage).version).toBe('0.1.3');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('does not require the private Relay package to exist', async () => {
    const root = makeFixture();
    try {
      rmSync(join(root, relayPackageFile));
      const proc = Bun.spawn({
        cmd: [process.execPath, scriptPath, 'patch', '--root', root],
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [exitCode, stderr] = await Promise.all([proc.exited, new Response(proc.stderr).text()]);
      expect(exitCode, stderr).toBe(0);
      expect(readJson(join(root, 'package.json')).version).toBe('0.1.5');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
