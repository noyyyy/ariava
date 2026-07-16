import { describe, expect, test } from 'bun:test';
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function run(command: string, args: string[], cwd: string) {
  return spawnSync(command, args, { cwd, encoding: 'utf8', shell: false });
}

describe('published root tarball', () => {
  test('installs cleanly with npm and exposes a working CLI', () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-root-tarball-'));
    const packDirectory = join(root, 'pack');
    const installDirectory = join(root, 'install');
    mkdirSync(packDirectory);
    mkdirSync(installDirectory);

    try {
      const metadata = JSON.parse(readFileSync(join(repositoryRoot, 'package.json'), 'utf8')) as {
        dependencies?: Record<string, string>;
      };
      expect(metadata.dependencies?.['@ariava/protocol']).toBeUndefined();
      expect(metadata.dependencies?.['@ariava/shared-utils']).toBeUndefined();

      const packed = run('npm', ['pack', repositoryRoot, '--json', '--pack-destination', packDirectory], repositoryRoot);
      expect(packed.status, packed.stderr).toBe(0);
      const tarballName = (JSON.parse(packed.stdout) as Array<{ filename: string }>)[0]?.filename;
      expect(tarballName).toBeTruthy();

      const initialized = run('npm', ['init', '-y'], installDirectory);
      expect(initialized.status, initialized.stderr).toBe(0);
      const installed = run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', join(packDirectory, tarballName!)], installDirectory);
      expect(installed.status, installed.stderr).toBe(0);

      const cli = run(process.execPath, [join(installDirectory, 'node_modules', 'ariava', 'apps', 'bridge', 'dist', 'public-cli.js'), 'help'], installDirectory);
      expect(cli.status, cli.stderr).toBe(0);
      expect(cli.stdout).toContain('ariava init');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);
});
