import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const helper = join(process.cwd(), 'scripts', 'assert-repository-boundaries.mjs');
const roots: string[] = [];

const baseManifest = {
  version: 1,
  publicSourceRoots: ['apps/bridge', 'extensions/pi', 'packages/protocol', 'packages/shared-utils'],
  publicSourceFiles: ['Formula/ariava.rb', 'ariava.png', 'bunfig.toml', 'tsconfig.base.json'],
  publicRequiredFiles: [
    'apps/bridge/src/index.ts', 'extensions/pi/src/index.ts', 'packages/protocol/src/index.ts',
    'packages/shared-utils/src/index.ts',
  ],
  transitionRequiredRootFiles: ['.gitignore', 'bun.lock', 'package.json'],
  generatedCandidateRootFiles: [
    '.gitignore', 'AGENTS.md', 'CONTRIBUTING.md', 'LICENSE', 'README.md', 'SECURITY.md',
    'bun.lock', 'package.json',
  ],
  generatedCandidatePaths: [
    'apps/bridge/dist', 'extensions/pi/bundle', 'extensions/pi/dist',
    'packages/protocol/dist', 'packages/shared-utils/dist',
  ],
  excludedPaths: ['.env', '.git', 'README.md.private', 'apps/relay', 'apps/watchos', 'docs', 'notify.js', 'screenshots'],
  generatedPathSegments: ['bundle', 'dist', 'node_modules'],
  credentialFileNames: ['.env', 'AuthKey.p8', 'credentials.json'],
  credentialFilePatterns: ['^AuthKey_[A-Za-z0-9_-]+\\.p8$'],
  scriptClassifications: {
    'scripts/public.mjs': 'public',
    'scripts/private.sh': 'private',
    'scripts/review.ts': 'review-required',
  },
};

function makeRoot() {
  const root = mkdtempSync(join(tmpdir(), 'ariava-boundary-'));
  roots.push(root);
  return root;
}

function write(root: string, path: string, content = '// fixture\n') {
  const target = join(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

function writeManifest(overrides: Record<string, unknown> = {}) {
  const manifestRoot = makeRoot();
  const path = join(manifestRoot, 'manifest.json');
  writeFileSync(path, `${JSON.stringify({ ...baseManifest, ...overrides }, null, 2)}\n`);
  return path;
}

function populateAllowedCandidate(root: string) {
  for (const path of [
    '.gitignore', 'AGENTS.md', 'CONTRIBUTING.md', 'LICENSE', 'README.md', 'SECURITY.md',
    'bun.lock', 'package.json', 'Formula/ariava.rb', 'ariava.png', 'bunfig.toml', 'tsconfig.base.json',
    ...baseManifest.publicRequiredFiles, 'scripts/public.mjs',
  ]) write(root, path);
}

function populateTransition(root: string) {
  populateAllowedCandidate(root);
  write(root, 'scripts/private.sh');
  write(root, 'scripts/review.ts');
}

function run(root: string, mode: 'transition' | 'public-candidate', manifest = writeManifest(), reportOnly = false) {
  return Bun.spawnSync({
    cmd: [process.execPath, helper, '--mode', mode, '--root', root, '--manifest', manifest, ...(reportOnly ? ['--report-only'] : [])],
    stdout: 'pipe', stderr: 'pipe',
  });
}

function output(result: ReturnType<typeof run>) {
  return `${result.stdout.toString()}${result.stderr.toString()}`;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('repository boundary assertion', () => {
  test('accepts an allowlisted and complete public candidate', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    const result = run(root, 'public-candidate');
    expect(result.exitCode, output(result)).toBe(0);
  });

  test('ignores only Git metadata in a cloned public candidate', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    write(root, '.git/config', '[core]\n\trepositoryformatversion = 0\n');
    write(root, '.github/private.txt', 'unexpected');
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result)).not.toContain('.git/config');
    expect(output(result)).toContain('[UNEXPECTED_CANDIDATE_FILE] .github/private.txt');
  });

  test('strict transition is a failing regression gate and report-only is explicit', () => {
    const root = makeRoot();
    populateTransition(root);
    write(root, 'apps/bridge/src/client.ts', `import { isoNow } from '../../../packages/shared-utils/${'src'}';\n`);
    const strict = run(root, 'transition');
    expect(strict.exitCode).toBe(1);
    expect(output(strict)).toContain('[DEEP_PACKAGE_IMPORT] apps/bridge/src/client.ts:1');
    const report = run(root, 'transition', writeManifest(), true);
    expect(report.exitCode, output(report)).toBe(0);
    expect(output(report)).toContain('report-only mode did not fail');
  });

  test('rejects report-only for candidate mode', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    const result = run(root, 'public-candidate', writeManifest(), true);
    expect(result.exitCode).toBe(2);
    expect(output(result)).toContain('allowed only in transition mode');
  });

  test.each(['../private.txt', 'safe/..', 'safe/../private.txt', 'C:\\private\\file.txt', '\\\\server\\share\\file'])('rejects unsafe manifest path %s', (unsafe) => {
    const root = makeRoot();
    const result = run(root, 'public-candidate', writeManifest({ publicSourceFiles: [unsafe] }));
    expect(result.exitCode).toBe(2);
    expect(output(result)).toContain('path traversal or an absolute path');
  });

  test('rejects symlinks that escape the candidate root', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    const outside = makeRoot();
    write(outside, 'secret.txt', 'secret');
    symlinkSync(join(outside, 'secret.txt'), join(root, 'apps', 'bridge', 'escape.ts'));
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result)).toContain('[SYMLINK_ESCAPE] apps/bridge/escape.ts');
  });

  test('rejects public symlinks targeting excluded paths inside the root', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    write(root, 'apps/relay/private.ts', 'secret');
    symlinkSync(join(root, 'apps/relay/private.ts'), join(root, 'apps/bridge/private.ts'));
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result)).toContain('[SYMLINK_PRIVATE_TARGET] apps/bridge/private.ts');
  });

  test('rejects private directories and non-public scripts in a candidate', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    write(root, 'apps/relay/src/worker.ts');
    write(root, 'scripts/private.sh');
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result)).toContain('[PRIVATE_PATH] apps/relay/src/worker.ts');
    expect(output(result)).toContain('[NON_PUBLIC_SCRIPT] scripts/private.sh');
  });

  test('rejects unlisted source files under public roots but allows explicit generated outputs', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    write(root, 'apps/bridge/unlisted-extra.ts');
    write(root, 'apps/bridge/dist/public-cli.js');
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result)).toContain('[UNEXPECTED_CANDIDATE_FILE] apps/bridge/unlisted-extra.ts');
    expect(output(result)).not.toContain('[UNEXPECTED_CANDIDATE_FILE] apps/bridge/dist/public-cli.js');
    expect(output(result)).not.toContain('[GENERATED_PATH] apps/bridge/dist/public-cli.js');
  });

  test('enforces manifest completeness for public source files and scripts', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    rmSync(join(root, 'apps/bridge/src/index.ts'));
    rmSync(join(root, 'scripts/public.mjs'));
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result)).toContain('[MISSING_CANDIDATE_FILE] apps/bridge/src/index.ts');
    expect(output(result)).toContain('[MISSING_CANDIDATE_FILE] scripts/public.mjs');
  });

  test('uses the public root lockfile for the pi workspace', () => {
    const manifest = JSON.parse(readFileSync(join(process.cwd(), 'scripts', 'public-core-manifest.json'), 'utf8'));
    expect(manifest.publicRequiredFiles).not.toContain('extensions/pi/bun.lock');
    expect(manifest.generatedCandidateRootFiles).toContain('bun.lock');
  });

  test('detects side-effect private and deep imports but ignores comment-only examples', () => {
    const root = makeRoot();
    populateTransition(root);
    write(root, 'apps/bridge/src/leak.ts', [
      `// import '../../../apps/${'relay'}/src/commented';`,
      `/* import '../../../packages/protocol/${'src'}/commented'; */`,
      `import '../../../apps/${'watchos'}/Models';`,
      `import '../../../packages/protocol/${'src'}/identity';`,
      '',
    ].join('\n'));
    const result = run(root, 'transition');
    expect(result.exitCode).toBe(1);
    expect(output(result)).toContain('[PRIVATE_IMPORT] apps/bridge/src/leak.ts:3');
    expect(output(result)).toContain('[DEEP_PACKAGE_IMPORT] apps/bridge/src/leak.ts:4');
    expect(output(result)).not.toContain('leak.ts:1');
    expect(output(result)).not.toContain('leak.ts:2');
  });

  test('rejects broader Unix and Windows developer home paths plus HTTPS, SSH, and SCP private URLs', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    write(root, 'apps/bridge/src/private-leak.ts', [
      `const a = '/Users/alice/Desktop/file';`,
      `const b = '/home/alice/.config/file';`,
      String.raw`const c = 'C:\Users\alice\source\repo';`,
      `const c2 = 'D:/Users/alice/source/repo';`,
      `const d = 'https://github.com/noyyyy/${'ariava-private'}.git';`,
      `const e = 'ssh://git@github.com/noyyyy/${'ariava-private'}.git';`,
      `const f = 'git@github.com:noyyyy/${'ariava-private'}.git';`,
      '',
    ].join('\n'));
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result).match(/\[LOCAL_CHECKOUT_PATH\]/g)?.length).toBe(4);
    expect(output(result).match(/\[PRIVATE_REPOSITORY_URL\]/g)?.length).toBe(3);
  });

  test('rejects executable private tooling in single-line and multiline command arrays/calls', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    write(root, 'apps/bridge/src/tools.ts', [
      `spawnSync(['${'wrangler'}', 'deploy']);`,
      `const command = ['${'xcodebuild'}', '-project', 'A'];`,
      `execFile('${'asc'}', ['xcode', 'archive']);`,
      `spawnSync(`,
      `  '${'wrangler'}',`,
      `  ['deploy'],`,
      `);`,
      `const config = { args: [`,
      `  '${'xcodebuild'}',`,
      `  '-project',`,
      `] };`,
      `// spawnSync(`,
      `//   '${'asc'}',`,
      `// );`,
      `/* const ignored = [` ,
      `  '${'wrangler'}',`,
      `]; */`,
      '',
    ].join('\n'));
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result).match(/\[PRIVATE_TOOLING\]/g)?.length).toBe(5);
    expect(output(result)).not.toContain('tools.ts:13');
    expect(output(result)).not.toContain('tools.ts:16');
  });

  test('rejects wildcard APNs credential filenames', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    write(root, 'apps/bridge/AuthKey_AB12CD34.p8', 'credential');
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result)).toContain('[CREDENTIAL_FILE] apps/bridge/AuthKey_AB12CD34.p8');
  });

  test('fails when a scripts file has no explicit classification', () => {
    const root = makeRoot();
    populateAllowedCandidate(root);
    write(root, 'scripts/new-helper.ts');
    const result = run(root, 'public-candidate');
    expect(result.exitCode).toBe(1);
    expect(output(result)).toContain('[UNCLASSIFIED_SCRIPT] scripts/new-helper.ts');
  });
});
