import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
const publish = readFileSync('.github/workflows/publish-npm.yml', 'utf8');
const releaseLibrary = readFileSync('scripts/npm-release-lib.mjs', 'utf8');

const FULL_SHA_ACTION = /^\s*uses:\s*[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}\s*$/u;
const FORBIDDEN_PUBLICATION_INPUT = /NPM_TOKEN|NODE_AUTH_TOKEN|npm[_ -]?password|TOTP|--otp|secrets\./iu;
const NODE_VERSION = '24.18.0';
const NPM_VERSION = '11.18.0';
const BUN_VERSION = '1.3.14';

function jobBody(source: string, name: string): string {
  const match = new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9_-]+:\\n|(?![\\s\\S]))`, 'mu').exec(source);
  if (!match) throw new Error(`missing workflow job: ${name}`);
  return match[1]!;
}

function assertPinnedActions(source: string) {
  const uses = source.split('\n').filter((line) => /^\s*uses:/u.test(line));
  expect(uses.length).toBeGreaterThan(0);
  for (const line of uses) expect(line, `action must use a reviewed full SHA: ${line.trim()}`).toMatch(FULL_SHA_ACTION);
  expect(source).toMatch(/# actions\/checkout v5\.1\.0/u);
  expect(source).toMatch(/# actions\/setup-node v5\.0\.0/u);
}

function assertCiHostJob(source: string, options: { job: string; name: string; runner: string; command: string }) {
  const body = jobBody(source, options.job);
  expect(body).toContain(`name: ${options.name}`);
  expect(body).toContain(`runs-on: ${options.runner}`);
  expect(body).toContain('persist-credentials: false');
  expect(body).toContain(`node-version: ${NODE_VERSION}`);
  expect(body).toContain(`bun-version: ${BUN_VERSION}`);
  expect(body).toContain(`npm@${NPM_VERSION}`);
  expect(body).toContain('node --version');
  expect(body).toContain('npm --version');
  expect(body).toContain('bun --version');
  expect(body).toContain('bun install --frozen-lockfile');
  expect(body).toContain(`run: bun run ${options.command}`);
  expect(body).not.toMatch(/^\s*run:\s*bun run verify\s*$/mu);
  expect(body).not.toMatch(FORBIDDEN_PUBLICATION_INPUT);
  expect(body).not.toMatch(/id-token:\s*write/u);
}

export function assertWorkflowPolicy(ciSource: string, publishSource: string) {
  expect(ciSource).toContain('pull_request:');
  expect(ciSource).toContain('branches:\n      - main');
  expect(ciSource).toContain('permissions:\n  contents: read');
  expect(ciSource).not.toContain('id-token: write');
  expect(ciSource).not.toMatch(FORBIDDEN_PUBLICATION_INPUT);
  assertCiHostJob(ciSource, { job: 'linux', name: 'Linux', runner: 'ubuntu-latest', command: 'verify:linux' });
  assertCiHostJob(ciSource, { job: 'macos', name: 'macOS', runner: 'macos-latest', command: 'verify:macos' });
  expect((ciSource.match(/bun install --frozen-lockfile/gu) ?? [])).toHaveLength(2);
  expect((ciSource.match(/node-version: 24\.18\.0/gu) ?? [])).toHaveLength(2);
  expect((ciSource.match(/bun-version: 1\.3\.14/gu) ?? [])).toHaveLength(2);
  expect((ciSource.match(/npm@11\.18\.0/gu) ?? [])).toHaveLength(2);
  expect(ciSource).not.toMatch(/verify:linux:docker|docker.sock|--privileged/iu);

  expect(publishSource).toContain('tags:\n      - "v*.*.*"');
  expect(publishSource).toContain('group: npm-production');
  expect(publishSource).toContain('cancel-in-progress: false');
  const prepare = jobBody(publishSource, 'prepare');
  const publishJob = jobBody(publishSource, 'publish');
  expect(prepare).toContain('runs-on: ubuntu-latest');
  expect(publishJob).toContain('runs-on: ubuntu-latest');
  expect(prepare).toContain('permissions:\n      contents: read');
  expect(prepare).not.toContain('id-token: write');
  expect(publishJob).toContain('environment: npm-production');
  expect(publishJob).toContain('contents: read\n      id-token: write');
  expect((publishSource.match(/id-token: write/gu) ?? [])).toHaveLength(1);

  expect(prepare).toContain('persist-credentials: false');
  expect(prepare).toContain('fetch-depth: 0');
  expect(prepare).toContain('github.event.repository.default_branch');
  expect(prepare).toContain('git fetch --no-tags origin');
  expect(prepare).toContain('--prepare --output-dir');
  expect(prepare).toContain('upload-artifact@');
  expect(prepare).toContain('release-manifest.json');
  expect(prepare).toContain('*.tgz');
  expect(publishJob).toContain('needs: prepare');
  expect(publishJob).toContain('download-artifact@');
  expect(publishJob).toContain('needs.prepare.outputs.release_commit');
  expect(publishJob).not.toMatch(/run-id:|github\.event\.inputs|https?:\/\/.*artifact/iu);
  expect(publishJob).toContain('--publish-prepared');
  expect(publishJob).toContain('--trusted-publishing');
  expect(publishJob).toContain('--summary-file');
  expect(publishJob).not.toMatch(/>\s*"?\$\{RUNNER_TEMP\}\/release-summary\.json/u);
  expect(publishJob).not.toMatch(/\bnpm\s+(?:pack|publish)\b|\bbun\s+(?:install|run|build)\b/iu);
  expect(publishJob).toContain('GITHUB_STEP_SUMMARY');
  expect(publishJob).not.toMatch(/\b(?:env|printenv|set)\b\s*(?:>>|>)/u);

  expect(publishSource).toContain('registry=https://registry.npmjs.org/');
  expect(prepare).toContain('NPM_CONFIG_USERCONFIG: ${{ runner.temp }}/ariava-npm-config/user.npmrc');
  expect(prepare).toContain('NPM_CONFIG_GLOBALCONFIG: ${{ runner.temp }}/ariava-npm-config/global.npmrc');
  expect(publishSource).not.toContain('NPM_CONFIG_USERCONFIG: /dev/null');
  expect(releaseLibrary).not.toMatch(/NPM_CONFIG_(?:USER|GLOBAL)CONFIG:\s*['"]\/dev\/null['"]/u);
  expect(publishSource).not.toContain('registry-url:');
  expect(publishSource).not.toMatch(FORBIDDEN_PUBLICATION_INPUT);
  expect(releaseLibrary).toContain('parseStableTag');
  expect(releaseLibrary).toContain('validateGitRelease');
  expect(releaseLibrary).toContain("['install', '--frozen-lockfile']");
  expect(releaseLibrary).toContain("['run', 'verify']");

  assertPinnedActions(ciSource);
  assertPinnedActions(publishSource);
}

describe('GitHub workflow least-privilege policy', () => {
  test('CI has separate exact-toolchain Linux/macOS host jobs and publication remains Ubuntu/OIDC-only', () => {
    assertWorkflowPolicy(ci, publish);
  });

  test('negative mutation: adding OIDC or publication credentials to CI is rejected', () => {
    const oidc = ci.replace('contents: read', 'contents: read\n  id-token: write');
    expect(() => assertWorkflowPolicy(oidc, publish)).toThrow();
    const token = ci.replace('permissions:', 'env:\n  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n\npermissions:');
    expect(() => assertWorkflowPolicy(token, publish)).toThrow();
  });

  test('negative mutation: swapping runners, weakening commands, or drifting toolchains is rejected', () => {
    expect(() => assertWorkflowPolicy(ci.replace('runs-on: macos-latest', 'runs-on: ubuntu-latest'), publish)).toThrow();
    expect(() => assertWorkflowPolicy(ci.replace('bun run verify:linux', 'bun run verify:shared'), publish)).toThrow();
    expect(() => assertWorkflowPolicy(ci.replace('node-version: 24.18.0', 'node-version: 24'), publish)).toThrow();
    expect(() => assertWorkflowPolicy(ci.replace('bun install --frozen-lockfile', 'bun install'), publish)).toThrow();
  });

  test('negative mutation: introducing a publication token is rejected', () => {
    const mutated = publish.replace('contents: read\n', 'contents: read\n    env:\n      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n');
    expect(() => assertWorkflowPolicy(ci, mutated)).toThrow();
  });

  test('negative mutation: rebuilding in the publish job is rejected', () => {
    const mutated = publish.replace('      - name: Publish prepared artifacts with OIDC', '      - name: Rebuild\n        run: bun run build\n\n      - name: Publish prepared artifacts with OIDC');
    expect(() => assertWorkflowPolicy(ci, mutated)).toThrow();
  });
});
