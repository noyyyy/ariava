import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
const publish = readFileSync('.github/workflows/publish-npm.yml', 'utf8');
const releaseLibrary = readFileSync('scripts/npm-release-lib.mjs', 'utf8');

const FULL_SHA_ACTION = /^\s*uses:\s*[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}\s*$/u;
const FORBIDDEN_PUBLICATION_INPUT = /NPM_TOKEN|NODE_AUTH_TOKEN|npm[_ -]?password|TOTP|--otp|secrets\./iu;

function jobBody(source: string, name: string): string {
  const match = new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9_-]+:\\n|(?![\\s\\S]))`, 'mu').exec(source);
  if (!match) throw new Error(`missing workflow job: ${name}`);
  return match[1]!;
}

function assertPinnedActions(source: string) {
  const uses = source.split('\n').filter((line) => /^\s*uses:/u.test(line));
  expect(uses.length).toBeGreaterThan(0);
  for (const line of uses) expect(line, `action must use a reviewed full SHA: ${line.trim()}`).toMatch(FULL_SHA_ACTION);
  expect(source).toMatch(/# actions\/checkout v4\.2\.2/u);
  expect(source).toMatch(/# actions\/setup-node v4\.4\.0/u);
}

export function assertWorkflowPolicy(ciSource: string, publishSource: string) {
  expect(ciSource).toContain('pull_request:');
  expect(ciSource).toContain('branches:\n      - main');
  expect(ciSource).toContain('permissions:\n  contents: read');
  expect(ciSource).not.toContain('id-token: write');
  expect(ciSource).toContain('bun install --frozen-lockfile');
  expect(ciSource).toContain('bun run verify');
  expect(ciSource).not.toMatch(FORBIDDEN_PUBLICATION_INPUT);

  expect(publishSource).toContain('tags:\n      - "v*.*.*"');
  expect(publishSource).toContain('group: npm-production');
  expect(publishSource).toContain('cancel-in-progress: false');
  const prepare = jobBody(publishSource, 'prepare');
  const publishJob = jobBody(publishSource, 'publish');
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

  assertPinnedActions(ciSource);
  assertPinnedActions(publishSource);
}

describe('GitHub workflow least-privilege policy', () => {
  test('CI is read-only and tag publication uses exact dependent artifacts with OIDC only in publish', () => {
    assertWorkflowPolicy(ci, publish);
  });

  test('negative mutation: adding OIDC to CI is rejected', () => {
    const mutated = ci.replace('contents: read', 'contents: read\n  id-token: write');
    expect(() => assertWorkflowPolicy(mutated, publish)).toThrow();
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
