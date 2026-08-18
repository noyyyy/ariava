import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ARTIFACTS_DIR,
  inspectPackageExclusion,
  inspectScopeGuard,
  type PackageExclusionResult,
  type ScopeGuardResult,
} from './scope-guard';

const paths: string[] = [];

function makeRepo(): string {
  const root = mkdtempSync(join(tmpdir(), 'codex-poc-guard-'));
  paths.push(root);
  return root;
}

function write(repositoryRoot: string, relativePath: string, content = 'x') {
  const absolute = join(repositoryRoot, relativePath);
  mkdirSync(join(absolute, '..'), { recursive: true });
  writeFileSync(absolute, content);
}

afterEach(() => {
  for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('forbidden path guard', () => {
  test('passes on a clean repo with no forbidden changes', () => {
    const root = makeRepo();
    write(root, 'package.json', JSON.stringify({ files: ['apps/bridge/dist'] }));
    write(root, '.gitignore', '.artifacts/\n');
    write(root, 'apps/bridge/test/codex-poc/example.test.ts');
    const result = inspectScopeGuard(root, { indexEntries: ['apps/bridge/test/codex-poc/example.test.ts'], trackedFiles: ['apps/bridge/test/codex-poc/example.test.ts'] });
    expect(result.pass).toBe(true);
    expect(result.forbiddenTrackedChanges).toEqual([]);
    expect(result.forbiddenUntrackedFiles).toEqual([]);
  });

  test('passes on a checkout containing committed production src', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    // Committed production files exist in the working tree (baseline).
    write(root, 'apps/bridge/src/agent-adapter/registry.ts');
    write(root, 'apps/relay/src/worker.ts');
    const result = inspectScopeGuard(root, { indexEntries: [], trackedFiles: ['apps/bridge/src/agent-adapter/registry.ts', 'apps/relay/src/worker.ts'] });
    expect(result.pass).toBe(true);
    expect(result.forbiddenTrackedChanges).toEqual([]);
    expect(result.forbiddenUntrackedFiles).toEqual([]);
  });

  test('flags genuinely new untracked files under bridge production src', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    write(root, 'apps/bridge/src/daemon-new.ts');
    write(root, 'apps/bridge/src/cli.ts');
    const result = inspectScopeGuard(root, { indexEntries: [], trackedFiles: ['apps/bridge/src/cli.ts'] });
    expect(result.pass).toBe(false);
    expect(result.forbiddenUntrackedFiles).toContain('apps/bridge/src/daemon-new.ts');
    expect(result.forbiddenUntrackedFiles).not.toContain('apps/bridge/src/cli.ts');
  });

  test('flags staged changes under apps/relay', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    const result = inspectScopeGuard(root, { indexEntries: ['apps/relay/src/worker.ts'] });
    expect(result.pass).toBe(false);
    expect(result.forbiddenTrackedChanges).toContain('apps/relay/src/worker.ts');
  });

  test('flags staged changes under apps/watchos', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    const result = inspectScopeGuard(root, { indexEntries: ['apps/watchos/AriavaWatchApp/ContentView.swift'] });
    expect(result.pass).toBe(false);
    expect(result.forbiddenTrackedChanges).toContain('apps/watchos/AriavaWatchApp/ContentView.swift');
  });

  test('flags staged changes under bridge production src', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    const result = inspectScopeGuard(root, { indexEntries: ['apps/bridge/src/agent-adapter/registry.ts', 'apps/bridge/src/command-router.ts'] });
    expect(result.pass).toBe(false);
    expect(result.forbiddenTrackedChanges).toContain('apps/bridge/src/agent-adapter/registry.ts');
    expect(result.forbiddenTrackedChanges).toContain('apps/bridge/src/command-router.ts');
  });

  test('flags untracked files under bridge production src', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    write(root, 'apps/bridge/src/daemon-new.ts');
    const result = inspectScopeGuard(root, { indexEntries: [], trackedFiles: [] });
    expect(result.pass).toBe(false);
    expect(result.forbiddenUntrackedFiles).toContain('apps/bridge/src/daemon-new.ts');
  });

  test('flags production wiring (ariava codex CLI) in bridge source', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    write(root, 'apps/bridge/src/cli.ts', 'export function run() { return "ariava codex"; }\n');
    const result = inspectScopeGuard(root);
    expect(result.pass).toBe(false);
    expect(result.productionWiringFound.length).toBeGreaterThan(0);
  });

  test('flags production wiring in package.json scripts', () => {
    const root = makeRepo();
    write(root, 'package.json', JSON.stringify({ scripts: { 'codex': 'true' } }));
    const result = inspectScopeGuard(root);
    expect(result.pass).toBe(false);
  });

  test('allows the PoC harness scripts (codex:poc:*) in package.json', () => {
    const root = makeRepo();
    write(root, 'package.json', JSON.stringify({ scripts: { 'codex:poc:inspect': 'bun ./scripts/codex-poc/inspect-release.ts', 'codex:poc:run': 'bun ./scripts/codex-poc/run-tui.ts', 'codex:poc:review': 'bun ./scripts/codex-poc/review-evidence.ts' } }));
    const result = inspectScopeGuard(root);
    expect(result.pass).toBe(true);
    expect(result.productionWiringFound).toEqual([]);
  });

  test('flags .artifacts evidence tracked or staged', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    const result = inspectScopeGuard(root, { indexEntries: ['.artifacts/codex-poc/evidence.json'] });
    expect(result.pass).toBe(false);
    expect(result.artifactsTrackedOrStaged).toContain('.artifacts/codex-poc/evidence.json');
  });

  test('allows .artifacts dir existence (gitignored) without flagging untracked', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    write(root, '.gitignore', '.artifacts/\n');
    // .artifacts is ignored, so it is not a forbidden untracked file.
    const result = inspectScopeGuard(root);
    expect(result.pass).toBe(true);
  });

  test('normalizes backslashes on Windows-style index entries', () => {
    const root = makeRepo();
    write(root, 'package.json', '{}');
    const result = inspectScopeGuard(root, { indexEntries: ['apps\\relay\\src\\worker.ts'] });
    expect(result.forbiddenTrackedChanges).toContain('apps/relay/src/worker.ts');
  });
});

describe('package exclusion guard', () => {
  test('passes when files field and gitignore exclude PoC paths', () => {
    const root = makeRepo();
    write(root, 'package.json', JSON.stringify({ files: ['README.md', 'apps/bridge/dist'] }));
    write(root, '.gitignore', '.artifacts/\n');
    const result: PackageExclusionResult = inspectPackageExclusion(root);
    expect(result.pass).toBe(true);
    expect(result.violations).toEqual([]);
    expect(result.excluded).toContain('.artifacts/ (gitignore)');
  });

  test('flags files field explicitly including codex-poc test path', () => {
    const root = makeRepo();
    write(root, 'package.json', JSON.stringify({ files: ['apps/bridge/test/codex-poc'] }));
    write(root, '.gitignore', '.artifacts/\n');
    const result = inspectPackageExclusion(root);
    expect(result.pass).toBe(false);
    expect(result.violations.some((violation) => violation.includes('files field explicitly includes PoC path'))).toBe(true);
  });

  test('flags missing .artifacts gitignore entry', () => {
    const root = makeRepo();
    write(root, 'package.json', JSON.stringify({ files: ['README.md'] }));
    write(root, '.gitignore', 'node_modules/\n');
    const result = inspectPackageExclusion(root);
    expect(result.pass).toBe(false);
    expect(result.violations.some((violation) => violation.includes('.gitignore does not exclude'))).toBe(true);
  });

  test('flags packed entries containing PoC evidence', () => {
    const root = makeRepo();
    write(root, 'package.json', JSON.stringify({ files: ['README.md'] }));
    write(root, '.gitignore', '.artifacts/\n');
    const result = inspectPackageExclusion(root, { packEntries: ['.artifacts/codex-poc/evidence.json', 'apps/bridge/test/codex-poc/evidence-codec.ts'] });
    expect(result.pass).toBe(false);
    expect(result.violations.some((violation) => violation.includes('packed artifact contains PoC evidence'))).toBe(true);
  });

  test('real public repo has no PoC evidence in files field or gitignore violations', () => {
    const repositoryRoot = join(import.meta.dir, '../../../..');
    const result = inspectPackageExclusion(repositoryRoot);
    expect(result.pass).toBe(true);
  });

  test('real public repo working tree has no forbidden production changes', () => {
    const repositoryRoot = join(import.meta.dir, '../../../..');
    // Omit `trackedFiles` so the guard derives committed files via `git ls-files`;
    // passing [] would mark every committed production file as untracked.
    const result: ScopeGuardResult = inspectScopeGuard(repositoryRoot, { indexEntries: [] });
    // The PoC work adds only test/codex-poc files, never production src. The real
    // checkout contains committed production src (baseline), so the guard must pass.
    expect(result.pass).toBe(true);
    expect(result.forbiddenTrackedChanges).toEqual([]);
    expect(result.forbiddenUntrackedFiles).toEqual([]);
    expect(result.productionWiringFound).toEqual([]);
    expect(result.artifactsTrackedOrStaged).toEqual([]);
    expect(ARTIFACTS_DIR).toBe('.artifacts');
  });
});
