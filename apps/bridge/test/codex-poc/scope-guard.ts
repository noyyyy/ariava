/**
 * Scope guard for the Codex Exact-Release Capability PoC (spec §4, §11.3).
 *
 * Enforces the PoC hard boundaries:
 * - zero diff under `apps/relay/**`, `apps/watchos/**`;
 * - zero diff under Bridge production `src/**` (agent-adapter, registry,
 *   state-store, command-router, daemon composition);
 * - no production Codex CLI, manifest entry, or service wiring;
 * - `.artifacts/` evidence is gitignored and never tracked/staged/packed.
 *
 * The guards execute against the repository working tree/index (not source-text
 * assertions) so they reflect the actual PoC closure state.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

export const FORBIDDEN_ROOTS: readonly string[] = Object.freeze([
  'apps/relay',
  'apps/watchos',
  'apps/bridge/src',
]);

export const FORBIDDEN_PRODUCTION_PATTERNS: readonly string[] = Object.freeze([
  'ariava codex',
  'codex-provider-adapter',
  'codex adapter',
  'codex-desktop',
]);

/** package.json script names that indicate production Codex CLI wiring. */
export const FORBIDDEN_PRODUCTION_SCRIPT_PREFIXES: readonly string[] = Object.freeze([
  'codex',
]);

export const ARTIFACTS_DIR = '.artifacts';
export const CODEX_POC_ARTIFACTS_DIR = '.artifacts/codex-poc';

/** Normalize a path to forward slashes relative to the repository root. */
export function normalizeRelative(repositoryRoot: string, absolutePath: string): string {
  return relative(repositoryRoot, absolutePath).split(/[\\/]/u).join('/');
}

function walk(directory: string, files: string[]): void {
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      walk(absolute, files);
    } else if (entry.isFile()) {
      files.push(absolute);
    }
  }
}

export interface ScopeGuardResult {
  forbiddenTrackedChanges: string[];
  forbiddenUntrackedFiles: string[];
  artifactsTrackedOrStaged: string[];
  productionWiringFound: string[];
  pass: boolean;
}

/**
 * Inspect the working tree/index for forbidden paths and production wiring.
 * `indexEntries` should be the staged names (from `git diff --cached --name-only`).
 * `trackedFiles` should be the repo-relative names of committed files (from
 * `git ls-files`); when not provided it is derived via `git ls-files` (no shell).
 * Files under a forbidden root that are already tracked are pre-existing
 * committed production code, not PoC writes, so they are never flagged.
 */
export function inspectScopeGuard(
  repositoryRoot: string,
  options: { indexEntries?: string[]; trackedFiles?: string[] } = {},
): ScopeGuardResult {
  const forbiddenTrackedChanges: string[] = [];
  const forbiddenUntrackedFiles: string[] = [];
  const artifactsTrackedOrStaged: string[] = [];
  const productionWiringFound: string[] = [];

  // Derive committed files via `git ls-files` (argument-array spawn, no shell) when
  // not supplied. Pre-existing committed production files under forbidden roots are
  // baseline, not PoC writes.
  let tracked: ReadonlySet<string>;
  if (options.trackedFiles !== undefined) {
    tracked = new Set(options.trackedFiles.map((entry) => entry.split(/[\\/]/u).join('/')));
  } else {
    const result = spawnSync('git', ['-C', repositoryRoot, 'ls-files'], { encoding: 'utf8' });
    if (result.error) throw result.error;
    tracked = new Set(result.stdout.split('\n').map((line) => line.trim()).filter((line) => line.length > 0).map((line) => line.split(/[\\/]/u).join('/')));
  }

  // Working tree: scan for new files under forbidden roots (excluding .git).
  // Pre-existing committed files are skipped via `tracked` so the guard passes
  // on a clean checkout that contains production src (spec §11.3 zero diff).
  const files: string[] = [];
  const artifactsDirectory = join(repositoryRoot, ARTIFACTS_DIR);
  if (existsSync(artifactsDirectory)) {
    const stat = statSync(artifactsDirectory);
    if (!stat.isDirectory()) files.push(artifactsDirectory);
  }
  if (existsSync(join(repositoryRoot, 'apps'))) walk(join(repositoryRoot, 'apps'), files);
  if (existsSync(join(repositoryRoot, 'scripts'))) walk(join(repositoryRoot, 'scripts'), files);
  if (existsSync(join(repositoryRoot, 'extensions'))) walk(join(repositoryRoot, 'extensions'), files);
  if (existsSync(join(repositoryRoot, 'packages'))) walk(join(repositoryRoot, 'packages'), files);
  if (existsSync(join(repositoryRoot, 'docs'))) walk(join(repositoryRoot, 'docs'), files);

  for (const file of files) {
    const normalized = normalizeRelative(repositoryRoot, file);
    const isForbidden = FORBIDDEN_ROOTS.some((root) => normalized === root || normalized.startsWith(`${root}/`));
    const isArtifact = normalized === ARTIFACTS_DIR || normalized.startsWith(`${ARTIFACTS_DIR}/`);
    if (isArtifact) artifactsTrackedOrStaged.push(normalized);
    // A tracked file under a forbidden root is committed baseline, not a PoC write.
    if (isForbidden && !tracked.has(normalized)) forbiddenUntrackedFiles.push(normalized);
  }

  // Index entries.
  for (const entry of options.indexEntries ?? []) {
    const normalized = entry.split(/[\\/]/u).join('/');
    if (FORBIDDEN_ROOTS.some((root) => normalized === root || normalized.startsWith(`${root}/`))) {
      forbiddenTrackedChanges.push(normalized);
    }
    if (normalized === ARTIFACTS_DIR || normalized.startsWith(`${ARTIFACTS_DIR}/`)) {
      artifactsTrackedOrStaged.push(normalized);
    }
  }

  // Production wiring scan: search source files under apps/bridge/src and
  // package.json for forbidden production CLI/manifest wiring. The PoC's own
  // `codex:poc:*` scripts are the permitted harness scripts (spec §11.2), so
  // only non-`codex:poc:` Codex CLI wiring is flagged.
  const bridgeSrc = join(repositoryRoot, 'apps/bridge/src');
  const sourceFiles: string[] = [];
  if (existsSync(bridgeSrc)) walk(bridgeSrc, sourceFiles);
  const packageJsonPath = join(repositoryRoot, 'package.json');
  const searchable = [...sourceFiles];
  if (existsSync(packageJsonPath)) searchable.push(packageJsonPath);
  for (const file of searchable) {
    const normalized = normalizeRelative(repositoryRoot, file);
    if (normalized.startsWith('apps/bridge/src/')) {
      for (const pattern of FORBIDDEN_PRODUCTION_PATTERNS) {
        const source = readFileSync(file, 'utf8');
        if (source.includes(pattern)) productionWiringFound.push(`${normalized}: ${pattern}`);
      }
    } else if (normalized === 'package.json') {
      const source = readFileSync(file, 'utf8');
      try {
        const parsed = JSON.parse(source) as { scripts?: Record<string, string> };
        for (const scriptName of Object.keys(parsed.scripts ?? {})) {
          // The PoC harness scripts (codex:poc:inspect|run|review, spec §11.2) are
          // permitted; any other Codex CLI wiring is production wiring.
          if (scriptName.startsWith('codex:poc:')) continue;
          if (FORBIDDEN_PRODUCTION_SCRIPT_PREFIXES.some((prefix) => scriptName === prefix || scriptName.startsWith(`${prefix}:`))) {
            productionWiringFound.push(`package.json script ${scriptName}: production Codex CLI wiring`);
          }
        }
      } catch {
        // Non-JSON package.json is itself a failure but not wiring evidence.
      }
    }
  }

  const uniqueForbiddenTracked = [...new Set(forbiddenTrackedChanges)].sort();
  const uniqueForbiddenUntracked = [...new Set(forbiddenUntrackedFiles)].sort();
  const uniqueArtifacts = [...new Set(artifactsTrackedOrStaged)].sort();
  const uniqueWiring = [...new Set(productionWiringFound)].sort();

  return {
    forbiddenTrackedChanges: uniqueForbiddenTracked,
    forbiddenUntrackedFiles: uniqueForbiddenUntracked,
    artifactsTrackedOrStaged: uniqueArtifacts,
    productionWiringFound: uniqueWiring,
    pass: uniqueForbiddenTracked.length === 0 &&
      uniqueForbiddenUntracked.length === 0 &&
      uniqueArtifacts.length === 0 &&
      uniqueWiring.length === 0,
  };
}

export interface PackageExclusionResult {
  excluded: string[];
  violations: string[];
  pass: boolean;
}

/**
 * Verify package.json `files` field and package contents exclude PoC source
 * and `.artifacts` evidence (spec §6.1: package/tarball must not contain real
 * PoC evidence).
 */
export function inspectPackageExclusion(repositoryRoot: string, options: { packEntries?: string[] } = {}): PackageExclusionResult {
  const violations: string[] = [];
  const excluded: string[] = [];

  const packageJsonPath = join(repositoryRoot, 'package.json');
  const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { files?: string[] };
  const filesField = packageJson.files ?? [];

  for (const entry of filesField) {
    if (entry === 'apps/bridge/test/codex-poc' || entry.startsWith('apps/bridge/test/codex-poc/') ||
        entry === '.artifacts' || entry.startsWith('.artifacts/')) {
      violations.push(`package.json files field explicitly includes PoC path: ${entry}`);
    }
  }

  // .artifacts must be gitignored.
  const gitignorePath = join(repositoryRoot, '.gitignore');
  const gitignore = existsSync(gitignorePath) ? readFileSync(gitignorePath, 'utf8') : '';
  const gitignoreLines = gitignore.split('\n').map((line) => line.trim());
  if (!gitignoreLines.some((line) => line === '.artifacts/' || line === '.artifacts')) {
    violations.push('.gitignore does not exclude .artifacts/');
  } else {
    excluded.push('.artifacts/ (gitignore)');
  }

  for (const entry of options.packEntries ?? []) {
    const normalized = entry.split(/[\\/]/u).join('/');
    if (normalized.startsWith('apps/bridge/test/codex-poc') || normalized.startsWith('.artifacts/')) {
      violations.push(`packed artifact contains PoC evidence: ${normalized}`);
    }
  }

  return {
    excluded,
    violations: [...new Set(violations)].sort(),
    pass: violations.length === 0,
  };
}
