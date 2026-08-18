#!/usr/bin/env bun
/**
 * Shared harness utilities for the Codex Exact-Release Capability PoC
 * (spec §6.3, §7.3, §8, §11.2).
 *
 * Research-only harness code. Never part of the production import graph and
 * never shipped in the npm package (package.json `files` only includes dist /
 * bundle directories).
 */

import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { jcs } from '../../apps/bridge/test/codex-poc/jcs';
import {
  CODEX_POC_REGISTRY_VERSION,
  SURFACES,
  type OperatingSystem,
  type Surface,
  type VerdictReason,
} from '../../apps/bridge/test/codex-poc/constants';
import {
  OWNER_ONLY_MODE,
  isOwnerOnlyMode,
  type EvidenceArtifact,
} from '../../apps/bridge/test/codex-poc/evidence-codec';
import { registryDigest, selectCasesForTuple } from '../../apps/bridge/test/codex-poc/case-registry';
import { TUI_ATTACHMENT_STRATEGY_ID } from '../../apps/bridge/test/codex-poc/tui-attachment';
import { DESKTOP_ATTACHMENT_STRATEGY_ID } from '../../apps/bridge/test/codex-poc/desktop-attachment.macos';

/** Opt-in danger switch (spec §11.2): explicit env var, never a credential. */
export const OPT_IN_ENV = 'ARIAVA_CODEX_POC_OPT_IN';

/** Where real-run evidence artifacts and review records are written (gitignored). */
export function artifactsRoot(repositoryRoot: string): string {
  return join(repositoryRoot, '.artifacts', 'codex-poc');
}

/** Repository root = the Public repo checkout (parent of scripts/). */
export function publicRepositoryRoot(): string {
  // harness-common.ts lives in scripts/codex-poc/; two levels up is the repo root.
  return resolve(fileURLToPath(new URL('../..', import.meta.url)));
}

export function currentGitRevision(): string {
  const result = spawnSync('git', ['-C', publicRepositoryRoot(), 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  if (result.status !== 0 || !result.stdout) return 'unknown';
  return result.stdout.trim();
}

export function workingTreeClean(): boolean {
  const result = spawnSync('git', ['-C', publicRepositoryRoot(), 'status', '--porcelain'], { encoding: 'utf8' });
  if (result.status !== 0) return false;
  return result.stdout.trim().length === 0;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function newRunId(): string {
  return randomUUID();
}

/** Ensure a directory exists with owner-only permissions (0700 dirs: owner rwx). */
export function ensureOwnerOnlyDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: OWNER_ONLY_DIR_MODE });
  chmodSync(path, OWNER_ONLY_DIR_MODE);
}

/** Write a file with owner-only permissions (0600). */
export function writeOwnerOnlyFile(path: string, content: string): void {
  ensureOwnerOnlyDir(dirname(path));
  writeFileSync(path, content, { mode: OWNER_ONLY_MODE });
  chmodSync(path, OWNER_ONLY_MODE);
}

export interface ParsedArgs {
  flags: Record<string, string | string[] | boolean>;
  positionals: string[];
}

/** Minimal `--flag value` / `--flag=value` / `--boolean` parser (no shell). */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const flags: Record<string, string | string[] | boolean> = {};
  const positionals: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (arg === '--') continue;
    if (arg.startsWith('--')) {
      const equals = arg.indexOf('=');
      if (equals !== -1) {
        const name = arg.slice(2, equals);
        flags[name] = arg.slice(equals + 1);
        continue;
      }
      const name = arg.slice(2);
      const next = argv[index + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[name] = next;
        index += 1;
      } else {
        flags[name] = true;
      }
      continue;
    }
    positionals.push(arg);
  }
  return { flags, positionals };
}

export function flagString(flags: Record<string, string | string[] | boolean>, name: string): string | undefined {
  const value = flags[name];
  return typeof value === 'string' ? value : undefined;
}

export function flagStrings(flags: Record<string, string | string[] | boolean>, name: string): string[] {
  const value = flags[name];
  if (Array.isArray(value)) return value.flatMap((entry) => entry.split(','));
  if (typeof value === 'string') return value.split(',');
  return [];
}

export function flagBoolean(flags: Record<string, string | string[] | boolean>, name: string): boolean {
  return flags[name] === true || flags[name] === 'true' || flags[name] === '1';
}

/** Refuse to run a real experiment without the explicit opt-in switch. */
export function requireOptIn(): void {
  if (process.env[OPT_IN_ENV] !== '1') {
    throw new Error(
      `Refusing to run: ${OPT_IN_ENV}=1 is required for real Codex experiments (spec §6.2, §11.2). ` +
        `This env var is an explicit danger switch, not a credential or persistent config.`,
    );
  }
}

export function isOptInSet(): boolean {
  return process.env[OPT_IN_ENV] === '1';
}

export interface TupleSelection {
  surface: Surface;
  os: OperatingSystem;
  architecture: 'arm64' | 'x86_64';
  requiredCaseIds: string[];
  diagnosticCaseIds: string[];
  /** Canonical registry digest (JCS of the full canonical case registry). */
  registry: { version: number; digest: string };
}

const ARCHITECTURES = ['arm64', 'x86_64'] as const;

/**
 * Resolve the tuple selection from a `--tuple` file + `--cases`/`--diagnostic`
 * (spec §7.2/§11.2). `--cases` may only select the full canonical set or an
 * explicit list that includes every required case for the tuple.
 */
export function resolveTupleSelection(
  tupleFilePath: string,
  casesSpec: string | undefined,
  diagnosticSpec: string | undefined,
): TupleSelection {
  if (!existsSync(tupleFilePath)) {
    throw new Error(`tuple file not found: ${tupleFilePath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(tupleFilePath, 'utf8'));
  } catch (error) {
    throw new Error(`tuple file is not valid JSON: ${tupleFilePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (typeof parsed !== 'object' || parsed === null) throw new Error('tuple file must contain a JSON object');
  const record = parsed as Record<string, unknown>;
  const surface = record.surface;
  const os = record.os;
  const architecture = record.architecture;
  if (typeof surface !== 'string' || !SURFACES.includes(surface as Surface)) {
    throw new Error(`tuple.surface must be one of ${SURFACES.join(', ')}`);
  }
  if (typeof os !== 'string' || !['macos', 'linux', 'wsl'].includes(os)) {
    throw new Error('tuple.os must be one of macos, linux, wsl');
  }
  if (typeof architecture !== 'string' || !ARCHITECTURES.includes(architecture as 'arm64' | 'x86_64')) {
    throw new Error('tuple.architecture must be one of arm64, x86_64');
  }

  const filter = { surface: surface as Surface, os: os as OperatingSystem, architecture: architecture as 'arm64' | 'x86_64' };
  const selected = selectCasesForTuple(filter);
  const required = selected.requiredCaseIds;
  const diagnostics = selected.diagnosticCaseIds;
  const registry = registryDigest();

  if (casesSpec === undefined || casesSpec === '' || casesSpec === 'all') {
    return {
      surface: filter.surface,
      os: filter.os,
      architecture: filter.architecture,
      requiredCaseIds: [...required].sort(),
      diagnosticCaseIds: [...diagnostics].sort(),
      registry: { version: CODEX_POC_REGISTRY_VERSION, digest: registry.digest },
    };
  }

  const requested = casesSpec.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  const unknown = requested.filter((caseId) => !required.includes(caseId) && !diagnostics.includes(caseId));
  if (unknown.length > 0) {
    throw new Error(`--cases contains unknown case ids: ${unknown.join(', ')}`);
  }
  const missingRequired = required.filter((caseId) => !requested.includes(caseId));
  if (missingRequired.length > 0) {
    throw new Error(`--cases cannot drop required cases for this tuple; missing: ${missingRequired.join(', ')}`);
  }
  const extraDiagnostic = requested.filter((caseId) => !required.includes(caseId));
  const extraFromDiagnostic = diagnosticSpec === undefined ? [] : diagnosticSpec.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  const extraUnknown = extraFromDiagnostic.filter((caseId) => !diagnostics.includes(caseId));
  if (extraUnknown.length > 0) {
    throw new Error(`--diagnostic contains unknown diagnostic case ids: ${extraUnknown.join(', ')}`);
  }
  const combinedDiagnostic = [...new Set([...extraDiagnostic, ...extraFromDiagnostic])].sort();
  return {
    surface: filter.surface,
    os: filter.os,
    architecture: filter.architecture,
    requiredCaseIds: [...required].sort(),
    diagnosticCaseIds: combinedDiagnostic,
    registry: { version: CODEX_POC_REGISTRY_VERSION, digest: registry.digest },
  };
}

/** Resolve an explicit candidate to its verified absolute realpath (no symlinks). */
export function resolveCandidateRealpath(candidate: string): { realpath: string; error?: string } {
  if (!isAbsolute(candidate)) {
    return { realpath: '', error: `candidate must be an absolute path, got ${JSON.stringify(candidate)}` };
  }
  try {
    const real = realpathSync(candidate);
    const stat = lstatSync(real);
    if (!stat.isFile() && !stat.isDirectory()) {
      return { realpath: '', error: `candidate is not a regular file or directory: ${candidate}` };
    }
    return { realpath: real };
  } catch (error) {
    return { realpath: '', error: `candidate cannot be resolved: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Bounded tuple digest (sha256 of JCS of the tuple evidence fields). */
export function tupleDigest(artifact: EvidenceArtifact): string {
  const canonical = jcs({
    surface: artifact.tuple.surface,
    os: artifact.tuple.os,
    architecture: artifact.tuple.architecture,
    codexVersion: artifact.tuple.codexVersion,
    binarySha256: artifact.tuple.binarySha256,
    schemaFingerprint: artifact.tuple.schemaFingerprint,
    attachmentStrategy: artifact.tuple.attachmentStrategy,
  } as Parameters<typeof jcs>[0]);
  return sha256Hex(canonical);
}

/** Observer attestation binding (spec §6.3): runId + registry + tuple + case + outcome. */
export function observerAttestationDigest(input: {
  runId: string;
  caseRegistryDigest: string;
  tupleDigest: string;
  caseId: string;
  observedOutcomeCode: string;
}): string {
  const canonical = jcs({
    runId: input.runId,
    caseRegistryDigest: input.caseRegistryDigest,
    tupleDigest: input.tupleDigest,
    caseId: input.caseId,
    observedOutcomeCode: input.observedOutcomeCode,
  } as Parameters<typeof jcs>[0]);
  return sha256Hex(canonical);
}

/** Attachment strategy id for a surface (reviewed stable id). */
export function attachmentStrategyFor(surface: Surface): 'reviewed-tui-app-server-argv' | 'reviewed-macos-desktop-local-daemon-socket' {
  return surface === 'macos_desktop' ? DESKTOP_ATTACHMENT_STRATEGY_ID : TUI_ATTACHMENT_STRATEGY_ID;
}

/**
 * Disposable workspace audit (spec §6.3): record only relative path classes and
 * counts, never absolute user paths.
 */
export interface WorkspaceAuditSummary {
  fileCount: number;
  dirCount: number;
  symlinkCount: number;
  /** Relative path classes by extension group (e.g. `.md`, `.ts`, `other`). */
  extensionCounts: Record<string, number>;
}

export function auditWorkspace(workspaceRoot: string): WorkspaceAuditSummary {
  let fileCount = 0;
  let dirCount = 0;
  let symlinkCount = 0;
  const extensionCounts: Record<string, number> = {};
  const walk = (directory: string): void => {
    let entries: string[] = [];
    try {
      entries = readdirSync(directory).sort();
    } catch {
      return;
    }
    for (const entry of entries) {
      const path = join(directory, entry);
      let stat: ReturnType<typeof lstatSync>;
      try {
        stat = lstatSync(path);
      } catch {
        continue;
      }
      if (stat.isSymbolicLink()) symlinkCount += 1;
      else if (stat.isDirectory()) {
        dirCount += 1;
        walk(path);
      } else if (stat.isFile()) {
        fileCount += 1;
        const ext = entry.includes('.') ? entry.slice(entry.lastIndexOf('.')) : 'other';
        extensionCounts[ext] = (extensionCounts[ext] ?? 0) + 1;
      }
    }
  };
  if (existsSync(workspaceRoot)) walk(workspaceRoot);
  return { fileCount, dirCount, symlinkCount, extensionCounts };
}

/** Owner-only workspace mode: dirs need the owner execute bit to be a valid cwd. */
export const OWNER_ONLY_DIR_MODE = 0o700;

/** Create a fresh disposable workspace (owner-only temp dir, 0700). */
export function makeDisposableWorkspace(): string {
  const root = join(tmpdir(), `codex-poc-workspace-${newRunId()}`);
  mkdirSync(root, { recursive: true, mode: OWNER_ONLY_DIR_MODE });
  chmodSync(root, OWNER_ONLY_DIR_MODE);
  return root;
}

export interface OwnedResourceRecord {
  kind: 'process' | 'socket' | 'temp';
  /** Durable ownership identity (spec §8.9): distinguishes owned vs external. */
  ownershipId: string;
  pid?: number;
  path?: string;
}

/** Durable run manifest (spec §8.9/§11.1): cleanup only touches owned identity. */
export interface RunManifest {
  runId: string;
  startedAt: string;
  resources: OwnedResourceRecord[];
}

export function writeRunManifest(repositoryRoot: string, manifest: RunManifest): string {
  const path = join(artifactsRoot(repositoryRoot), `manifest-${manifest.runId}.json`);
  writeOwnerOnlyFile(path, JSON.stringify(manifest, null, 2));
  return path;
}

/** Sort + dedupe verdict reasons (validateArtifact requires strictly sorted unique). */
export function normalizeVerdictReasons(reasons: readonly VerdictReason[]): VerdictReason[] {
  return [...new Set(reasons)].sort();
}

export { existsSync, readFileSync, writeFileSync, isOwnerOnlyMode, OWNER_ONLY_MODE };
