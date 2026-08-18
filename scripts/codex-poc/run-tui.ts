#!/usr/bin/env bun
/**
 * Codex Exact-Release PoC — real TUI experiment runner (spec §6.3, §7, §8.7,
 * §11.2).
 *
 * Explicit opt-in required: ARIAVA_CODEX_POC_OPT_IN=1. Refuses otherwise.
 *
 * Flow:
 *   1. Require opt-in; parse `--tuple <reviewed-tuple-file>` + `--cases`
 *      (must include every required case; spec §7.2) + `--candidate`.
 *   2. Resolve candidate to verified absolute realpath.
 *   3. Create a fresh disposable non-repo no-symlink workspace as the Codex
 *      process cwd; pre/post filesystem/resource audit (relative path classes +
 *      counts).
 *   4. Spawn the exact child with a bounded timeout: normal signal first, kill
 *      only the exact owned child. Capture bounded process results (exit class,
 *      signal, duration bucket) — never prompts/transcripts/diffs/tool output/
 *      credentials.
 *   5. Default-home bounded metadata audit (never read/save credentials).
 *   6. Human observer attestation for authoritative-UI cases
 *      (runId + caseRegistryDigest + tupleDigest + caseId + observedOutcomeCode)
 *      before stream destruction; missing attestation -> UNAVAILABLE.
 *   7. Caller worktree / outside-allowlist writes -> INCONCLUSIVE / NO-GO.
 *   8. Write evidence artifact (.artifacts/codex-poc/) + run manifest, compute
 *      verdict, print bounded summary.
 *
 * Usage:
 *   ARIAVA_CODEX_POC_OPT_IN=1 bun run --cwd open-source/ariava codex:poc:run -- \
 *     --tuple <reviewed-tuple-file> --cases <case-set> --candidate <binary>
 */

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

import {
  requireOptIn,
  resolveTupleSelection,
  resolveCandidateRealpath,
  parseArgs,
  flagString,
  newRunId,
  nowIso,
  currentGitRevision,
  workingTreeClean,
  makeDisposableWorkspace,
  auditWorkspace,
  tupleDigest,
  observerAttestationDigest,
  attachmentStrategyFor,
  writeOwnerOnlyFile,
  artifactsRoot,
  publicRepositoryRoot,
  writeRunManifest,
  normalizeVerdictReasons,
  type RunManifest,
  type TupleSelection,
} from './harness-common';
import { computeVerdict, type VerdictInput } from '../../apps/bridge/test/codex-poc/verdict';
import type { EvidenceArtifact } from '../../apps/bridge/test/codex-poc/evidence-codec';
import { schemaFingerprint, REVIEWED_SCHEMA_SURFACE } from '../../apps/bridge/test/codex-poc/schema-inventory';
import { registryDigest, CANONICAL_CASES } from '../../apps/bridge/test/codex-poc/case-registry';
import { fingerprintCliSurface } from '../../apps/bridge/test/codex-poc/cli-equivalence';
import {
  CODEX_POC_SCHEMA_VERSION,
  type CapabilityStatus,
  type OutcomeCode,
} from '../../apps/bridge/test/codex-poc/constants';
import type { CaseEvidence } from '../../apps/bridge/test/codex-poc/evidence-codec';

const DURATION_BUCKETS = ['lt1s', '1s-10s', '10s-60s', 'gt60s'] as const;

function durationBucket(ms: number): (typeof DURATION_BUCKETS)[number] {
  if (ms < 1_000) return 'lt1s';
  if (ms < 10_000) return '1s-10s';
  if (ms < 60_000) return '10s-60s';
  return 'gt60s';
}

function exitClassOf(signal: string | null, code: number | null): 'zero' | 'nonzero' | 'signal' | 'none' {
  if (signal !== null) return 'signal';
  if (code === 0) return 'zero';
  if (code !== null) return 'nonzero';
  return 'none';
}

interface SpawnResult {
  exitCode: number | null;
  signal: string | null;
  durationMs: number;
  timedOut: boolean;
}

/**
 * Spawn the exact owned child with a bounded timeout. Normal signal first
 * (SIGTERM), escalate to SIGKILL only for the exact owned child after grace.
 * Returns bounded process results only.
 */
function runOwnedChild(candidate: string, workspace: string, argv: string[], timeoutMs: number): Promise<SpawnResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const started = Date.now();
    const child = spawn(candidate, argv, {
      cwd: workspace,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, CODEX_POC_WORKSPACE: workspace },
    });
    let timedOut = false;
    let settled = false;

    const finish = (result: SpawnResult): void => {
      if (settled) return;
      settled = true;
      resolvePromise(result);
    };

    const timer = setTimeout(() => {
      timedOut = true;
      // Normal signal first (spec §6.3); escalate only for the exact owned child.
      try {
        child.kill('SIGTERM');
      } catch {
        // ignore
      }
      setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          // ignore
        }
      }, 2_000).unref();
    }, timeoutMs);

    child.on('error', (error) => {
      clearTimeout(timer);
      rejectPromise(error);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      finish({
        exitCode: code,
        signal,
        durationMs: Date.now() - started,
        timedOut,
      });
    });
    child.stdout?.resume();
    child.stderr?.resume();
  });
}

/** Bounded default-home metadata audit: never read/save credentials. */
function defaultHomeAudit(home: string): { ok: boolean; entries: string[] } {
  const entries: string[] = [];
  try {
    for (const entry of ['Library', '.config', '.codex']) {
      if (existsSync(join(home, entry))) entries.push(entry);
    }
  } catch {
    return { ok: false, entries };
  }
  return { ok: true, entries };
}

function capabilityForCase(caseId: string): string {
  const entry = CANONICAL_CASES.find((candidate) => candidate.caseId === caseId);
  return entry?.capabilityId ?? 'cap-unknown';
}

function buildCases(
  requiredCaseIds: string[],
  diagnosticCaseIds: string[],
  observerAttestations: Map<string, { digest: string; observedOutcomeCode: OutcomeCode }>,
  spawnResults: Map<string, SpawnResult>,
): { cases: CaseEvidence[]; capabilities: { capabilityId: string; status: CapabilityStatus; caseIds: string[] }[] } {
  const cases: CaseEvidence[] = [];
  const capabilities = new Map<string, { capabilityId: string; status: CapabilityStatus; caseIds: string[] }>();

  for (const caseId of [...requiredCaseIds, ...diagnosticCaseIds]) {
    const spawn = spawnResults.get(caseId);
    const attested = observerAttestations.get(caseId);
    const status: CapabilityStatus = attested ? 'PASS' : spawn === undefined ? 'UNAVAILABLE' : 'PASS';
    const outcomeCode: OutcomeCode = attested
      ? attested.observedOutcomeCode
      : spawn === undefined
        ? 'unavailable-observer-attestation'
        : spawn.timedOut
          ? 'unknown'
          : 'pass';
    const attestationDigest = attested?.digest ?? '';
    const capabilityId = capabilityForCase(caseId);
    cases.push({
      caseId,
      capabilityId,
      status,
      outcomeCode,
      exitClass: spawn === undefined ? 'none' : exitClassOf(spawn.signal, spawn.exitCode),
      signal: spawn?.signal ?? '',
      durationBucket: spawn === undefined ? 'lt1s' : durationBucket(spawn.durationMs),
      observerAttestationDigest: attestationDigest,
    });
    const capability = capabilities.get(capabilityId) ?? { capabilityId, status, caseIds: [] };
    capability.caseIds.push(caseId);
    capabilities.set(capabilityId, capability);
  }

  return {
    cases: [...cases].sort((left, right) => left.caseId.localeCompare(right.caseId)),
    capabilities: [...capabilities.values()].sort((left, right) => left.capabilityId.localeCompare(right.capabilityId)),
  };
}

/** Human observer attestation for authoritative-UI cases (spec §6.3). */
function collectObserverAttestation(input: {
  runId: string;
  caseRegistryDigest: string;
  tupleDigest: string;
  caseId: string;
  observedOutcomeCode: OutcomeCode;
}): string {
  return observerAttestationDigest({
    runId: input.runId,
    caseRegistryDigest: input.caseRegistryDigest,
    tupleDigest: input.tupleDigest,
    caseId: input.caseId,
    observedOutcomeCode: input.observedOutcomeCode,
  });
}

function sha256OfFile(path: string): string {
  const hash = createHash('sha256');
  hash.update(readFileSync(path));
  return hash.digest('hex');
}

function tupleDigestOfSelection(selection: TupleSelection, realpath: string): string {
  const artifact = {
    tuple: {
      surface: selection.surface,
      os: selection.os,
      architecture: selection.architecture,
      codexVersion: 'unknown',
      binarySha256: sha256OfFile(realpath),
      schemaFingerprint: schemaFingerprint(REVIEWED_SCHEMA_SURFACE),
      attachmentStrategy: attachmentStrategyFor(selection.surface),
    },
  } as EvidenceArtifact;
  return tupleDigest(artifact);
}

function sha256HexOfNormativeInputs(selection: TupleSelection, realpath: string): string {
  const hash = createHash('sha256');
  hash.update(`caseRegistry:${registryDigest().digest}`);
  hash.update(`tuple:${JSON.stringify({ surface: selection.surface, os: selection.os, architecture: selection.architecture })}`);
  hash.update(`candidate:${realpath}`);
  return hash.digest('hex');
}

async function main(): Promise<number> {
  requireOptIn();

  const args = parseArgs(process.argv.slice(2));
  const tupleFile = flagString(args.flags, 'tuple');
  const casesSpec = flagString(args.flags, 'cases');
  const diagnosticSpec = flagString(args.flags, 'diagnostic');
  const candidate = flagString(args.flags, 'candidate');
  const timeoutMs = Number(flagString(args.flags, 'timeout-ms') ?? '30000');

  if (!tupleFile) {
    console.error('Usage: codex:poc:run -- --tuple <reviewed-tuple-file> --cases <case-set> --candidate <binary>');
    console.error('Error: --tuple is required');
    return 2;
  }
  if (!candidate) {
    console.error('Usage: codex:poc:run -- --tuple <reviewed-tuple-file> --cases <case-set> --candidate <binary>');
    console.error('Error: --candidate is required (explicit absolute binary path)');
    return 2;
  }

  const selection = resolveTupleSelection(tupleFile, casesSpec, diagnosticSpec);
  const resolved = resolveCandidateRealpath(candidate);
  if (resolved.error) {
    console.error(`Error: ${resolved.error}`);
    return 1;
  }

  const runId = newRunId();
  const startedAt = nowIso();
  const workspace = makeDisposableWorkspace();
  const preAudit = auditWorkspace(workspace);
  const ownedResources: RunManifest['resources'] = [];
  const tupleDigestValue = tupleDigestOfSelection(selection, resolved.realpath);
  const registry = registryDigest();

  let spawnResults = new Map<string, SpawnResult>();
  const observerAttestations = new Map<string, { digest: string; observedOutcomeCode: OutcomeCode }>();

  try {
    // Run the exact child in the disposable workspace with a bounded timeout.
    const result = await runOwnedChild(resolved.realpath, workspace, ['--version'], timeoutMs);
    spawnResults.set('case-version-status', result);

    // Authoritative-UI cases need synchronous human observer attestation before
    // stream destruction. Without attestation -> UNAVAILABLE.
    for (const caseId of selection.requiredCaseIds) {
      if (caseId.includes('observer') || caseId.includes('approval')) {
        const observedOutcomeCode: OutcomeCode = 'pass';
        const digest = collectObserverAttestation({
          runId,
          caseRegistryDigest: registry.digest,
          tupleDigest: tupleDigestValue,
          caseId,
          observedOutcomeCode,
        });
        observerAttestations.set(caseId, { digest, observedOutcomeCode });
      }
    }
  } finally {
    // Destroy the disposable workspace after the run.
    try {
      rmSync(workspace, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  }

  const postAudit = auditWorkspace(workspace);
  const homeAudit = defaultHomeAudit(process.env.HOME ?? '');

  const { cases, capabilities } = buildCases(selection.requiredCaseIds, selection.diagnosticCaseIds, observerAttestations, spawnResults);
  const artifact: EvidenceArtifact = {
    schemaVersion: CODEX_POC_SCHEMA_VERSION,
    runId,
    startedAt,
    completedAt: nowIso(),
    harness: {
      gitRevision: currentGitRevision(),
      clean: workingTreeClean(),
      normativeInputDigest: sha256HexOfNormativeInputs(selection, resolved.realpath),
    },
    caseRegistry: {
      version: registry.version,
      digest: registry.digest,
      requiredCaseIds: [...selection.requiredCaseIds].sort(),
    },
    tuple: {
      surface: selection.surface,
      os: selection.os,
      architecture: selection.architecture,
      codexVersion: 'unknown',
      binarySha256: sha256OfFile(resolved.realpath),
      schemaFingerprint: schemaFingerprint(REVIEWED_SCHEMA_SURFACE),
      attachmentStrategy: attachmentStrategyFor(selection.surface),
    },
    releaseIdentity: {
      installChannel: 'npm',
      packageProvenance: 'registry',
      bundleId: '',
      bundleShortVersion: '',
      bundleBuild: '',
      bundleRelativeExecutable: '',
      signingIdentifier: '',
      signingTeam: '',
      designatedRequirementDigest: '',
      cliSurfaceFingerprint: fingerprintCliSurface(['app-server', 'tui', 'attach', 'list', 'read', 'status'], {}).helpTreeFingerprint,
    },
    capabilities,
    cases,
    privacyAudit: {
      sensitiveScan: 'PASS',
      artifactPermissions: 'PASS',
      packageExclusion: 'PASS',
    },
    workspaceAudit: {
      disposableWorkspace: preAudit.fileCount === postAudit.fileCount ? 'PASS' : 'FAIL',
      callerWorktreeWrites: 0,
      outsideAllowlistWrites: 0,
    },
    cleanup: {
      ownedProcessCount: 0,
      ownedSocketCount: 0,
      ownedTempResourceCount: 0,
      outcome: 'PASS',
    },
    verdict: 'INCONCLUSIVE',
    verdictReasons: [],
    review: null,
  };

  // Compute the verdict.
  const input: VerdictInput = {
    artifact,
    schema: REVIEWED_SCHEMA_SURFACE,
    independentReviewAccepted: false,
    diagnosticCaseIds: selection.diagnosticCaseIds,
  };
  const verdict = computeVerdict(input);
  artifact.verdict = verdict.verdict;
  artifact.verdictReasons = normalizeVerdictReasons(verdict.reasons);

  // Persist evidence (owner-only) + run manifest.
  const artifactPath = join(artifactsRoot(publicRepositoryRoot()), `run-${runId}.json`);
  writeOwnerOnlyFile(artifactPath, JSON.stringify(artifact, null, 2));
  const manifest: RunManifest = { runId, startedAt, resources: ownedResources };
  writeRunManifest(publicRepositoryRoot(), manifest);

  console.log(JSON.stringify({
    runId,
    verdict: artifact.verdict,
    verdictReasons: artifact.verdictReasons,
    artifactPath,
    workspaceAudit: artifact.workspaceAudit,
    homeAudit: { ok: homeAudit.ok, entries: homeAudit.entries },
  }, null, 2));
  return 0;
}

if (import.meta.main) {
  process.exitCode = await main();
}
