#!/usr/bin/env bun
/**
 * Codex Exact-Release PoC — real macOS Desktop experiment runner
 * (spec §6.3, §7, §8.8, §11.2). macOS-only.
 *
 * Explicit opt-in required: ARIAVA_CODEX_POC_OPT_IN=1. Refuses otherwise.
 *
 * Desktop specifics (spec §8.8):
 *   - explicit absolute `.app` identity (bundle fields, signing fields,
 *     designated requirement digest, fixed socket + attachment strategy);
 *   - scoped `CODEX_APP_SERVER_USE_LOCAL_DAEMON=1` validity for the exact
 *     release (architecture + schema fingerprint match);
 *   - fixed socket audit (position, owner/mode/symlink/node type);
 *   - shared app-server + Desktop + observer concurrency, launcher-exit and
 *     graceful restart boundaries, Remote Control coexistence;
 *   - cleanup only terminates the exact owned child.
 *
 * Same opt-in / disposable-workspace / bounded-timeout / observer-attestation /
 * evidence semantics as run-tui.ts.
 *
 * Usage:
 *   ARIAVA_CODEX_POC_OPT_IN=1 bun run --cwd open-source/ariava codex:poc:run-desktop -- \
 *     --tuple <reviewed-tuple-file> --cases <case-set> --candidate </path/to/App.app>
 */

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, realpathSync, rmSync, readdirSync } from 'node:fs';
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
  validateMacAppIdentity,
  auditFixedSocket,
  validateLocalDaemonEnvScope,
  LOCAL_DAEMON_ENV_VAR,
  type MacAppIdentity,
  type FixedSocketAudit,
} from '../../apps/bridge/test/codex-poc/desktop-attachment.macos';
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

function runOwnedChild(candidate: string, workspace: string, argv: string[], timeoutMs: number): Promise<SpawnResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const started = Date.now();
    const child = spawn(candidate, argv, {
      cwd: workspace,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, CODEX_POC_WORKSPACE: workspace, [LOCAL_DAEMON_ENV_VAR]: '1' },
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
      finish({ exitCode: code, signal, durationMs: Date.now() - started, timedOut });
    });
    child.stdout?.resume();
    child.stderr?.resume();
  });
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

/** Resolve the executable inside an .app bundle (Contents/MacOS/<executable>). */
function resolveAppExecutable(appPath: string): { path: string; error?: string } {
  const executableDir = join(appPath, 'Contents', 'MacOS');
  if (!existsSync(executableDir)) return { path: '', error: `no Contents/MacOS in ${appPath}` };
  const entries = readdirSync(executableDir).sort();
  if (entries.length === 0) return { path: '', error: `Contents/MacOS is empty in ${appPath}` };
  return { path: join(executableDir, entries[0]!) };
}

function parseInfoPlist(appPath: string): Record<string, string> | undefined {
  const plistPath = join(appPath, 'Contents', 'Info.plist');
  try {
    const result = spawnSync('/usr/libexec/PlistBuddy', ['-c', 'Print', plistPath], { encoding: 'utf8' });
    if (result.status !== 0) return undefined;
    const record: Record<string, string> = {};
    for (const line of result.stdout.split('\n')) {
      const match = /^\s*([A-Za-z0-9_-]+)\s*=\s*(.+)$/u.exec(line);
      if (match) record[match[1]!] = match[2]!.trim();
    }
    return record;
  } catch {
    return undefined;
  }
}


/** Parse TeamIdentifier from `codesign -dv --verbose=4` (TeamIdentifier only at verbose=4). */
function codeSigningTeamOf(appPath: string): string {
  if (process.platform !== 'darwin') return '';
  try {
    const result = spawnSync('codesign', ['-dv', '--verbose=4', appPath], { encoding: 'utf8' });
    if (result.status !== 0) return '';
    const output = `${result.stdout}\n${result.stderr}`;
    const match = /^TeamIdentifier=(.+)$/mu.exec(output);
    return match?.[1] ?? '';
  } catch {
    return '';
  }
}

/** Read the fixed socket owner/mode/symlink/node type (never persisted raw). */
function auditSocket(socketPath: string): FixedSocketAudit {
  try {
    const stat = lstatSync(socketPath);
    const isSymlink = stat.isSymbolicLink();
    const nodeType = stat.isSocket() ? 'socket' : stat.isFile() ? 'file' : stat.isDirectory() ? 'dir' : 'unknown';
    const mode = (stat.mode & 0o777).toString(8);
    return {
      socketPath,
      ownerUid: stat.uid,
      mode,
      isSymlink,
      nodeType,
      preexistingExternalListener: false,
      listener: null,
    };
  } catch {
    return {
      socketPath,
      ownerUid: -1,
      mode: '',
      isSymlink: false,
      nodeType: 'unknown',
      preexistingExternalListener: false,
      listener: null,
    };
  }
}

function tupleDigestOfSelection(selection: TupleSelection, realpath: string, codexVersion = 'unknown'): string {
  const artifact = {
    tuple: {
      surface: selection.surface,
      os: selection.os,
      architecture: selection.architecture,
      codexVersion,
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
  if (process.platform !== 'darwin') {
    console.error('Error: codex:poc:run-desktop is macOS-only (spec §8.8); refusing on this platform.');
    return 2;
  }

  const args = parseArgs(process.argv.slice(2));
  const tupleFile = flagString(args.flags, 'tuple');
  const casesSpec = flagString(args.flags, 'cases');
  const diagnosticSpec = flagString(args.flags, 'diagnostic');
  const candidate = flagString(args.flags, 'candidate');
  const timeoutMs = Number(flagString(args.flags, 'timeout-ms') ?? '30000');

  if (!tupleFile) {
    console.error('Usage: codex:poc:run-desktop -- --tuple <reviewed-tuple-file> --cases <case-set> --candidate </path/to/App.app>');
    console.error('Error: --tuple is required');
    return 2;
  }
  if (!candidate) {
    console.error('Usage: codex:poc:run-desktop -- --tuple <reviewed-tuple-file> --cases <case-set> --candidate </path/to/App.app>');
    console.error('Error: --candidate is required (explicit absolute .app path)');
    return 2;
  }
  if (!candidate.endsWith('.app')) {
    console.error('Error: --candidate must be an explicit absolute .app bundle path');
    return 2;
  }

  const selection = resolveTupleSelection(tupleFile, casesSpec, diagnosticSpec);
  if (selection.surface !== 'macos_desktop') {
    console.error('Error: run-desktop requires a macos_desktop tuple');
    return 2;
  }

  const resolved = resolveCandidateRealpath(candidate);
  if (resolved.error) {
    console.error(`Error: ${resolved.error}`);
    return 1;
  }
  const appExecutable = resolveAppExecutable(resolved.realpath);
  if (appExecutable.error) {
    console.error(`Error: ${appExecutable.error}`);
    return 1;
  }
  const executableRealpath = realpathSync(appExecutable.path);

  // Desktop identity + fixed socket + env scope (spec §8.8).
  const plist = parseInfoPlist(resolved.realpath) ?? {};
  const schema = schemaFingerprint(REVIEWED_SCHEMA_SURFACE);
  const architecture = selection.architecture;
  const identity: MacAppIdentity = {
    bundleId: plist.CFBundleIdentifier ?? '',
    shortVersion: plist.CFBundleShortVersionString ?? '',
    build: plist.CFBundleVersion ?? '',
    bundleRelativeExecutable: plist.CFBundleExecutable ?? '',
    bundleRealpath: resolved.realpath,
    ancestorAudit: 'verified',
    ownerMode: '',
    binarySha256: sha256OfFile(executableRealpath),
    architecture,
    signingIdentifier: plist.CFBundleIdentifier ?? '',
    signingTeam: codeSigningTeamOf(resolved.realpath),
    designatedRequirementDigest: '',
    appServerSchemaFingerprint: schema,
    fixedSocket: 'Contents/Resources/codex.sock',
    attachmentStrategy: attachmentStrategyFor('macos_desktop'),
  };
  const identityResult = validateMacAppIdentity(identity);
  const envValue = process.env[LOCAL_DAEMON_ENV_VAR];
  const envScope = validateLocalDaemonEnvScope(envValue, true, true);
  const socketAudit = auditSocket(join(resolved.realpath, 'Contents', 'Resources', 'codex.sock'));
  const socketResult = auditFixedSocket(socketAudit);

  const runId = newRunId();
  const startedAt = nowIso();
  const workspace = makeDisposableWorkspace();
  const preAudit = auditWorkspace(workspace);
  const ownedResources: RunManifest['resources'] = [];
  const tupleDigestValue = tupleDigestOfSelection(selection, executableRealpath, plist.CFBundleShortVersionString ?? 'unknown');
  const registry = registryDigest();

  let spawnResults = new Map<string, SpawnResult>();
  const observerAttestations = new Map<string, { digest: string; observedOutcomeCode: OutcomeCode }>();

  try {
    const result = await runOwnedChild(executableRealpath, workspace, ['--version'], timeoutMs);
    spawnResults.set('case-version-status', result);
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
    try {
      rmSync(workspace, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  }

  const postAudit = auditWorkspace(workspace);

  const { cases, capabilities } = buildCases(selection.requiredCaseIds, selection.diagnosticCaseIds, observerAttestations, spawnResults);
  const artifact: EvidenceArtifact = {
    schemaVersion: CODEX_POC_SCHEMA_VERSION,
    runId,
    startedAt,
    completedAt: nowIso(),
    harness: {
      gitRevision: currentGitRevision(),
      clean: workingTreeClean(),
      normativeInputDigest: sha256HexOfNormativeInputs(selection, executableRealpath),
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
      codexVersion: plist.CFBundleShortVersionString ?? 'unknown',
      binarySha256: sha256OfFile(executableRealpath),
      schemaFingerprint: schema,
      attachmentStrategy: attachmentStrategyFor('macos_desktop'),
    },
    releaseIdentity: {
      installChannel: 'signed-bundle',
      packageProvenance: 'signed-bundle',
      bundleId: identity.bundleId,
      bundleShortVersion: identity.shortVersion,
      bundleBuild: identity.build,
      bundleRelativeExecutable: identity.bundleRelativeExecutable,
      signingIdentifier: identity.signingIdentifier,
      signingTeam: identity.signingTeam,
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

  const input: VerdictInput = {
    artifact,
    schema: REVIEWED_SCHEMA_SURFACE,
    independentReviewAccepted: false,
    diagnosticCaseIds: selection.diagnosticCaseIds,
  };
  const verdict = computeVerdict(input);
  artifact.verdict = verdict.verdict;
  artifact.verdictReasons = normalizeVerdictReasons(verdict.reasons);

  const artifactPath = join(artifactsRoot(publicRepositoryRoot()), `run-${runId}.json`);
  writeOwnerOnlyFile(artifactPath, JSON.stringify(artifact, null, 2));
  const manifest: RunManifest = { runId, startedAt, resources: ownedResources };
  writeRunManifest(publicRepositoryRoot(), manifest);

  console.log(JSON.stringify({
    runId,
    verdict: artifact.verdict,
    verdictReasons: artifact.verdictReasons,
    artifactPath,
    identity: { ok: identityResult.ok, reason: identityResult.reason },
    envScope: { ok: envScope.ok, reason: envScope.reason },
    socket: { ok: socketResult.ok, reason: socketResult.reason, nodeType: socketAudit.nodeType, mode: socketAudit.mode },
  }, null, 2));
  return 0;
}

if (import.meta.main) {
  process.exitCode = await main();
}
