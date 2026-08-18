/**
 * Strict exact-key evidence codec for the Codex Exact-Release Capability PoC
 * (spec §7.3).
 *
 * Every object type is exact-key: unknown keys are rejected, missing keys are
 * rejected. Arrays are sorted by stable id and duplicates are rejected. Unused
 * `releaseIdentity` fields serialize as empty strings (never omitted). Paths are
 * restricted to reviewed bundle-relative paths or closed install-channel
 * classifications; real user home/temp absolute paths are rejected.
 *
 * The evidence digest is `SHA-256(RFC 8785 JCS(artifact with review = null))`;
 * the review record is stored separately and never written back into the hashed
 * payload.
 *
 * Research-only harness code; never part of the production import graph.
 */

import { createHash } from 'node:crypto';
import {
  CAPABILITY_STATUSES,
  CODEX_POC_SCHEMA_VERSION,
  DURATION_BUCKETS,
  EXIT_CLASSES,
  OUTCOME_CODES,
  SURFACES,
  VERDICTS,
  type Architecture,
  type AttachmentStrategy,
  type CapabilityStatus,
  type DurationBucket,
  type ExitClass,
  type OperatingSystem,
  type OutcomeCode,
  type Surface,
  type Verdict,
  type VerdictReason,
  VERDICT_REASONS,
  OPERATING_SYSTEMS,
  ARCHITECTURES,
} from './constants';
import { jcs, type JcsValue } from './jcs';

export interface HarnessEvidence {
  gitRevision: string;
  clean: boolean;
  normativeInputDigest: string;
}

export interface CaseRegistryEvidence {
  version: number;
  digest: string;
  requiredCaseIds: string[];
}

export interface TupleEvidence {
  surface: Surface;
  os: OperatingSystem;
  architecture: Architecture;
  codexVersion: string;
  binarySha256: string;
  schemaFingerprint: string;
  attachmentStrategy: AttachmentStrategy;
}

export interface ReleaseIdentityEvidence {
  installChannel: string;
  packageProvenance: string;
  bundleId: string;
  bundleShortVersion: string;
  bundleBuild: string;
  bundleRelativeExecutable: string;
  signingIdentifier: string;
  signingTeam: string;
  designatedRequirementDigest: string;
  cliSurfaceFingerprint: string;
}

export interface CapabilityEvidence {
  capabilityId: string;
  status: CapabilityStatus;
  caseIds: string[];
}

export interface CaseEvidence {
  caseId: string;
  capabilityId: string;
  status: CapabilityStatus;
  outcomeCode: OutcomeCode;
  exitClass: ExitClass;
  signal: string;
  durationBucket: DurationBucket;
  observerAttestationDigest: string;
}

export interface PrivacyAuditEvidence {
  sensitiveScan: 'PASS' | 'FAIL';
  artifactPermissions: 'PASS' | 'FAIL';
  packageExclusion: 'PASS' | 'FAIL';
}

export interface WorkspaceAuditEvidence {
  disposableWorkspace: 'PASS' | 'FAIL';
  callerWorktreeWrites: number;
  outsideAllowlistWrites: number;
}

export interface CleanupEvidence {
  ownedProcessCount: number;
  ownedSocketCount: number;
  ownedTempResourceCount: number;
  outcome: 'PASS' | 'FAIL';
}

export interface EvidenceArtifact {
  schemaVersion: typeof CODEX_POC_SCHEMA_VERSION;
  runId: string;
  startedAt: string;
  completedAt: string;
  harness: HarnessEvidence;
  caseRegistry: CaseRegistryEvidence;
  tuple: TupleEvidence;
  releaseIdentity: ReleaseIdentityEvidence;
  capabilities: CapabilityEvidence[];
  cases: CaseEvidence[];
  privacyAudit: PrivacyAuditEvidence;
  workspaceAudit: WorkspaceAuditEvidence;
  cleanup: CleanupEvidence;
  verdict: Verdict;
  verdictReasons: VerdictReason[];
  review: null;
}

const EXACT_KEYS = {
  artifact: [
    'schemaVersion', 'runId', 'startedAt', 'completedAt', 'harness', 'caseRegistry',
    'tuple', 'releaseIdentity', 'capabilities', 'cases', 'privacyAudit',
    'workspaceAudit', 'cleanup', 'verdict', 'verdictReasons', 'review',
  ],
  harness: ['gitRevision', 'clean', 'normativeInputDigest'],
  caseRegistry: ['version', 'digest', 'requiredCaseIds'],
  tuple: ['surface', 'os', 'architecture', 'codexVersion', 'binarySha256', 'schemaFingerprint', 'attachmentStrategy'],
  releaseIdentity: [
    'installChannel', 'packageProvenance', 'bundleId', 'bundleShortVersion', 'bundleBuild',
    'bundleRelativeExecutable', 'signingIdentifier', 'signingTeam', 'designatedRequirementDigest',
    'cliSurfaceFingerprint',
  ],
  capability: ['capabilityId', 'status', 'caseIds'],
  case: ['caseId', 'capabilityId', 'status', 'outcomeCode', 'exitClass', 'signal', 'durationBucket', 'observerAttestationDigest'],
  privacyAudit: ['sensitiveScan', 'artifactPermissions', 'packageExclusion'],
  workspaceAudit: ['disposableWorkspace', 'callerWorktreeWrites', 'outsideAllowlistWrites'],
  cleanup: ['ownedProcessCount', 'ownedSocketCount', 'ownedTempResourceCount', 'outcome'],
} as const;

function assertExactKeys(object: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const actual = Object.keys(object).sort();
  const expected = [...allowed].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    const unknown = actual.filter((key) => !allowed.includes(key));
    const missing = expected.filter((key) => !actual.includes(key));
    throw new Error(`${label}: exact-key violation; unknown=${JSON.stringify(unknown)} missing=${JSON.stringify(missing)}`);
  }
}

function assertArraySortedUnique(values: string[], label: string): void {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1]! >= values[index]!) {
      throw new Error(`${label}: array must be strictly sorted with unique stable ids`);
    }
  }
}

function assertHexSha256(value: string, label: string): void {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new Error(`${label}: expected 64-char lowercase hex sha256, got ${JSON.stringify(value)}`);
}

function assertRfc3339(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value)) {
    throw new Error(`${label}: expected RFC3339 UTC timestamp, got ${JSON.stringify(value)}`);
  }
}

function assertUuid(value: string, label: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)) {
    throw new Error(`${label}: expected canonical lowercase uuid, got ${JSON.stringify(value)}`);
  }
}

function assertReviewedPath(value: string, label: string): void {
  if (value === '') return;
  if (value.startsWith('/') || /^[A-Za-z]:[\\/]/u.test(value)) {
    throw new Error(`${label}: absolute path not allowed in evidence; use bundle-relative path or closed install-channel classification`);
  }
  if (value.includes('..')) throw new Error(`${label}: traversal path not allowed in evidence`);
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

/** Validate and normalize a candidate artifact (exact-key, bounded enums). */
export function validateArtifact(candidate: unknown): EvidenceArtifact {
  if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) {
    throw new Error('evidence: artifact must be an object');
  }
  const object = candidate as Record<string, unknown>;
  assertExactKeys(object, EXACT_KEYS.artifact, 'evidence.artifact');

  if (object.schemaVersion !== CODEX_POC_SCHEMA_VERSION) {
    throw new Error(`evidence: schemaVersion must be ${CODEX_POC_SCHEMA_VERSION}, got ${JSON.stringify(object.schemaVersion)}`);
  }
  const runId = object.runId;
  if (typeof runId !== 'string' || !UUID_RE.test(runId)) throw new Error('evidence: runId must be canonical lowercase uuid');
  const startedAt = object.startedAt;
  if (typeof startedAt !== 'string') throw new Error('evidence: startedAt must be a string');
  assertRfc3339(startedAt, 'evidence.startedAt');
  const completedAt = object.completedAt;
  if (typeof completedAt !== 'string') throw new Error('evidence: completedAt must be a string');
  assertRfc3339(completedAt, 'evidence.completedAt');

  const harness = object.harness;
  if (typeof harness !== 'object' || harness === null) throw new Error('evidence.harness must be an object');
  assertExactKeys(harness as Record<string, unknown>, EXACT_KEYS.harness, 'evidence.harness');
  const harnessObj = harness as Record<string, unknown>;
  if (typeof harnessObj.gitRevision !== 'string' || !/^[0-9a-f]{7,40}$/u.test(harnessObj.gitRevision)) throw new Error('evidence.harness.gitRevision must be a git sha');
  if (typeof harnessObj.clean !== 'boolean') throw new Error('evidence.harness.clean must be a boolean');
  if (typeof harnessObj.normativeInputDigest !== 'string') throw new Error('evidence.harness.normativeInputDigest must be a string');
  assertHexSha256(harnessObj.normativeInputDigest, 'evidence.harness.normativeInputDigest');

  const caseRegistry = object.caseRegistry;
  if (typeof caseRegistry !== 'object' || caseRegistry === null) throw new Error('evidence.caseRegistry must be an object');
  assertExactKeys(caseRegistry as Record<string, unknown>, EXACT_KEYS.caseRegistry, 'evidence.caseRegistry');
  const caseRegistryObj = caseRegistry as Record<string, unknown>;
  if (typeof caseRegistryObj.version !== 'number' || caseRegistryObj.version !== 1) throw new Error('evidence.caseRegistry.version must be 1');
  if (typeof caseRegistryObj.digest !== 'string') throw new Error('evidence.caseRegistry.digest must be a string');
  assertHexSha256(caseRegistryObj.digest, 'evidence.caseRegistry.digest');
  if (!Array.isArray(caseRegistryObj.requiredCaseIds)) throw new Error('evidence.caseRegistry.requiredCaseIds must be an array');
  const requiredCaseIds = caseRegistryObj.requiredCaseIds as unknown[];
  if (requiredCaseIds.some((value) => typeof value !== 'string')) throw new Error('evidence.caseRegistry.requiredCaseIds must be string[]');
  assertArraySortedUnique(requiredCaseIds as string[], 'evidence.caseRegistry.requiredCaseIds');

  const tuple = object.tuple;
  if (typeof tuple !== 'object' || tuple === null) throw new Error('evidence.tuple must be an object');
  assertExactKeys(tuple as Record<string, unknown>, EXACT_KEYS.tuple, 'evidence.tuple');
  const tupleObj = tuple as Record<string, unknown>;
  if (typeof tupleObj.surface !== 'string' || !SURFACES.includes(tupleObj.surface as Surface)) throw new Error('evidence.tuple.surface must be a reviewed surface');
  if (typeof tupleObj.os !== 'string' || !OPERATING_SYSTEMS.includes(tupleObj.os as OperatingSystem)) throw new Error('evidence.tuple.os must be a reviewed os');
  if (typeof tupleObj.architecture !== 'string' || !ARCHITECTURES.includes(tupleObj.architecture as Architecture)) throw new Error('evidence.tuple.architecture must be a reviewed architecture');
  if (typeof tupleObj.codexVersion !== 'string' || tupleObj.codexVersion.length === 0) throw new Error('evidence.tuple.codexVersion must be non-empty');
  if (typeof tupleObj.binarySha256 !== 'string') throw new Error('evidence.tuple.binarySha256 must be a string');
  assertHexSha256(tupleObj.binarySha256, 'evidence.tuple.binarySha256');
  if (typeof tupleObj.schemaFingerprint !== 'string') throw new Error('evidence.tuple.schemaFingerprint must be a string');
  assertHexSha256(tupleObj.schemaFingerprint, 'evidence.tuple.schemaFingerprint');
  if (typeof tupleObj.attachmentStrategy !== 'string' || tupleObj.attachmentStrategy.length === 0) throw new Error('evidence.tuple.attachmentStrategy must be a reviewed stable id');

  const releaseIdentity = object.releaseIdentity;
  if (typeof releaseIdentity !== 'object' || releaseIdentity === null) throw new Error('evidence.releaseIdentity must be an object');
  assertExactKeys(releaseIdentity as Record<string, unknown>, EXACT_KEYS.releaseIdentity, 'evidence.releaseIdentity');
  const releaseIdentityObj = releaseIdentity as Record<string, unknown>;
  for (const key of EXACT_KEYS.releaseIdentity) {
    if (typeof releaseIdentityObj[key] !== 'string') throw new Error(`evidence.releaseIdentity.${key} must be a string (empty string when not applicable)`);
  }
  const designated = releaseIdentityObj.designatedRequirementDigest as string;
  if (designated !== '' && !/^[0-9a-f]{64}$/u.test(designated)) throw new Error('evidence.releaseIdentity.designatedRequirementDigest must be empty or sha256 hex');
  const cli = releaseIdentityObj.cliSurfaceFingerprint as string;
  if (!/^[0-9a-f]{64}$/u.test(cli)) throw new Error('evidence.releaseIdentity.cliSurfaceFingerprint must be sha256 hex');
  assertReviewedPath(releaseIdentityObj.bundleRelativeExecutable as string, 'evidence.releaseIdentity.bundleRelativeExecutable');

  const capabilities = object.capabilities;
  if (!Array.isArray(capabilities)) throw new Error('evidence.capabilities must be an array');
  const capabilityIds = new Set<string>();
  const normalizedCapabilities: CapabilityEvidence[] = [];
  for (const entry of capabilities) {
    if (typeof entry !== 'object' || entry === null) throw new Error('evidence.capabilities[] must be objects');
    assertExactKeys(entry as Record<string, unknown>, EXACT_KEYS.capability, 'evidence.capabilities[]');
    const capability = entry as Record<string, unknown>;
    if (typeof capability.capabilityId !== 'string' || capability.capabilityId.length === 0) throw new Error('evidence.capabilities[].capabilityId must be non-empty');
    if (capabilityIds.has(capability.capabilityId)) throw new Error(`evidence.capabilities[].capabilityId duplicate: ${capability.capabilityId}`);
    capabilityIds.add(capability.capabilityId);
    if (typeof capability.status !== 'string' || !CAPABILITY_STATUSES.includes(capability.status as CapabilityStatus)) throw new Error('evidence.capabilities[].status must be PASS|FAIL|UNAVAILABLE');
    if (!Array.isArray(capability.caseIds) || (capability.caseIds as unknown[]).some((value) => typeof value !== 'string')) {
      throw new Error('evidence.capabilities[].caseIds must be string[]');
    }
    assertArraySortedUnique(capability.caseIds as string[], `evidence.capabilities[].caseIds (${capability.capabilityId as string})`);
    normalizedCapabilities.push({
      capabilityId: capability.capabilityId as string,
      status: capability.status as CapabilityStatus,
      caseIds: [...(capability.caseIds as string[])],
    });
  }

  const cases = object.cases;
  if (!Array.isArray(cases)) throw new Error('evidence.cases must be an array');
  const caseIds = new Set<string>();
  const normalizedCases: CaseEvidence[] = [];
  for (const entry of cases) {
    if (typeof entry !== 'object' || entry === null) throw new Error('evidence.cases[] must be objects');
    assertExactKeys(entry as Record<string, unknown>, EXACT_KEYS.case, 'evidence.cases[]');
    const caseEntry = entry as Record<string, unknown>;
    if (typeof caseEntry.caseId !== 'string' || caseEntry.caseId.length === 0) throw new Error('evidence.cases[].caseId must be non-empty');
    if (caseIds.has(caseEntry.caseId)) throw new Error(`evidence.cases[].caseId duplicate: ${caseEntry.caseId}`);
    caseIds.add(caseEntry.caseId);
    if (typeof caseEntry.capabilityId !== 'string' || caseEntry.capabilityId.length === 0) throw new Error('evidence.cases[].capabilityId must be non-empty');
    if (typeof caseEntry.status !== 'string' || !CAPABILITY_STATUSES.includes(caseEntry.status as CapabilityStatus)) throw new Error('evidence.cases[].status must be PASS|FAIL|UNAVAILABLE');
    if (typeof caseEntry.outcomeCode !== 'string' || !OUTCOME_CODES.includes(caseEntry.outcomeCode as OutcomeCode)) throw new Error('evidence.cases[].outcomeCode must be a reviewed bounded code');
    if (typeof caseEntry.exitClass !== 'string' || !EXIT_CLASSES.includes(caseEntry.exitClass as ExitClass)) throw new Error('evidence.cases[].exitClass must be zero|nonzero|signal|none');
    if (typeof caseEntry.signal !== 'string') throw new Error('evidence.cases[].signal must be a string (bounded name or empty)');
    if (typeof caseEntry.durationBucket !== 'string' || !DURATION_BUCKETS.includes(caseEntry.durationBucket as DurationBucket)) throw new Error('evidence.cases[].durationBucket must be lt1s|1s-10s|10s-60s|gt60s');
    const attestation = caseEntry.observerAttestationDigest as string;
    if (typeof attestation !== 'string') throw new Error('evidence.cases[].observerAttestationDigest must be a string');
    if (attestation !== '' && !/^[0-9a-f]{64}$/u.test(attestation)) throw new Error('evidence.cases[].observerAttestationDigest must be empty or sha256 hex');
    normalizedCases.push({
      caseId: caseEntry.caseId as string,
      capabilityId: caseEntry.capabilityId as string,
      status: caseEntry.status as CapabilityStatus,
      outcomeCode: caseEntry.outcomeCode as OutcomeCode,
      exitClass: caseEntry.exitClass as ExitClass,
      signal: caseEntry.signal as string,
      durationBucket: caseEntry.durationBucket as DurationBucket,
      observerAttestationDigest: attestation,
    });
  }

  const privacyAudit = object.privacyAudit;
  if (typeof privacyAudit !== 'object' || privacyAudit === null) throw new Error('evidence.privacyAudit must be an object');
  assertExactKeys(privacyAudit as Record<string, unknown>, EXACT_KEYS.privacyAudit, 'evidence.privacyAudit');
  const privacyAuditObj = privacyAudit as Record<string, unknown>;
  for (const key of ['sensitiveScan', 'artifactPermissions', 'packageExclusion'] as const) {
    if (privacyAuditObj[key] !== 'PASS' && privacyAuditObj[key] !== 'FAIL') throw new Error(`evidence.privacyAudit.${key} must be PASS|FAIL`);
  }

  const workspaceAudit = object.workspaceAudit;
  if (typeof workspaceAudit !== 'object' || workspaceAudit === null) throw new Error('evidence.workspaceAudit must be an object');
  assertExactKeys(workspaceAudit as Record<string, unknown>, EXACT_KEYS.workspaceAudit, 'evidence.workspaceAudit');
  const workspaceAuditObj = workspaceAudit as Record<string, unknown>;
  if (workspaceAuditObj.disposableWorkspace !== 'PASS' && workspaceAuditObj.disposableWorkspace !== 'FAIL') throw new Error('evidence.workspaceAudit.disposableWorkspace must be PASS|FAIL');
  if (typeof workspaceAuditObj.callerWorktreeWrites !== 'number' || !Number.isInteger(workspaceAuditObj.callerWorktreeWrites) || (workspaceAuditObj.callerWorktreeWrites as number) < 0) throw new Error('evidence.workspaceAudit.callerWorktreeWrites must be a non-negative integer');
  if (typeof workspaceAuditObj.outsideAllowlistWrites !== 'number' || !Number.isInteger(workspaceAuditObj.outsideAllowlistWrites) || (workspaceAuditObj.outsideAllowlistWrites as number) < 0) throw new Error('evidence.workspaceAudit.outsideAllowlistWrites must be a non-negative integer');

  const cleanup = object.cleanup;
  if (typeof cleanup !== 'object' || cleanup === null) throw new Error('evidence.cleanup must be an object');
  assertExactKeys(cleanup as Record<string, unknown>, EXACT_KEYS.cleanup, 'evidence.cleanup');
  const cleanupObj = cleanup as Record<string, unknown>;
  for (const key of ['ownedProcessCount', 'ownedSocketCount', 'ownedTempResourceCount'] as const) {
    if (typeof cleanupObj[key] !== 'number' || !Number.isInteger(cleanupObj[key]) || (cleanupObj[key] as number) < 0) throw new Error(`evidence.cleanup.${key} must be a non-negative integer`);
  }
  if (cleanupObj.outcome !== 'PASS' && cleanupObj.outcome !== 'FAIL') throw new Error('evidence.cleanup.outcome must be PASS|FAIL');

  if (typeof object.verdict !== 'string' || !VERDICTS.includes(object.verdict as Verdict)) throw new Error('evidence.verdict must be GO|NO-GO|INCONCLUSIVE');
  const verdictReasons = object.verdictReasons;
  if (!Array.isArray(verdictReasons)) throw new Error('evidence.verdictReasons must be an array');
  for (const reason of verdictReasons) {
    if (typeof reason !== 'string' || !VERDICT_REASONS.includes(reason as VerdictReason)) throw new Error(`evidence.verdictReasons unknown reason: ${JSON.stringify(reason)}`);
  }
  assertArraySortedUnique(verdictReasons as string[], 'evidence.verdictReasons');
  if (object.review !== null) throw new Error('evidence.review must be null in the hashed artifact');

  return {
    schemaVersion: CODEX_POC_SCHEMA_VERSION,
    runId,
    startedAt,
    completedAt,
    harness: {
      gitRevision: harnessObj.gitRevision as string,
      clean: harnessObj.clean as boolean,
      normativeInputDigest: harnessObj.normativeInputDigest as string,
    },
    caseRegistry: {
      version: caseRegistryObj.version as number,
      digest: caseRegistryObj.digest as string,
      requiredCaseIds: [...requiredCaseIds] as string[],
    },
    tuple: {
      surface: tupleObj.surface as Surface,
      os: tupleObj.os as OperatingSystem,
      architecture: tupleObj.architecture as Architecture,
      codexVersion: tupleObj.codexVersion as string,
      binarySha256: tupleObj.binarySha256 as string,
      schemaFingerprint: tupleObj.schemaFingerprint as string,
      attachmentStrategy: tupleObj.attachmentStrategy as AttachmentStrategy,
    },
    releaseIdentity: {
      installChannel: releaseIdentityObj.installChannel as string,
      packageProvenance: releaseIdentityObj.packageProvenance as string,
      bundleId: releaseIdentityObj.bundleId as string,
      bundleShortVersion: releaseIdentityObj.bundleShortVersion as string,
      bundleBuild: releaseIdentityObj.bundleBuild as string,
      bundleRelativeExecutable: releaseIdentityObj.bundleRelativeExecutable as string,
      signingIdentifier: releaseIdentityObj.signingIdentifier as string,
      signingTeam: releaseIdentityObj.signingTeam as string,
      designatedRequirementDigest: designated,
      cliSurfaceFingerprint: cli,
    },
    capabilities: normalizedCapabilities.sort((left, right) => left.capabilityId.localeCompare(right.capabilityId)),
    cases: normalizedCases.sort((left, right) => left.caseId.localeCompare(right.caseId)),
    privacyAudit: {
      sensitiveScan: privacyAuditObj.sensitiveScan as 'PASS' | 'FAIL',
      artifactPermissions: privacyAuditObj.artifactPermissions as 'PASS' | 'FAIL',
      packageExclusion: privacyAuditObj.packageExclusion as 'PASS' | 'FAIL',
    },
    workspaceAudit: {
      disposableWorkspace: workspaceAuditObj.disposableWorkspace as 'PASS' | 'FAIL',
      callerWorktreeWrites: workspaceAuditObj.callerWorktreeWrites as number,
      outsideAllowlistWrites: workspaceAuditObj.outsideAllowlistWrites as number,
    },
    cleanup: {
      ownedProcessCount: cleanupObj.ownedProcessCount as number,
      ownedSocketCount: cleanupObj.ownedSocketCount as number,
      ownedTempResourceCount: cleanupObj.ownedTempResourceCount as number,
      outcome: cleanupObj.outcome as 'PASS' | 'FAIL',
    },
    verdict: object.verdict as Verdict,
    verdictReasons: [...verdictReasons] as VerdictReason[],
    review: null,
  };
}

/** Convert the validated artifact to a JCS-canonical JSON string. */
export function artifactToJcs(artifact: EvidenceArtifact): string {
  const value: JcsValue = {
    schemaVersion: artifact.schemaVersion,
    runId: artifact.runId,
    startedAt: artifact.startedAt,
    completedAt: artifact.completedAt,
    harness: {
      gitRevision: artifact.harness.gitRevision,
      clean: artifact.harness.clean,
      normativeInputDigest: artifact.harness.normativeInputDigest,
    },
    caseRegistry: {
      version: artifact.caseRegistry.version,
      digest: artifact.caseRegistry.digest,
      requiredCaseIds: artifact.caseRegistry.requiredCaseIds,
    },
    tuple: {
      surface: artifact.tuple.surface,
      os: artifact.tuple.os,
      architecture: artifact.tuple.architecture,
      codexVersion: artifact.tuple.codexVersion,
      binarySha256: artifact.tuple.binarySha256,
      schemaFingerprint: artifact.tuple.schemaFingerprint,
      attachmentStrategy: artifact.tuple.attachmentStrategy,
    },
    releaseIdentity: {
      installChannel: artifact.releaseIdentity.installChannel,
      packageProvenance: artifact.releaseIdentity.packageProvenance,
      bundleId: artifact.releaseIdentity.bundleId,
      bundleShortVersion: artifact.releaseIdentity.bundleShortVersion,
      bundleBuild: artifact.releaseIdentity.bundleBuild,
      bundleRelativeExecutable: artifact.releaseIdentity.bundleRelativeExecutable,
      signingIdentifier: artifact.releaseIdentity.signingIdentifier,
      signingTeam: artifact.releaseIdentity.signingTeam,
      designatedRequirementDigest: artifact.releaseIdentity.designatedRequirementDigest,
      cliSurfaceFingerprint: artifact.releaseIdentity.cliSurfaceFingerprint,
    },
    capabilities: artifact.capabilities.map((capability) => ({
      capabilityId: capability.capabilityId,
      status: capability.status,
      caseIds: capability.caseIds,
    })),
    cases: artifact.cases.map((caseEntry) => ({
      caseId: caseEntry.caseId,
      capabilityId: caseEntry.capabilityId,
      status: caseEntry.status,
      outcomeCode: caseEntry.outcomeCode,
      exitClass: caseEntry.exitClass,
      signal: caseEntry.signal,
      durationBucket: caseEntry.durationBucket,
      observerAttestationDigest: caseEntry.observerAttestationDigest,
    })),
    privacyAudit: {
      sensitiveScan: artifact.privacyAudit.sensitiveScan,
      artifactPermissions: artifact.privacyAudit.artifactPermissions,
      packageExclusion: artifact.privacyAudit.packageExclusion,
    },
    workspaceAudit: {
      disposableWorkspace: artifact.workspaceAudit.disposableWorkspace,
      callerWorktreeWrites: artifact.workspaceAudit.callerWorktreeWrites,
      outsideAllowlistWrites: artifact.workspaceAudit.outsideAllowlistWrites,
    },
    cleanup: {
      ownedProcessCount: artifact.cleanup.ownedProcessCount,
      ownedSocketCount: artifact.cleanup.ownedSocketCount,
      ownedTempResourceCount: artifact.cleanup.ownedTempResourceCount,
      outcome: artifact.cleanup.outcome,
    },
    verdict: artifact.verdict,
    verdictReasons: artifact.verdictReasons,
    review: null,
  };
  return jcs(value);
}

/**
 * Evidence digest: SHA-256 of the JCS-canonical artifact bytes. Because the
 * artifact carries `review: null`, the review record is never part of the hash.
 */
export function evidenceDigest(artifact: EvidenceArtifact): string {
  return createHash('sha256').update(artifactToJcs(artifact)).digest('hex');
}

/**
 * Privacy scanner: rejects sensitive raw content in evidence fields.
 * Never stores prompts, transcripts, diffs, tool output, credentials, account
 * metadata, or user home/temp absolute paths (spec §7.1, §7.3).
 */
const SENSITIVE_PATTERNS: readonly RegExp[] = [
  /(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|Bearer\s+[A-Za-z0-9._~+/=-]{16,})/u,
  /\b(?:password|passwd|secret|token|credential|api[_-]?key|private[_-]?key)\b\s*[:=]\s*[^\s]{6,}/iu,
  /(?:^|[/\\])\.ssh(?:[/\\]|$)/u,
  /(?:^|[/\\])\.config(?:[/\\]|$)/u,
  /(?:^|[/\\])\.aws(?:[/\\]|$)/u,
];

const HOME_TEMP_PATTERNS: readonly RegExp[] = [
  /(?:^|[/\\])Users[/\\][^/\\]+(?:[/\\]|$)/u,
  /(?:^|[/\\])home[/\\][^/\\]+(?:[/\\]|$)/u,
  /\/var\/folders\//u,
  /(?:^|[/\\])tmp(?:[/\\]|$)/u,
];

export interface PrivacyScanResult {
  violations: string[];
  pass: boolean;
}

export function scanEvidenceForSensitiveContent(artifact: EvidenceArtifact): PrivacyScanResult {
  const violations: string[] = [];
  const check = (value: string, label: string) => {
    if (SENSITIVE_PATTERNS.some((pattern) => pattern.test(value))) {
      violations.push(`${label}: sensitive content pattern matched`);
    }
    if (HOME_TEMP_PATTERNS.some((pattern) => pattern.test(value))) {
      violations.push(`${label}: user home/temp absolute path present`);
    }
  };
  check(artifact.runId, 'runId');
  check(artifact.harness.gitRevision, 'harness.gitRevision');
  check(artifact.harness.normativeInputDigest, 'harness.normativeInputDigest');
  check(artifact.caseRegistry.digest, 'caseRegistry.digest');
  check(artifact.tuple.codexVersion, 'tuple.codexVersion');
  check(artifact.tuple.binarySha256, 'tuple.binarySha256');
  check(artifact.tuple.schemaFingerprint, 'tuple.schemaFingerprint');
  check(artifact.tuple.attachmentStrategy, 'tuple.attachmentStrategy');
  for (const key of Object.keys(artifact.releaseIdentity) as (keyof ReleaseIdentityEvidence)[]) {
    check(artifact.releaseIdentity[key], `releaseIdentity.${key}`);
  }
  for (const caseEntry of artifact.cases) {
    check(caseEntry.caseId, 'cases[].caseId');
    check(caseEntry.capabilityId, 'cases[].capabilityId');
    check(caseEntry.outcomeCode, 'cases[].outcomeCode');
    check(caseEntry.signal, 'cases[].signal');
    check(caseEntry.observerAttestationDigest, 'cases[].observerAttestationDigest');
  }
  for (const reason of artifact.verdictReasons) check(reason, 'verdictReasons[]');
  for (const capability of artifact.capabilities) {
    check(capability.capabilityId, 'capabilities[].capabilityId');
    for (const caseId of capability.caseIds) check(caseId, 'capabilities[].caseIds[]');
  }
  return { violations: [...new Set(violations)].sort(), pass: violations.length === 0 };
}

/** Owner-only file permission mask used when writing evidence artifacts. */
export const OWNER_ONLY_MODE = 0o600;

/** Verify a file mode is owner-only (no group/other bits). */
export function isOwnerOnlyMode(mode: number): boolean {
  return (mode & 0o077) === 0;
}
