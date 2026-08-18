#!/usr/bin/env bun
/**
 * Codex Exact-Release PoC — offline strict review (spec §7.4, §11.2).
 *
 * NEVER launches Codex. Reads a hashed evidence artifact, recomputes digests,
 * checks canonical completeness + privacy/workspace/cleanup audits + verdict
 * truth table, verifies observer attestations bind
 * (runId + caseRegistryDigest + tupleDigest + caseId + observedOutcomeCode),
 * and writes an independent review record. The review record is stored
 * separately from the hashed artifact (spec §7.3: review is never written back
 * into the hashed payload).
 *
 * Usage:
 *   bun run --cwd open-source/ariava codex:poc:review -- --evidence <artifact.json>
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { validateArtifact, evidenceDigest, scanEvidenceForSensitiveContent, type EvidenceArtifact } from '../../apps/bridge/test/codex-poc/evidence-codec';
import { computeVerdict, type VerdictInput } from '../../apps/bridge/test/codex-poc/verdict';
import { inventorySchema, REVIEWED_SCHEMA_SURFACE } from '../../apps/bridge/test/codex-poc/schema-inventory';
import { registryDigest, selectCasesForTuple } from '../../apps/bridge/test/codex-poc/case-registry';
import { parseArgs, flagString, nowIso, tupleDigest, observerAttestationDigest, writeOwnerOnlyFile, artifactsRoot, publicRepositoryRoot, currentGitRevision } from './harness-common';
import type { OutcomeCode } from '../../apps/bridge/test/codex-poc/constants';

export interface ReviewRecord {
  schemaVersion: 1;
  reviewId: string;
  reviewedAt: string;
  reviewerCanonicalRepositoryRevision: string;
  evidenceDigest: string;
  tupleDigest: string;
  reviewedHarnessRevision: string;
  normativeInputDigest: string;
  acceptedVerdict: 'GO' | 'NO-GO' | 'INCONCLUSIVE';
  artifactVerdict: 'GO' | 'NO-GO' | 'INCONCLUSIVE';
  rationale: string[];
  /** Attestation binding failures (empty when all verified). */
  attestationFailures: string[];
  /** Whether this review accepts the artifact verdict as-is. */
  accepted: boolean;
}

function newReviewId(): string {
  return `review-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Verify observer attestations bind run/registry/tuple/case/outcome (§6.3/§7.4). */
function verifyAttestations(artifact: EvidenceArtifact): string[] {
  const failures: string[] = [];
  const tDigest = tupleDigest(artifact);
  for (const caseEntry of artifact.cases) {
    const stored = caseEntry.observerAttestationDigest;
    if (stored === '') continue;
    const expected = observerAttestationDigest({
      runId: artifact.runId,
      caseRegistryDigest: artifact.caseRegistry.digest,
      tupleDigest: tDigest,
      caseId: caseEntry.caseId,
      observedOutcomeCode: caseEntry.outcomeCode as OutcomeCode,
    });
    if (stored !== expected) {
      failures.push(`case ${caseEntry.caseId}: attestation digest does not bind (${stored} != ${expected})`);
    }
  }
  return failures;
}

export function reviewEvidence(evidencePath: string): ReviewRecord {
  if (!existsSync(evidencePath)) {
    throw new Error(`evidence file not found: ${evidencePath}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(evidencePath, 'utf8'));
  } catch (error) {
    throw new Error(`evidence file is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }

  // Strict exact-key validation + JCS digest recomputation (spec §7.3).
  const artifact = validateArtifact(raw);
  const recomputedDigest = evidenceDigest(artifact);
  const tDigest = tupleDigest(artifact);
  const registry = registryDigest();

  // Canonical completeness: the artifact's required case set must match the
  // registry-filtered required set for the tuple (spec §7.2).
  const selected = selectCasesForTuple({
    surface: artifact.tuple.surface,
    os: artifact.tuple.os,
    architecture: artifact.tuple.architecture,
  });
  const requiredIds = selected.requiredCaseIds;
  // Completeness is tuple-scoped: every required case for THIS tuple must be
  // present exactly once; unknown/duplicate ids fail closed (spec §7.2).
  const artifactCaseIds = artifact.cases.map((caseEntry) => caseEntry.caseId);
  const artifactIdSet = new Set(artifactCaseIds);
  const missingRequired = requiredIds.filter((caseId) => !artifactIdSet.has(caseId));
  const unknownCases = artifactCaseIds.filter((caseId) => !requiredIds.includes(caseId) && !artifact.caseRegistry.requiredCaseIds.includes(caseId));
  const duplicateCases = artifactCaseIds.filter((caseId, index) => artifactCaseIds.indexOf(caseId) !== index);
  const completenessFailures = [...missingRequired, ...unknownCases, ...duplicateCases];
  const canonicalOk = completenessFailures.length === 0;
  const schema = inventorySchema(REVIEWED_SCHEMA_SURFACE);

  // Privacy + workspace + cleanup audits must all pass for GO (spec §9.1(8)).
  const privacy = scanEvidenceForSensitiveContent(artifact);
  const attestationFailures = verifyAttestations(artifact);

  const artifactVerdict = artifact.verdict;
  const input: VerdictInput = {
    artifact,
    schema: REVIEWED_SCHEMA_SURFACE,
    independentReviewAccepted: false,
    diagnosticCaseIds: artifact.cases
      .map((caseEntry) => caseEntry.caseId)
      .filter((caseId) => !requiredIds.includes(caseId)),
  };
  const verdict = computeVerdict(input);

  const rationale: string[] = [];
  rationale.push(`evidence digest recomputed: ${recomputedDigest}`);
  rationale.push(`tuple digest: ${tDigest}`);
  rationale.push(`registry digest: ${registry.digest}`);
  rationale.push(`required case set: ${requiredIds.length} cases (canonical completeness: ${canonicalOk ? 'PASS' : 'FAIL'})`);
  rationale.push(`schema completeness: ${schema.complete ? 'PASS' : 'FAIL'}`);
  rationale.push(`privacy sensitive scan: ${privacy.pass ? 'PASS' : 'FAIL'}`);
  rationale.push(`observer attestation binding: ${attestationFailures.length === 0 ? 'PASS' : 'FAIL'}`);
  rationale.push(`verdict truth table: ${verdict.verdict} (artifact: ${artifactVerdict})`);

  const attestationOk = attestationFailures.length === 0;
  const auditsOk = artifact.privacyAudit.sensitiveScan === 'PASS' && artifact.privacyAudit.artifactPermissions === 'PASS' && artifact.privacyAudit.packageExclusion === 'PASS' &&
    artifact.workspaceAudit.disposableWorkspace === 'PASS' && artifact.workspaceAudit.callerWorktreeWrites === 0 && artifact.workspaceAudit.outsideAllowlistWrites === 0 &&
    artifact.cleanup.outcome === 'PASS' && artifact.cleanup.ownedProcessCount === 0 && artifact.cleanup.ownedSocketCount === 0 && artifact.cleanup.ownedTempResourceCount === 0;

  const accepted = attestationOk && canonicalOk && auditsOk && verdict.verdict === artifactVerdict;
  const acceptedVerdict = accepted ? artifactVerdict : artifactVerdict === 'GO' ? 'INCONCLUSIVE' : artifactVerdict;

  const review: ReviewRecord = {
    schemaVersion: 1,
    reviewId: newReviewId(),
    reviewedAt: nowIso(),
    reviewerCanonicalRepositoryRevision: currentGitRevision(),
    evidenceDigest: recomputedDigest,
    tupleDigest: tDigest,
    reviewedHarnessRevision: artifact.harness.gitRevision,
    normativeInputDigest: artifact.harness.normativeInputDigest,
    acceptedVerdict,
    artifactVerdict,
    rationale,
    attestationFailures,
    accepted,
  };

  // Write the independent review record (owner-only, separate from hashed artifact).
  const reviewPath = join(artifactsRoot(publicRepositoryRoot()), `${artifact.runId}.review.json`);
  writeOwnerOnlyFile(reviewPath, JSON.stringify(review, null, 2));

  return review;
}

function main(): number {
  const args = parseArgs(process.argv.slice(2));
  const evidence = flagString(args.flags, 'evidence');
  if (!evidence) {
    console.error('Usage: codex:poc:review -- --evidence <artifact.json>');
    console.error('Error: --evidence is required');
    return 2;
  }
  try {
    const review = reviewEvidence(evidence);
    console.log(JSON.stringify(review, null, 2));
    return review.accepted ? 0 : 1;
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}

if (import.meta.main) {
  process.exitCode = main();
}
