/**
 * Verdict pure function for the Codex Exact-Release Capability PoC (spec §9).
 *
 * The verdict is computed strictly from the evidence artifact and the canonical
 * case registry:
 *
 * - `GO` requires: complete exact release identity + schema; every
 *   `requiredForGo` capability case PASS; stable thread identity; event source
 *   identity/order/gap repair; three command-specific positive commit
 *   predicates; approval authority; multi-client fanout; surface
 *   attachment/lifecycle; platform containment; privacy/workspace/cleanup
 *   audits all PASS; no unknown authority-changing request/notification; and an
 *   independent review record.
 * - `NO-GO` facts (any one): missing seam; no stable event identity/order;
 *   any planned command without a positive commit predicate; observer approval
 *   preemption; unsafe multi-client or cross-client correlation; ownership
 *   indistinguishable; wrapper must break argv/TTY/signal/exit semantics;
 *   required environment only via forbidden persistent override; unbounded
 *   parser/memory/process risk.
 * - `INCONCLUSIVE`: environment/account/platform/TTY/Desktop unavailable;
 *   interrupted by external failure; incomplete evidence; privacy/cleanup
 *   audit failure; identity drift; unreviewable.
 *
 * `NO-GO` and `INCONCLUSIVE` never authorize production, and retries never
 * upgrade a verdict (spec §9.2, §9.3).
 *
 * Pure function: no I/O, no randomness; deterministic over its inputs.
 */

import {
  type CanonicalCase,
  CANONICAL_CASES,
} from './case-registry';
import {
  type CapabilityEvidence,
  type CaseEvidence,
  type EvidenceArtifact,
  type WorkspaceAuditEvidence,
  type CleanupEvidence,
  type PrivacyAuditEvidence,
} from './evidence-codec';
import { REVIEWED_SCHEMA_SURFACE, type SchemaSurface } from './schema-inventory';
import type { CapabilityStatus, Verdict, VerdictReason } from './constants';

export interface VerdictInput {
  artifact: EvidenceArtifact;
  /** Discovered schema surface (from inventory). */
  schema: SchemaSurface;
  /** Independent review record presence (offline reviewer). */
  independentReviewAccepted: boolean;
  /**
   * Diagnostic-only case ids run separately; they never participate in `GO`
   * (spec §7.3: extra diagnostic cases cannot contribute to `GO`).
   */
  diagnosticCaseIds: string[];
}

export interface VerdictResult {
  verdict: Verdict;
  reasons: VerdictReason[];
}

interface CapabilityGate {
  capabilityId: string;
  requiredCaseIds: string[];
}

function capabilityGates(cases: readonly CanonicalCase[]): CapabilityGate[] {
  const map = new Map<string, string[]>();
  for (const entry of cases) {
    if (!entry.requiredForGo) continue;
    const list = map.get(entry.capabilityId) ?? [];
    list.push(entry.caseId);
    map.set(entry.capabilityId, list);
  }
  return [...map.entries()].map(([capabilityId, requiredCaseIds]) => ({ capabilityId, requiredCaseIds }));
}

function capabilityStatusFor(artifact: EvidenceArtifact, capabilityId: string): CapabilityStatus | undefined {
  return artifact.capabilities.find((capability) => capability.capabilityId === capabilityId)?.status;
}

function requiredCaseById(artifact: EvidenceArtifact): Map<string, CaseEvidence> {
  return new Map(artifact.cases.map((caseEntry) => [caseEntry.caseId, caseEntry]));
}

/** Checks the per-capability required case gates. */
export function checkCapabilityGates(input: VerdictInput): {
  blocked: boolean;
  reasons: VerdictReason[];
  failedCapabilities: string[];
} {
  const reasons: VerdictReason[] = [];
  const failedCapabilities: string[] = [];
  const gates = capabilityGates(CANONICAL_CASES.filter((entry) => {
    const tuple = input.artifact.tuple;
    return entry.surfaces.includes(tuple.surface) &&
      entry.operatingSystems.includes(tuple.os) &&
      entry.architectures.includes(tuple.architecture);
  }));
  const caseById = requiredCaseById(input.artifact);

  // Required case completeness: the artifact must include exactly the required
  // set for the tuple, all with status PASS.
  const requiredIds = new Set(gates.flatMap((gate) => gate.requiredCaseIds));
  const artifactCaseIds = new Set(input.artifact.cases.map((caseEntry) => caseEntry.caseId));
  for (const requiredId of requiredIds) {
    if (!artifactCaseIds.has(requiredId)) {
      reasons.push('required-case-missing');
      failedCapabilities.push('(missing)');
    }
  }
  for (const caseId of artifactCaseIds) {
    if (!requiredIds.has(caseId) && !input.diagnosticCaseIds.includes(caseId)) {
      reasons.push('required-case-unknown');
      failedCapabilities.push('(unknown)');
    }
  }

  for (const gate of gates) {
    const status = capabilityStatusFor(input.artifact, gate.capabilityId);
    if (status !== 'PASS') {
      reasons.push(status === 'UNAVAILABLE' ? 'required-case-unavailable' : 'required-case-missing');
      failedCapabilities.push(gate.capabilityId);
      continue;
    }
    for (const caseId of gate.requiredCaseIds) {
      const caseEvidence = caseById.get(caseId);
      if (!caseEvidence) {
        // The required-case-missing loop above already flags absent required cases;
        // avoid double-reporting the same case as not-run.
        continue;
      }
      if (caseEvidence.status !== 'PASS') {
        reasons.push(caseEvidence.status === 'UNAVAILABLE' ? 'required-case-unavailable' : 'required-case-missing');
        failedCapabilities.push(gate.capabilityId);
      }
      if (caseEvidence.status === 'UNAVAILABLE') {
        // UNAVAILABLE required case always blocks GO.
        reasons.push('required-case-unavailable');
        failedCapabilities.push(gate.capabilityId);
      }
    }
  }
  const deduped = [...new Set(reasons)];
  const failed = [...new Set(failedCapabilities)];
  return { blocked: deduped.length > 0, reasons: deduped, failedCapabilities: failed };
}

function isReleaseIdentityComplete(artifact: EvidenceArtifact): boolean {
  const identity = artifact.releaseIdentity;
  const surface = artifact.tuple.surface;
  const baseComplete = identity.installChannel !== '' &&
    identity.packageProvenance !== '' &&
    /^[0-9a-f]{64}$/u.test(identity.cliSurfaceFingerprint) &&
    /^[0-9a-f]{64}$/u.test(artifact.tuple.binarySha256) &&
    /^[0-9a-f]{64}$/u.test(artifact.tuple.schemaFingerprint);
  if (surface !== 'macos_desktop') return baseComplete;
  // spec §5.3/§9.1(1): Desktop identity must record the bundle/signing fields.
  return baseComplete &&
    identity.bundleId !== '' &&
    identity.bundleShortVersion !== '' &&
    identity.bundleBuild !== '' &&
    identity.bundleRelativeExecutable !== '' &&
    identity.signingIdentifier !== '' &&
    identity.signingTeam !== '';
}

function isSchemaComplete(schema: SchemaSurface): boolean {
  // spec §8.1/§9.1(1): the discovered schema must contain the full reviewed
  // allowlist, not merely be non-empty.
  const containsAll = (reviewed: readonly string[], discovered: readonly string[]) =>
    reviewed.every((entry) => discovered.includes(entry));
  return containsAll(REVIEWED_SCHEMA_SURFACE.methods, schema.methods) &&
    containsAll(REVIEWED_SCHEMA_SURFACE.notifications, schema.notifications) &&
    containsAll(REVIEWED_SCHEMA_SURFACE.serverRequests, schema.serverRequests);
}

function isThreadIdentityEstablished(artifact: EvidenceArtifact): boolean {
  return artifact.capabilities.some((capability) =>
    capability.capabilityId === 'cap-thread-identity' && capability.status === 'PASS');
}

function isEventOrderEstablished(artifact: EvidenceArtifact): boolean {
  return artifact.capabilities.some((capability) =>
    capability.capabilityId === 'cap-event-order' && capability.status === 'PASS');
}

function hasThreeCommandCommitPredicates(artifact: EvidenceArtifact): boolean {
  const capability = artifact.capabilities.find((entry) => entry.capabilityId === 'cap-command-commit');
  return capability?.status === 'PASS' &&
    capability.caseIds.includes('case-commit-reply-steer-predicate') &&
    capability.caseIds.includes('case-commit-done-start-predicate') &&
    capability.caseIds.includes('case-commit-interrupt-predicate');
}

function isApprovalAuthorityEstablished(artifact: EvidenceArtifact): boolean {
  return artifact.capabilities.some((capability) =>
    capability.capabilityId === 'cap-approval-authority' && capability.status === 'PASS');
}

function isMultiClientFanoutEstablished(artifact: EvidenceArtifact): boolean {
  return artifact.capabilities.some((capability) =>
    capability.capabilityId === 'cap-multi-client-fanout' && capability.status === 'PASS');
}

function isSurfaceAttachmentEstablished(artifact: EvidenceArtifact): boolean {
  const surface = artifact.tuple.surface;
  const capabilityId = surface === 'macos_desktop' ? 'cap-desktop-attachment' : 'cap-tui-attachment';
  return artifact.capabilities.some((capability) =>
    capability.capabilityId === capabilityId && capability.status === 'PASS');
}

function isPlatformContainmentEstablished(artifact: EvidenceArtifact): boolean {
  return artifact.capabilities.some((capability) =>
    capability.capabilityId === 'cap-platform-containment' && capability.status === 'PASS');
}

function isAuditsPass(artifact: EvidenceArtifact): boolean {
  const privacy: PrivacyAuditEvidence = artifact.privacyAudit;
  const workspace: WorkspaceAuditEvidence = artifact.workspaceAudit;
  const cleanup: CleanupEvidence = artifact.cleanup;
  return privacy.sensitiveScan === 'PASS' &&
    privacy.artifactPermissions === 'PASS' &&
    privacy.packageExclusion === 'PASS' &&
    workspace.disposableWorkspace === 'PASS' &&
    workspace.callerWorktreeWrites === 0 &&
    workspace.outsideAllowlistWrites === 0 &&
    cleanup.ownedProcessCount === 0 &&
    cleanup.ownedSocketCount === 0 &&
    cleanup.ownedTempResourceCount === 0 &&
    cleanup.outcome === 'PASS';
}

/** Check NO-GO facts that are determined by evidence fields. */
function noGoFacts(input: VerdictInput): VerdictReason[] {
  const reasons: VerdictReason[] = [];
  const schema = input.schema;
  if (!isSchemaComplete(schema)) reasons.push('missing-seam');
  if (schema.unknownAuthorityChanging.length > 0) reasons.push('unknown-authority-changing-request');
  const artifact = input.artifact;

  const capabilityStatus = (capabilityId: string): CapabilityStatus | undefined =>
    artifact.capabilities.find((capability) => capability.capabilityId === capabilityId)?.status;

  if (capabilityStatus('cap-event-order') === 'FAIL') reasons.push('event-no-stable-identity-order');
  if (capabilityStatus('cap-command-commit') === 'FAIL') reasons.push('command-no-positive-commit-predicate');
  if (capabilityStatus('cap-approval-authority') === 'FAIL') reasons.push('approval-preemption');
  if (capabilityStatus('cap-multi-client-fanout') === 'FAIL') reasons.push('unsafe-multiclient');
  const surface = artifact.tuple.surface;
  const attachmentCapability = surface === 'macos_desktop' ? 'cap-desktop-attachment' : 'cap-tui-attachment';
  if (capabilityStatus(attachmentCapability) === 'FAIL') reasons.push('wrapper-breaks-semantics');
  if (capabilityStatus('cap-platform-containment') === 'FAIL') reasons.push('ownership-indistinguishable');

  // spec §6.3/§9.2: proven provider out-of-allowlist write, required environment
  // only via forbidden persistent override, and unbounded parser/memory/process
  // risk are each a hard NO-GO fact expressed through the case outcome code.
  const OUTCOME_NO_GO: ReadonlyArray<readonly [string, VerdictReason]> = [
    ['fail-provider-outside-allowlist-write', 'provider-outside-allowlist-write'],
    ['fail-forbidden-env-override', 'forbidden-env-override'],
    ['fail-unbounded-parser-risk', 'unbounded-parser-risk'],
  ];
  for (const caseEntry of artifact.cases) {
    for (const [outcome, reason] of OUTCOME_NO_GO) {
      if (caseEntry.outcomeCode === outcome) reasons.push(reason);
    }
  }


  // Audit failures produce INCONCLUSIVE per spec §9.3 (evidence incomplete /
  // privacy/cleanup audit failure), but a FAIL verdict reason is still emitted.
  return [...new Set(reasons)];
}

/** Check INCONCLUSIVE conditions. */
function inconclusiveFacts(input: VerdictInput): VerdictReason[] {
  const reasons: VerdictReason[] = [];
  const artifact = input.artifact;
  const privacy: PrivacyAuditEvidence = artifact.privacyAudit;
  const workspace: WorkspaceAuditEvidence = artifact.workspaceAudit;
  const cleanup: CleanupEvidence = artifact.cleanup;

  if (privacy.sensitiveScan === 'FAIL' || privacy.artifactPermissions === 'FAIL' || privacy.packageExclusion === 'FAIL') {
    reasons.push('privacy-audit-failed');
  }
  if (workspace.disposableWorkspace === 'FAIL' || workspace.callerWorktreeWrites !== 0 || workspace.outsideAllowlistWrites !== 0) {
    reasons.push('workspace-audit-failed');
  }
  if (cleanup.outcome === 'FAIL' || cleanup.ownedProcessCount !== 0 || cleanup.ownedSocketCount !== 0 || cleanup.ownedTempResourceCount !== 0) {
    reasons.push('cleanup-audit-failed');
  }
  if (!input.independentReviewAccepted) reasons.push('review-missing');
  if (!artifact.harness.clean) reasons.push('harness-vs-provider-indistinguishable');
  return [...new Set(reasons)];
}

/** Deterministic verdict computation (spec §9). */
export function computeVerdict(input: VerdictInput): VerdictResult {
  const artifact = input.artifact;

  // Hard NO-GO facts first: they dominate (spec §9.2).
  const noGo = noGoFacts(input);
  if (noGo.length > 0) return { verdict: 'NO-GO', reasons: noGo };

  // INCONCLUSIVE conditions (spec §9.3).
  const inconclusive = inconclusiveFacts(input);
  if (inconclusive.length > 0) return { verdict: 'INCONCLUSIVE', reasons: inconclusive };

  // Capability gates: any missing/duplicate/unknown/not-run/UNAVAILABLE
  // required case blocks GO.
  const gates = checkCapabilityGates(input);
  if (gates.blocked) return { verdict: 'INCONCLUSIVE', reasons: gates.reasons };

  // GO requirements (spec §9.1).
  const goReasons: VerdictReason[] = [];
  if (!isReleaseIdentityComplete(artifact)) {
    return { verdict: 'INCONCLUSIVE', reasons: ['release-identity-incomplete'] };
  }
  goReasons.push('release-identity-complete');
  if (!isSchemaComplete(input.schema)) {
    return { verdict: 'INCONCLUSIVE', reasons: ['schema-incomplete'] };
  }
  goReasons.push('schema-complete');
  goReasons.push('all-required-cases-pass');

  if (!isThreadIdentityEstablished(artifact)) return { verdict: 'INCONCLUSIVE', reasons: ['event-no-stable-identity-order'] };
  goReasons.push('thread-identity-stable');
  if (!isEventOrderEstablished(artifact)) return { verdict: 'INCONCLUSIVE', reasons: ['event-no-stable-identity-order'] };
  goReasons.push('event-identity-order-gap-repair');
  if (!hasThreeCommandCommitPredicates(artifact)) return { verdict: 'INCONCLUSIVE', reasons: ['command-no-positive-commit-predicate'] };
  goReasons.push('three-command-commit-predicates');
  if (!isApprovalAuthorityEstablished(artifact)) return { verdict: 'INCONCLUSIVE', reasons: ['approval-preemption'] };
  goReasons.push('approval-authority');
  if (!isMultiClientFanoutEstablished(artifact)) return { verdict: 'INCONCLUSIVE', reasons: ['unsafe-multiclient'] };
  goReasons.push('multi-client-fanout');
  if (!isSurfaceAttachmentEstablished(artifact)) return { verdict: 'INCONCLUSIVE', reasons: ['missing-seam'] };
  goReasons.push('surface-attachment-lifecycle');
  if (!isPlatformContainmentEstablished(artifact)) return { verdict: 'INCONCLUSIVE', reasons: ['ownership-indistinguishable'] };
  goReasons.push('platform-containment');
  if (!isAuditsPass(artifact)) return { verdict: 'INCONCLUSIVE', reasons: ['privacy-audit-failed'] };
  goReasons.push('privacy-workspace-cleanup-audits-pass');
  if (input.schema.unknownAuthorityChanging.length > 0) return { verdict: 'NO-GO', reasons: ['unknown-authority-changing-request'] };
  goReasons.push('no-unknown-authority-changing-request');
  if (!input.independentReviewAccepted) return { verdict: 'INCONCLUSIVE', reasons: ['review-missing'] };
  goReasons.push('independent-review-accepted');

  return { verdict: 'GO', reasons: goReasons };
}

/** `NO-GO`/`INCONCLUSIVE` never authorize production; retries do not upgrade. */
export function isAuthorizing(verdict: Verdict): boolean {
  return verdict === 'GO';
}
