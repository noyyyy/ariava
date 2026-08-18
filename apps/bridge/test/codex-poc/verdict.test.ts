import { describe, expect, test } from 'bun:test';
import { CANONICAL_CASES, selectCasesForTuple } from './case-registry';
import type { EvidenceArtifact } from './evidence-codec';
import { REVIEWED_SCHEMA_SURFACE, type SchemaSurface } from './schema-inventory';
import { checkCapabilityGates, computeVerdict, isAuthorizing, type VerdictInput } from './verdict';

function makeCaseEntry(caseId: string, capabilityId: string, status: 'PASS' | 'FAIL' | 'UNAVAILABLE') {
  return {
    caseId,
    capabilityId,
    status,
    outcomeCode: status === 'PASS' ? 'pass' : status === 'FAIL' ? 'fail-missing-seam' : 'unavailable-environment',
    exitClass: status === 'PASS' ? 'zero' : 'none',
    signal: '',
    durationBucket: 'lt1s',
    observerAttestationDigest: '',
  };
}

function capabilityFor(capabilityId: string, status: 'PASS' | 'FAIL' | 'UNAVAILABLE', caseIds: string[]) {
  return { capabilityId, status, caseIds: [...caseIds].sort() };
}

function makeGoArtifact(): EvidenceArtifact {
  const tuple = { surface: 'standalone_tui' as const, os: 'macos' as const, architecture: 'arm64' as const };
  const selected = selectCasesForTuple(tuple);
  const requiredIds = selected.requiredCaseIds;
  const casesById = new Map(CANONICAL_CASES.map((entry) => [entry.caseId, entry]));
  const cases = requiredIds.map((caseId) => {
    const entry = casesById.get(caseId)!;
    return makeCaseEntry(entry.caseId, entry.capabilityId, 'PASS');
  });
  const capabilities = [...new Set(cases.map((caseEntry) => caseEntry.capabilityId))].sort().map((capabilityId) =>
    capabilityFor(capabilityId, 'PASS', cases.filter((caseEntry) => caseEntry.capabilityId === capabilityId).map((caseEntry) => caseEntry.caseId)));

  return {
    schemaVersion: 1,
    runId: '123e4567-e89b-12d3-a456-426614174000',
    startedAt: '2026-08-18T00:00:00.000Z',
    completedAt: '2026-08-18T00:01:00.000Z',
    harness: { gitRevision: 'aefe244c4dc334260f6751e39f2aef5ca0a6ed60', clean: true, normativeInputDigest: 'a'.repeat(64) },
    caseRegistry: { version: 1, digest: 'b'.repeat(64), requiredCaseIds: requiredIds },
    tuple: {
      surface: tuple.surface,
      os: tuple.os,
      architecture: tuple.architecture,
      codexVersion: '0.1.0',
      binarySha256: 'c'.repeat(64),
      schemaFingerprint: 'd'.repeat(64),
      attachmentStrategy: 'reviewed-tui-app-server-argv',
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
      cliSurfaceFingerprint: 'e'.repeat(64),
    },
    capabilities,
    cases,
    privacyAudit: { sensitiveScan: 'PASS', artifactPermissions: 'PASS', packageExclusion: 'PASS' },
    workspaceAudit: { disposableWorkspace: 'PASS', callerWorktreeWrites: 0, outsideAllowlistWrites: 0 },
    cleanup: { ownedProcessCount: 0, ownedSocketCount: 0, ownedTempResourceCount: 0, outcome: 'PASS' },
    verdict: 'GO',
    verdictReasons: ['all-required-cases-pass'],
    review: null,
  };
}

function makeInput(overrides: { artifact?: Partial<EvidenceArtifact>; schema?: Partial<SchemaSurface>; independentReviewAccepted?: boolean; diagnosticCaseIds?: string[] } = {}): VerdictInput {
  const artifact = makeGoArtifact();
  return {
    artifact: { ...artifact, ...(overrides.artifact ?? {}) },
    schema: { ...REVIEWED_SCHEMA_SURFACE, ...(overrides.schema ?? {}) },
    independentReviewAccepted: overrides.independentReviewAccepted ?? true,
    diagnosticCaseIds: overrides.diagnosticCaseIds ?? [],
  };
}

/** Build a GO-capable artifact for the macos_desktop tuple (desktop case set + bundle/signing identity). */
function makeDesktopGoArtifact(): EvidenceArtifact {
  const tuple = { surface: 'macos_desktop' as const, os: 'macos' as const, architecture: 'arm64' as const };
  const selected = selectCasesForTuple(tuple);
  const requiredIds = selected.requiredCaseIds;
  const casesById = new Map(CANONICAL_CASES.map((entry) => [entry.caseId, entry]));
  const cases = requiredIds.map((caseId) => {
    const entry = casesById.get(caseId)!;
    return makeCaseEntry(entry.caseId, entry.capabilityId, 'PASS');
  });
  const capabilities = [...new Set(cases.map((caseEntry) => caseEntry.capabilityId))].sort().map((capabilityId) =>
    capabilityFor(capabilityId, 'PASS', cases.filter((caseEntry) => caseEntry.capabilityId === capabilityId).map((caseEntry) => caseEntry.caseId)));
  return {
    ...makeGoArtifact(),
    tuple: {
      surface: tuple.surface,
      os: tuple.os,
      architecture: tuple.architecture,
      codexVersion: '0.1.0',
      binarySha256: 'c'.repeat(64),
      schemaFingerprint: 'd'.repeat(64),
      attachmentStrategy: 'reviewed-macos-desktop-local-daemon-socket',
    },
    releaseIdentity: {
      installChannel: 'npm',
      packageProvenance: 'registry',
      bundleId: 'io.noyx.codex',
      bundleShortVersion: '1.2.3',
      bundleBuild: '42',
      bundleRelativeExecutable: 'Contents/MacOS/ChatGPT',
      signingIdentifier: 'Developer ID Application: X',
      signingTeam: 'ABC123',
      designatedRequirementDigest: '',
      cliSurfaceFingerprint: 'e'.repeat(64),
    },
    caseRegistry: { version: 1, digest: 'b'.repeat(64), requiredCaseIds: requiredIds },
    capabilities,
    cases,
  };
}

describe('verdict truth table', () => {
  test('GO when all requirements satisfied', () => {
    const result = computeVerdict(makeInput());
    expect(result.verdict).toBe('GO');
    expect(result.reasons).toContain('independent-review-accepted');
    expect(isAuthorizing(result.verdict)).toBe(true);
  });

  test('NO-GO when required seam is missing (incomplete schema)', () => {
    const result = computeVerdict(makeInput({ schema: { methods: [], notifications: [], serverRequests: [], unknownAuthorityChanging: [] } }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('missing-seam');
    expect(isAuthorizing(result.verdict)).toBe(false);
  });

  test('NO-GO when an unknown authority-changing notification exists', () => {
    const result = computeVerdict(makeInput({ schema: { unknownAuthorityChanging: ['approval.dismiss'] } }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('unknown-authority-changing-request');
  });

  test('NO-GO when event order fails', () => {
    const artifact = makeGoArtifact();
    artifact.capabilities = artifact.capabilities.map((capability) =>
      capability.capabilityId === 'cap-event-order' ? { ...capability, status: 'FAIL' as const } : capability);
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('event-no-stable-identity-order');
  });

  test('NO-GO when command commit fails', () => {
    const artifact = makeGoArtifact();
    artifact.capabilities = artifact.capabilities.map((capability) =>
      capability.capabilityId === 'cap-command-commit' ? { ...capability, status: 'FAIL' as const } : capability);
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('command-no-positive-commit-predicate');
  });

  test('NO-GO when approval preempted', () => {
    const artifact = makeGoArtifact();
    artifact.capabilities = artifact.capabilities.map((capability) =>
      capability.capabilityId === 'cap-approval-authority' ? { ...capability, status: 'FAIL' as const } : capability);
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('approval-preemption');
  });

  test('NO-GO when multi-client unsafe', () => {
    const artifact = makeGoArtifact();
    artifact.capabilities = artifact.capabilities.map((capability) =>
      capability.capabilityId === 'cap-multi-client-fanout' ? { ...capability, status: 'FAIL' as const } : capability);
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('unsafe-multiclient');
  });

  test('NO-GO when surface attachment fails', () => {
    const artifact = makeGoArtifact();
    artifact.capabilities = artifact.capabilities.map((capability) =>
      capability.capabilityId === 'cap-tui-attachment' ? { ...capability, status: 'FAIL' as const } : capability);
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('NO-GO');
  });

  test('NO-GO when platform containment fails', () => {
    const artifact = makeGoArtifact();
    artifact.capabilities = artifact.capabilities.map((capability) =>
      capability.capabilityId === 'cap-platform-containment' ? { ...capability, status: 'FAIL' as const } : capability);
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('ownership-indistinguishable');
  });

  test('INCONCLUSIVE when a required case is UNAVAILABLE', () => {
    const artifact = makeGoArtifact();
    const index = artifact.cases.findIndex((caseEntry) => caseEntry.caseId === 'case-approval-observer-no-response');
    artifact.cases[index]!.status = 'UNAVAILABLE';
    artifact.cases[index]!.outcomeCode = 'unavailable-observer-attestation';
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('INCONCLUSIVE');
    expect(result.reasons).toContain('required-case-unavailable');
  });

  test('INCONCLUSIVE when a required case is missing entirely', () => {
    const artifact = makeGoArtifact();
    const { schemaVersion, ...rest } = artifact;
    const pruned = artifact.cases.filter((caseEntry) => caseEntry.caseId !== 'case-identity-wellformed-stable');
    const mutated = { ...rest, schemaVersion, cases: pruned };
    const result = computeVerdict(makeInput({ artifact: mutated }));
    expect(result.verdict).toBe('INCONCLUSIVE');
    expect(result.reasons).toContain('required-case-missing');
  });

  test('INCONCLUSIVE when a required case is not run (missing from cases)', () => {
    const artifact = makeGoArtifact();
    const pruned = artifact.cases.filter((caseEntry) => caseEntry.caseId !== 'case-commit-done-start-predicate');
    const result = computeVerdict(makeInput({ artifact: { ...artifact, cases: pruned } }));
    expect(result.verdict).toBe('INCONCLUSIVE');
  });

  test('INCONCLUSIVE when privacy audit fails', () => {
    const result = computeVerdict(makeInput({ artifact: { privacyAudit: { sensitiveScan: 'FAIL', artifactPermissions: 'PASS', packageExclusion: 'PASS' } } }));
    expect(result.verdict).toBe('INCONCLUSIVE');
    expect(result.reasons).toContain('privacy-audit-failed');
  });

  test('INCONCLUSIVE when workspace audit fails', () => {
    const result = computeVerdict(makeInput({ artifact: { workspaceAudit: { disposableWorkspace: 'PASS', callerWorktreeWrites: 1, outsideAllowlistWrites: 0 } } }));
    expect(result.verdict).toBe('INCONCLUSIVE');
    expect(result.reasons).toContain('workspace-audit-failed');
  });

  test('INCONCLUSIVE when cleanup audit fails', () => {
    const result = computeVerdict(makeInput({ artifact: { cleanup: { ownedProcessCount: 1, ownedSocketCount: 0, ownedTempResourceCount: 0, outcome: 'FAIL' } } }));
    expect(result.verdict).toBe('INCONCLUSIVE');
    expect(result.reasons).toContain('cleanup-audit-failed');
  });

  test('INCONCLUSIVE when review missing', () => {
    const result = computeVerdict(makeInput({ independentReviewAccepted: false }));
    expect(result.verdict).toBe('INCONCLUSIVE');
    expect(result.reasons).toContain('review-missing');
  });

  test('INCONCLUSIVE when harness is dirty', () => {
    const result = computeVerdict(makeInput({ artifact: { harness: { gitRevision: 'aefe244c4dc334260f6751e39f2aef5ca0a6ed60', clean: false, normativeInputDigest: 'a'.repeat(64) } } }));
    expect(result.verdict).toBe('INCONCLUSIVE');
    expect(result.reasons).toContain('harness-vs-provider-indistinguishable');
  });

  test('INCONCLUSIVE when release identity incomplete', () => {
    const result = computeVerdict(makeInput({ artifact: { releaseIdentity: { installChannel: '', packageProvenance: '', bundleId: '', bundleShortVersion: '', bundleBuild: '', bundleRelativeExecutable: '', signingIdentifier: '', signingTeam: '', designatedRequirementDigest: '', cliSurfaceFingerprint: 'e'.repeat(64) } } }));
    expect(result.verdict).toBe('INCONCLUSIVE');
    expect(result.reasons).toContain('release-identity-incomplete');
  });

  test('NO-GO when a case outcome is fail-provider-outside-allowlist-write', () => {
    const artifact = makeGoArtifact();
    artifact.cases[0]!.outcomeCode = 'fail-provider-outside-allowlist-write';
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('provider-outside-allowlist-write');
  });

  test('NO-GO when a case outcome is fail-forbidden-env-override', () => {
    const artifact = makeGoArtifact();
    artifact.cases[0]!.outcomeCode = 'fail-forbidden-env-override';
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('forbidden-env-override');
  });

  test('NO-GO when a case outcome is fail-unbounded-parser-risk', () => {
    const artifact = makeGoArtifact();
    artifact.cases[0]!.outcomeCode = 'fail-unbounded-parser-risk';
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('unbounded-parser-risk');
  });

  test('diagnostic cases never participate in GO', () => {
    const result = computeVerdict(makeInput({ diagnosticCaseIds: ['case-platform-docker-only-container-tuple'] }));
    expect(result.verdict).toBe('GO');
  });

  test('capability gates surface failed capabilities', () => {
    const input = makeInput();
    const gates = checkCapabilityGates(input);
    expect(gates.blocked).toBe(false);
    expect(gates.failedCapabilities).toEqual([]);
  });

  test('INCONCLUSIVE when macos_desktop release identity lacks bundle/signing fields', () => {
    const artifact = makeDesktopGoArtifact();
    artifact.releaseIdentity.bundleId = '';
    artifact.releaseIdentity.bundleShortVersion = '';
    artifact.releaseIdentity.bundleBuild = '';
    artifact.releaseIdentity.bundleRelativeExecutable = '';
    artifact.releaseIdentity.signingIdentifier = '';
    artifact.releaseIdentity.signingTeam = '';
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('INCONCLUSIVE');
    expect(result.reasons).toContain('release-identity-incomplete');
  });

  test('GO for macos_desktop when bundle/signing fields are present', () => {
    const artifact = makeDesktopGoArtifact();
    const result = computeVerdict(makeInput({ artifact }));
    expect(result.verdict).toBe('GO');
  });

  test('schema incomplete when a reviewed method is missing', () => {
    const schema = { ...REVIEWED_SCHEMA_SURFACE, methods: REVIEWED_SCHEMA_SURFACE.methods.filter((method) => method !== 'turn/steer') };
    const result = computeVerdict(makeInput({ schema }));
    expect(result.verdict).toBe('NO-GO');
    expect(result.reasons).toContain('missing-seam');
  });

  test('schema incomplete when a reviewed notification is missing', () => {
    const schema = { ...REVIEWED_SCHEMA_SURFACE, notifications: REVIEWED_SCHEMA_SURFACE.notifications.filter((notification) => notification !== 'turn/completed') };
    const result = computeVerdict(makeInput({ schema }));
    expect(result.verdict).toBe('NO-GO');
  });
});
