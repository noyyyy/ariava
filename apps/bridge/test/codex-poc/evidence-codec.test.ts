import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  artifactToJcs,
  evidenceDigest,
  isOwnerOnlyMode,
  OWNER_ONLY_MODE,
  scanEvidenceForSensitiveContent,
  validateArtifact,
  type EvidenceArtifact,
} from './evidence-codec';

const paths: string[] = [];

function makeValidArtifact(overrides: Partial<EvidenceArtifact> = {}): EvidenceArtifact {
  return {
    schemaVersion: 1,
    runId: '123e4567-e89b-12d3-a456-426614174000',
    startedAt: '2026-08-18T00:00:00.000Z',
    completedAt: '2026-08-18T00:01:00.000Z',
    harness: {
      gitRevision: 'aefe244c4dc334260f6751e39f2aef5ca0a6ed60',
      clean: true,
      normativeInputDigest: 'a'.repeat(64),
    },
    caseRegistry: {
      version: 1,
      digest: 'b'.repeat(64),
      requiredCaseIds: ['case-a', 'case-b'],
    },
    tuple: {
      surface: 'standalone_tui',
      os: 'macos',
      architecture: 'arm64',
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
    capabilities: [
      { capabilityId: 'cap-a', status: 'PASS', caseIds: ['case-a'] },
    ],
    cases: [
      {
        caseId: 'case-a',
        capabilityId: 'cap-a',
        status: 'PASS',
        outcomeCode: 'pass',
        exitClass: 'zero',
        signal: '',
        durationBucket: 'lt1s',
        observerAttestationDigest: '',
      },
    ],
    privacyAudit: { sensitiveScan: 'PASS', artifactPermissions: 'PASS', packageExclusion: 'PASS' },
    workspaceAudit: { disposableWorkspace: 'PASS', callerWorktreeWrites: 0, outsideAllowlistWrites: 0 },
    cleanup: { ownedProcessCount: 0, ownedSocketCount: 0, ownedTempResourceCount: 0, outcome: 'PASS' },
    verdict: 'INCONCLUSIVE',
    verdictReasons: ['diagnostic-only'],
    review: null,
    ...overrides,
  };
}

afterEach(() => {
  for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('evidence codec exact-key validation', () => {
  test('accepts a fully valid artifact', () => {
    const artifact = makeValidArtifact();
    expect(validateArtifact(artifact)).toEqual(artifact);
  });

  test('rejects unknown top-level key', () => {
    const artifact = makeValidArtifact() as EvidenceArtifact & { extra?: string };
    artifact.extra = 'nope';
    expect(() => validateArtifact(artifact)).toThrow('exact-key');
  });

  test('rejects missing top-level key', () => {
    const artifact = makeValidArtifact();
    const { verdict, ...withoutVerdict } = artifact;
    expect(() => validateArtifact(withoutVerdict)).toThrow('exact-key');
  });

  test('rejects unknown nested key in harness', () => {
    const artifact = makeValidArtifact();
    (artifact.harness as Record<string, unknown>).extra = 'nope';
    expect(() => validateArtifact(artifact)).toThrow('evidence.harness');
  });

  test('rejects missing nested key in tuple', () => {
    const artifact = makeValidArtifact();
    const { surface, ...tupleWithoutSurface } = artifact.tuple;
    const mutated = { ...artifact, tuple: tupleWithoutSurface };
    expect(() => validateArtifact(mutated)).toThrow('evidence.tuple');
  });

  test('rejects schemaVersion migration', () => {
    const artifact = makeValidArtifact({ schemaVersion: 2 });
    expect(() => validateArtifact(artifact)).toThrow('schemaVersion');
  });

  test('rejects non-canonical runId', () => {
    const artifact = makeValidArtifact({ runId: 'UPPER-CASE-UUID' });
    expect(() => validateArtifact(artifact)).toThrow('runId');
  });

  test('rejects non-RFC3339 timestamps', () => {
    const artifact = makeValidArtifact({ startedAt: 'not-a-date' });
    expect(() => validateArtifact(artifact)).toThrow('RFC3339');
  });

  test('rejects unsorted requiredCaseIds', () => {
    const artifact = makeValidArtifact();
    artifact.caseRegistry.requiredCaseIds = ['case-b', 'case-a'];
    expect(() => validateArtifact(artifact)).toThrow('sorted');
  });

  test('rejects duplicate requiredCaseIds', () => {
    const artifact = makeValidArtifact();
    artifact.caseRegistry.requiredCaseIds = ['case-a', 'case-a'];
    expect(() => validateArtifact(artifact)).toThrow('sorted');
  });

  test('rejects unsorted capability caseIds', () => {
    const artifact = makeValidArtifact();
    artifact.capabilities[0]!.caseIds = ['case-b', 'case-a'];
    expect(() => validateArtifact(artifact)).toThrow('sorted');
  });

  test('rejects duplicate capability ids', () => {
    const artifact = makeValidArtifact();
    artifact.capabilities.push({ capabilityId: 'cap-a', status: 'PASS', caseIds: ['case-b'] });
    expect(() => validateArtifact(artifact)).toThrow('duplicate');
  });

  test('rejects unknown outcomeCode', () => {
    const artifact = makeValidArtifact();
    (artifact.cases[0] as Record<string, unknown>).outcomeCode = 'raw-exception-text';
    expect(() => validateArtifact(artifact)).toThrow('outcomeCode');
  });

  test('rejects unknown exitClass', () => {
    const artifact = makeValidArtifact();
    (artifact.cases[0] as Record<string, unknown>).exitClass = 'crashed';
    expect(() => validateArtifact(artifact)).toThrow('exitClass');
  });

  test('rejects unknown durationBucket', () => {
    const artifact = makeValidArtifact();
    (artifact.cases[0] as Record<string, unknown>).durationBucket = 'forever';
    expect(() => validateArtifact(artifact)).toThrow('durationBucket');
  });

  test('rejects non-empty review', () => {
    const artifact = makeValidArtifact();
    (artifact as Record<string, unknown>).review = { accepted: true };
    expect(() => validateArtifact(artifact)).toThrow('review must be null');
  });

  test('releaseIdentity unused fields are empty strings, never omitted', () => {
    const artifact = makeValidArtifact();
    artifact.releaseIdentity.bundleId = '';
    artifact.releaseIdentity.bundleShortVersion = '';
    const validated = validateArtifact(artifact);
    expect(validated.releaseIdentity.bundleId).toBe('');
    expect(validated.releaseIdentity.bundleShortVersion).toBe('');
    const json = JSON.stringify(validated.releaseIdentity);
    for (const key of ['bundleId', 'bundleShortVersion', 'bundleBuild', 'bundleRelativeExecutable', 'signingIdentifier', 'signingTeam', 'designatedRequirementDigest']) {
      expect(json).toContain(`"${key}":""`);
    }
  });

  test('rejects absolute path in bundleRelativeExecutable', () => {
    const artifact = makeValidArtifact();
    artifact.releaseIdentity.bundleRelativeExecutable = '/Users/me/Applications/Codex.app/Contents/MacOS/codex';
    expect(() => validateArtifact(artifact)).toThrow('absolute path');
  });

  test('rejects traversal path in bundleRelativeExecutable', () => {
    const artifact = makeValidArtifact();
    artifact.releaseIdentity.bundleRelativeExecutable = '../../etc/passwd';
    expect(() => validateArtifact(artifact)).toThrow('traversal');
  });
});

describe('evidence digest (JCS with review=null)', () => {
  test('is stable across key insertion order', () => {
    const artifact = makeValidArtifact();
    const first = evidenceDigest(artifact);
    // Rebuild the same logical artifact with different insertion order.
    const rebuilt = validateArtifact(JSON.parse(JSON.stringify(artifact))) as EvidenceArtifact;
    const second = evidenceDigest(rebuilt);
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/u);
  });

  test('review record is excluded from the digest', () => {
    const artifact = makeValidArtifact();
    const digestWithoutReview = evidenceDigest(artifact);
    const withReviewAdded = { ...artifact, review: { accepted: true, reviewer: 'x' } } as unknown as EvidenceArtifact;
    // digest must equal the artifact with review=null; adding review must not change it.
    expect(evidenceDigest(withReviewAdded)).toBe(digestWithoutReview);
  });

  test('cases[] and capabilities[] sorted by stable id produce the same digest', () => {
    const artifact = makeValidArtifact();
    const first = evidenceDigest(artifact);
    const shuffled = makeValidArtifact();
    shuffled.cases = [...shuffled.cases].reverse();
    shuffled.capabilities = [...shuffled.capabilities].reverse();
    const second = evidenceDigest(validateArtifact(shuffled));
    expect(first).toBe(second);
  });

  test('artifactToJcs is canonical JCS', () => {
    const artifact = makeValidArtifact();
    const canonical = artifactToJcs(artifact);
    // JCS sorts top-level keys: capabilities < caseRegistry < ... < tuple.
    expect(canonical.startsWith('{"capabilities":')).toBe(true);
    expect(canonical).toContain('"caseRegistry":');
    expect(canonical).toContain('"review":null');
  });
});

describe('privacy scanner', () => {
  test('passes on clean artifact', () => {
    const artifact = makeValidArtifact();
    const result = scanEvidenceForSensitiveContent(artifact);
    expect(result.pass).toBe(true);
    expect(result.violations).toEqual([]);
  });

  test('flags API token', () => {
    const artifact = makeValidArtifact();
    artifact.releaseIdentity.installChannel = 'sk-abcdefghijklmnop1234567890';
    const result = scanEvidenceForSensitiveContent(artifact);
    expect(result.pass).toBe(false);
    expect(result.violations[0]).toContain('releaseIdentity.installChannel');
  });

  test('flags credential assignment', () => {
    const artifact = makeValidArtifact();
    artifact.tuple.codexVersion = 'password=hunter2secret';
    const result = scanEvidenceForSensitiveContent(artifact);
    expect(result.pass).toBe(false);
  });

  test('flags user home absolute path', () => {
    const artifact = makeValidArtifact();
    artifact.releaseIdentity.packageProvenance = '/Users/alice/.config/codex';
    const result = scanEvidenceForSensitiveContent(artifact);
    expect(result.pass).toBe(false);
    // The .config segment matches the sensitive pattern; either way it fails closed.
    expect(result.violations.some((violation) => violation.startsWith('releaseIdentity.packageProvenance'))).toBe(true);
  });

  test('flags /var/folders temp path', () => {
    const artifact = makeValidArtifact();
    artifact.releaseIdentity.installChannel = '/var/folders/0l/abc123/T/codex';
    const result = scanEvidenceForSensitiveContent(artifact);
    expect(result.pass).toBe(false);
  });

  test('does not flag bundle-relative reviewed path', () => {
    const artifact = makeValidArtifact();
    artifact.releaseIdentity.bundleRelativeExecutable = 'Contents/MacOS/codex';
    const result = scanEvidenceForSensitiveContent(artifact);
    expect(result.pass).toBe(true);
  });
});

describe('artifact permissions', () => {
  test('owner-only mode is enforced', () => {
    expect(isOwnerOnlyMode(OWNER_ONLY_MODE)).toBe(true);
    expect(isOwnerOnlyMode(0o644)).toBe(false);
    expect(isOwnerOnlyMode(0o600)).toBe(true);
    expect(isOwnerOnlyMode(0o640)).toBe(false);
  });

  test('written artifact file has owner-only permissions', () => {
    const directory = mkdtempSync(join(tmpdir(), 'codex-poc-perm-'));
    paths.push(directory);
    const file = join(directory, 'evidence.json');
    writeFileSync(file, JSON.stringify(makeValidArtifact()), { mode: OWNER_ONLY_MODE });
    const mode = statSync(file).mode & 0o777;
    expect(isOwnerOnlyMode(mode)).toBe(true);
  });
});
