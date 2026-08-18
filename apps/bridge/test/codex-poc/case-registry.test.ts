import { describe, expect, test } from 'bun:test';
import {
  CANONICAL_CASES,
  CANONICAL_CAPABILITIES,
  CANONICAL_PROFILES,
  registryDigest,
  selectCasesForTuple,
  validateCaseIds,
} from './case-registry';
import { assertRequirementCoverage, REQUIREMENT_REGISTRY } from './requirement-registry';

describe('canonical case registry', () => {
  test('case ids are globally unique; capability ids are shared across cases but stable', () => {
    const caseIds = CANONICAL_CASES.map((entry) => entry.caseId);
    expect(new Set(caseIds).size).toBe(caseIds.length);
    const capabilityIds = new Set(CANONICAL_CASES.map((entry) => entry.capabilityId));
    expect(capabilityIds.size).toBe(CANONICAL_CAPABILITIES.length);
    for (const capabilityId of CANONICAL_CAPABILITIES) expect(capabilityIds.has(capabilityId)).toBe(true);
  });

  test('registry entries have the exact reviewed keys', () => {
    const expectedKeys = [
      'caseId', 'capabilityId', 'surfaces', 'operatingSystems', 'architectures',
      'requiredForGo', 'fixtureClass', 'requiresRealAccount', 'requiresSynchronousObserver',
      'expectedOutcomeClass',
    ];
    for (const entry of CANONICAL_CASES) {
      expect(Object.keys(entry).sort()).toEqual([...expectedKeys].sort());
    }
  });

  test('registry version is 1 and digest is a stable sha256', () => {
    const digest = registryDigest();
    expect(digest.version).toBe(1);
    expect(digest.digest).toMatch(/^[0-9a-f]{64}$/u);
    const second = registryDigest();
    expect(second.digest).toBe(digest.digest);
  });

  test('every capability has at least one case', () => {
    const capabilityIds = new Set(CANONICAL_CASES.map((entry) => entry.capabilityId));
    for (const capabilityId of CANONICAL_CAPABILITIES) {
      expect(capabilityIds.has(capabilityId)).toBe(true);
    }
  });

  test('tuple filtering produces a deterministic required set', () => {
    const tui = selectCasesForTuple({ surface: 'standalone_tui', os: 'macos', architecture: 'arm64' });
    const tuiAgain = selectCasesForTuple({ surface: 'standalone_tui', os: 'macos', architecture: 'arm64' });
    expect(tui.requiredCaseIds).toEqual(tuiAgain.requiredCaseIds);
    expect(tui.requiredCaseIds.length).toBeGreaterThan(0);
    const desktop = selectCasesForTuple({ surface: 'macos_desktop', os: 'macos', architecture: 'x86_64' });
    expect(desktop.requiredCaseIds.length).toBeGreaterThan(0);
    // Desktop is macOS-only: no desktop-specific cases for linux, but shared
    // cases (schema/identity/order/commit/approval/fanout/containment) still
    // apply because desktop tuples on non-macOS are out of scope entirely.
    const desktopLinux = selectCasesForTuple({ surface: 'macos_desktop', os: 'linux', architecture: 'arm64' });
    expect(desktopLinux.requiredCaseIds).not.toContain('case-desktop-app-identity');
  });

  test('diagnostic (non-required) cases are excluded from required set', () => {
    const linux = selectCasesForTuple({ surface: 'standalone_tui', os: 'linux', architecture: 'arm64' });
    expect(linux.diagnosticCaseIds).toContain('case-platform-docker-only-container-tuple');
    expect(linux.requiredCaseIds).not.toContain('case-platform-docker-only-container-tuple');
  });

  test('profiles cannot exclude requiredForGo cases', () => {
    for (const profile of CANONICAL_PROFILES) {
      expect(profile.fullCanonicalSet).toBe(true);
    }
    // A profile that tries to drop required cases is rejected.
    expect(() => selectCasesForTuple(
      { surface: 'standalone_tui', os: 'macos', architecture: 'arm64' },
      { profile: { id: 'broken', fullCanonicalSet: false } },
    )).toThrow('full-canonical-set');
  });

  test('unknown extra case in profile is rejected', () => {
    expect(() => selectCasesForTuple(
      { surface: 'standalone_tui', os: 'macos', architecture: 'arm64' },
      { profile: { id: 'x', fullCanonicalSet: true, extraCaseIds: ['case-does-not-exist'] } },
    )).toThrow('unknown extra case');
  });

  test('validateCaseIds reports unknown, duplicate, missing required cases', () => {
    const result = validateCaseIds(['case-schema-initialize', 'case-schema-initialize', 'bogus-case']);
    expect(result.unknown).toEqual(['bogus-case']);
    expect(result.duplicates).toEqual(['case-schema-initialize']);
    expect(result.missing.length).toBeGreaterThan(0);
    expect(result.missing.every((id) => id.startsWith('case-'))).toBe(true);
  });

  test('every required case id exists in the canonical registry', () => {
    const known = new Set(CANONICAL_CASES.map((entry) => entry.caseId));
    for (const entry of CANONICAL_CASES) {
      if (entry.requiredForGo) expect(known.has(entry.caseId)).toBe(true);
    }
  });
});

describe('requirement registry mapping', () => {
  test('every requirement maps to at least one canonical case', () => {
    const caseIds = new Set(CANONICAL_CASES.map((entry) => entry.caseId));
    const missing = assertRequirementCoverage(caseIds);
    expect(missing).toEqual([]);
  });

  test('every canonical case is reachable from at least one requirement', () => {
    const caseIds = new Set(CANONICAL_CASES.map((entry) => entry.caseId));
    const violations = assertRequirementCoverage(caseIds);
    expect(violations.filter((violation) => violation.startsWith('unreachable case'))).toEqual([]);
  });

  test('every requirement id is unique and stable', () => {
    const ids = REQUIREMENT_REGISTRY.map((entry) => entry.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(/^CODEX-POC-[A-Z0-9-]+-\d{3}$/u);
    }
  });

  test('every requirement references only known case ids', () => {
    const known = new Set(CANONICAL_CASES.map((entry) => entry.caseId));
    for (const entry of REQUIREMENT_REGISTRY) {
      for (const caseId of entry.caseIds) {
        expect(known.has(caseId)).toBe(true);
      }
    }
  });
});
