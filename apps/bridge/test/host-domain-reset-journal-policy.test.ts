import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import type { ProfileResourceSet } from '../src/cli/profile';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
  encodeHostDomainResetJournal,
  hostDomainResourceDigest,
  identityResourceDigest,
  parseHostDomainResetJournal,
  type HostDomainResetJournalV1,
  type HostDomainResetPhase,
  type HostDomainResetSigningCleanupV1,
} from '../src/cli/operations/host-domain-reset-journal-schema';
import {
  applyHostDomainResetJournalTransition,
  validateInitialJournal,
  type HostDomainResetJournalTransition,
  type HostResetJournalViolation,
} from '../src/cli/operations/host-domain-reset-journal-policy';

const OLD_HOST = `host_${'A'.repeat(43)}`;
const OLD_KEY = `key_${'B'.repeat(43)}`;
const OLD_EKEY = `ekey_${'C'.repeat(43)}`;
const NEW_HOST = `host_${'D'.repeat(43)}`;
const NEW_KEY = `key_${'E'.repeat(43)}`;
const TS0 = '2026-08-11T00:00:00.000Z';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function temporaryHome(): string {
  const root = mkdtempSync(join(tmpdir(), 'ariava-journal-policy-'));
  roots.push(root);
  return root;
}

function resourcesFor(profileId: 'default' | 'dev'): ProfileResourceSet {
  const home = temporaryHome();
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  try {
    const profile = profileId === 'default' ? createDefaultProfile() : createDevProfile();
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    return profile.resources;
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousXdg;
  }
}

function stepTimestamp(step: number): string {
  return new Date(Date.parse(TS0) + step * 1000).toISOString();
}

function initialJournal(resources: ProfileResourceSet): HostDomainResetJournalV1 {
  return {
    version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
    operationId: 'reset_0123456789abcdef',
    profile: resources.identityProfile,
    phase: 'quarantine-pending',
    oldHostId: null,
    oldKeyId: null,
    newHostId: null,
    newKeyId: null,
    oldEncryptionKeyId: null,
    signingCleanup: null,
    signingReplacementAttemptedAt: null,
    encryptionIdentityReplacedAt: null,
    runtimeArtifactsClearedAt: null,
    configSavedAt: null,
    enrolledAt: null,
    serviceMetadataSynchronizedAt: null,
    resourceDigest: hostDomainResourceDigest(resources),
    createdAt: TS0,
    updatedAt: TS0,
    revoke: { state: 'not-attempted', outcome: null },
    service: {
      managed: resources.identityProfile === 'default',
      installed: false,
      enabled: false,
      wasRunning: false,
      backend: resources.identityProfile === 'default' ? 'launchd' : 'none',
    },
  };
}

function macosCleanup(resources: ProfileResourceSet): HostDomainResetSigningCleanupV1 {
  return {
    kind: 'macos-keychain',
    resourceDigest: identityResourceDigest(resources.identityMetadataPath),
    profile: resources.identityProfile,
    previousAccount: null,
    previousPendingAccount: null,
    interruptedCreationAccount: null,
  };
}

/**
 * Apply a transition and assert it succeeds; the returned candidate must also
 * pass the exact decoder (the schema re-validates digest, phase evidence, and
 * timestamp invariants after every accepted transition).
 */
function expectOk(
  current: HostDomainResetJournalV1,
  transition: HostDomainResetJournalTransition,
  resources: ProfileResourceSet,
): HostDomainResetJournalV1 {
  const result = applyHostDomainResetJournalTransition(current, transition, resources);
  if (!result.ok) {
    throw new Error(`expected transition ${transition.kind} to be accepted, got ${result.reason.kind}`);
  }
  expect(() => parseHostDomainResetJournal(result.journal, resources)).not.toThrow();
  return result.journal;
}

function expectViolation(
  current: HostDomainResetJournalV1,
  transition: HostDomainResetJournalTransition,
  resources: ProfileResourceSet,
): HostResetJournalViolation {
  const result = applyHostDomainResetJournalTransition(current, transition, resources);
  if (result.ok) {
    throw new Error(`expected transition ${transition.kind} to be rejected`);
  }
  return result.reason;
}

interface ChainOptions {
  unreadableRevoke?: boolean;
  completeRevokeOutcome?: 'revoked' | 'identity-already-revoked';
}

/** Build the full frozen chain; returns the journal reached at each phase. */
function buildChain(resources: ProfileResourceSet, options: ChainOptions = {}): Map<HostDomainResetPhase, HostDomainResetJournalV1> {
  const chain = new Map<HostDomainResetPhase, HostDomainResetJournalV1>();
  let journal = initialJournal(resources);
  chain.set('quarantine-pending', journal);
  let step = 1;
  const apply = (transition: HostDomainResetJournalTransition) => {
    journal = expectOk(journal, transition, resources);
    chain.set(journal.phase, journal);
  };
  apply({ kind: 'advance', phase: 'quarantined', at: stepTimestamp(step++) });
  if (options.unreadableRevoke) {
    apply({
      kind: 'bind-prepared', at: stepTimestamp(step++), oldHostId: null, oldKeyId: null,
      oldEncryptionKeyId: null, signingCleanup: macosCleanup(resources),
      revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
    });
  } else {
    apply({
      kind: 'bind-prepared', at: stepTimestamp(step++), oldHostId: OLD_HOST, oldKeyId: OLD_KEY,
      oldEncryptionKeyId: OLD_EKEY, signingCleanup: null,
      revoke: { state: 'not-attempted', outcome: null },
    });
    apply({ kind: 'start-revoke', at: stepTimestamp(step++) });
    apply({ kind: 'complete-revoke', at: stepTimestamp(step++), outcome: options.completeRevokeOutcome ?? 'revoked' });
  }
  apply({ kind: 'begin-signing-replacement', at: stepTimestamp(step++) });
  apply({ kind: 'complete-signing-replacement', at: stepTimestamp(step++), newHostId: NEW_HOST, newKeyId: NEW_KEY });
  apply({ kind: 'complete-encryption-replacement', at: stepTimestamp(step++) });
  apply({ kind: 'complete-artifact-cleanup', at: stepTimestamp(step++) });
  apply({ kind: 'complete-config-save', at: stepTimestamp(step++) });
  apply({ kind: 'complete-enrollment', at: stepTimestamp(step++) });
  apply({ kind: 'complete-metadata-sync', at: stepTimestamp(step++) });
  apply({ kind: 'complete-restore-intent', at: stepTimestamp(step++) });
  return chain;
}

describe('Host-domain reset journal policy: exact adjacent edges', () => {
  test('applies every adjacent edge in the frozen phase order', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    expect([...chain.keys()]).toEqual([...HOST_DOMAIN_RESET_PHASES]);
    const final = chain.get('service-restore-pending')!;
    expect(final.phase).toBe('service-restore-pending');
    expect(parseHostDomainResetJournal(final, resources).phase).toBe('service-restore-pending');
  });

  test('accepts the identity-already-revoked completion outcome', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources, { completeRevokeOutcome: 'identity-already-revoked' });
    expect(chain.get('old-identity-revoked')!.revoke).toEqual({ state: 'complete', outcome: 'identity-already-revoked' });
    expect(chain.get('service-restore-pending')).not.toBeUndefined();
  });

  test('walking the chain twice with equal timestamps is byte-identical replay', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const quarantined = chain.get('quarantined')!;
    const replay = expectOk(quarantined, { kind: 'advance', phase: 'quarantined', at: quarantined.updatedAt }, resources);
    expect(encodeHostDomainResetJournal(replay)).toBe(encodeHostDomainResetJournal(quarantined));
  });

  test('explicit replay transitions are accepted on any phase', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      const journal = chain.get(phase)!;
      const result = applyHostDomainResetJournalTransition(journal, { kind: 'replay' }, resources);
      expect(result, phase).toMatchObject({ ok: true });
      if (result.ok) expect(result.journal).toBe(journal);
    }
  });
});

describe('Host-domain reset journal policy: recognized unreadable skip', () => {
  test('accepts prepared to signing-replacement-pending with skipped revoke and signing cleanup', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources, { unreadableRevoke: true });
    const pending = chain.get('signing-replacement-pending')!;
    expect(pending.revoke).toEqual({ state: 'skipped', outcome: 'old-identity-unreadable' });
    expect(pending.signingCleanup).not.toBeNull();
    expect(pending.signingReplacementAttemptedAt).not.toBeNull();
    expect(chain.get('service-restore-pending')).not.toBeUndefined();
  });

  test('rejects prepared to signing-replacement-pending without skipped revoke evidence', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const prepared = chain.get('prepared')!;
    const reason = expectViolation(prepared, { kind: 'begin-signing-replacement', at: stepTimestamp(9) }, resources);
    expect(reason).toEqual({ kind: 'forbidden-skip' });
  });

  test('rejects prepared to signing-replacement-pending when signing cleanup is missing', () => {
    const resources = resourcesFor('default');
    // A structurally prepared journal with skipped revoke but no signing cleanup.
    const prepared = {
      ...initialJournal(resources),
      phase: 'prepared' as const,
      oldHostId: null,
      oldKeyId: null,
      oldEncryptionKeyId: null,
      signingCleanup: null,
      updatedAt: stepTimestamp(2),
      revoke: { state: 'skipped' as const, outcome: 'old-identity-unreadable' as const },
    };
    const reason = expectViolation(prepared, { kind: 'begin-signing-replacement', at: stepTimestamp(3) }, resources);
    expect(reason).toEqual({ kind: 'forbidden-skip' });
  });
});

describe('Host-domain reset journal policy: forbidden skips and rollbacks', () => {
  test('rejects non-adjacent forward skips', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const far = stepTimestamp(20);
    const cases: Array<[HostDomainResetPhase, HostDomainResetJournalTransition]> = [
      ['quarantine-pending', { kind: 'bind-prepared', at: far, oldHostId: OLD_HOST, oldKeyId: OLD_KEY, oldEncryptionKeyId: OLD_EKEY, signingCleanup: null, revoke: { state: 'not-attempted', outcome: null } }],
      ['quarantine-pending', { kind: 'complete-restore-intent', at: far }],
      ['prepared', { kind: 'complete-enrollment', at: far }],
      ['prepared', { kind: 'complete-revoke', at: far, outcome: 'revoked' }],
      ['revoke-pending', { kind: 'complete-signing-replacement', at: far, newHostId: NEW_HOST, newKeyId: NEW_KEY }],
      ['signing-replacement-pending', { kind: 'complete-restore-intent', at: far }],
      ['enrolled', { kind: 'complete-restore-intent', at: far }],
    ];
    for (const [phase, transition] of cases) {
      const reason = expectViolation(chain.get(phase)!, transition, resources);
      expect(reason.kind, phase).toBe('phase-skip');
    }
  });

  test('rejects every rollback edge', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const far = stepTimestamp(20);
    const cases: Array<[HostDomainResetPhase, HostDomainResetJournalTransition]> = [
      ['old-identity-revoked', { kind: 'advance', phase: 'quarantined', at: far }],
      ['signing-replacement-pending', { kind: 'start-revoke', at: far }],
      ['service-restore-pending', { kind: 'complete-metadata-sync', at: far }],
    ];
    for (const [phase, transition] of cases) {
      const reason = expectViolation(chain.get(phase)!, transition, resources);
      expect(reason.kind, phase).toBe('phase-rollback');
    }
  });
});

describe('Host-domain reset journal policy: same-phase semantics', () => {
  test('accepts byte-identical same-phase replay and rejects any mutation', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const quarantined = chain.get('quarantined')!;
    expectOk(quarantined, { kind: 'advance', phase: 'quarantined', at: quarantined.updatedAt }, resources);
    const changedAt = expectViolation(quarantined, { kind: 'advance', phase: 'quarantined', at: stepTimestamp(9) }, resources);
    expect(changedAt).toEqual({ kind: 'same-phase-mutation' });
  });

  test('rejects a same-phase field patch', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const pending = chain.get('signing-replacement-pending')!;
    const reason = expectViolation(pending, { kind: 'begin-signing-replacement', at: stepTimestamp(9) }, resources);
    expect(reason).toEqual({ kind: 'same-phase-mutation' });
  });

  test('rejects re-running a completed binding or replacement edge on the same phase', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const prepared = chain.get('prepared')!;
    const rebind = expectViolation(
      prepared,
      { kind: 'bind-prepared', at: stepTimestamp(9), oldHostId: OLD_HOST, oldKeyId: OLD_KEY, oldEncryptionKeyId: OLD_EKEY, signingCleanup: null, revoke: { state: 'not-attempted', outcome: null } },
      resources,
    );
    expect(rebind).toEqual({ kind: 'same-phase-mutation' });
    const replaced = chain.get('signing-identity-replaced')!;
    const reReplace = expectViolation(
      replaced,
      { kind: 'complete-signing-replacement', at: stepTimestamp(9), newHostId: NEW_HOST, newKeyId: NEW_KEY },
      resources,
    );
    expect(reReplace).toEqual({ kind: 'same-phase-mutation' });
  });
});

describe('Host-domain reset journal policy: timestamp semantics', () => {
  test('rejects a transition timestamp before the current updatedAt', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const prepared = chain.get('prepared')!;
    const reason = expectViolation(prepared, { kind: 'start-revoke', at: stepTimestamp(1) }, resources);
    expect(reason).toEqual({ kind: 'timestamp-rollback' });
  });

  test('advancing transitions set updatedAt to their at timestamp', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    expect(chain.get('quarantined')!.updatedAt).toBe(stepTimestamp(1));
    expect(chain.get('prepared')!.updatedAt).toBe(stepTimestamp(2));
    expect(chain.get('signing-replacement-pending')!.signingReplacementAttemptedAt).toBe(chain.get('signing-replacement-pending')!.updatedAt);
    expect(chain.get('encryption-identity-replaced')!.encryptionIdentityReplacedAt).toBe(chain.get('encryption-identity-replaced')!.updatedAt);
  });
});

describe('Host-domain reset journal policy: immutable bindings', () => {
  test('never changes operation, profile, resource digest, createdAt, or the service snapshot', () => {
    const resources = resourcesFor('default');
    const initial = initialJournal(resources);
    const final = buildChain(resources).get('service-restore-pending')!;
    expect(final.version).toBe(initial.version);
    expect(final.operationId).toBe(initial.operationId);
    expect(final.profile).toBe(initial.profile);
    expect(final.resourceDigest).toBe(initial.resourceDigest);
    expect(final.createdAt).toBe(initial.createdAt);
    expect(final.service).toEqual(initial.service);
  });

  test('binds old identity evidence exactly once on the quarantined to prepared edge', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      const journal = chain.get(phase)!;
      const oldBinding = { oldHostId: journal.oldHostId, oldKeyId: journal.oldKeyId, oldEncryptionKeyId: journal.oldEncryptionKeyId, signingCleanup: journal.signingCleanup };
      if (phase === 'quarantine-pending' || phase === 'quarantined') {
        expect(oldBinding).toEqual({ oldHostId: null, oldKeyId: null, oldEncryptionKeyId: null, signingCleanup: null });
      } else {
        expect(oldBinding).toEqual({ oldHostId: OLD_HOST, oldKeyId: OLD_KEY, oldEncryptionKeyId: OLD_EKEY, signingCleanup: null });
      }
    }
  });

  test('fills new ids and effect timestamps only at their exact edge', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const before = chain.get('signing-replacement-pending')!;
    expect(before.newHostId).toBeNull();
    expect(before.newKeyId).toBeNull();
    const after = chain.get('signing-identity-replaced')!;
    expect(after.newHostId).toBe(NEW_HOST);
    expect(after.newKeyId).toBe(NEW_KEY);
    const replaced = chain.get('encryption-identity-replaced')!;
    expect(replaced.encryptionIdentityReplacedAt).toBe(replaced.updatedAt);
    expect(chain.get('service-restore-pending')!.serviceMetadataSynchronizedAt).not.toBeNull();
  });
});

describe('Host-domain reset journal policy: candidate hardening', () => {
  test('rejects a current journal whose resource digest does not match the resources', () => {
    const resources = resourcesFor('default');
    const tampered = { ...initialJournal(resources), resourceDigest: 'f'.repeat(64) };
    const reason = expectViolation(tampered, { kind: 'advance', phase: 'quarantined', at: stepTimestamp(1) }, resources);
    expect(reason).toEqual({ kind: 'digest-mismatch' });
  });

  test('rejects a candidate that fails schema invariants after applying', () => {
    const resources = resourcesFor('default');
    const chain = buildChain(resources);
    const pending = chain.get('signing-replacement-pending')!;
    const reason = expectViolation(
      pending,
      { kind: 'complete-signing-replacement', at: stepTimestamp(9), newHostId: OLD_HOST, newKeyId: NEW_KEY },
      resources,
    );
    expect(reason).toEqual({ kind: 'invalid-candidate' });
  });
});

describe('Host-domain reset journal policy: initial journal validation', () => {
  test('accepts an exact schema-valid quarantine-pending initial journal', () => {
    const resources = resourcesFor('default');
    const initial = initialJournal(resources);
    const result = validateInitialJournal(initial, resources);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.journal).toEqual(initial);
  });

  test('rejects a non-quarantine-pending initial journal', () => {
    const resources = resourcesFor('default');
    const initial = { ...initialJournal(resources), phase: 'quarantined' as const };
    const reason = validateInitialJournal(initial, resources);
    expect(reason).toMatchObject({ ok: false, reason: { kind: 'invalid-candidate' } });
  });

  test('rejects initial journals that bind identity evidence or effect timestamps', () => {
    const resources = resourcesFor('default');
    const withOldId = { ...initialJournal(resources), oldHostId: OLD_HOST, oldKeyId: OLD_KEY };
    const withNewId = { ...initialJournal(resources), newHostId: NEW_HOST, newKeyId: NEW_KEY };
    const withCleanup = { ...initialJournal(resources), signingCleanup: macosCleanup(resources) };
    const withAttempt = { ...initialJournal(resources), signingReplacementAttemptedAt: stepTimestamp(1) };
    for (const [label, journal] of [
      ['old ids', withOldId],
      ['new ids', withNewId],
      ['signing cleanup', withCleanup],
      ['effect timestamp', withAttempt],
    ] as Array<[string, HostDomainResetJournalV1]>) {
      const reason = validateInitialJournal(journal, resources);
      expect(reason, label).toMatchObject({ ok: false, reason: { kind: 'invalid-candidate' } });
    }
  });

  test('rejects a non-initial revoke decision', () => {
    const resources = resourcesFor('default');
    const pending = { ...initialJournal(resources), revoke: { state: 'pending' as const, outcome: null } };
    const reason = validateInitialJournal(pending, resources);
    expect(reason).toMatchObject({ ok: false, reason: { kind: 'invalid-candidate' } });
  });

  test('rejects updatedAt differing from createdAt', () => {
    const resources = resourcesFor('default');
    const moved = { ...initialJournal(resources), updatedAt: stepTimestamp(1) };
    const reason = validateInitialJournal(moved, resources);
    expect(reason).toMatchObject({ ok: false, reason: { kind: 'invalid-candidate' } });
  });

  test('rejects an unparseable initial journal', () => {
    const resources = resourcesFor('default');
    const bogus = { ...initialJournal(resources), phase: 'bogus-phase' };
    const reason = validateInitialJournal(bogus, resources);
    expect(reason).toMatchObject({ ok: false, reason: { kind: 'invalid-candidate' } });
  });

  test('validateInitialJournal accepts the dev profile unmanaged initial journal', () => {
    const resources = resourcesFor('dev');
    const result = validateInitialJournal(initialJournal(resources), resources);
    expect(result.ok).toBe(true);
  });
});
