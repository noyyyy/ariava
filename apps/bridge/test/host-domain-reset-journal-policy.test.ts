import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ProfileResourceSet } from '../src/cli/profile';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
  encodeHostDomainResetJournal,
  hostDomainResourceDigest,
  identityResourceDigest,
  parseHostDomainResetJournal,
  type HostDomainResetJournalV1,
} from '../src/cli/operations/host-domain-reset-journal-schema';
import {
  HOST_DOMAIN_RESET_PHASE_ORDER,
  hostResetJournalViolationMessage,
  validateHostDomainResetTransition,
  type HostResetJournalViolation,
} from '../src/cli/operations/host-domain-reset-journal-policy';

const roots: string[] = [];

function temporaryHome(): string {
  const root = mkdtempSync(join(tmpdir(), 'ariava-host-reset-journal-policy-'));
  roots.push(root);
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

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

function journalFor(
  resources: ProfileResourceSet,
  patch: Partial<HostDomainResetJournalV1> = {},
): HostDomainResetJournalV1 {
  return {
    version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
    operationId: 'reset_0123456789abcdef',
    profile: resources.identityProfile,
    phase: 'prepared',
    oldHostId: `host_${'A'.repeat(43)}`,
    oldKeyId: `key_${'B'.repeat(43)}`,
    newHostId: null,
    newKeyId: null,
    oldEncryptionKeyId: `ekey_${'C'.repeat(43)}`,
    signingCleanup: null,
    signingReplacementAttemptedAt: null,
    encryptionIdentityReplacedAt: null,
    runtimeArtifactsClearedAt: null,
    configSavedAt: null,
    enrolledAt: null,
    serviceMetadataSynchronizedAt: null,
    resourceDigest: hostDomainResourceDigest(resources),
    createdAt: '2026-08-11T00:00:00.000Z',
    updatedAt: '2026-08-11T00:00:00.000Z',
    revoke: { state: 'not-attempted', outcome: null },
    service: {
      managed: resources.identityProfile === 'default',
      installed: false,
      enabled: false,
      wasRunning: false,
      backend: resources.identityProfile === 'default' ? 'launchd' : 'none',
    },
    ...patch,
  };
}

/** Builds a schema-valid journal at `phase` with the evidence its phase requires. */
function journalAtPhase(
  resources: ProfileResourceSet,
  phase: typeof HOST_DOMAIN_RESET_PHASES[number],
  extra: Partial<HostDomainResetJournalV1> = {},
): HostDomainResetJournalV1 {
  const index = HOST_DOMAIN_RESET_PHASES.indexOf(phase);
  const atLeast = (candidate: typeof phase) => index >= HOST_DOMAIN_RESET_PHASES.indexOf(candidate);
  const timestamp = '2026-08-11T00:00:01.000Z';
  const journal = journalFor(resources, {
    phase,
    ...(phase === 'quarantine-pending' || phase === 'quarantined'
      ? { oldHostId: null, oldKeyId: null, oldEncryptionKeyId: null }
      : {}),
    ...(atLeast('revoke-pending')
      ? { revoke: { state: 'pending' as const, outcome: null } }
      : {}),
    ...(atLeast('old-identity-revoked')
      ? { revoke: { state: 'complete' as const, outcome: 'revoked' as const } }
      : {}),
    ...(atLeast('signing-replacement-pending') ? { signingReplacementAttemptedAt: timestamp } : {}),
    ...(atLeast('signing-identity-replaced') ? {
      newHostId: `host_${'D'.repeat(43)}`, newKeyId: `key_${'E'.repeat(43)}`,
    } : {}),
    ...(atLeast('encryption-identity-replaced') ? { encryptionIdentityReplacedAt: timestamp } : {}),
    ...(atLeast('runtime-artifacts-cleared') ? { runtimeArtifactsClearedAt: timestamp } : {}),
    ...(atLeast('config-saved') ? { configSavedAt: timestamp } : {}),
    ...(atLeast('enrolled') ? { enrolledAt: timestamp } : {}),
    ...(atLeast('service-metadata-synchronized') ? { serviceMetadataSynchronizedAt: timestamp } : {}),
    updatedAt: timestamp,
    ...extra,
  });
  return parseHostDomainResetJournal(journal, resources);
}

function expectLegal(current: HostDomainResetJournalV1, candidate: HostDomainResetJournalV1): void {
  const result = validateHostDomainResetTransition(current, candidate);
  expect(result.ok, result.ok ? undefined : hostResetJournalViolationMessage(result.reason)).toBe(true);
}

function expectViolation(
  current: HostDomainResetJournalV1,
  candidate: HostDomainResetJournalV1,
  kind: HostResetJournalViolation['kind'],
): HostResetJournalViolation {
  const result = validateHostDomainResetTransition(current, candidate);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error('unreachable');
  expect(result.reason.kind).toBe(kind);
  return result.reason;
}

describe('Host-domain reset journal policy', () => {
  test('frozen phase order matches the schema phase vocabulary', () => {
    expect(HOST_DOMAIN_RESET_PHASE_ORDER).toEqual(HOST_DOMAIN_RESET_PHASES);
  });

  test('accepts every fixed adjacent phase edge', () => {
    const resources = resourcesFor('dev');
    const edges: Array<[typeof HOST_DOMAIN_RESET_PHASES[number], typeof HOST_DOMAIN_RESET_PHASES[number]]> = [];
    for (let index = 0; index < HOST_DOMAIN_RESET_PHASES.length - 1; index += 1) {
      edges.push([HOST_DOMAIN_RESET_PHASES[index], HOST_DOMAIN_RESET_PHASES[index + 1]]);
    }
    for (const [from, to] of edges) {
      const current = journalAtPhase(resources, from);
      const candidate = journalAtPhase(resources, to, {
        updatedAt: '2026-08-11T00:00:02.000Z',
      });
      expectLegal(current, candidate);
    }
  });

  test('accepts the unique recognized-unreadable skip prepared -> signing-replacement-pending', () => {
    const resources = resourcesFor('dev');
    const current = journalAtPhase(resources, 'prepared', {
      oldHostId: null,
      oldKeyId: null,
      oldEncryptionKeyId: null,
      signingCleanup: {
        kind: 'linux-json',
        resourceDigest: identityResourceDigest(resources.identityMetadataPath),
        profile: 'dev',
        previousAccount: null,
        previousPendingAccount: null,
        interruptedCreationAccount: null,
      },
      revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
    });
    const candidate = journalAtPhase(resources, 'signing-replacement-pending', {
      oldHostId: null,
      oldKeyId: null,
      oldEncryptionKeyId: null,
      signingCleanup: {
        kind: 'linux-json',
        resourceDigest: identityResourceDigest(resources.identityMetadataPath),
        profile: 'dev',
        previousAccount: null,
        previousPendingAccount: null,
        interruptedCreationAccount: null,
      },
      revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    expectLegal(current, candidate);
  });

  test('rejects the prepared -> signing-replacement-pending skip without journaled unreadable evidence', () => {
    const resources = resourcesFor('dev');
    const current = journalAtPhase(resources, 'prepared');
    const candidate = journalAtPhase(resources, 'signing-replacement-pending', {
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    const reason = expectViolation(current, candidate, 'unreadable-skip-without-evidence');
    expect(reason.from).toBe('prepared');
    expect(reason.to).toBe('signing-replacement-pending');
  });

  test('rejects a readable prepared journal advancing into the skip target', () => {
    const resources = resourcesFor('dev');
    const current = journalAtPhase(resources, 'prepared');
    const candidate = journalAtPhase(resources, 'signing-replacement-pending', {
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    const reason = expectViolation(current, candidate, 'unreadable-skip-without-evidence');
    expect(reason.from).toBe('prepared');
  });

  test('rejects phase rollback', () => {
    const resources = resourcesFor('default');
    const current = journalAtPhase(resources, 'service-restore-pending');
    const candidate = journalAtPhase(resources, 'prepared', { updatedAt: '2026-08-11T00:00:02.000Z' });
    const reason = expectViolation(current, candidate, 'phase-rollback');
    expect(reason.from).toBe('service-restore-pending');
    expect(reason.to).toBe('prepared');
  });

  test('rejects non-adjacent forward jumps', () => {
    const resources = resourcesFor('default');
    const cases: Array<[typeof HOST_DOMAIN_RESET_PHASES[number], typeof HOST_DOMAIN_RESET_PHASES[number]]> = [
      ['quarantine-pending', 'prepared'],
      ['quarantined', 'revoke-pending'],
      ['prepared', 'old-identity-revoked'],
      ['revoke-pending', 'signing-identity-replaced'],
      ['signing-identity-replaced', 'runtime-artifacts-cleared'],
    ];
    for (const [from, to] of cases) {
      const current = journalAtPhase(resources, from);
      const candidate = journalAtPhase(resources, to, { updatedAt: '2026-08-11T00:00:02.000Z' });
      expectViolation(current, candidate, 'non-adjacent-transition');
    }
  });

  test('rejects advancement out of the terminal service-restore-pending phase', () => {
    const resources = resourcesFor('default');
    const current = journalAtPhase(resources, 'service-restore-pending');
    const candidate = journalAtPhase(resources, 'service-metadata-synchronized', {
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    expectViolation(current, candidate, 'phase-rollback');
  });

  test('accepts byte-identical same-phase replay', () => {
    const resources = resourcesFor('default');
    const current = journalAtPhase(resources, 'prepared');
    const replay = parseHostDomainResetJournal(
      JSON.parse(encodeHostDomainResetJournal(current, resources)), resources,
    );
    expectLegal(current, replay);
  });

  test('rejects same-phase field and updatedAt patching', () => {
    const resources = resourcesFor('default');
    const current = journalAtPhase(resources, 'prepared');
    expectViolation(current, { ...current, revoke: { state: 'pending', outcome: null } }, 'same-phase-modification');
    expectViolation(current, { ...current, updatedAt: '2026-08-11T00:00:05.000Z' }, 'same-phase-modification');
    expectViolation(current, { ...current, signingReplacementAttemptedAt: '2026-08-11T00:00:01.000Z' }, 'same-phase-modification');
  });

  test('rejects immutable operation/profile/resource/service/createdAt changes', () => {
    const resources = resourcesFor('default');
    const current = journalAtPhase(resources, 'prepared');
    const candidate = journalAtPhase(resources, 'revoke-pending', { updatedAt: '2026-08-11T00:00:02.000Z' });

    expectViolation(current, { ...candidate, operationId: 'reset_9999999999999999' }, 'immutable-field-changed');
    expectViolation(current, { ...candidate, profile: 'dev' }, 'immutable-field-changed');
    expectViolation(current, { ...candidate, resourceDigest: '0'.repeat(64) }, 'immutable-field-changed');
    expectViolation(current, {
      ...candidate,
      service: { ...candidate.service, wasRunning: true },
    }, 'immutable-field-changed');
    expectViolation(current, { ...candidate, createdAt: '2026-08-11T00:00:00.001Z' }, 'immutable-field-changed');
  });

  test('rejects writes to fields outside the edge writable set', () => {
    const resources = resourcesFor('default');
    const current = journalAtPhase(resources, 'prepared');
    // prepared -> revoke-pending may only change revoke (and phase/updatedAt).
    const candidate = journalAtPhase(resources, 'revoke-pending', {
      updatedAt: '2026-08-11T00:00:02.000Z',
      oldHostId: `host_${'Z'.repeat(43)}`,
    });
    expectViolation(current, candidate, 'field-change-not-allowed');
  });

  test('binds old identity/E2E/cleanup/revoke decision only on quarantined -> prepared', () => {
    const resources = resourcesFor('default');
    const current = journalAtPhase(resources, 'quarantined');
    const candidate = journalAtPhase(resources, 'prepared', { updatedAt: '2026-08-11T00:00:02.000Z' });
    expectLegal(current, candidate);

    // The same binding on a later edge is rejected.
    const prepared = journalAtPhase(resources, 'prepared');
    const moved = journalAtPhase(resources, 'revoke-pending', {
      updatedAt: '2026-08-11T00:00:02.000Z',
      oldHostId: `host_${'Z'.repeat(43)}`,
    });
    expectViolation(prepared, moved, 'field-change-not-allowed');
  });

  test('fills new IDs and effect timestamps only one-way on their exact edge', () => {
    const resources = resourcesFor('default');
    const pending = journalAtPhase(resources, 'signing-replacement-pending');
    const replaced = journalAtPhase(resources, 'signing-identity-replaced', {
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    expectLegal(pending, replaced);

    // A current journal that already carries newHostId cannot be overwritten on the fill edge.
    const alreadyFilled = journalFor(resources, {
      phase: 'signing-replacement-pending',
      newHostId: `host_${'D'.repeat(43)}`,
      newKeyId: `key_${'E'.repeat(43)}`,
      signingReplacementAttemptedAt: '2026-08-11T00:00:01.000Z',
      revoke: { state: 'complete', outcome: 'revoked' },
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    const overwrite = journalFor(resources, {
      phase: 'signing-identity-replaced',
      newHostId: `host_${'F'.repeat(43)}`,
      newKeyId: `key_${'E'.repeat(43)}`,
      signingReplacementAttemptedAt: '2026-08-11T00:00:01.000Z',
      revoke: { state: 'complete', outcome: 'revoked' },
      updatedAt: '2026-08-11T00:00:03.000Z',
    });
    const reason = expectViolation(alreadyFilled, overwrite, 'one-way-fill-violation');
    expect(reason.field).toBe('newHostId');

    // The encryption replacement timestamp fills once on its exact edge.
    const encryptionPending = journalAtPhase(resources, 'signing-identity-replaced');
    const withTimestamp = journalAtPhase(resources, 'encryption-identity-replaced', {
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    expectLegal(encryptionPending, withTimestamp);

    // An already-filled timestamp cannot be rewritten on the same edge.
    const alreadyTimed = journalFor(resources, {
      phase: 'signing-identity-replaced',
      newHostId: `host_${'D'.repeat(43)}`,
      newKeyId: `key_${'E'.repeat(43)}`,
      signingReplacementAttemptedAt: '2026-08-11T00:00:01.000Z',
      encryptionIdentityReplacedAt: '2026-08-11T00:00:02.000Z',
      revoke: { state: 'complete', outcome: 'revoked' },
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    const timestampOverwrite = journalFor(resources, {
      phase: 'encryption-identity-replaced',
      newHostId: `host_${'D'.repeat(43)}`,
      newKeyId: `key_${'E'.repeat(43)}`,
      signingReplacementAttemptedAt: '2026-08-11T00:00:01.000Z',
      encryptionIdentityReplacedAt: '2026-08-11T00:00:03.000Z',
      revoke: { state: 'complete', outcome: 'revoked' },
      updatedAt: '2026-08-11T00:00:03.000Z',
    });
    const timestampReason = expectViolation(alreadyTimed, timestampOverwrite, 'one-way-fill-violation');
    expect(timestampReason.field).toBe('encryptionIdentityReplacedAt');
  });

  test('rejects updatedAt rollback on a real transition', () => {
    const resources = resourcesFor('default');
    const current = journalAtPhase(resources, 'prepared');
    const candidate = journalAtPhase(resources, 'revoke-pending', {
      updatedAt: '2026-08-11T00:00:00.500Z',
    });
    expectViolation(current, candidate, 'timestamp-rollback');
  });

  test('rejects revoke transitions that skip the pending step', () => {
    const resources = resourcesFor('default');
    // readable prepared must go through revoke-pending; jumping to old-identity-revoked is non-adjacent
    const prepared = journalAtPhase(resources, 'prepared');
    const jumped = journalAtPhase(resources, 'old-identity-revoked', {
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    expectViolation(prepared, jumped, 'non-adjacent-transition');

    // old-identity-revoked requires current revoke pending
    const current = journalAtPhase(resources, 'revoke-pending');
    const oldIdentityRevoked = journalAtPhase(resources, 'old-identity-revoked', {
      updatedAt: '2026-08-11T00:00:02.000Z',
    });
    expectLegal(current, oldIdentityRevoked);
  });

  test('digests are deterministic and change with resource paths', () => {
    const first = resourcesFor('default');
    const second = resourcesFor('default');
    expect(hostDomainResourceDigest(first)).toBe(hostDomainResourceDigest(first));
    expect(hostDomainResourceDigest(second)).toBe(hostDomainResourceDigest(second));
    expect(hostDomainResourceDigest(first)).not.toBe(hostDomainResourceDigest(second));
  });

  test('violation messages name the failing surface for diagnostics', () => {
    const resources = resourcesFor('default');
    const current = journalAtPhase(resources, 'prepared');
    const rolledBack = journalAtPhase(resources, 'prepared', { phase: 'prepared' });
    const reason = expectViolation(current, { ...rolledBack, revoke: { state: 'pending', outcome: null } }, 'same-phase-modification');
    expect(hostResetJournalViolationMessage(reason)).toMatch(/cannot change/i);
    expect(hostResetJournalViolationMessage({ kind: 'phase-rollback', from: 'prepared', to: 'quarantined' })).toMatch(/rollback/i);
  });
});
