import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
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
import { loadHostDomainResetJournal } from '../src/cli/operations/host-domain-reset-journal-store';
import {
  BASELINE_V1_JOURNAL_BYTES,
  BASELINE_V1_RESOURCES,
  BASELINE_V1_RESOURCE_DIGEST,
} from './fixtures/host-domain-reset-journal-v1-baseline';

const OLD_HOST = `host_${'A'.repeat(43)}`;
const OLD_KEY = `key_${'B'.repeat(43)}`;
const OLD_EKEY = `ekey_${'C'.repeat(43)}`;
const NEW_HOST = `host_${'D'.repeat(43)}`;
const NEW_KEY = `key_${'E'.repeat(43)}`;
const TS0 = '2026-08-11T00:00:00.000Z';
const TS1 = '2026-08-11T00:00:01.000Z';

const EXPECTED_TOP_LEVEL_KEYS = [
  'version', 'operationId', 'profile', 'phase', 'oldHostId', 'oldKeyId', 'newHostId', 'newKeyId',
  'oldEncryptionKeyId', 'signingCleanup', 'signingReplacementAttemptedAt', 'encryptionIdentityReplacedAt',
  'runtimeArtifactsClearedAt', 'configSavedAt', 'enrolledAt', 'serviceMetadataSynchronizedAt',
  'resourceDigest', 'createdAt', 'updatedAt', 'revoke', 'service',
];

const roots: string[] = [];

function temporaryHome(): string {
  const root = mkdtempSync(join(tmpdir(), 'ariava-journal-schema-'));
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

/**
 * Build a schema-valid journal at any frozen v1 phase with the evidence the
 * normative phase table requires for that phase (readable revoke path).
 */
function journalAtPhase(
  resources: ProfileResourceSet,
  phase: HostDomainResetPhase,
  patch: Partial<HostDomainResetJournalV1> = {},
): HostDomainResetJournalV1 {
  const index = HOST_DOMAIN_RESET_PHASES.indexOf(phase);
  const atLeast = (candidate: HostDomainResetPhase) => index >= HOST_DOMAIN_RESET_PHASES.indexOf(candidate);
  const preInspection = phase === 'quarantine-pending' || phase === 'quarantined';
  const oldKnown = !preInspection;
  const revoke = preInspection
    ? { state: 'not-attempted' as const, outcome: null }
    : phase === 'prepared'
      ? { state: 'not-attempted' as const, outcome: null }
      : phase === 'revoke-pending'
        ? { state: 'pending' as const, outcome: null }
        : { state: 'complete' as const, outcome: 'revoked' as const };
  return {
    version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
    operationId: 'reset_0123456789abcdef',
    profile: resources.identityProfile,
    phase,
    oldHostId: oldKnown ? OLD_HOST : null,
    oldKeyId: oldKnown ? OLD_KEY : null,
    newHostId: atLeast('signing-identity-replaced') ? NEW_HOST : null,
    newKeyId: atLeast('signing-identity-replaced') ? NEW_KEY : null,
    oldEncryptionKeyId: oldKnown ? OLD_EKEY : null,
    signingCleanup: null,
    signingReplacementAttemptedAt: atLeast('signing-replacement-pending') ? TS1 : null,
    encryptionIdentityReplacedAt: atLeast('encryption-identity-replaced') ? TS1 : null,
    runtimeArtifactsClearedAt: atLeast('runtime-artifacts-cleared') ? TS1 : null,
    configSavedAt: atLeast('config-saved') ? TS1 : null,
    enrolledAt: atLeast('enrolled') ? TS1 : null,
    serviceMetadataSynchronizedAt: atLeast('service-metadata-synchronized') ? TS1 : null,
    resourceDigest: hostDomainResourceDigest(resources),
    createdAt: TS0,
    updatedAt: TS1,
    revoke,
    service: unmanagedOrLaunchedService(resources),
    ...patch,
  };
}

function unmanagedOrLaunchedService(resources: ProfileResourceSet): HostDomainResetJournalV1['service'] {
  return {
    managed: resources.identityProfile === 'default',
    installed: false,
    enabled: false,
    wasRunning: false,
    backend: resources.identityProfile === 'default' ? 'launchd' : 'none',
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

function expectInvalid(value: unknown, resources: ProfileResourceSet, label?: string): void {
  expect(() => parseHostDomainResetJournal(value, resources), label).toThrow(/journal is invalid/i);
}

describe('Host-domain reset journal schema: exact decode', () => {
  test('decodes a complete v1 journal at every frozen phase with its required evidence', () => {
    const resources = resourcesFor('default');
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      const journal = journalAtPhase(resources, phase);
      const decoded = parseHostDomainResetJournal(journal, resources);
      expect(decoded, phase).toEqual(journal);
    }
  });

  test('decodes a complete v1 journal for the dev profile with an unmanaged service snapshot', () => {
    const resources = resourcesFor('dev');
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      expect(parseHostDomainResetJournal(journalAtPhase(resources, phase), resources), phase).not.toBeNull();
    }
  });

  test('rejects unknown keys at every nesting level', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'service-restore-pending');
    expectInvalid({ ...journal, extra: true }, resources, 'top-level unknown key');
    expectInvalid({ ...journal, revoke: { ...journal.revoke, extra: true } }, resources, 'revoke unknown key');
    expectInvalid({ ...journal, service: { ...journal.service, extra: true } }, resources, 'service unknown key');
    expectInvalid(
      { ...journal, signingCleanup: { ...macosCleanup(resources), extra: true } },
      resources,
      'signingCleanup unknown key',
    );
  });

  test('rejects each missing required key', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'service-restore-pending');
    for (const key of EXPECTED_TOP_LEVEL_KEYS) {
      const { [key as keyof HostDomainResetJournalV1]: _omitted, ...rest } = journal as unknown as Record<string, unknown>;
      expectInvalid(rest, resources, `missing key ${key}`);
    }
  });

  test('rejects malformed identity-independent scalar fields', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'service-restore-pending');
    const cases: Array<[string, Record<string, unknown>]> = [
      ['version 2', { version: 2 }],
      ['version string', { version: '1' }],
      ['version 0', { version: 0 }],
      ['operationId too short', { operationId: 'reset_0' }],
      ['operationId with space', { operationId: 'reset_01 234567' }],
      ['operationId with symbol', { operationId: 'reset_01!23456' }],
      ['operationId empty', { operationId: '' }],
      ['profile mismatch', { profile: 'dev' }],
      ['phase outside enum', { phase: 'bogus-phase' }],
      ['resourceDigest not hex', { resourceDigest: 'deadbeef' }],
      ['resourceDigest wrong value', { resourceDigest: 'f'.repeat(64) }],
      ['createdAt non-canonical', { createdAt: '2026-08-11 00:00:00' }],
      ['updatedAt non-canonical', { updatedAt: '2026-08-11 00:00:01+00:00' }],
      ['updatedAt before createdAt', { createdAt: TS1, updatedAt: TS0 }],
    ];
    for (const [label, patch] of cases) {
      expectInvalid({ ...journal, ...patch }, resources, label);
    }
  });

  test('rejects malformed signing identity ids', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'service-restore-pending');
    const cases: Array<[string, Record<string, unknown>]> = [
      ['oldHostId wrong prefix', { oldHostId: `key_${'A'.repeat(43)}` }],
      ['oldHostId wrong length', { oldHostId: `host_${'A'.repeat(42)}` }],
      ['oldKeyId wrong prefix', { oldKeyId: `host_${'B'.repeat(43)}` }],
      ['oldKeyId wrong length', { oldKeyId: `key_${'B'.repeat(44)}` }],
      ['newHostId wrong prefix', { newHostId: `key_${'D'.repeat(43)}` }],
      ['newKeyId wrong prefix', { newKeyId: `host_${'E'.repeat(43)}` }],
      ['oldEncryptionKeyId wrong prefix', { oldEncryptionKeyId: `host_${'C'.repeat(43)}` }],
      ['oldEncryptionKeyId wrong length', { oldEncryptionKeyId: `ekey_${'C'.repeat(42)}` }],
      ['oldHostId without oldKeyId', { oldKeyId: null }],
      ['oldKeyId without oldHostId', { oldHostId: null }],
      ['newHostId without newKeyId', { newKeyId: null }],
      ['newKeyId without newHostId', { newHostId: null }],
      ['same old and new Host id', { newHostId: OLD_HOST }],
    ];
    for (const [label, patch] of cases) {
      expectInvalid({ ...journal, ...patch }, resources, label);
    }
  });

  test('rejects malformed signing cleanup evidence', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'prepared', { signingCleanup: macosCleanup(resources) });
    const cases: Array<[string, unknown]> = [
      ['cleanup wrong digest', { ...macosCleanup(resources), resourceDigest: 'f'.repeat(64) }],
      ['cleanup wrong profile', { ...macosCleanup(resources), profile: 'dev' }],
      ['cleanup unknown kind', { ...macosCleanup(resources), kind: 'windows-json' }],
      ['cleanup missing key', { kind: 'macos-keychain', resourceDigest: macosCleanup(resources).resourceDigest, profile: resources.identityProfile }],
      ['linux-json with previous account', {
        kind: 'linux-json', resourceDigest: macosCleanup(resources).resourceDigest, profile: resources.identityProfile,
        previousAccount: OLD_HOST, previousPendingAccount: null, interruptedCreationAccount: null,
      }],
      ['macos-keychain pending without previous', {
        kind: 'macos-keychain', resourceDigest: macosCleanup(resources).resourceDigest, profile: resources.identityProfile,
        previousAccount: null, previousPendingAccount: `${OLD_HOST}.pending`, interruptedCreationAccount: null,
      }],
      ['macos-keychain pending mismatch', {
        kind: 'macos-keychain', resourceDigest: macosCleanup(resources).resourceDigest, profile: resources.identityProfile,
        previousAccount: OLD_HOST, previousPendingAccount: `${NEW_HOST}.pending`, interruptedCreationAccount: null,
      }],
      ['macos-keychain malformed previous', {
        kind: 'macos-keychain', resourceDigest: macosCleanup(resources).resourceDigest, profile: resources.identityProfile,
        previousAccount: 'not-a-host-id', previousPendingAccount: null, interruptedCreationAccount: null,
      }],
      ['macos-keychain interrupted not equal previous', {
        kind: 'macos-keychain', resourceDigest: macosCleanup(resources).resourceDigest, profile: resources.identityProfile,
        previousAccount: OLD_HOST, previousPendingAccount: null, interruptedCreationAccount: NEW_HOST,
      }],
      ['macos-keychain malformed interrupted', {
        kind: 'macos-keychain', resourceDigest: macosCleanup(resources).resourceDigest, profile: resources.identityProfile,
        previousAccount: null, previousPendingAccount: null, interruptedCreationAccount: 'bad',
      }],
    ];
    for (const [label, cleanup] of cases) {
      expectInvalid({ ...journal, signingCleanup: cleanup }, resources, label);
    }
  });

  test('accepts valid macos-keychain cleanup account combinations', () => {
    const resources = resourcesFor('default');
    const base = macosCleanup(resources);
    const valid = [
      { ...base, previousAccount: OLD_HOST, previousPendingAccount: null, interruptedCreationAccount: null },
      { ...base, previousAccount: OLD_HOST, previousPendingAccount: `${OLD_HOST}.pending`, interruptedCreationAccount: null },
      { ...base, previousAccount: OLD_HOST, previousPendingAccount: `${OLD_HOST}.pending`, interruptedCreationAccount: OLD_HOST },
    ];
    for (const cleanup of valid) {
      const journal = journalAtPhase(resources, 'prepared', {
        signingCleanup: cleanup,
        revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
        oldHostId: null,
        oldKeyId: null,
        oldEncryptionKeyId: null,
      });
      expect(parseHostDomainResetJournal(journal, resources).signingCleanup, cleanup.kind).toEqual(cleanup);
    }
  });

  test('rejects malformed revoke state/outcome pairs', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'old-identity-revoked');
    const cases: Array<[string, HostDomainResetJournalV1['revoke']]> = [
      ['complete without outcome', { state: 'complete', outcome: null }],
      ['complete unknown outcome', { state: 'complete', outcome: 'old-identity-unreadable' }],
      ['pending with outcome', { state: 'pending', outcome: 'revoked' }],
      ['not-attempted with outcome', { state: 'not-attempted', outcome: 'revoked' }],
      ['skipped wrong outcome', { state: 'skipped', outcome: 'revoked' }],
      ['unknown state', { state: 'in-progress', outcome: null }],
      ['unknown outcome', { state: 'not-attempted', outcome: 'unknown' }],
      ['missing outcome', { state: 'complete' } as unknown as HostDomainResetJournalV1['revoke']],
    ];
    for (const [label, revoke] of cases) {
      expectInvalid({ ...journal, revoke }, resources, label);
    }
  });

  test('rejects malformed service snapshots', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'service-restore-pending');
    const cases: Array<[string, HostDomainResetJournalV1['service']]> = [
      ['managed with none backend', { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'none' }],
      ['unmanaged with launchd backend', { managed: false, installed: false, enabled: false, wasRunning: false, backend: 'launchd' }],
      ['unmanaged with installed true', { managed: false, installed: true, enabled: false, wasRunning: false, backend: 'none' }],
      ['enabled without installed', { managed: true, installed: false, enabled: true, wasRunning: false, backend: 'launchd' }],
      ['unknown backend', { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'windows' }],
      ['non-boolean managed', { managed: 'yes', installed: false, enabled: false, wasRunning: false, backend: 'launchd' } as unknown as HostDomainResetJournalV1['service']],
    ];
    for (const [label, service] of cases) {
      expectInvalid({ ...journal, service }, resources, label);
    }
  });

  test('rejects a managed service snapshot for the dev profile', () => {
    const resources = resourcesFor('dev');
    const journal = journalAtPhase(resources, 'service-restore-pending', {
      service: { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'launchd' },
    });
    expectInvalid(journal, resources, 'dev profile managed service');
  });

  test('rejects effect timestamps outside the journal lifetime or non-canonical', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'service-restore-pending');
    const cases: Array<[string, HostDomainResetJournalV1]> = [
      ['attempt before createdAt', { ...journal, signingReplacementAttemptedAt: '2026-08-10T00:00:00.000Z' }],
      ['attempt after updatedAt', { ...journal, signingReplacementAttemptedAt: '2026-08-11T00:00:03.000Z' }],
      ['attempt non-canonical', { ...journal, signingReplacementAttemptedAt: 'not-a-time' }],
      ['encryption before createdAt', { ...journal, encryptionIdentityReplacedAt: '2026-08-10T00:00:00.000Z' }],
      ['artifacts after updatedAt', { ...journal, runtimeArtifactsClearedAt: '2026-08-11T00:00:03.000Z' }],
      ['config non-canonical', { ...journal, configSavedAt: '2026-08-11T00:00:01+00:00' }],
      ['enrolled after updatedAt', { ...journal, enrolledAt: '2026-08-11T00:00:03.000Z' }],
      ['metadata non-canonical', { ...journal, serviceMetadataSynchronizedAt: 'yesterday' }],
    ];
    for (const [label, mutated] of cases) {
      expectInvalid(mutated, resources, label);
    }
  });
});

describe('Host-domain reset journal schema: phase invariants', () => {
  test('quarantine-pending and quarantined forbid all identity and effect evidence', () => {
    const resources = resourcesFor('default');
    for (const phase of ['quarantine-pending', 'quarantined'] as const) {
      const journal = journalAtPhase(resources, phase);
      const withOldHost = { ...journal, oldHostId: OLD_HOST, oldKeyId: OLD_KEY };
      const withOldEkey = { ...journal, oldEncryptionKeyId: OLD_EKEY };
      const withCleanup = { ...journal, signingCleanup: macosCleanup(resources) };
      const withNewIds = { ...journal, newHostId: NEW_HOST, newKeyId: NEW_KEY };
      const withAttempt = { ...journal, signingReplacementAttemptedAt: TS1, updatedAt: TS1 };
      const withRevokeOutcome = { ...journal, revoke: { state: 'complete', outcome: 'revoked' } };
      expectInvalid(withOldHost, resources, `${phase} with old host id`);
      expectInvalid(withOldEkey, resources, `${phase} with old encryption key id`);
      expectInvalid(withCleanup, resources, `${phase} with signing cleanup`);
      expectInvalid(withNewIds, resources, `${phase} with new ids`);
      expectInvalid(withAttempt, resources, `${phase} with effect timestamp`);
      expectInvalid(withRevokeOutcome, resources, `${phase} with revoke outcome`);
    }
  });

  test('prepared requires bound old evidence and a legal revoke decision', () => {
    const resources = resourcesFor('default');
    const prepared = journalAtPhase(resources, 'prepared');
    expect(parseHostDomainResetJournal(prepared, resources).phase).toBe('prepared');
    expectInvalid(
      { ...prepared, oldHostId: null, oldKeyId: null, oldEncryptionKeyId: null, revoke: { state: 'not-attempted', outcome: null } },
      resources,
      'prepared without old evidence',
    );
    expectInvalid(
      { ...prepared, revoke: { state: 'skipped', outcome: 'old-identity-unreadable' } },
      resources,
      'prepared skipped revoke without signing cleanup',
    );
    expect(parseHostDomainResetJournal(
      {
        ...prepared,
        oldHostId: null,
        oldKeyId: null,
        oldEncryptionKeyId: null,
        signingCleanup: macosCleanup(resources),
        revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
      },
      resources,
    ).phase).toBe('prepared');
  });

  test('revoke-pending and old-identity-revoked require a known old identity', () => {
    const resources = resourcesFor('default');
    for (const phase of ['revoke-pending', 'old-identity-revoked'] as const) {
      const journal = journalAtPhase(resources, phase);
      expectInvalid(
        { ...journal, oldHostId: null, oldKeyId: null, oldEncryptionKeyId: null },
        resources,
        `${phase} without old identity`,
      );
    }
  });

  test('signing-replacement-pending requires an attempt and forbids replacement ids', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'signing-replacement-pending');
    expectInvalid({ ...journal, signingReplacementAttemptedAt: null }, resources, 'without attempt');
    expectInvalid({ ...journal, newHostId: NEW_HOST, newKeyId: NEW_KEY }, resources, 'with replacement ids');
  });

  test('signing-identity-replaced requires replacement ids', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'signing-identity-replaced');
    expectInvalid({ ...journal, newHostId: null, newKeyId: null }, resources, 'without replacement ids');
    expectInvalid({ ...journal, newHostId: null }, resources, 'host without key');
  });

  test('each effect phase requires its own exact evidence timestamp', () => {
    const resources = resourcesFor('default');
    const cases: Array<[HostDomainResetPhase, keyof HostDomainResetJournalV1]> = [
      ['encryption-identity-replaced', 'encryptionIdentityReplacedAt'],
      ['runtime-artifacts-cleared', 'runtimeArtifactsClearedAt'],
      ['config-saved', 'configSavedAt'],
      ['enrolled', 'enrolledAt'],
      ['service-metadata-synchronized', 'serviceMetadataSynchronizedAt'],
    ];
    for (const [phase, field] of cases) {
      expectInvalid({ ...journalAtPhase(resources, phase), [field]: null }, resources, `${phase} without ${field}`);
    }
  });

  test('service-restore-pending requires every earlier evidence piece', () => {
    const resources = resourcesFor('default');
    const complete = journalAtPhase(resources, 'service-restore-pending');
    const cases: Array<[string, HostDomainResetJournalV1]> = [
      ['missing attempt', { ...complete, signingReplacementAttemptedAt: null }],
      ['missing replacement ids', { ...complete, newHostId: null, newKeyId: null }],
      ['missing encryption timestamp', { ...complete, encryptionIdentityReplacedAt: null }],
      ['missing artifacts timestamp', { ...complete, runtimeArtifactsClearedAt: null }],
      ['missing config timestamp', { ...complete, configSavedAt: null }],
      ['missing enrollment timestamp', { ...complete, enrolledAt: null }],
      ['missing metadata timestamp', { ...complete, serviceMetadataSynchronizedAt: null }],
      ['regressed revoke', { ...complete, revoke: { state: 'pending', outcome: null } }],
    ];
    for (const [label, mutated] of cases) {
      expectInvalid(mutated, resources, label);
    }
  });
});

describe('Host-domain reset journal schema: historical compatibility', () => {
  test('loads literal Public 3a55152 baseline-v1 bytes at all 13 phases', () => {
    const readable = BASELINE_V1_JOURNAL_BYTES.filter((fixture) => fixture.variant === 'readable');
    expect(readable.map((fixture) => fixture.phase)).toEqual(HOST_DOMAIN_RESET_PHASES);
    expect(hostDomainResourceDigest(BASELINE_V1_RESOURCES)).toBe(BASELINE_V1_RESOURCE_DIGEST);
    for (const fixture of readable) {
      const decoded = parseHostDomainResetJournal(JSON.parse(fixture.bytes), BASELINE_V1_RESOURCES);
      expect(decoded.phase, fixture.name).toBe(fixture.phase);
      expect(decoded.resourceDigest, fixture.name).toBe(BASELINE_V1_RESOURCE_DIGEST);
    }
  });

  test('production load accepts literal 3a55152 recognized-unreadable and final restore fixtures', () => {
    const fixtures = BASELINE_V1_JOURNAL_BYTES.filter((fixture) =>
      fixture.variant === 'recognized-unreadable' || fixture.phase === 'service-restore-pending',
    );
    expect(fixtures.map((fixture) => fixture.name)).toEqual([
      'readable-service-restore-pending',
      'recognized-unreadable-prepared',
    ]);
    for (const fixture of fixtures) {
      rmSync(BASELINE_V1_RESOURCES.hostDomainResetJournalPath, { force: true });
      mkdirSync(dirname(BASELINE_V1_RESOURCES.hostDomainResetJournalPath), { recursive: true, mode: 0o700 });
      writeFileSync(BASELINE_V1_RESOURCES.hostDomainResetJournalPath, fixture.bytes, { mode: 0o600 });
      const loaded = loadHostDomainResetJournal(BASELINE_V1_RESOURCES);
      expect(loaded?.phase, fixture.name).toBe(fixture.phase);
      expect(loaded?.revoke.outcome, fixture.name).toBe(
        fixture.variant === 'recognized-unreadable' ? 'old-identity-unreadable' : 'revoked',
      );
    }
    rmSync(BASELINE_V1_RESOURCES.root, { recursive: true, force: true });
  });
});

describe('Host-domain reset journal schema: canonical encoding', () => {
  test('encode is deterministic and byte-identical across clones and repeated calls', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'service-restore-pending');
    const encoded = encodeHostDomainResetJournal(journal);
    expect(encodeHostDomainResetJournal(structuredClone(journal))).toBe(encoded);
    expect(encodeHostDomainResetJournal(journal)).toBe(encoded);
  });

  test('encode emits keys in exact interface order at every nesting level', () => {
    const resources = resourcesFor('default');
    const journal = journalAtPhase(resources, 'prepared', {
      signingCleanup: macosCleanup(resources),
      revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
      oldHostId: null,
      oldKeyId: null,
      oldEncryptionKeyId: null,
    });
    const record = JSON.parse(encodeHostDomainResetJournal(journal)) as Record<string, unknown>;
    expect(Object.keys(record)).toEqual(EXPECTED_TOP_LEVEL_KEYS);
    expect(Object.keys(record.signingCleanup as Record<string, unknown>)).toEqual([
      'kind', 'resourceDigest', 'profile', 'previousAccount', 'previousPendingAccount', 'interruptedCreationAccount',
    ]);
    expect(Object.keys(record.revoke as Record<string, unknown>)).toEqual(['state', 'outcome']);
    expect(Object.keys(record.service as Record<string, unknown>)).toEqual([
      'managed', 'installed', 'enabled', 'wasRunning', 'backend',
    ]);
  });

  test('decode(encode(journal)) round-trips exactly', () => {
    const resources = resourcesFor('default');
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      const journal = journalAtPhase(resources, phase);
      const roundTripped = parseHostDomainResetJournal(JSON.parse(encodeHostDomainResetJournal(journal)), resources);
      expect(roundTripped, phase).toEqual(journal);
      expect(encodeHostDomainResetJournal(roundTripped)).toBe(encodeHostDomainResetJournal(journal));
    }
  });
});

describe('Host-domain reset journal schema: filesystem independence', () => {
  test('parsing never reads or creates the journal file', () => {
    const resources = resourcesFor('default');
    const journalPath = resources.hostDomainResetJournalPath;
    const valid = journalAtPhase(resources, 'service-restore-pending');
    const decoded = parseHostDomainResetJournal(valid, resources);
    expect(decoded.phase).toBe('service-restore-pending');
    expect(() => parseHostDomainResetJournal({ ...valid, phase: 'bogus' }, resources)).toThrow(/journal is invalid/i);
    // The journal path must remain absent: parse performed no read that required
    // the file and no write that created it.
    expect(existsSync(journalPath)).toBe(false);
  });
});

describe('Host-domain reset journal schema: resource digest', () => {
  test('host domain digest is deterministic for the same resources', () => {
    const resources = resourcesFor('default');
    expect(hostDomainResourceDigest(resources)).toBe(hostDomainResourceDigest(resources));
    expect(hostDomainResourceDigest(resources)).toBe(hostDomainResourceDigest({ ...resources }));
  });

  test('host domain digest changes when a bound path changes', () => {
    const resources = resourcesFor('default');
    const digest = hostDomainResourceDigest(resources);
    const mutated = { ...resources, statePath: `${resources.statePath}-moved` };
    expect(hostDomainResourceDigest(mutated)).not.toBe(digest);
    const journal = journalAtPhase(resources, 'service-restore-pending');
    expectInvalid({ ...journal, resourceDigest: hostDomainResourceDigest(mutated) }, resources, 'digest bound to different paths');
  });

  test('signing cleanup digest binds the identity metadata path', () => {
    const resources = resourcesFor('default');
    const cleanup = macosCleanup(resources);
    expect(cleanup.resourceDigest).toBe(identityResourceDigest(resources.identityMetadataPath));
    expect(identityResourceDigest(resources.identityMetadataPath)).not.toBe(identityResourceDigest(`${resources.identityMetadataPath}-other`));
  });
});
