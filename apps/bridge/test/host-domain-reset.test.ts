import { afterEach, describe, expect, test } from 'bun:test';
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import type { ProfileResourceSet } from '../src/cli/profile';
import type { ProcessAwareLockDependencies } from '../src/host-manager/process-aware-lock';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
  advanceHostDomainResetJournal as advanceHostDomainResetJournalWithDependencies,
  createHostDomainResetJournal,
  hostDomainResourceDigest,
  loadHostDomainResetJournal,
  type HostDomainResetJournalV1,
  type HostDomainResetTransition,
} from '../src/cli/operations/host-domain-reset-journal';
import { validateHostDomainResetTransition } from '../src/cli/operations/host-domain-reset-journal-policy';
import {
  withHostIdentityOperationLock,
  type HostIdentityOperationLease,
} from '../src/cli/operations/host-identity-operation-lock';
import { removeJournalFixture, writeJournalFixture } from './fixtures/host-domain-reset-journal-fixtures';

const roots: string[] = [];

function operationLockDependencies(): Partial<ProcessAwareLockDependencies> {
  return {
    platform: 'linux',
    uid: process.getuid!(),
    pid: process.pid,
    now: () => new Date(),
    ownerToken: () => 'e'.repeat(48),
    currentProcessStart: () => 'test-operation-process-start',
    inspector: { inspect: () => ({ status: 'alive', processStart: 'test-operation-process-start' }) },
  };
}

function withOperationLease<T>(
  resources: ProfileResourceSet,
  run: (lease: HostIdentityOperationLease) => T | Promise<T>,
): Promise<T> {
  return withHostIdentityOperationLock(resources, async (lease) => run(lease), operationLockDependencies());
}

function advanceHostDomainResetJournal(
  resources: AdvanceJournalParameters[0],
  current: AdvanceJournalParameters[1],
  transition: HostDomainResetTransition,
  lease: HostIdentityOperationLease,
  options: AdvanceJournalParameters[4] = {},
): ReturnType<typeof advanceHostDomainResetJournalWithDependencies> {
  const supplied = options.lockDependencies ?? {};
  return advanceHostDomainResetJournalWithDependencies(resources, current, transition, lease, {
    ...options,
    lockDependencies: {
      platform: 'linux',
      uid: process.getuid!(),
      pid: process.pid,
      now: () => new Date(),
      ownerToken: () => 'f'.repeat(48),
      currentProcessStart: () => 'test-process-start',
      inspector: { inspect: () => ({ status: 'alive', processStart: 'test-process-start' }) },
      ...supplied,
    },
  });
}

function temporaryHome(): string {
  const root = mkdtempSync(join(tmpdir(), 'ariava-host-reset-journal-'));
  roots.push(root);
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('Host-domain reset journal', () => {
  test('writes and loads the exact owner-only v1 schema without secrets or resource paths', () => {
    const resources = resourcesFor('default');
    const journal = journalFor(resources);

    writeJournalFixture(resources, journal);

    expect(lstatSync(resources.hostDomainResetJournalPath).mode & 0o777).toBe(0o600);
    expect(loadHostDomainResetJournal(resources)).toEqual(journal);
    const stored = JSON.parse(readFileSync(resources.hostDomainResetJournalPath, 'utf8'));
    expect(Object.keys(stored).sort()).toEqual([
      'configSavedAt', 'createdAt', 'encryptionIdentityReplacedAt', 'enrolledAt', 'newHostId', 'newKeyId',
      'oldEncryptionKeyId', 'oldHostId', 'oldKeyId', 'operationId', 'phase', 'profile', 'resourceDigest', 'revoke',
      'runtimeArtifactsClearedAt', 'service', 'serviceMetadataSynchronizedAt', 'signingCleanup',
      'signingReplacementAttemptedAt', 'updatedAt', 'version',
    ]);
    expect(JSON.stringify(stored)).not.toMatch(/private|secret|credential|payload|command|spoolKey/i);
    expect(JSON.stringify(stored)).not.toContain(resources.identityMetadataPath);
  });

  test('rejects phase-inconsistent journal evidence without rewriting bytes', () => {
    const resources = resourcesFor('default');
    const complete = journalFor(resources, {
      phase: 'service-restore-pending',
      newHostId: `host_${'C'.repeat(43)}`,
      newKeyId: `key_${'D'.repeat(43)}`,
      signingReplacementAttemptedAt: '2026-08-11T00:00:01.000Z',
      encryptionIdentityReplacedAt: '2026-08-11T00:00:01.000Z',
      runtimeArtifactsClearedAt: '2026-08-11T00:00:01.000Z',
      configSavedAt: '2026-08-11T00:00:01.000Z',
      enrolledAt: '2026-08-11T00:00:01.000Z',
      serviceMetadataSynchronizedAt: '2026-08-11T00:00:01.000Z',
      updatedAt: '2026-08-11T00:00:02.000Z',
      revoke: { state: 'complete', outcome: 'revoked' },
    });
    const cases: Array<[string, HostDomainResetJournalV1]> = [
      ['post-revoke incomplete revoke', { ...complete, revoke: { state: 'pending', outcome: null } }],
      ['replacement phase without attempt', { ...complete, signingReplacementAttemptedAt: null }],
      ['replacement phase without IDs', { ...complete, newHostId: null, newKeyId: null }],
      ['same old and new Host', { ...complete, newHostId: complete.oldHostId }],
      ['E2E phase without evidence', { ...complete, encryptionIdentityReplacedAt: null }],
      ['runtime phase without evidence', { ...complete, runtimeArtifactsClearedAt: null }],
      ['config phase without evidence', { ...complete, configSavedAt: null }],
      ['enrolled phase without evidence', { ...complete, enrolledAt: null }],
      ['service phase without evidence', { ...complete, serviceMetadataSynchronizedAt: null }],
    ];

    for (const [label, journal] of cases) {
      writeFileSync(resources.hostDomainResetJournalPath, JSON.stringify(journal), { mode: 0o600 });
      const before = readFileSync(resources.hostDomainResetJournalPath);
      expect(() => loadHostDomainResetJournal(resources), label).toThrow(/journal is invalid/i);
      expect(readFileSync(resources.hostDomainResetJournalPath), label).toEqual(before);
    }
  });

  test('rejects future evidence before the phase that creates it', () => {
    const resources = resourcesFor('default');
    const timestamp = '2026-08-11T00:00:01.000Z';
    const cases: Array<[string, HostDomainResetJournalV1]> = [
      ['prepared replacement attempt', journalFor(resources, { updatedAt: timestamp, signingReplacementAttemptedAt: timestamp })],
      ['prepared replacement IDs', journalFor(resources, {
        newHostId: `host_${'C'.repeat(43)}`, newKeyId: `key_${'D'.repeat(43)}`,
      })],
      ['replacement pending IDs', journalFor(resources, {
        phase: 'signing-replacement-pending', revoke: { state: 'complete', outcome: 'revoked' },
        signingReplacementAttemptedAt: timestamp, updatedAt: timestamp,
        newHostId: `host_${'C'.repeat(43)}`, newKeyId: `key_${'D'.repeat(43)}`,
      })],
      ['signing replaced E2E timestamp', journalFor(resources, {
        ...phasePatch('signing-identity-replaced', timestamp), updatedAt: timestamp,
        encryptionIdentityReplacedAt: timestamp,
      })],
      ['E2E replaced runtime timestamp', journalFor(resources, {
        ...phasePatch('encryption-identity-replaced', timestamp), updatedAt: timestamp,
        runtimeArtifactsClearedAt: timestamp,
      })],
      ['runtime cleared config timestamp', journalFor(resources, {
        ...phasePatch('runtime-artifacts-cleared', timestamp), updatedAt: timestamp, configSavedAt: timestamp,
      })],
      ['config saved enroll timestamp', journalFor(resources, {
        ...phasePatch('config-saved', timestamp), updatedAt: timestamp, enrolledAt: timestamp,
      })],
      ['enrolled service timestamp', journalFor(resources, {
        ...phasePatch('enrolled', timestamp), updatedAt: timestamp, serviceMetadataSynchronizedAt: timestamp,
      })],
    ];

    for (const [label, journal] of cases) {
      writeFileSync(resources.hostDomainResetJournalPath, JSON.stringify(journal), { mode: 0o600 });
      expect(() => loadHostDomainResetJournal(resources), label).toThrow(/journal is invalid/i);
    }
  });

  test('supports every fixed phase and advances only monotonically with stable binding fields', async () => {
    const resources = resourcesFor('dev');
    await withOperationLease(resources, (lease) => {
      let current = journalFor(resources, {
        profile: 'dev',
        ...phasePatch(HOST_DOMAIN_RESET_PHASES[0], '2026-08-11T00:00:00.000Z'),
      });
      writeJournalFixture(resources, current);

      for (const phase of HOST_DOMAIN_RESET_PHASES.slice(1)) {
        current = advanceHostDomainResetJournal(resources, current, transitionToPhase(phase), lease);
        expect(loadHostDomainResetJournal(resources)).toEqual(current);
      }

      const bytes = readFileSync(resources.hostDomainResetJournalPath);
      expect(() => advanceHostDomainResetJournal(resources, current, transitionToPhase('prepared'), lease)).toThrow(/phase|rollback|monotonic|journal is invalid/i);
      expect(readFileSync(resources.hostDomainResetJournalPath)).toEqual(bytes);
    });
  });

  test('serializes competing advancement so a newer phase cannot be overwritten by an older retry', async () => {
    const resources = resourcesFor('default');
    await withOperationLease(resources, (lease) => {
      const current = journalFor(resources);
      writeJournalFixture(resources, current);
      let competingError: unknown;
      let newerPhaseWasCommitted = false;
      let phaseRegressed = false;
      let lockEvidence: Record<string, unknown> | undefined;

      const advanced = advanceHostDomainResetJournal(resources, current, transitionToPhase('revoke-pending'), lease, {
        hooks: {
          beforePromotion() {
            const lockPath = `${resources.hostDomainResetJournalPath}.advance.lock`;
            expect(lstatSync(lockPath).mode & 0o777).toBe(0o600);
            lockEvidence = JSON.parse(readFileSync(lockPath, 'utf8')) as Record<string, unknown>;
            try {
              advanceHostDomainResetJournal(resources, current, transitionToPhase('old-identity-revoked'), lease);
              newerPhaseWasCommitted = true;
            } catch (error) {
              competingError = error;
            }
          },
          afterPromotion() {
            phaseRegressed = newerPhaseWasCommitted
              && loadHostDomainResetJournal(resources)?.phase === 'revoke-pending';
          },
        },
      });

      expect(competingError).toBeInstanceOf(Error);
      expect(String(competingError)).toMatch(/lock|advancement|another/i);
      expect(newerPhaseWasCommitted).toBe(false);
      expect(phaseRegressed).toBe(false);
      expect(lockEvidence).toMatchObject({ schemaVersion: 1, pid: process.pid });
      expect(lockEvidence?.ownerToken).toMatch(/^[0-9a-f]{48}$/);
      expect(typeof lockEvidence?.processStart).toBe('string');
      expect(loadHostDomainResetJournal(resources)).toEqual(advanced);
    });
  });

  test('fails closed on stale or disappeared advancement lock evidence without changing the journal', async () => {
    const resources = resourcesFor('default');
    await withOperationLease(resources, (lease) => {
      const current = journalFor(resources);
      const lockPath = `${resources.hostDomainResetJournalPath}.advance.lock`;
      writeJournalFixture(resources, current);
      const before = readFileSync(resources.hostDomainResetJournalPath);
      writeFileSync(lockPath, JSON.stringify({ stale: true }), { mode: 0o600 });

      expect(() => advanceHostDomainResetJournal(resources, current, transitionToPhase('revoke-pending'), lease)).toThrow(/already exists|lock|advancement/i);
      expect(readFileSync(resources.hostDomainResetJournalPath)).toEqual(before);
      expect(readFileSync(lockPath, 'utf8')).toContain('stale');

      rmSync(lockPath);
      expect(() => advanceHostDomainResetJournal(resources, current, transitionToPhase('revoke-pending'), lease, {
        hooks: { beforePromotion: () => rmSync(lockPath) },
      })).toThrow(/lock|unsafe|changed|atomic write/i);
      expect(readFileSync(resources.hostDomainResetJournalPath)).toEqual(before);
    });
  });

  test('recovers only a provably stale process-start-aware advancement lock', async () => {
    const resources = resourcesFor('default');
    await withOperationLease(resources, (lease) => {
      const current = journalFor(resources);
      writeJournalFixture(resources, current);
      const lockPath = `${resources.hostDomainResetJournalPath}.advance.lock`;
      writeFileSync(lockPath, JSON.stringify({
        schemaVersion: 1, pid: 4242, processStart: 'old-start',
        createdAt: '2026-08-11T00:00:00.000Z', ownerToken: 'a'.repeat(48),
      }), { mode: 0o600 });

      const advanced = advanceHostDomainResetJournal(resources, current, transitionToPhase('revoke-pending'), lease, {
        lockDependencies: {
          platform: 'linux', uid: process.getuid!(), pid: 5252,
          now: () => new Date('2026-08-11T00:10:00.000Z'), ownerToken: () => 'b'.repeat(48),
          currentProcessStart: () => 'new-start', inspector: { inspect: () => ({ status: 'absent' }) },
        },
      });
      expect(advanced.phase).toBe('revoke-pending');
      expect(loadHostDomainResetJournal(resources)).toEqual(advanced);
      expect(() => lstatSync(lockPath)).toThrow();
    });
  });

  test.each([
    ['live', { status: 'alive', processStart: 'same-start' }],
    ['unprovable', { status: 'unprovable' }],
  ] as const)('fails closed on %s advancement lock ownership', async (_name, inspection) => {
    const resources = resourcesFor('default');
    await withOperationLease(resources, (lease) => {
      const current = journalFor(resources);
      writeJournalFixture(resources, current);
      const lockPath = `${resources.hostDomainResetJournalPath}.advance.lock`;
      writeFileSync(lockPath, JSON.stringify({
        schemaVersion: 1, pid: 4242, processStart: 'same-start',
        createdAt: '2026-08-11T00:00:00.000Z', ownerToken: 'a'.repeat(48),
      }), { mode: 0o600 });
      expect(() => advanceHostDomainResetJournal(resources, current, transitionToPhase('revoke-pending'), lease, {
        lockDependencies: {
          platform: 'linux', uid: process.getuid!(), pid: 5252,
          now: () => new Date('2026-08-11T00:10:00.000Z'), ownerToken: () => 'b'.repeat(48),
          currentProcessStart: () => 'new-start', inspector: { inspect: () => inspection },
        },
      })).toThrow(/lock|progress/i);
      expect(loadHostDomainResetJournal(resources)).toEqual(current);
    });
  });

  test('rejects malformed, unknown, invalid, mismatched, and counterpart evidence without rewriting bytes', () => {
    const resources = resourcesFor('default');
    const counterpart = resourcesFor('dev');
    const valid = journalFor(resources);
    const cases: Array<[string, string]> = [
      ['malformed JSON', '{not-json'],
      ['unknown key', JSON.stringify({ ...valid, privateKey: 'forbidden' })],
      ['invalid phase', JSON.stringify({ ...valid, phase: 'finished' })],
      ['invalid version', JSON.stringify({ ...valid, version: 2 })],
      ['digest mismatch', JSON.stringify({ ...valid, resourceDigest: '0'.repeat(64) })],
      ['counterpart profile', JSON.stringify(journalFor(counterpart, { profile: 'dev' }))],
      ['invalid timestamp order', JSON.stringify({ ...valid, updatedAt: '2026-08-10T23:59:59.000Z' })],
      ['secret-shaped nested key', JSON.stringify({ ...valid, service: { ...valid.service, rawCommandOutput: 'secret' } })],
    ];

    mkdirSync(resources.root, { recursive: true, mode: 0o700 });
    for (const [label, bytes] of cases) {
      writeFileSync(resources.hostDomainResetJournalPath, bytes, { mode: 0o600 });
      const before = readFileSync(resources.hostDomainResetJournalPath);
      expect(() => loadHostDomainResetJournal(resources), label).toThrow();
      expect(readFileSync(resources.hostDomainResetJournalPath), label).toEqual(before);
    }
  });

  test('rejects noncanonical Host and key IDs in every old and new field', () => {
    const resources = resourcesFor('default');
    const valid = journalFor(resources, {
      newHostId: `host_${'C'.repeat(43)}`,
      newKeyId: `key_${'D'.repeat(43)}`,
    });
    const invalidPayloads = [
      ['too short', 'A'.repeat(42)],
      ['too long', 'A'.repeat(44)],
      ['malformed', `${'A'.repeat(42)}+`],
    ] as const;
    const fields = [
      ['oldHostId', 'host_'],
      ['oldKeyId', 'key_'],
      ['newHostId', 'host_'],
      ['newKeyId', 'key_'],
    ] as const;

    for (const [field, prefix] of fields) {
      for (const [kind, payload] of invalidPayloads) {
        const journal = { ...valid, [field]: `${prefix}${payload}` };
        expect(() => writeJournalFixture(resources, journal), `${field}: ${kind}`).toThrow(
          /journal is invalid/i,
        );
      }
    }
  });

  test('rejects symlink, non-0600, non-file, and foreign-owner evidence without mutation', () => {
    const resources = resourcesFor('default');
    const journalPath = resources.hostDomainResetJournalPath;
    mkdirSync(resources.root, { recursive: true, mode: 0o700 });
    const target = join(resources.root, 'target.json');
    writeFileSync(target, JSON.stringify(journalFor(resources)), { mode: 0o600 });
    symlinkSync(target, journalPath);
    expect(() => loadHostDomainResetJournal(resources)).toThrow();
    expect(readFileSync(target, 'utf8')).toContain('operationId');

    rmSync(journalPath);
    writeFileSync(journalPath, JSON.stringify(journalFor(resources)), { mode: 0o644 });
    const permissive = readFileSync(journalPath);
    expect(() => loadHostDomainResetJournal(resources)).toThrow();
    expect(readFileSync(journalPath)).toEqual(permissive);

    rmSync(journalPath);
    mkdirSync(journalPath, { mode: 0o700 });
    expect(() => loadHostDomainResetJournal(resources)).toThrow();
    expect(lstatSync(journalPath).isDirectory()).toBe(true);

    rmSync(journalPath, { recursive: true });
    writeFileSync(journalPath, JSON.stringify(journalFor(resources)), { mode: 0o600 });
    const foreign = readFileSync(journalPath);
    expect(() => loadHostDomainResetJournal(resources, (process.getuid?.() ?? 0) + 1)).toThrow();
    expect(readFileSync(journalPath)).toEqual(foreign);
  });

  test('treats a missing journal as idle and secure removal as idempotent', () => {
    const resources = resourcesFor('default');
    expect(loadHostDomainResetJournal(resources)).toBeNull();
    expect(() => removeJournalFixture(resources)).not.toThrow();

    writeJournalFixture(resources, journalFor(resources));
    let unlinked = 0;
    let synced = 0;
    removeJournalFixture(resources, {
      afterUnlink: () => { unlinked += 1; },
      afterDirectorySync: () => { synced += 1; },
    });
    expect(unlinked).toBe(1);
    expect(synced).toBe(1);
    expect(loadHostDomainResetJournal(resources)).toBeNull();
    expect(() => removeJournalFixture(resources)).not.toThrow();
    rmSync(resources.root, { recursive: true });
    expect(() => removeJournalFixture(resources)).toThrow();
  });

  test('refuses writes through journal symlinks without replacing either path', async () => {
    const resources = resourcesFor('default');
    mkdirSync(resources.root, { recursive: true, mode: 0o700 });
    const target = join(resources.root, 'journal-target.json');
    writeFileSync(target, 'sentinel', { mode: 0o600 });
    symlinkSync(target, resources.hostDomainResetJournalPath);

    await withOperationLease(resources, (lease) => {
      expect(() => createHostDomainResetJournal(resources, {
        ...journalFor(resources),
        phase: 'quarantine-pending',
        oldHostId: null,
        oldKeyId: null,
        oldEncryptionKeyId: null,
      }, lease)).toThrow();
    });
    expect(readFileSync(target, 'utf8')).toBe('sentinel');
    expect(lstatSync(resources.hostDomainResetJournalPath).isSymbolicLink()).toBe(true);
  });

  test('rejects journal modes with special bits without rewriting bytes when supported', () => {
    const resources = resourcesFor('default');
    const journalPath = resources.hostDomainResetJournalPath;
    writeFileSync(journalPath, JSON.stringify(journalFor(resources)), { mode: 0o600 });
    chmodSync(journalPath, 0o4600);
    const effectiveMode = lstatSync(journalPath).mode & 0o7777;
    const before = readFileSync(journalPath);

    if (effectiveMode === 0o4600) {
      expect(() => loadHostDomainResetJournal(resources)).toThrow();
      expect(readFileSync(journalPath)).toEqual(before);
    } else {
      expect(effectiveMode).toBe(0o600);
    }
  });

  test('binds dev journals to the canonical unmanaged no-service snapshot', () => {
    const resources = resourcesFor('dev');
    const valid = journalFor(resources);
    const nonDevSnapshots: Array<[string, HostDomainResetJournalV1['service']]> = [
      ['managed', { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'launchd' }],
      ['installed', { managed: true, installed: true, enabled: false, wasRunning: false, backend: 'launchd' }],
      ['enabled', { managed: true, installed: true, enabled: true, wasRunning: false, backend: 'launchd' }],
      ['running', { managed: true, installed: true, enabled: false, wasRunning: true, backend: 'launchd' }],
      ['backend', { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'systemd-user' }],
    ];

    expect(() => writeJournalFixture(resources, valid)).not.toThrow();
    removeJournalFixture(resources);
    for (const [label, service] of nonDevSnapshots) {
      expect(
        () => writeJournalFixture(resources, { ...valid, service }),
        label,
      ).toThrow(/journal is invalid/i);
    }
  });

  test('retains platform-neutral consistent service snapshots for default journals', () => {
    const resources = resourcesFor('default');
    const validServices: HostDomainResetJournalV1['service'][] = [
      { managed: false, installed: false, enabled: false, wasRunning: false, backend: 'none' },
      { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'launchd' },
      { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'systemd-user' },
      { managed: true, installed: true, enabled: false, wasRunning: false, backend: 'launchd' },
      { managed: true, installed: true, enabled: true, wasRunning: false, backend: 'systemd-user' },
      { managed: true, installed: true, enabled: false, wasRunning: true, backend: 'launchd' },
      { managed: true, installed: true, enabled: true, wasRunning: true, backend: 'systemd-user' },
    ];
    const inconsistentServices: HostDomainResetJournalV1['service'][] = [
      { managed: false, installed: true, enabled: false, wasRunning: false, backend: 'none' },
      { managed: false, installed: false, enabled: false, wasRunning: false, backend: 'launchd' },
      { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'none' },
      { managed: true, installed: false, enabled: true, wasRunning: false, backend: 'launchd' },
      { managed: true, installed: false, enabled: false, wasRunning: true, backend: 'systemd-user' },
    ];

    for (const service of validServices) {
      expect(() => writeJournalFixture(resources, journalFor(resources, { service }))).not.toThrow();
      removeJournalFixture(resources);
    }
    for (const service of inconsistentServices) {
      expect(() => writeJournalFixture(resources, journalFor(resources, { service }))).toThrow(
        /journal is invalid/i,
      );
    }
  });


  test('rejects mutation of the complete service snapshot at the same or a forward phase', () => {
    const resources = resourcesFor('default');
    const base = journalFor(resources, {
      service: {
        managed: true,
        installed: true,
        enabled: true,
        wasRunning: true,
        backend: 'launchd',
      },
    });
    const mutations: HostDomainResetJournalV1['service'][] = [
      { ...base.service, managed: false, installed: false, enabled: false, wasRunning: false, backend: 'none' },
      { ...base.service, installed: false, enabled: false, wasRunning: false },
      { ...base.service, enabled: false },
      { ...base.service, wasRunning: false },
      { ...base.service, backend: 'systemd-user' },
    ];

    for (const [index, service] of mutations.entries()) {
      rmSync(resources.hostDomainResetJournalPath, { force: true });
      writeJournalFixture(resources, base);
      const before = readFileSync(resources.hostDomainResetJournalPath);
      expect(validateHostDomainResetTransition(base, {
        ...base,
        ...phasePatch(index % 2 === 0 ? base.phase : 'revoke-pending', base.updatedAt),
        service,
        updatedAt: '2026-08-11T00:00:01.000Z',
      })).toMatchObject({ ok: false });
      expect(readFileSync(resources.hostDomainResetJournalPath)).toEqual(before);
    }
  });
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

function phasePatch(
  phase: typeof HOST_DOMAIN_RESET_PHASES[number], _timestamp: string,
): Partial<HostDomainResetJournalV1> {
  const index = HOST_DOMAIN_RESET_PHASES.indexOf(phase);
  const atLeast = (candidate: typeof phase) => index >= HOST_DOMAIN_RESET_PHASES.indexOf(candidate);
  const evidenceTimestamp = '2026-08-11T00:00:00.000Z';
  return {
    phase,
    ...(phase === 'quarantine-pending' || phase === 'quarantined'
      ? { oldHostId: null, oldKeyId: null, oldEncryptionKeyId: null }
      : {
        oldHostId: `host_${'A'.repeat(43)}`, oldKeyId: `key_${'B'.repeat(43)}`,
        oldEncryptionKeyId: `ekey_${'C'.repeat(43)}`,
      }),
    ...(atLeast('revoke-pending') ? { revoke: { state: 'pending' as const, outcome: null } } : {}),
    ...(atLeast('old-identity-revoked') ? { revoke: { state: 'complete' as const, outcome: 'revoked' as const } } : {}),
    ...(atLeast('signing-replacement-pending') ? { signingReplacementAttemptedAt: evidenceTimestamp } : {}),
    ...(atLeast('signing-identity-replaced') ? {
      newHostId: `host_${'D'.repeat(43)}`, newKeyId: `key_${'E'.repeat(43)}`,
    } : {}),
    ...(atLeast('encryption-identity-replaced') ? { encryptionIdentityReplacedAt: evidenceTimestamp } : {}),
    ...(atLeast('runtime-artifacts-cleared') ? { runtimeArtifactsClearedAt: evidenceTimestamp } : {}),
    ...(atLeast('config-saved') ? { configSavedAt: evidenceTimestamp } : {}),
    ...(atLeast('enrolled') ? { enrolledAt: evidenceTimestamp } : {}),
    ...(atLeast('service-metadata-synchronized') ? { serviceMetadataSynchronizedAt: evidenceTimestamp } : {}),
  };
}

/**
 * Maps a target phase to the exact machine transition that reaches it from its
 * predecessor, using the same evidence values as `phasePatch`.
 */
function transitionToPhase(phase: typeof HOST_DOMAIN_RESET_PHASES[number]): HostDomainResetTransition {
  const evidenceTimestamp = '2026-08-11T00:00:00.000Z';
  switch (phase) {
    case 'quarantined':
      return { phase: 'quarantined' };
    case 'prepared':
      return {
        phase: 'prepared',
        oldHostId: `host_${'A'.repeat(43)}`,
        oldKeyId: `key_${'B'.repeat(43)}`,
        oldEncryptionKeyId: `ekey_${'C'.repeat(43)}`,
        signingCleanup: null,
        revoke: { state: 'not-attempted', outcome: null },
      };
    case 'revoke-pending':
      return { phase: 'revoke-pending', revoke: { state: 'pending', outcome: null } };
    case 'old-identity-revoked':
      return { phase: 'old-identity-revoked', revoke: { state: 'complete', outcome: 'revoked' } };
    case 'signing-replacement-pending':
      return { phase: 'signing-replacement-pending', signingReplacementAttemptedAt: evidenceTimestamp };
    case 'signing-identity-replaced':
      return {
        phase: 'signing-identity-replaced',
        newHostId: `host_${'D'.repeat(43)}`,
        newKeyId: `key_${'E'.repeat(43)}`,
      };
    case 'encryption-identity-replaced':
      return { phase: 'encryption-identity-replaced', encryptionIdentityReplacedAt: evidenceTimestamp };
    case 'runtime-artifacts-cleared':
      return { phase: 'runtime-artifacts-cleared', runtimeArtifactsClearedAt: evidenceTimestamp };
    case 'config-saved':
      return { phase: 'config-saved', configSavedAt: evidenceTimestamp };
    case 'enrolled':
      return { phase: 'enrolled', enrolledAt: evidenceTimestamp };
    case 'service-metadata-synchronized':
      return { phase: 'service-metadata-synchronized', serviceMetadataSynchronizedAt: evidenceTimestamp };
    case 'service-restore-pending':
      return { phase: 'service-restore-pending' };
  }
}

describe('Host-domain runtime artifact cleanup', () => {
  test('requires exclusive runtime ownership and deletes selected artifacts opaquely', async () => {
    const { acquireRuntimeCoordinator } = await import('../src/runtime-lock');
    const { clearHostDomainArtifacts } = await import('../src/cli/operations/host-domain-reset-artifacts');
    const resources = resourcesFor('default');
    for (const path of [resources.linkKeyringPath, resources.statePath, resources.encryptedSpoolPath, resources.runtimeResetIntentPath]) {
      mkdirSync(join(path, '..'), { recursive: true, mode: 0o700 });
      writeFileSync(path, Buffer.from([0, 1, 2, 255]), { mode: 0o600 });
    }
    let spoolRemovals = 0;
    const coordinator = acquireRuntimeCoordinator(resources.statePath, resources.encryptedSpoolPath);
    expect(() => clearHostDomainArtifacts(resources, coordinator, {
      removeForHostReplacement: () => { spoolRemovals += 1; },
      assertAbsentForHostReplacement() {},
    }, `host_${'A'.repeat(43)}`)).not.toThrow();
    for (const path of [resources.linkKeyringPath, resources.statePath, resources.encryptedSpoolPath, resources.runtimeResetIntentPath]) {
      expect(() => lstatSync(path)).toThrow();
    }
    expect(spoolRemovals).toBe(1);
    coordinator.dispose();
    expect(() => lstatSync(resources.runtimeLockPath)).toThrow();
  });

  test('refuses mismatched coordinator before deletion or platform key access', async () => {
    const { acquireRuntimeCoordinator } = await import('../src/runtime-lock');
    const { clearHostDomainArtifacts } = await import('../src/cli/operations/host-domain-reset-artifacts');
    const resources = resourcesFor('default');
    mkdirSync(join(resources.statePath, '..'), { recursive: true, mode: 0o700 });
    writeFileSync(resources.statePath, 'selected', { mode: 0o600 });
    let spoolRemovals = 0;
    const mismatch = acquireRuntimeCoordinator(`${resources.statePath}.other`);
    expect(() => clearHostDomainArtifacts(resources, mismatch, {
      removeForHostReplacement: () => { spoolRemovals += 1; }, assertAbsentForHostReplacement() {},
    })).toThrow();
    mismatch.dispose();
    expect(readFileSync(resources.statePath, 'utf8')).toBe('selected');
    expect(spoolRemovals).toBe(0);
  });

  test('unsafe selected artifact fails closed without touching later artifacts', async () => {
    const { acquireRuntimeCoordinator } = await import('../src/runtime-lock');
    const { clearHostDomainArtifacts } = await import('../src/cli/operations/host-domain-reset-artifacts');
    const resources = resourcesFor('dev');
    mkdirSync(join(resources.statePath, '..'), { recursive: true, mode: 0o700 });
    writeFileSync(resources.linkKeyringPath, 'unsafe', { mode: 0o644 });
    writeFileSync(resources.statePath, 'later', { mode: 0o600 });
    let spoolRemovals = 0;
    const coordinator = acquireRuntimeCoordinator(resources.statePath, resources.encryptedSpoolPath);
    expect(() => clearHostDomainArtifacts(resources, coordinator, {
      removeForHostReplacement: () => { spoolRemovals += 1; }, assertAbsentForHostReplacement() {},
    })).toThrow();
    expect(readFileSync(resources.linkKeyringPath, 'utf8')).toBe('unsafe');
    expect(readFileSync(resources.statePath, 'utf8')).toBe('later');
    expect(spoolRemovals).toBe(0);
    coordinator.dispose();
  });
});

describe('Host-domain reset runtime start guard', () => {
  test('blocks ordinary runtime startup for every persisted reset phase', async () => {
    const { assertHostDomainResetRuntimeStartAllowed } = await import('../src/cli/operations/host-domain-reset-journal');
    const resources = resourcesFor('default');
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      const journal = journalFor(resources, { ...phasePatch(phase, '2026-08-11T00:00:00.000Z') });
      writeJournalFixture(resources, journal);
      expect(() => assertHostDomainResetRuntimeStartAllowed(resources)).toThrow(/recovery|required|phase/i);
      removeJournalFixture(resources);
    }
  });
});
