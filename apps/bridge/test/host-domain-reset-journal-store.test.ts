import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefaultProfile } from '../src/cli/profiles/default';
import type { ProcessAwareLockDependencies } from '../src/host-manager/process-aware-lock';
import type { ProfileResourceSet } from '../src/cli/profile';
import {
  advanceHostDomainResetJournal,
  createHostDomainResetJournal,
  loadHostDomainResetJournal,
  removeAfterServiceRestoreConfirmed,
  restoreHostDomainServiceAndConfirm,
  type RestoreConfirmation,
} from '../src/cli/operations/host-domain-reset-journal-store';
import type { HostDomainResetJournalV1 } from '../src/cli/operations/host-domain-reset-journal-schema';
import {
  hostIdentityOperationLockPath,
  withHostIdentityOperationLock,
  type HostIdentityOperationLease,
} from '../src/cli/operations/host-identity-operation-lock';
import {
  buildJournal,
  removeJournalFixture,
  writeJournalFixture,
  TS0,
} from './helpers/host-domain-reset-journal-fixture';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function resourcesFor(): ProfileResourceSet {
  const home = mkdtempSync(join(tmpdir(), 'ariava-journal-store-'));
  roots.push(home);
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  try {
    const profile = createDefaultProfile();
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    return profile.resources;
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousXdg;
  }
}

function lockDependencies(): Partial<ProcessAwareLockDependencies> {
  let token = 0;
  return {
    platform: 'linux',
    uid: process.getuid!(),
    pid: process.pid,
    now: () => new Date(),
    ownerToken: () => (++token).toString(16).padStart(48, 'f'),
    currentProcessStart: () => 'test-process-start',
    inspector: { inspect: () => ({ status: 'alive', processStart: 'test-process-start' }) },
  };
}

async function withRealLease<T>(
  resources: ProfileResourceSet,
  run: (lease: HostIdentityOperationLease) => T | Promise<T>,
): Promise<T> {
  return withHostIdentityOperationLock(resources, run, lockDependencies());
}

function initialJournal(resources: ProfileResourceSet): HostDomainResetJournalV1 {
  return buildJournal(resources, 'quarantine-pending', { updatedAt: TS0 });
}

function replacementReference(resources: ProfileResourceSet) {
  return { type: 'linux-json' as const, path: resources.identityMetadataPath };
}

function restore(
  resources: ProfileResourceSet,
  current: HostDomainResetJournalV1,
  lease: HostIdentityOperationLease,
  restoreReturn = false,
) {
  return restoreHostDomainServiceAndConfirm(
    resources,
    current,
    lease,
    replacementReference(resources),
    () => restoreReturn,
  );
}

describe('host-domain-reset-journal-store', () => {
  describe('authentic Host identity operation leases', () => {
    test('rejects plain-object lease forgeries before create, advance, and restore', async () => {
      const resources = resourcesFor();
      const forged = { assertOwned() {} } as HostIdentityOperationLease;
      expect(() => createHostDomainResetJournal(resources, initialJournal(resources), forged, {
        lockDependencies: lockDependencies(),
      })).toThrow(/lease.*invalid|unsafe/i);

      const prepared = buildJournal(resources, 'prepared');
      writeJournalFixture(resources, prepared);
      expect(() => advanceHostDomainResetJournal(resources, prepared, {
        kind: 'start-revoke', at: '2026-08-11T00:00:02.000Z',
      }, forged, { lockDependencies: lockDependencies() })).toThrow(/lease.*invalid|unsafe/i);

      const final = buildJournal(resources, 'service-restore-pending');
      removeJournalFixture(resources);
      writeJournalFixture(resources, final);
      expect(() => restoreHostDomainServiceAndConfirm(
        resources, final, forged, replacementReference(resources), () => false,
      )).toThrow(/lease.*invalid|unsafe/i);
    });

    test('rejects a live authentic lease against journals for another resource set', async () => {
      const resourcesA = resourcesFor();
      const resourcesB = resourcesFor();
      const journalA = initialJournal(resourcesA);
      writeJournalFixture(resourcesA, journalA);

      await withRealLease(resourcesA, async (leaseA) => {
        leaseA.assertOwned();

        expect(() => createHostDomainResetJournal(resourcesB, initialJournal(resourcesB), leaseA, {
          lockDependencies: lockDependencies(),
        })).toThrow(/lease.*invalid|unsafe/i);
        expect(loadHostDomainResetJournal(resourcesA)).toEqual(journalA);
        expect(loadHostDomainResetJournal(resourcesB)).toBeNull();

        const preparedB = buildJournal(resourcesB, 'prepared');
        writeJournalFixture(resourcesB, preparedB);
        expect(() => advanceHostDomainResetJournal(resourcesB, preparedB, {
          kind: 'start-revoke', at: '2026-08-11T00:00:02.000Z',
        }, leaseA, { lockDependencies: lockDependencies() })).toThrow(/lease.*invalid|unsafe/i);
        expect(loadHostDomainResetJournal(resourcesA)).toEqual(journalA);
        expect(loadHostDomainResetJournal(resourcesB)).toEqual(preparedB);

        removeJournalFixture(resourcesB);
        const finalB = buildJournal(resourcesB, 'service-restore-pending');
        writeJournalFixture(resourcesB, finalB);
        let restoreCalls = 0;
        expect(() => restoreHostDomainServiceAndConfirm(
          resourcesB,
          finalB,
          leaseA,
          replacementReference(resourcesB),
          () => { restoreCalls += 1; return false; },
        )).toThrow(/lease.*invalid|unsafe/i);
        expect(restoreCalls).toBe(0);
        expect(loadHostDomainResetJournal(resourcesA)).toEqual(journalA);
        expect(loadHostDomainResetJournal(resourcesB)).toEqual(finalB);

        const confirmationB = await withRealLease(resourcesB, (leaseB) =>
          restore(resourcesB, finalB, leaseB).confirmation,
        );
        expect(() => removeAfterServiceRestoreConfirmed(
          resourcesB, finalB, leaseA, confirmationB,
        )).toThrow(/lease.*invalid|unsafe/i);
        expect(loadHostDomainResetJournal(resourcesA)).toEqual(journalA);
        expect(loadHostDomainResetJournal(resourcesB)).toEqual(finalB);
      });
    });

    test('rejects a real lease after its lock scope ends', async () => {
      const resources = resourcesFor();
      let captured: HostIdentityOperationLease | undefined;
      await withRealLease(resources, (lease) => { captured = lease; });
      expect(() => captured!.assertOwned()).toThrow();
      expect(() => createHostDomainResetJournal(resources, initialJournal(resources), captured!, {
        lockDependencies: lockDependencies(),
      })).toThrow();
    });
  });

  describe('createHostDomainResetJournal', () => {
    test('creates exclusively under a live authentic lease', async () => {
      const resources = resourcesFor();
      await withRealLease(resources, (lease) => {
        const created = createHostDomainResetJournal(resources, initialJournal(resources), lease, {
          lockDependencies: lockDependencies(),
        });
        expect(loadHostDomainResetJournal(resources)).toEqual(created);
        expect(() => createHostDomainResetJournal(resources, initialJournal(resources), lease, {
          lockDependencies: lockDependencies(),
        })).toThrow(/already exists/i);
      });
    });

    test('fails closed when operation ownership is lost before create promotion', async () => {
      const resources = resourcesFor();
      await expect(withRealLease(resources, (lease) => createHostDomainResetJournal(
        resources,
        initialJournal(resources),
        lease,
        {
          lockDependencies: lockDependencies(),
          writeHooks: { beforePromotion: () => rmSync(hostIdentityOperationLockPath(resources)) },
        },
      ))).rejects.toThrow();
      expect(loadHostDomainResetJournal(resources)).toBeNull();
    });
  });

  describe('advanceHostDomainResetJournal', () => {
    test('advances a machine edge under a live authentic lease', async () => {
      const resources = resourcesFor();
      const current = buildJournal(resources, 'quarantine-pending');
      writeJournalFixture(resources, current);
      await withRealLease(resources, (lease) => {
        const advanced = advanceHostDomainResetJournal(resources, current, {
          kind: 'advance', phase: 'quarantined', at: '2026-08-11T00:00:02.000Z',
        }, lease, { lockDependencies: lockDependencies() });
        expect(advanced.phase).toBe('quarantined');
        expect(loadHostDomainResetJournal(resources)).toEqual(advanced);
      });
    });

    test('rejects stale snapshots and policy-invalid transitions', async () => {
      const resources = resourcesFor();
      const current = buildJournal(resources, 'prepared');
      const stored = buildJournal(resources, 'prepared', { operationId: 'reset_ffffffffffffffff' });
      writeJournalFixture(resources, stored);
      await withRealLease(resources, (lease) => {
        expect(() => advanceHostDomainResetJournal(resources, current, {
          kind: 'start-revoke', at: '2026-08-11T00:00:02.000Z',
        }, lease, { lockDependencies: lockDependencies() })).toThrow(/changed before advancement/i);
      });
      removeJournalFixture(resources);
      writeJournalFixture(resources, current);
      await withRealLease(resources, (lease) => {
        expect(() => advanceHostDomainResetJournal(resources, current, {
          kind: 'complete-enrollment', at: '2026-08-11T00:00:02.000Z',
        }, lease, { lockDependencies: lockDependencies() })).toThrow(/phase-skip/i);
      });
    });

    test('fails closed when operation ownership is lost before advance promotion', async () => {
      const resources = resourcesFor();
      const current = buildJournal(resources, 'prepared');
      writeJournalFixture(resources, current);
      await expect(withRealLease(resources, (lease) => advanceHostDomainResetJournal(
        resources,
        current,
        { kind: 'start-revoke', at: '2026-08-11T00:00:02.000Z' },
        lease,
        {
          lockDependencies: lockDependencies(),
          writeHooks: { beforePromotion: () => rmSync(hostIdentityOperationLockPath(resources)) },
        },
      ))).rejects.toThrow();
      expect(loadHostDomainResetJournal(resources)).toEqual(current);
    });
  });

  describe('restore authority and guarded removal', () => {
    test('invokes restore itself and preserves a legal false return', async () => {
      const resources = resourcesFor();
      const current = buildJournal(resources, 'service-restore-pending');
      writeJournalFixture(resources, current);
      await withRealLease(resources, (lease) => {
        const calls: unknown[][] = [];
        const restored = restoreHostDomainServiceAndConfirm(
          resources,
          current,
          lease,
          replacementReference(resources),
          (...args) => { calls.push(args); return false; },
        );
        expect(restored.processRunning).toBe(false);
        expect(calls).toEqual([[current.service, replacementReference(resources)]]);
        removeAfterServiceRestoreConfirmed(resources, current, lease, restored.confirmation);
        expect(loadHostDomainResetJournal(resources)).toBeNull();
      });
    });

    test('rejects wrong phase or identity before invoking restore', async () => {
      const resources = resourcesFor();
      const enrolled = buildJournal(resources, 'enrolled');
      writeJournalFixture(resources, enrolled);
      await withRealLease(resources, (lease) => {
        let calls = 0;
        expect(() => restoreHostDomainServiceAndConfirm(
          resources, enrolled, lease, replacementReference(resources), () => { calls += 1; return true; },
        )).toThrow(/service-restore-pending/i);
        expect(calls).toBe(0);
      });

      const current = buildJournal(resources, 'service-restore-pending');
      removeJournalFixture(resources);
      writeJournalFixture(resources, current);
      await withRealLease(resources, (lease) => {
        let calls = 0;
        expect(() => restoreHostDomainServiceAndConfirm(
          resources,
          current,
          lease,
          { type: 'linux-json', path: join(resources.root, 'wrong.json') },
          () => { calls += 1; return true; },
        )).toThrow(/confirmation is invalid/i);
        expect(calls).toBe(0);
      });
    });

    test('rejects stale journal before restore and does not create a confirmation', async () => {
      const resources = resourcesFor();
      const current = buildJournal(resources, 'service-restore-pending');
      const stored = buildJournal(resources, 'service-restore-pending', { operationId: 'reset_ffffffffffffffff' });
      writeJournalFixture(resources, stored);
      await withRealLease(resources, (lease) => {
        let calls = 0;
        expect(() => restoreHostDomainServiceAndConfirm(
          resources, current, lease, replacementReference(resources), () => { calls += 1; return true; },
        )).toThrow(/changed before service restoration/i);
        expect(calls).toBe(0);
      });
    });

    test('rejects forged and reused confirmations', async () => {
      const resources = resourcesFor();
      const current = buildJournal(resources, 'service-restore-pending');
      writeJournalFixture(resources, current);
      await withRealLease(resources, (lease) => {
        const issued = restore(resources, current, lease).confirmation;
        const forged = { ...issued } as unknown as RestoreConfirmation;
        expect(() => removeAfterServiceRestoreConfirmed(resources, current, lease, forged)).toThrow(
          /confirmation is invalid/i,
        );
        removeAfterServiceRestoreConfirmed(resources, current, lease, issued);
        writeJournalFixture(resources, current);
        expect(() => removeAfterServiceRestoreConfirmed(resources, current, lease, issued)).toThrow(
          /confirmation is invalid/i,
        );
      });
    });

    test('does not burn confirmation when stored journal changed before removal', async () => {
      const resources = resourcesFor();
      const current = buildJournal(resources, 'service-restore-pending');
      writeJournalFixture(resources, current);
      await withRealLease(resources, (lease) => {
        const confirmation = restore(resources, current, lease).confirmation;
        removeJournalFixture(resources);
        const replacement = buildJournal(resources, 'service-restore-pending', {
          operationId: 'reset_ffffffffffffffff',
        });
        writeJournalFixture(resources, replacement);
        expect(() => removeAfterServiceRestoreConfirmed(resources, current, lease, confirmation)).toThrow(
          /changed before removal/i,
        );
        removeJournalFixture(resources);
        writeJournalFixture(resources, current);
        removeAfterServiceRestoreConfirmed(resources, current, lease, confirmation);
      });
    });

    test('does not issue confirmation when ownership is lost after restore returns', async () => {
      const resources = resourcesFor();
      const current = buildJournal(resources, 'service-restore-pending');
      writeJournalFixture(resources, current);
      let restoreCalls = 0;
      await expect(withRealLease(resources, (lease) => restoreHostDomainServiceAndConfirm(
        resources,
        current,
        lease,
        replacementReference(resources),
        () => {
          restoreCalls += 1;
          rmSync(hostIdentityOperationLockPath(resources));
          return true;
        },
      ))).rejects.toThrow();
      expect(restoreCalls).toBe(1);
      expect(loadHostDomainResetJournal(resources)).toEqual(current);
    });

    test('burns confirmation and refuses unlink when ownership is lost before unlink', async () => {
      const resources = resourcesFor();
      const current = buildJournal(resources, 'service-restore-pending');
      writeJournalFixture(resources, current);
      let confirmation: RestoreConfirmation | undefined;
      await expect(withRealLease(resources, (lease) => {
        confirmation = restore(resources, current, lease).confirmation;
        removeAfterServiceRestoreConfirmed(resources, current, lease, confirmation, {
          removeHooks: { beforeUnlink: () => rmSync(hostIdentityOperationLockPath(resources)) },
        });
      })).rejects.toThrow();
      expect(loadHostDomainResetJournal(resources)).toEqual(current);
      await withRealLease(resources, (lease) => {
        expect(() => removeAfterServiceRestoreConfirmed(resources, current, lease, confirmation!)).toThrow(
          /confirmation is invalid/i,
        );
      });
    });
  });
});
