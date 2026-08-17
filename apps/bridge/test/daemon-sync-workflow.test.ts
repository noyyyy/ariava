import { describe, expect, test } from 'bun:test';
import type { CanonicalSessionState, CommandResult, HostProjection } from '@ariava/protocol';
import { RelayClientError, RelayTransportError } from '../src/relay-client';
import type { AgentDriver } from '../src/types';
import {
  performBridgeSyncOnce,
  type SessionPublicationOutcome,
  type SyncWorkflowDependencies,
} from '../src/daemon/sync-workflow';

/**
 * Focused runner tests for the Task 6C sync workflow extraction (plan
 * `2026-08-16-bridge-daemon-lifecycle-decomposition.md`, spec §5/§8/§9):
 * the single linear sync orchestration previously inside
 * `BridgeDaemon.performSyncOnce` — §9 step order, every early-return/failure
 * category, offline/degraded semantics, and the exact `BridgeSyncResult`
 * fields — behind the explicit narrow dependency contract, independently of
 * `BridgeDaemon` single-flight/timer/stop/health state. All daemon-owned
 * effects (stop, scheduling, snapshot failure state, logging/health
 * authorities, flights) are asserted as delegation boundaries, not reimplemented.
 */

async function waitFor(condition: () => boolean, context: string, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${context}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function session(sessionId: string): CanonicalSessionState {
  return {
    sessionId, hostId: 'host-sync', provider: 'pi', projectName: 'project', nameText: sessionId,
    status: 'working', updatedAt: '2026-08-12T00:00:00.000Z',
  };
}

interface ReplaceCall {
  driverName: string;
  sessions: CanonicalSessionState[];
}

/**
 * Fake daemon contract backed by a tiny in-memory reconciled session store:
 * `replaceDriverSessions` swaps the attributed driver set (recording the exact
 * driverName/sessions arguments), later `listSessions` reads return that
 * replaced snapshot, publication receives it, and the pass result carries it —
 * never the stale initial array. Order and effect capture stay independent of
 * the real `BridgeDaemon` single-flight/timer/stop/health state.
 */
function createHarness(overrides: Partial<SyncWorkflowDependencies> = {}) {
  const order: string[] = [];
  const initialSessions = [session('s-1'), session('s-2')];
  const handledCommands: CommandResult[] = [];
  const replaceCalls: ReplaceCall[] = [];
  const publicationInputs: CanonicalSessionState[][] = [];
  const sessionDrivers = new Map<string, string>([['s-1', 'pi'], ['s-2', 'pi']]);
  let storeSessions: CanonicalSessionState[] = [...initialSessions];
  const driver: AgentDriver = {
    name: 'pi',
    listSessions: async () => { order.push('driver:listSessions'); return [session('s-new')]; },
    executeCommand: async () => { throw new Error('unused'); },
  };
  const deps: SyncWorkflowDependencies = {
    assertHostDomainResetStartAllowed: () => { order.push('assertHostDomainResetStartAllowed'); },
    stop: () => { order.push('stop'); },
    validateStartup: async () => { order.push('validateStartup'); },
    acknowledgeSyncPass: () => { order.push('acknowledgeSyncPass'); },
    ensureHostPresence: async () => { order.push('ensureHostPresence'); },
    reconcileRecipientsAndDrainReceipts: async () => { order.push('reconcileRecipientsAndDrainReceipts'); return 1; },
    drivers: () => { order.push('drivers'); return [driver]; },
    hostId: 'host-sync',
    pollIntervalMs: 15_000,
    listSessions: () => { order.push('listSessions'); return storeSessions; },
    getDriverNameForSession: (sessionId) => { order.push(`getDriverNameForSession:${sessionId}`); return sessionDrivers.get(sessionId); },
    replaceDriverSessions: (driverName, sessions) => {
      order.push('replaceDriverSessions');
      replaceCalls.push({ driverName, sessions });
      const retained = storeSessions.filter((existing) => sessionDrivers.get(existing.sessionId) !== driverName);
      for (const replaced of sessions) sessionDrivers.set(replaced.sessionId, driverName);
      storeSessions = [...retained, ...sessions];
    },
    recordDriverReconciliationFailure: (_driverName, _observedAt, _nextRetryAt) => { order.push('recordDriverReconciliationFailure'); },
    recordDriverReconciliationSuccess: () => { order.push('recordDriverReconciliationSuccess'); },
    flushCurrentSessionsSnapshot: async (currentSessions) => {
      order.push('flushCurrentSessionsSnapshot');
      publicationInputs.push(currentSessions);
      return { type: 'published' };
    },
    recordLocalSnapshotPublicationFailure: () => { order.push('recordLocalSnapshotPublicationFailure'); },
    handleCurrentSessionsSnapshotFailure: async () => {
      order.push('handleCurrentSessionsSnapshotFailure');
      return { online: true, outcome: { type: 'deferred', reason: 'network' } };
    },
    sessionPublicationRecovered: () => { order.push('sessionPublicationRecovered'); },
    sessionPublicationBlocked: (count) => { order.push(`sessionPublicationBlocked:${count}`); },
    eventsMayDrain: (outcome) => {
      order.push(`eventsMayDrain:${outcome.type}`);
      return outcome.type === 'published' || outcome.type === 'unchanged';
    },
    flushPendingEvents: async () => { order.push('flushPendingEvents'); return 3; },
    flushPendingHandles: async () => { order.push('flushPendingHandles'); return 2; },
    pullAndHandleCommands: async () => { order.push('pullAndHandleCommands'); return handledCommands; },
    getHost: () => { order.push('getHost'); return null as HostProjection | null; },
    ...overrides,
  };
  return {
    deps, order, driver, initialSessions,
    currentSessions: () => storeSessions, replaceCalls, publicationInputs, handledCommands,
  };
}

describe('performBridgeSyncOnce linear sync orchestration', () => {
  test('runs the exact §9 serial order, replaces the store, and returns the replaced sessions in the result', async () => {
    const { deps, order, replaceCalls, publicationInputs, currentSessions } = createHarness();
    const result = await performBridgeSyncOnce(deps);
    expect(order).toEqual([
      'assertHostDomainResetStartAllowed',
      'validateStartup',
      'acknowledgeSyncPass',
      'ensureHostPresence',
      'reconcileRecipientsAndDrainReceipts',
      'drivers',
      'listSessions',
      'getDriverNameForSession:s-1',
      'getDriverNameForSession:s-2',
      'driver:listSessions',
      'replaceDriverSessions',
      'recordDriverReconciliationSuccess',
      'listSessions',
      'flushCurrentSessionsSnapshot',
      'sessionPublicationRecovered',
      'eventsMayDrain:published',
      'flushPendingEvents',
      'flushPendingHandles',
      'pullAndHandleCommands',
      'getHost',
    ]);
    // The replacement is durable in the store: exact arguments captured, the
    // next listSessions read returns the replaced snapshot, publication
    // receives it, and BridgeSyncResult.sessions carries it (not the stale
    // initial array).
    expect(replaceCalls).toEqual([{ driverName: 'pi', sessions: [session('s-new')] }]);
    expect(currentSessions()).toEqual([session('s-new')]);
    expect(publicationInputs).toEqual([[session('s-new')]]);
    expect(publicationInputs[0]).toBe(currentSessions());
    expect(result).toEqual({
      host: null,
      sessions: currentSessions(),
      emittedEvents: [],
      flushedEvents: 3,
      flushedReads: 2,
      handledCommands: [],
      offline: false,
    });
    expect(result.sessions).toBe(currentSessions());
  });

  test('reset-guard failure stops through the daemon-owned stop dependency and aborts before any other step', async () => {
    const resetError = new Error('reset blocked');
    const { deps, order } = createHarness({
      assertHostDomainResetStartAllowed: () => { order.push('assertHostDomainResetStartAllowed'); throw resetError; },
    });
    await expect(performBridgeSyncOnce(deps)).rejects.toBe(resetError);
    expect(order).toEqual(['assertHostDomainResetStartAllowed', 'stop']);
  });

  test('Host presence failure marks the pass offline: no receipt drain, publication, handles, or commands', async () => {
    const { deps, order } = createHarness({
      ensureHostPresence: async () => { order.push('ensureHostPresence'); throw new Error('relay unreachable'); },
    });
    const result = await performBridgeSyncOnce(deps);
    expect(order).toEqual([
      'assertHostDomainResetStartAllowed',
      'validateStartup',
      'acknowledgeSyncPass',
      'ensureHostPresence',
      'drivers',
      'listSessions',
      'getDriverNameForSession:s-1',
      'getDriverNameForSession:s-2',
      'driver:listSessions',
      'replaceDriverSessions',
      'recordDriverReconciliationSuccess',
      'listSessions',
      'getHost',
    ]);
    expect(result).toMatchObject({ offline: true, flushedEvents: 0, flushedReads: 0, handledCommands: [], emittedEvents: [] });
  });

  test('driver list failure records failure with observed/next-retry clock evidence and suppresses publication', async () => {
    const failureTimes: Array<{ observedAt: string; nextRetryAt: string }> = [];
    const { deps, order, initialSessions } = createHarness({
      drivers: () => { order.push('drivers'); return [{
        name: 'pi',
        listSessions: async () => { order.push('driver:listSessions'); throw new Error('driver offline'); },
        executeCommand: async () => { throw new Error('unused'); },
      }]; },
      recordDriverReconciliationFailure: (_driverName, observedAt, nextRetryAt) => {
        order.push('recordDriverReconciliationFailure');
        failureTimes.push({ observedAt, nextRetryAt });
      },
    });
    const result = await performBridgeSyncOnce(deps);
    expect(order).toEqual([
      'assertHostDomainResetStartAllowed',
      'validateStartup',
      'acknowledgeSyncPass',
      'ensureHostPresence',
      'reconcileRecipientsAndDrainReceipts',
      'drivers',
      'listSessions',
      'getDriverNameForSession:s-1',
      'getDriverNameForSession:s-2',
      'driver:listSessions',
      'recordDriverReconciliationFailure',
      'listSessions',
      'eventsMayDrain:deferred',
      'flushPendingHandles',
      'pullAndHandleCommands',
      'getHost',
    ]);
    expect(failureTimes).toHaveLength(1);
    expect(failureTimes[0]!.observedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/u);
    expect(Date.parse(failureTimes[0]!.nextRetryAt) - Date.parse(failureTimes[0]!.observedAt)).toBe(15_000);
    // The failed driver retains its last complete persisted set: no replacement
    // happened, so the result carries the unchanged initial store content.
    expect(result).toMatchObject({ offline: false, sessions: initialSessions, flushedEvents: 0, flushedReads: 2, handledCommands: [] });
  });

  test('readiness-check failure records failure without replacing the persisted driver set', async () => {
    const { deps, order, replaceCalls } = createHarness({
      drivers: () => [{
        name: 'pi',
        listSessions: async () => { order.push('driver:listSessions'); return [session('s-new')]; },
        isAuthoritativeSetReady: () => false,
        executeCommand: async () => { throw new Error('unused'); },
      }],
    });
    const result = await performBridgeSyncOnce(deps);
    expect(order).toContain('recordDriverReconciliationFailure');
    expect(order).not.toContain('replaceDriverSessions');
    expect(replaceCalls).toEqual([]);
    expect(order).not.toContain('flushCurrentSessionsSnapshot');
    expect(result).toMatchObject({ offline: false, flushedEvents: 0 });
  });

  test('serial driver reconciliation: driver B never starts until driver A is released', async () => {
    let releaseA!: () => void;
    const gate = new Promise<void>((resolve) => { releaseA = resolve; });
    const driverA: AgentDriver = {
      name: 'alpha',
      listSessions: async () => { order.push('driverA:listSessions'); await gate; return [session('a-new')]; },
      executeCommand: async () => { throw new Error('unused'); },
    };
    let bStarted = false;
    const driverB: AgentDriver = {
      name: 'beta',
      listSessions: async () => { order.push('driverB:listSessions'); bStarted = true; return [session('b-new')]; },
      executeCommand: async () => { throw new Error('unused'); },
    };
    const { deps, order, replaceCalls } = createHarness({
      drivers: () => { order.push('drivers'); return [driverA, driverB]; },
    });
    const running = performBridgeSyncOnce(deps);
    await waitFor(() => order.includes('driverA:listSessions'), 'driver A listSessions to start');
    // A concurrent (Promise.all) driver loop would already have started B while
    // A is still gated; the serial loop must not have.
    expect(bStarted).toBe(false);
    expect(order).not.toContain('driverB:listSessions');
    releaseA!();
    const result = await running;
    expect(order).toEqual([
      'assertHostDomainResetStartAllowed',
      'validateStartup',
      'acknowledgeSyncPass',
      'ensureHostPresence',
      'reconcileRecipientsAndDrainReceipts',
      'drivers',
      'listSessions',
      'getDriverNameForSession:s-1',
      'getDriverNameForSession:s-2',
      'driverA:listSessions',
      'replaceDriverSessions',
      'recordDriverReconciliationSuccess',
      'listSessions',
      'getDriverNameForSession:s-1',
      'getDriverNameForSession:s-2',
      'getDriverNameForSession:a-new',
      'driverB:listSessions',
      'replaceDriverSessions',
      'recordDriverReconciliationSuccess',
      'listSessions',
      'flushCurrentSessionsSnapshot',
      'sessionPublicationRecovered',
      'eventsMayDrain:published',
      'flushPendingEvents',
      'flushPendingHandles',
      'pullAndHandleCommands',
      'getHost',
    ]);
    expect(replaceCalls).toEqual([
      { driverName: 'alpha', sessions: [session('a-new')] },
      { driverName: 'beta', sessions: [session('b-new')] },
    ]);
    expect(result).toMatchObject({
      offline: false,
      sessions: [session('s-1'), session('s-2'), session('a-new'), session('b-new')],
    });
  });

  test('Relay snapshot conflict rethrows the exact fail-closed error and aborts the pass', async () => {
    const conflict = new RelayClientError(409, 'conflict', { code: 'session_snapshot_conflict' });
    const { deps, order } = createHarness({
      flushCurrentSessionsSnapshot: async () => { order.push('flushCurrentSessionsSnapshot'); throw conflict; },
    });
    const error = await performBridgeSyncOnce(deps).then(() => null, (caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe('Relay rejected the persisted E2E lifecycle revision as conflicting');
    expect((error as Error).cause).toBe(conflict);
    expect(order).toEqual([
      'assertHostDomainResetStartAllowed',
      'validateStartup',
      'acknowledgeSyncPass',
      'ensureHostPresence',
      'reconcileRecipientsAndDrainReceipts',
      'drivers',
      'listSessions',
      'getDriverNameForSession:s-1',
      'getDriverNameForSession:s-2',
      'driver:listSessions',
      'replaceDriverSessions',
      'recordDriverReconciliationSuccess',
      'listSessions',
      'flushCurrentSessionsSnapshot',
    ]);
  });

  test('non-Relay local faults fail closed through the daemon-owned recorder without offline or block logs', async () => {
    const local = new Error('local storage fault');
    const localInputs: Array<{ error: unknown; activeSessions: CanonicalSessionState[] }> = [];
    const { deps, order, currentSessions } = createHarness({
      flushCurrentSessionsSnapshot: async () => { order.push('flushCurrentSessionsSnapshot'); throw local; },
      recordLocalSnapshotPublicationFailure: (error, activeSessions) => {
        order.push('recordLocalSnapshotPublicationFailure');
        localInputs.push({ error, activeSessions });
      },
    });
    const result = await performBridgeSyncOnce(deps);
    // The recorder receives the reconciled (replaced) session snapshot, not the
    // stale initial array.
    expect(localInputs).toEqual([{ error: local, activeSessions: currentSessions() }]);
    expect(localInputs[0]!.activeSessions).toBe(currentSessions());
    expect(order).toContain('eventsMayDrain:fail-closed');
    expect(order).not.toContain('sessionPublicationRecovered');
    expect(order).not.toContain('sessionPublicationBlocked');
    expect(order).not.toContain('flushPendingEvents');
    expect(result).toMatchObject({ offline: false, flushedEvents: 0, flushedReads: 2, handledCommands: [] });
  });

  test('Relay publication errors route to the daemon recovery pipeline and adopt its online verdict', async () => {
    const failures: unknown[] = [new RelayClientError(503, 'unavailable'), new RelayTransportError()];
    for (const failure of failures) {
      const { deps, order } = createHarness({
        flushCurrentSessionsSnapshot: async () => { order.push('flushCurrentSessionsSnapshot'); throw failure; },
        handleCurrentSessionsSnapshotFailure: async () => {
          order.push('handleCurrentSessionsSnapshotFailure');
          return { online: false, outcome: { type: 'deferred', reason: 'network' } };
        },
      });
      const result = await performBridgeSyncOnce(deps);
      expect(order).toContain('handleCurrentSessionsSnapshotFailure');
      expect(order).not.toContain('eventsMayDrain');
      expect(order).not.toContain('flushPendingHandles');
      expect(order).not.toContain('pullAndHandleCommands');
      expect(result).toMatchObject({ offline: true, flushedEvents: 0, flushedReads: 0, handledCommands: [] });
    }
  });

  test('Relay recovery that returns online keeps the pass online while Event drain stays stopped', async () => {
    const { deps, order } = createHarness({
      flushCurrentSessionsSnapshot: async () => { order.push('flushCurrentSessionsSnapshot'); throw new RelayClientError(503, 'unavailable'); },
      handleCurrentSessionsSnapshotFailure: async () => {
        order.push('handleCurrentSessionsSnapshotFailure');
        return { online: true, outcome: { type: 'deferred', reason: 'network' } };
      },
    });
    const result = await performBridgeSyncOnce(deps);
    // Only the direct flush return of deferred/network marks the pass offline;
    // a recovery verdict of online:true keeps handles/commands alive while the
    // deferred outcome still gates Event drain off.
    expect(result).toMatchObject({ offline: false, flushedEvents: 0, flushedReads: 2, handledCommands: [] });
    expect(order).toContain('eventsMayDrain:deferred');
    expect(order).toContain('flushPendingHandles');
    expect(order).toContain('pullAndHandleCommands');
    expect(order).not.toContain('flushPendingEvents');
  });

  test('a deferred network publication outcome marks the pass offline and suppresses handles and commands', async () => {
    const { deps, order } = createHarness({
      flushCurrentSessionsSnapshot: async () => { order.push('flushCurrentSessionsSnapshot'); return { type: 'deferred', reason: 'network' }; },
    });
    const result = await performBridgeSyncOnce(deps);
    expect(result).toMatchObject({ offline: true, flushedEvents: 0, flushedReads: 0, handledCommands: [] });
    expect(order).not.toContain('eventsMayDrain');
    expect(order).not.toContain('flushPendingHandles');
    expect(order).not.toContain('pullAndHandleCommands');
  });

  test('a deferred recipient-set outcome stays online and stops only Event drain', async () => {
    const { deps, order } = createHarness({
      flushCurrentSessionsSnapshot: async () => { order.push('flushCurrentSessionsSnapshot'); return { type: 'deferred', reason: 'recipient-set' }; },
    });
    const result = await performBridgeSyncOnce(deps);
    // recipient-set deferral is not evidence of offline: handles and commands
    // stay alive, only the Event drain is gated off by the daemon verdict.
    expect(result).toMatchObject({ offline: false, flushedEvents: 0, flushedReads: 2, handledCommands: [] });
    expect(order).toContain('eventsMayDrain:deferred');
    expect(order).toContain('flushPendingHandles');
    expect(order).toContain('pullAndHandleCommands');
    expect(order).not.toContain('flushPendingEvents');
    expect(order).not.toContain('sessionPublicationRecovered');
    expect(order).not.toContain('sessionPublicationBlocked');
  });

  test('locally-blocked publication logs the blocked count and gates Event drain on the daemon verdict', async () => {
    const blocked: SessionPublicationOutcome = {
      type: 'locally-blocked', reason: 'content', blockedSessionCount: 2, recipientSetVersion: 1,
    };
    const { deps, order } = createHarness({
      flushCurrentSessionsSnapshot: async () => { order.push('flushCurrentSessionsSnapshot'); return blocked; },
      eventsMayDrain: (outcome) => { order.push(`eventsMayDrain:${outcome.type}`); return false; },
    });
    const result = await performBridgeSyncOnce(deps);
    expect(order).toContain('sessionPublicationBlocked:2');
    expect(order).toContain('eventsMayDrain:locally-blocked');
    expect(order).not.toContain('sessionPublicationRecovered');
    expect(order).not.toContain('flushPendingEvents');
    expect(result).toMatchObject({ offline: false, flushedEvents: 0, flushedReads: 2, handledCommands: [] });
  });

  test('locally-blocked with an accepted recipient-set version allows Event drain through the daemon verdict', async () => {
    const blocked: SessionPublicationOutcome = {
      type: 'locally-blocked', reason: 'content', blockedSessionCount: 1, recipientSetVersion: 7,
    };
    let drainVerdict: SessionPublicationOutcome | undefined;
    const { deps, order } = createHarness({
      flushCurrentSessionsSnapshot: async () => { order.push('flushCurrentSessionsSnapshot'); return blocked; },
      eventsMayDrain: (outcome) => {
        order.push(`eventsMayDrain:${outcome.type}`);
        drainVerdict = outcome;
        return true;
      },
    });
    const result = await performBridgeSyncOnce(deps);
    // The §6.2 condition (accepted recipient-set version matches) is the
    // daemon-owned verdict; when it allows the drain, locally-blocked still
    // drains Events while logging the block.
    expect(drainVerdict).toEqual(blocked);
    expect(order).toContain('sessionPublicationBlocked:1');
    expect(order).toContain('flushPendingEvents');
    expect(result).toMatchObject({ offline: false, flushedEvents: 3, flushedReads: 2, handledCommands: [] });
  });

  test('an unchanged publication outcome also emits the recovery log and drains normally', async () => {
    const { deps, order } = createHarness({
      flushCurrentSessionsSnapshot: async () => { order.push('flushCurrentSessionsSnapshot'); return { type: 'unchanged' }; },
    });
    const result = await performBridgeSyncOnce(deps);
    expect(order).toContain('sessionPublicationRecovered');
    expect(result).toMatchObject({ offline: false, flushedEvents: 3, flushedReads: 2, handledCommands: [] });
  });
});
