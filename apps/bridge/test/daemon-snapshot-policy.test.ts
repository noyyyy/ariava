import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeDaemon, loadBridgeConfig, type ReconciliationScheduler } from '../src/daemon';
import { RelayClientError } from '../src/relay-client';
import {
  SNAPSHOT_FAILURE_ESCALATION_THRESHOLD,
  SNAPSHOT_FAILURE_LOG_NO_REVISION_ID_CAP,
  SNAPSHOT_FAILURE_LOG_THROTTLE_MS,
  createInitialSnapshotFailureState,
  decideSnapshotFailure,
  decideSnapshotFailureLog,
  resetSnapshotFailures,
  summarizeSnapshotFailures,
  type SnapshotFailureEvent,
  type SnapshotFailureState,
} from '../src/daemon/snapshot-policy';

/**
 * Focused tests for the snapshot failure policy extracted in Task 4 (plan
 * `2026-08-16-bridge-daemon-lifecycle-decomposition.md`, spec §7) plus
 * daemon-level wiring. The pure half proves the reducer stays free of clocks,
 * loggers, store reads, and summary evidence; the wiring half pins the
 * imperatives: policy decision/state assignment before summary inspection,
 * summary collection only when `shouldLog`, action-driven offline results, and
 * local faults staying outside the Relay escalation reducer.
 */

const T0 = 2_000_000_000; // offset far past 0 so the initial throttle gate is open

function relayPublication(now: number): SnapshotFailureEvent {
  return { type: 'publication-failure', now };
}

function recoveryFailure(now: number): SnapshotFailureEvent {
  return { type: 'recovery-failure', now };
}

describe('snapshot failure policy constants freeze the baseline', () => {
  test('threshold 2, 30-second throttle, and the 10-Session summary cap', () => {
    expect(SNAPSHOT_FAILURE_ESCALATION_THRESHOLD).toBe(2);
    expect(SNAPSHOT_FAILURE_LOG_THROTTLE_MS).toBe(30_000);
    expect(SNAPSHOT_FAILURE_LOG_NO_REVISION_ID_CAP).toBe(10);
  });

  test('initial state is a zero count and an open throttle window', () => {
    expect(createInitialSnapshotFailureState()).toEqual({ count: 0, lastLogAt: 0 });
  });
});

describe('Relay escalation reducer (threshold 2, recovery escalation, offline retry)', () => {
  test('first Relay failure retries offline; second escalates to pipeline recovery', () => {
    const first = decideSnapshotFailure(createInitialSnapshotFailureState(), relayPublication(T0));
    expect(first).toEqual({ next: { count: 1, lastLogAt: T0 }, action: 'retry', shouldLog: true });

    const second = decideSnapshotFailure(first.next, relayPublication(T0 + 1_000));
    expect(second.action).toBe('recover-pipeline');
    expect(second.next).toEqual({ count: 2, lastLogAt: T0 });
  });

  test('repeat failures keep escalating after the threshold', () => {
    let state = createInitialSnapshotFailureState();
    for (let index = 1; index <= 5; index += 1) {
      const decision = decideSnapshotFailure(state, relayPublication(T0 + index * 1_000));
      state = decision.next;
      expect(state.count).toBe(index);
      expect(decision.action).toBe(index < SNAPSHOT_FAILURE_ESCALATION_THRESHOLD ? 'retry' : 'recover-pipeline');
    }
  });
});

describe('log throttling (30s publish window, recovery always logs)', () => {
  test('30-second publish throttle suppresses repeat logs but keeps escalation', () => {
    const first = decideSnapshotFailure(createInitialSnapshotFailureState(), relayPublication(T0));
    expect(first.shouldLog).toBe(true);
    expect(first.next.lastLogAt).toBe(T0);

    const repeat = decideSnapshotFailure(first.next, relayPublication(T0 + 5_000));
    expect(repeat.shouldLog).toBe(false);
    expect(repeat.action).toBe('recover-pipeline');
    expect(repeat.next.lastLogAt).toBe(T0);

    const afterWindow = decideSnapshotFailure(repeat.next, relayPublication(T0 + 30_000));
    expect(afterWindow.shouldLog).toBe(true);
    expect(afterWindow.next.lastLogAt).toBe(T0 + 30_000);
  });

  test('recovery failures always log and advance the throttle gate', () => {
    const state: SnapshotFailureState = { count: 2, lastLogAt: T0 };
    const decision = decideSnapshotFailure(state, recoveryFailure(T0 + 1_000));
    expect(decision.shouldLog).toBe(true);
    expect(decision.next.lastLogAt).toBe(T0 + 1_000);
  });

  test('the reducer never carries summary evidence: decision shape is exactly spec §7', () => {
    const decision = decideSnapshotFailure(createInitialSnapshotFailureState(), relayPublication(T0));
    expect(Object.keys(decision).sort()).toEqual(['action', 'next', 'shouldLog']);
  });
});

describe('recovery-pipeline failure marks the pass offline without touching the count', () => {
  test('mark-offline result preserves the count and defers the pass', () => {
    const state: SnapshotFailureState = { count: 2, lastLogAt: T0 };
    const decision = decideSnapshotFailure(state, recoveryFailure(T0 + 2_000));
    expect(decision.action).toBe('mark-offline');
    expect(decision.next).toEqual({ count: 2, lastLogAt: T0 + 2_000 });
    expect(decision.shouldLog).toBe(true);
  });
});

describe('success reset clears only the failure count', () => {
  test('reset preserves the throttle window and is itself pure', () => {
    const state: SnapshotFailureState = { count: 2, lastLogAt: T0 };
    const next = resetSnapshotFailures(state);
    expect(state).toEqual({ count: 2, lastLogAt: T0 });
    expect(next).toEqual({ count: 0, lastLogAt: T0 });
  });
});

describe('active-session summary aggregation stays a separate pure summarizer', () => {
  test('caps no-revision Session ids at 10 while reporting the full count', () => {
    const ids = Array.from({ length: 15 }, (_, index) => `session-${index + 1}`);
    const summary = summarizeSnapshotFailures({ activeSessionCount: 16, sessionsWithoutRevision: ids });
    expect(summary).toEqual({
      activeSessionCount: 16,
      noRevisionSessionCount: 15,
      noRevisionSessionIds: ids.slice(0, SNAPSHOT_FAILURE_LOG_NO_REVISION_ID_CAP),
    });
  });

  test('the summary is not attached to escalation decisions (pure separation of concerns)', () => {
    const ids = ['a', 'b'];
    const decision = decideSnapshotFailure(createInitialSnapshotFailureState(), relayPublication(T0));
    expect(decision).not.toHaveProperty('summary');
    expect(summarizeSnapshotFailures({ activeSessionCount: ids.length, sessionsWithoutRevision: ids }))
      .toEqual({ activeSessionCount: 2, noRevisionSessionCount: 2, noRevisionSessionIds: ['a', 'b'] });
  });
});

describe('non-Relay local failures stay outside the escalation reducer', () => {
  test('decideSnapshotFailureLog never touches the count and has no action surface', () => {
    let state: SnapshotFailureState = { count: 2, lastLogAt: T0 };
    for (let index = 0; index < 10; index += 1) {
      const logDecision = decideSnapshotFailureLog(state, T0 + index * 60_000, 'publish');
      expect(logDecision).not.toHaveProperty('action');
      state = logDecision.next;
      expect(state.count).toBe(2);
    }
  });

  test('the local log-throttle follows the same 30s publish window and recovery always logs', () => {
    const first = decideSnapshotFailureLog(createInitialSnapshotFailureState(), T0, 'publish');
    expect(first.shouldLog).toBe(true);
    expect(first.next.lastLogAt).toBe(T0);

    const repeat = decideSnapshotFailureLog(first.next, T0 + 5_000, 'publish');
    expect(repeat.shouldLog).toBe(false);
    expect(repeat.next.lastLogAt).toBe(T0);

    const afterWindow = decideSnapshotFailureLog(repeat.next, T0 + 30_000, 'publish');
    expect(afterWindow.shouldLog).toBe(true);

    expect(decideSnapshotFailureLog(afterWindow.next, T0 + 30_001, 'recovery').shouldLog).toBe(true);
  });

  test('local and Relay logs share one throttle gate without local ever escalating', () => {
    // A logged local fault at T0 throttles a Relay failure inside the window...
    const localLog = decideSnapshotFailureLog(createInitialSnapshotFailureState(), T0, 'publish');
    expect(localLog.shouldLog).toBe(true);
    const relay = decideSnapshotFailure(localLog.next, relayPublication(T0 + 5_000));
    expect(relay.shouldLog).toBe(false);
    expect(relay.next.count).toBe(1); // ...while still incrementing the Relay count.
  });
});

// --- daemon-level wiring coverage ---

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

class RecordingScheduler implements ReconciliationScheduler {
  readonly scheduled: Array<{ callback: () => void; delayMs: number; canceled: boolean }> = [];
  readonly events: string[];
  constructor(events: string[]) { this.events = events; }
  schedule(callback: () => void, delayMs: number): unknown {
    this.events.push('schedule');
    const handle = { callback, delayMs, canceled: false };
    this.scheduled.push(handle);
    return handle;
  }
  cancel(handle: unknown): void {
    (handle as { canceled: boolean }).canceled = true;
  }
}

function harness(flush: () => Promise<unknown>) {
  const root = join(tmpdir(), `snapshot-policy-daemon-${Math.random().toString(36).slice(2)}-${roots.length}`);
  roots.push(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const config = loadBridgeConfig();
  Object.assign(config, {
    hostId: 'host-policy', hostPlatform: 'linux', runtimePlatform: 'linux', pollIntervalMs: 15_000,
    statePath: join(root, 'state.json'), configPath: join(root, 'config.json'), identityPath: join(root, 'identity.json'),
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  const events: string[] = [];
  const scheduler = new RecordingScheduler(events);
  const daemon = new BridgeDaemon(config, [] as never, undefined, undefined, scheduler);
  (daemon as any).stateStore.initializeEncryptedSpool(
    config.hostId, config.identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) },
  );
  (daemon as any).startupValidated = true;
  (daemon as any).registerHostPresence = async () => {};
  (daemon as any).flushCurrentSessionsSnapshot = flush;
  (daemon as any).flushPendingEvents = async () => 0;
  (daemon as any).flushPendingHandles = async () => 0;
  (daemon as any).pullAndHandleCommands = async () => [];
  return { daemon, scheduler, events, config };
}

describe('daemon wiring: Relay escalation executes from the returned action', () => {
  test('second Relay failure runs pipeline recovery, resets the count, and recovers online', async () => {
    let calls = 0;
    const { daemon, events } = harness(async () => {
      calls += 1;
      if (calls <= 2) throw new RelayClientError(503, 'offline');
      return { type: 'published' };
    });
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((line: unknown) => { events.push(`log:${String(line)}`); return true; }) as typeof process.stderr.write;
    try {
      const first = await daemon.syncOnce();
      expect(first.offline).toBe(true);
      expect((daemon as any).snapshotFailureState.count).toBe(1);
      expect(events.filter((event) => event === 'schedule')).toHaveLength(1);

      const second = await daemon.syncOnce();
      expect(second.offline).toBe(false);
      expect(second.flushedEvents).toBe(0);
      expect((daemon as any).snapshotFailureState.count).toBe(0); // success reset after recovery
      expect(calls).toBe(3); // failing publication, escalating publication, recovery flush
      expect(events.some((event) => event.startsWith('log:') && event.includes('Ariava recovered current-session snapshot publication after 2 failure(s)')))
        .toBe(true);
    } finally {
      process.stderr.write = originalWrite;
      daemon.stop();
    }
  });

  test('recovery-pipeline failure executes mark-offline: offline deferred result and recovery log', async () => {
    const { daemon, events } = harness(async () => { throw new RelayClientError(503, 'offline'); });
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((line: unknown) => { events.push(`log:${String(line)}`); return true; }) as typeof process.stderr.write;
    try {
      const first = await daemon.syncOnce();
      expect(first.offline).toBe(true);
      const second = await daemon.syncOnce();
      expect(second.offline).toBe(true);
      expect(second.handledCommands).toEqual([]);
      expect((daemon as any).snapshotFailureState.count).toBe(2); // mark-offline keeps the count
      const publishLogs = events.filter((event) => event.includes('"phase":"publish"'));
      const recoveryLogs = events.filter((event) => event.includes('"phase":"recovery"'));
      expect(publishLogs).toHaveLength(1); // second failure is throttled
      expect(recoveryLogs).toHaveLength(1); // recovery failure always logs
      const recoveryLine = recoveryLogs[0]!.slice(4);
      expect(JSON.parse(recoveryLine.slice(recoveryLine.indexOf('{')))).toMatchObject({ phase: 'recovery', failures: 2, relayStatus: 503 });
      // Explicit exact outcome: the handler result feeding BridgeSyncResult via
      // `offline = !recovery.online` is `{ online: false, outcome: deferred-network }`.
      const handlerOutcome = await (daemon as any).handleCurrentSessionsSnapshotFailure(new RelayClientError(503, 'offline'), []);
      expect(handlerOutcome).toEqual({ online: false, outcome: { type: 'deferred', reason: 'network' } });
    } finally {
      process.stderr.write = originalWrite;
      daemon.stop();
    }
  });

  test('summary log precedes scheduling and the throttled second failure adds no summary/log', async () => {
    let calls = 0;
    const { daemon, events } = harness(async () => {
      calls += 1;
      if (calls <= 2) throw new RelayClientError(503, 'offline');
      return { type: 'published' };
    });
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((line: unknown) => { events.push(`log:${String(line)}`); return true; }) as typeof process.stderr.write;
    try {
      await daemon.syncOnce(); // first failure: one publish-phase summary log, then schedule
      const afterFirst = [...events];
      expect(afterFirst[0]?.startsWith('log:')).toBe(true);
      expect(afterFirst[0]?.includes('"phase":"publish"')).toBe(true);
      expect(afterFirst[1]).toBe('schedule');
      expect(afterFirst.filter((event) => event === 'schedule')).toHaveLength(1);

      await daemon.syncOnce(); // second failure in-window: no new schedule, no summary log
      const afterSecond = events.filter((event) => event.startsWith('log:'));
      expect(events.filter((event) => event === 'schedule')).toHaveLength(1);
      expect(afterSecond.filter((event) => event.includes('"phase":"publish"'))).toHaveLength(1);
      expect(afterSecond.filter((event) => event.includes('Ariava recovered'))).toHaveLength(1);
      expect((daemon as any).snapshotFailureState.count).toBe(0); // still escalated and recovered
    } finally {
      process.stderr.write = originalWrite;
      daemon.stop();
    }
  });

  test('local faults stay outside the escalation reducer and fail closed without touching the count', async () => {
    let calls = 0;
    const { daemon } = harness(async () => {
      calls += 1;
      if (calls === 1) throw new RelayClientError(503, 'offline');
      throw new TypeError('local spool fault');
    });
    try {
      const relayFailure = await daemon.syncOnce();
      expect(relayFailure.offline).toBe(true);
      expect((daemon as any).snapshotFailureState.count).toBe(1);

      const localFailure = await daemon.syncOnce();
      expect(localFailure.offline).toBe(false);   // fail-closed, not an offline claim
      expect(localFailure.handledCommands).toEqual([]);
      expect((daemon as any).snapshotFailureState.count).toBe(1); // never entered the reducer
    } finally {
      daemon.stop();
    }
  });
});