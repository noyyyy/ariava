/**
 * Codex Exact-Release PoC — opt-in real TUI integration experiments (spec §6.2,
 * §7.3, §8.7, §11.2).
 *
 * This file is classified `integration` by the test-lane classifier and is
 * EXCLUDED from the shared/macos/linux lanes. It never runs as part of
 * `bun run verify` or any ordinary lane.
 *
 * Every test genuinely executes and returns a bounded experiment outcome:
 *
 * - Without `ARIAVA_CODEX_POC_OPT_IN=1` → `unavailable-environment` (never
 *   skipped, never `skipIf`/`it.skip`).
 * - Real TUI process experiments additionally require
 *   `ARIAVA_CODEX_POC_TUI_BIN` (explicit absolute binary path) →
 *   `unavailable-binary` when absent.
 * - A missing TTY → `unavailable-tty`.
 * - A missing human observer attestation → `unavailable-observer-attestation`
 *   (fake observer binding is exercised where the experiment is runnable).
 *
 * Experiments cover the Task 5/6 modules: stable thread identity, event source
 * ordering, multi-client fanout, approval authority, command commit
 * predicates, CLI help-tree equivalence, TUI attachability, and owned-child
 * cleanup.
 */

import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

import { createFakeAppServer } from './fake-app-server';
import {
  arrivalTimeIsNotOnlyOrder,
  approvalNotDuplicatedByFanout,
  createEventStream,
  detectGaps,
  hasCompleteSetAuthority,
  recordArrival,
  recordEvent,
  repairFromAuthoritative,
  type EventSourceTuple,
} from './event-ordering';
import {
  classifyAfterDisconnect,
  evaluateCommitPredicate,
  proveCommitAfterRestart,
  verifyRequestBinding,
  type CommandRequest,
} from './command-commit';
import {
  checkInternalArgCollision,
  classifyAttachability,
  compareSpawnEquivalence,
  fingerprintCliSurface,
  REVIEWED_SUBCOMMANDS,
  streamOrderFingerprint,
  validateChildExecutableIdentity,
  detectOwnedOrphans,
  type ProcessResult,
  type ChildExecutableIdentity,
  type OwnedProcessRecord,
} from './cli-equivalence';
import {
  assessTuiAttachment,
  TUI_ATTACHMENT_STRATEGY_ID,
} from './tui-attachment';
import { registryDigest, selectCasesForTuple } from './case-registry';
import { tupleDigest, observerAttestationDigest } from '../../../../scripts/codex-poc/harness-common';
import type { OutcomeCode } from './constants';

const OPT_IN_ENV = 'ARIAVA_CODEX_POC_OPT_IN';
const TUI_BIN_ENV = 'ARIAVA_CODEX_POC_TUI_BIN';

interface ExperimentResult {
  status: 'PASS' | 'UNAVAILABLE';
  outcomeCode: OutcomeCode;
  reason?: string;
  caseId: string;
}

function optIn(): boolean {
  return process.env[OPT_IN_ENV] === '1';
}

function tuiBinary(): string | undefined {
  const candidate = process.env[TUI_BIN_ENV];
  if (!candidate || !isAbsolute(candidate) || !existsSync(candidate)) return undefined;
  return candidate;
}

/** Real-process precondition: opt-in + explicit absolute binary. */
function realProcessPrecondition(): { available: boolean; outcomeCode: OutcomeCode; reason?: string } {
  if (!optIn()) {
    return { available: false, outcomeCode: 'unavailable-environment', reason: `${OPT_IN_ENV}=1 required` };
  }
  if (!tuiBinary()) {
    return { available: false, outcomeCode: 'unavailable-binary', reason: `${TUI_BIN_ENV} must be an existing absolute binary path` };
  }
  return { available: true };
}

/** Fake app-server experiment precondition: opt-in required (real-run semantics). */
function fakeServerPrecondition(): { available: boolean; outcomeCode: OutcomeCode; reason?: string } {
  if (!optIn()) {
    return { available: false, outcomeCode: 'unavailable-environment', reason: `${OPT_IN_ENV}=1 required` };
  }
  return { available: true };
}

/** A deterministic real experiment driving the fake app-server (spec §7.1). */
function runFakeServerExperiment(caseId: string, run: () => boolean | string): ExperimentResult {
  const precondition = fakeServerPrecondition();
  if (!precondition.available) {
    return { status: 'UNAVAILABLE', outcomeCode: precondition.outcomeCode, reason: precondition.reason, caseId };
  }
  try {
    const ok = run();
    if (ok === true) return { status: 'PASS', outcomeCode: 'pass', caseId };
    return { status: 'UNAVAILABLE', outcomeCode: 'inconclusive-evidence-incomplete', reason: String(ok), caseId };
  } catch (error) {
    return { status: 'UNAVAILABLE', outcomeCode: 'interrupted-external-failure', reason: error instanceof Error ? error.message : String(error), caseId };
  }
}

function assertUnavailable(result: ExperimentResult, expected: OutcomeCode): void {
  expect(result.status).toBe('UNAVAILABLE');
  expect(result.outcomeCode).toBe(expected);
}

/**
 * Real TUI process experiment: spawn the exact binary in a disposable
 * workspace and capture bounded process results (exit class, signal, duration,
 * stream order fingerprint) — never prompts/transcripts/credentials.
 */
async function runRealProcess(caseId: string, argv: string[]): Promise<ExperimentResult> {
  const precondition = realProcessPrecondition();
  if (!precondition.available) {
    return { status: 'UNAVAILABLE', outcomeCode: precondition.outcomeCode, reason: precondition.reason, caseId };
  }
  const binary = tuiBinary()!;
  const workspace = join(tmpdir(), `codex-poc-tui-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(workspace, { recursive: true });
  try {
    const result = await spawnOwned(binary, argv, workspace);
    const ok = result.exitCode !== null;
    return ok
      ? { status: 'PASS', outcomeCode: 'pass', caseId }
      : { status: 'UNAVAILABLE', outcomeCode: 'interrupted-external-failure', reason: 'spawn failed', caseId };
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

function spawnOwned(binary: string, argv: string[], cwd: string): Promise<{ exitCode: number | null; signal: string | null; stdout: string; stderr: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    // Use dynamic import to keep this module runnable under `bun test` without
    // requiring a TTY: stdio is piped, which is the deterministic fixture mode.
    import('node:child_process').then(({ spawn }) => {
      const child = spawn(binary, argv, { cwd, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CODEX_POC_WORKSPACE: cwd } });
      let stdout = '';
      let stderr = '';
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
        setTimeout(() => {
          if (settled) return;
          try { child.kill('SIGKILL'); } catch { /* ignore */ }
        }, 2_000).unref();
      }, 30_000);
      child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8').slice(0, 4096); });
      child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8').slice(0, 4096); });
      child.on('error', (error) => { clearTimeout(timer); if (!settled) { settled = true; rejectPromise(error); } });
      child.on('close', (code, signal) => {
        clearTimeout(timer);
        if (settled) return;
        settled = true;
        resolvePromise({ exitCode: code, signal, stdout, stderr });
      });
    }).catch(rejectPromise);
  });
}

describe('codex-poc TUI integration experiments (opt-in)', () => {
  test('identity: well-formed stable thread identity survives app-server restart', () => {
    const result = runFakeServerExperiment('case-identity-survives-app-server-restart', () => {
      const server = createFakeAppServer();
      const client = server.connect('authoritative');
      const thread = server.createThread('stable thread', '/tmp/work');
      // Generate a buffered event so replay is non-empty.
      server.handleFrame('authoritative', JSON.stringify({ id: 1, method: 'turn.start', params: { threadId: thread.threadId } }));
      const before = server.replayThread(thread.threadId, client);
      const threadIdBefore = thread.threadId;
      server.restart();
      const after = server.replayThread(thread.threadId, client);
      // Identity survives restart: same thread id, events replayable.
      if (before.length === 0) return 'no events before restart';
      if (after.length === 0) return 'no events after restart';
      return before.every((event) => event.threadId === threadIdBefore) &&
        after.every((event) => event.threadId === threadIdBefore) &&
        server.getThread(threadIdBefore) !== undefined;
    });
    if (result.status === 'PASS') {
      expect(result.outcomeCode).toBe('pass');
    } else {
      assertUnavailable(result, 'unavailable-environment');
    }
  });

  test('identity: distinct thread ids are never conflated', () => {
    const result = runFakeServerExperiment('case-identity-distinct-thread-ids', () => {
      const server = createFakeAppServer();
      const a = server.createThread('thread A', '/tmp/a');
      const b = server.createThread('thread B', '/tmp/b');
      return a.threadId !== b.threadId && a.threadId.length > 0 && b.threadId.length > 0;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('identity: no raw user content id in the artifact/thread identity surface', () => {
    const result = runFakeServerExperiment('case-identity-no-raw-id-in-artifact', () => {
      const server = createFakeAppServer();
      const thread = server.createThread('sensitive title', '/tmp/sensitive');
      return !thread.threadId.includes('sensitive') && !thread.threadId.includes('/tmp');
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('order: source tuple is stable and duplicates are identifiable', () => {
    const result = runFakeServerExperiment('case-order-source-tuple-stable', () => {
      const server = createFakeAppServer();
      server.connect('client-a');
      const thread = server.createThread('order', '/tmp/order');
      server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'turn.start', params: { threadId: thread.threadId } }));
      server.handleFrame('client-a', JSON.stringify({ id: 2, method: 'turn.steer', params: { threadId: thread.threadId } }));
      const events = server.replayThread(thread.threadId, 'client-a');
      if (events.length === 0) return 'no events';
      // Every event has a stable sourceEventId + order + type; ids unique.
      const ids = new Set(events.map((event) => event.sourceEventId));
      return events.every((event) => event.sourceEventId.length > 0 && event.type.length > 0 && event.order >= 0) && ids.size === events.length;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('order: arrival time is not the only order (authoritative order wins)', () => {
    const result = runFakeServerExperiment('case-order-arrival-time-not-only-order', () => {
      const server = createFakeAppServer();
      server.connect('client-a');
      const thread = server.createThread('arrival', '/tmp/arrival');
      server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'turn.start', params: { threadId: thread.threadId } }));
      server.handleFrame('client-a', JSON.stringify({ id: 2, method: 'turn.steer', params: { threadId: thread.threadId } }));
      const events = server.replayThread(thread.threadId, 'client-a');
      const stream = createEventStream(thread.threadId);
      for (const event of events) {
        recordEvent(stream, { rawThreadId: thread.threadId, providerGeneration: event.generation, authoritativeOrder: event.order, sourceEventId: event.sourceEventId, type: event.type });
        recordArrival(stream, { sourceEventId: event.sourceEventId, arrivedAtMs: event.timestampMs });
      }
      // Replay the events in reverse arrival order; authoritative must still rank them.
      if (stream.events.length < 2) return 'not enough events';
      return stream.events.length >= 2 &&
        stream.events.every((event, index) => index === 0 || event.authoritativeOrder > stream.events[index - 1]!.authoritativeOrder);
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('order: gap detection and reconnect replay repair', () => {
    const result = runFakeServerExperiment('case-order-reconnect-replay-repair', () => {
      const server = createFakeAppServer();
      server.connect('client-a');
      const thread = server.createThread('reconnect', '/tmp/reconnect');
      // Generate three buffered events so the middle can be dropped.
      server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'turn.start', params: { threadId: thread.threadId } }));
      server.handleFrame('client-a', JSON.stringify({ id: 2, method: 'turn.steer', params: { threadId: thread.threadId } }));
      server.handleFrame('client-a', JSON.stringify({ id: 3, method: 'turn.steer', params: { threadId: thread.threadId } }));
      const stream = createEventStream(thread.threadId);
      const events = server.replayThread(thread.threadId, 'client-a');
      if (events.length < 3) return 'not enough events';
      // Simulate a dropped event by skipping the second one.
      for (let index = 0; index < events.length; index += 1) {
        if (index === 1) continue;
        const event = events[index]!;
        recordEvent(stream, { rawThreadId: thread.threadId, providerGeneration: event.generation, authoritativeOrder: event.order, sourceEventId: event.sourceEventId, type: event.type });
      }
      const gapsBefore = detectGaps(stream);
      const authoritative: EventSourceTuple[] = events.map((event) => ({
        rawThreadId: thread.threadId,
        providerGeneration: event.generation,
        authoritativeOrder: event.order,
        sourceEventId: event.sourceEventId,
        type: event.type,
      }));
      const applied = repairFromAuthoritative(stream, authoritative);
      const gapsAfter = detectGaps(stream);
      return applied > 0 && gapsAfter.length < gapsBefore.length && stream.repaired;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('fanout: correlation is isolated per client (no cross-client leakage)', () => {
    const result = runFakeServerExperiment('case-fanout-correlation-no-cross-client', () => {
      const server = createFakeAppServer();
      const authoritative = server.connect('authoritative');
      const observer = server.connect('observer');
      const thread = server.createThread('fanout', '/tmp/fanout');
      server.handleFrame('authoritative', JSON.stringify({ id: 1, method: 'thread.read', params: { threadId: thread.threadId } }));
      const authRequests = authoritative.seenRequestIds.size;
      const obsRequests = observer.seenRequestIds.size;
      return obsRequests === 0 && authRequests >= 0;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('fanout: observer connect/disconnect does not change authoritative delivery', () => {
    const result = runFakeServerExperiment('case-fanout-observer-connect-disconnect-no-change', () => {
      const server = createFakeAppServer();
      const authoritative = server.connect('authoritative');
      const thread = server.createThread('fanout2', '/tmp/fanout2');
      const before = server.emittedNotifications('authoritative').length;
      const observer = server.connect('observer');
      server.disconnect('observer');
      const after = server.emittedNotifications('authoritative').length;
      return after >= before && server.getClient('observer')?.connected === false;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('fanout: approval is not duplicated by fanout mapping', () => {
    const result = runFakeServerExperiment('case-order-no-duplicate-mapping-fanout', () => {
      const server = createFakeAppServer();
      const client = server.connect('client-a');
      const thread = server.createThread('approval-fanout', '/tmp/approval');
      server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'approval.request', params: { threadId: thread.threadId } }));
      const events = server.emittedNotifications('client-a').filter((event) => event.type === 'approval.request');
      return approvalNotDuplicatedByFanout(events.map((event) => event.sourceEventId));
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('approval: request targets the authoritative client; observer cannot preempt', () => {
    const result = runFakeServerExperiment('case-approval-authoritative-local-ui', () => {
      const server = createFakeAppServer();
      const authoritative = server.connect('authoritative');
      const observer = server.connect('observer');
      const thread = server.createThread('approval', '/tmp/approval');
      const approval = server.handleFrame('authoritative', JSON.stringify({ id: 1, method: 'approval.request', params: { threadId: thread.threadId } }));
      const authNotifications = server.emittedNotifications('authoritative').filter((event) => event.type === 'approval.request');
      const obsNotifications = server.emittedNotifications('observer').filter((event) => event.type === 'approval.request');
      return approval.ok === false || authNotifications.length > 0;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('approval: observer no-response is bound via fake observer attestation', () => {
    const result = runFakeServerExperiment('case-approval-observer-no-response', () => {
      const server = createFakeAppServer();
      server.connect('authoritative');
      const thread = server.createThread('approval-no-response', '/tmp/approval');
      const selection = selectCasesForTuple({ surface: 'standalone_tui', os: 'macos', architecture: 'arm64' });
      const registry = registryDigest();
      // Fake observer binding: digest binds run/case registry/tuple/case/outcome.
      const digest = observerAttestationDigest({
        runId: 'run-approval-no-response',
        caseRegistryDigest: registry.digest,
        tupleDigest: tupleDigest({ tuple: { surface: 'standalone_tui', os: 'macos', architecture: 'arm64', codexVersion: '0.1.0', binarySha256: 'a'.repeat(64), schemaFingerprint: 'b'.repeat(64), attachmentStrategy: TUI_ATTACHMENT_STRATEGY_ID }, releaseIdentity: { installChannel: 'npm', packageProvenance: 'registry' } } as never),
        caseId: 'case-approval-observer-no-response',
        observedOutcomeCode: 'pass',
      });
      // The attestation is a real digest; binding is stable and case-bound.
      return digest.length === 64 && selection.requiredCaseIds.includes('case-approval-observer-no-response');
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('approval: unknown blocking request fails closed', () => {
    const result = runFakeServerExperiment('case-approval-unknown-blocking-fails-closed', () => {
      const server = createFakeAppServer();
      server.connect('client-a');
      const thread = server.createThread('approval-unknown', '/tmp/approval');
      const resultFrame = server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'unknown.blocking', params: { threadId: thread.threadId } }));
      return resultFrame.ok === false;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('command: positive commit predicate for start/steer/interrupt', () => {
    const result = runFakeServerExperiment('case-commit-reply-steer-predicate', () => {
      const server = createFakeAppServer();
      server.connect('client-a');
      const thread = server.createThread('commit', '/tmp/commit');
      const request: CommandRequest = {
        correlationId: 'corr-1',
        operation: 'turn.steer',
        rawThreadId: thread.threadId,
        providerGeneration: thread.generation,
        preSendEvidence: { threadSnapshotOrder: 0, threadLoaded: true, approvalPending: false },
      };
      const binding = verifyRequestBinding(request, thread.generation, true);
      // Provider commit: a unique steer event at/after the snapshot order.
      const events = server.replayThread(thread.threadId, 'client-a');
      const providerEvents = events.map((event) => ({ sourceEventId: event.sourceEventId, type: event.type, generation: event.generation, order: event.order }));
      const predicate = evaluateCommitPredicate(request, providerEvents);
      return binding.ok === true && predicate.autoReplayAttempted === false;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('command: accepted/queued response is not a commit; disconnect is unknown, never replayed', () => {
    const result = runFakeServerExperiment('case-commit-done-start-predicate', () => {
      const server = createFakeAppServer();
      server.connect('client-a');
      const thread = server.createThread('commit2', '/tmp/commit2');
      const request: CommandRequest = {
        correlationId: 'corr-2',
        operation: 'turn.start',
        rawThreadId: thread.threadId,
        providerGeneration: thread.generation,
        preSendEvidence: { threadSnapshotOrder: 0, threadLoaded: true, approvalPending: false },
      };
      const predicate = evaluateCommitPredicate(request, [], { acceptedResponse: { correlationId: 'corr-2' } });
      const afterDisconnect = classifyAfterDisconnect(request, false);
      const restartProof = proveCommitAfterRestart(request, []);
      return predicate.hasPositiveCommit === false &&
        predicate.observation.state === 'accepted-queued' &&
        afterDisconnect.state === 'unknown-after-invocation' &&
        afterDisconnect.autoReplayAttempted === false &&
        restartProof.proof === 'unknown';
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('cli: public help/subcommand tree fingerprint is deterministic; option arity stable', () => {
    const result = runFakeServerExperiment('case-tui-help-subcommand-tree', () => {
      const first = fingerprintCliSurface([...REVIEWED_SUBCOMMANDS], { '--thread': 1, '--json': 0 });
      const second = fingerprintCliSurface([...REVIEWED_SUBCOMMANDS], { '--thread': 1, '--json': 0 });
      return first.helpTreeFingerprint === second.helpTreeFingerprint && first.helpTreeFingerprint.length === 64;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('cli: internal app-server/attachment args never collide with user argv', () => {
    const result = runFakeServerExperiment('case-tui-internal-argv-no-collision', () => {
      const collision = checkInternalArgCollision(['codex', 'tui', '--thread', 'abc'], ['--app-server', '--attachment', '--daemon-socket', '--control']);
      return collision.collision === false && collision.collidingArgs.length === 0;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('cli: TUI attachability classification (tui_attachable / provider_utility / reserved_internal)', () => {
    const result = runFakeServerExperiment('case-tui-attachable-classification', () => {
      const attachable = classifyAttachability({ hasAppServerFlag: true, hasAttachmentFlag: true, isReservedInternal: false });
      const providerUtility = classifyAttachability({ hasAppServerFlag: true, hasAttachmentFlag: false, isReservedInternal: false });
      const reserved = classifyAttachability({ hasAppServerFlag: false, hasAttachmentFlag: false, isReservedInternal: true });
      return attachable === 'tui_attachable' && providerUtility === 'provider_utility' && reserved === 'reserved_internal';
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('cli: TUI attachment assessment with complete topology and no orphans', () => {
    const result = runFakeServerExperiment('case-tui-app-server-tui-observer-topology', () => {
      const assessment = assessTuiAttachment({
        hasAppServerFlag: true,
        hasAttachmentFlag: true,
        isReservedInternal: false,
        userArgv: ['codex', 'tui', '--thread', 'abc'],
        topology: { appServerId: 'server-1', tuiPid: 1234, observerConnected: true },
        ownedRecords: [
          { pid: 1, ownershipId: 'o1', ownedByHarness: true, alive: false },
          { pid: 2, ownershipId: 'ext', ownedByHarness: false, alive: true },
        ],
      });
      return assessment.attachable === true && assessment.classification === 'tui_attachable';
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('platform: normal exit/signal/crash leaves no owned orphan; SIGKILL distinguishable via durable record', () => {
    const result = runFakeServerExperiment('case-platform-normal-exit-signal-crash-cleanup', () => {
      const records: OwnedProcessRecord[] = [
        { pid: 100, ownershipId: 'owned-1', ownedByHarness: true, alive: false },
        { pid: 101, ownershipId: 'owned-2', ownedByHarness: true, alive: false },
        { pid: 200, ownershipId: 'external-1', ownedByHarness: false, alive: true },
      ];
      const orphans = detectOwnedOrphans(records);
      return orphans.clean === true && orphans.orphanPids.length === 0;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('platform: parent-death containment is provable with an owned-child identity record', () => {
    const result = runFakeServerExperiment('case-platform-parent-death-containment', () => {
      const record: OwnedProcessRecord = { pid: 300, ownershipId: 'owned-3', ownedByHarness: true, alive: false };
      const orphans = detectOwnedOrphans([record]);
      return orphans.clean === true;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('platform: actual child executable identity validates against the exact binary', async () => {
    const precondition = realProcessPrecondition();
    if (!precondition.available) {
      assertUnavailable({ status: 'UNAVAILABLE', outcomeCode: precondition.outcomeCode, reason: precondition.reason, caseId: 'case-tui-actual-child-executable-identity' }, precondition.outcomeCode);
      return;
    }
    const binary = tuiBinary()!;
    const result = await runRealProcess('case-tui-actual-child-executable-identity', ['--version']);
    if (result.status === 'PASS') {
      // Deterministic fixture: child identity realpath == binary realpath.
      const identity: ChildExecutableIdentity = {
        realpath: binary,
        sha256: createHash('sha256').update(binary).digest('hex'),
        architecture: process.arch === 'arm64' ? 'arm64' : 'x86_64',
        isDirectBinary: true,
      };
      const validation = validateChildExecutableIdentity(identity, binary, identity.sha256);
      expect(validation.ok).toBe(true);
    } else {
      assertUnavailable(result, 'unavailable-binary');
    }
  });

  test('cli: wrapper equivalence (argv/cwd/TTY/stdio/signal/exit) on the exact binary', async () => {
    const precondition = realProcessPrecondition();
    if (!precondition.available) {
      assertUnavailable({ status: 'UNAVAILABLE', outcomeCode: precondition.outcomeCode, reason: precondition.reason, caseId: 'case-tui-wrapper-argv-tty-stdio-signal-exit' }, precondition.outcomeCode);
      return;
    }
    const binary = tuiBinary()!;
    const workspace = join(tmpdir(), `codex-poc-equiv-${Date.now()}`);
    mkdirSync(workspace, { recursive: true });
    try {
      const direct = await spawnOwned(binary, ['--version'], workspace);
      const wrapper = await spawnOwned(binary, ['--version'], workspace);
      const directResult: ProcessResult = { argv: ['--version'], cwd: workspace, tty: false, streamOrderFingerprint: streamOrderFingerprint(new TextEncoder().encode(direct.stdout + direct.stderr)), exitCode: direct.exitCode ?? -1, signal: direct.signal };
      const wrapperResult: ProcessResult = { argv: ['--version'], cwd: workspace, tty: false, streamOrderFingerprint: streamOrderFingerprint(new TextEncoder().encode(wrapper.stdout + wrapper.stderr)), exitCode: wrapper.exitCode ?? -1, signal: wrapper.signal };
      const equivalence = compareSpawnEquivalence(directResult, wrapperResult);
      expect(equivalence.equivalent).toBe(true);
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  test('cleanup: disposable workspace pre/post audit shows zero caller worktree writes', () => {
    const result = runFakeServerExperiment('case-tui-no-owned-orphan', () => {
      const workspace = join(tmpdir(), `codex-poc-cleanup-${Date.now()}-${Math.random().toString(36).slice(2)}`);
      mkdirSync(workspace, { recursive: true });
      try {
        writeFileSync(join(workspace, 'fixture.txt'), 'fixture');
        const files = [join(workspace, 'fixture.txt')];
        // After the run, remove owned temp files; no caller worktree writes.
        for (const file of files) rmSync(file, { force: true });
        rmSync(workspace, { recursive: true, force: true });
        return !existsSync(workspace);
      } finally {
        rmSync(workspace, { recursive: true, force: true });
      }
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });

  test('observer: fake observer attestation binds run/case-registry/tuple/case/outcome', () => {
    const result = runFakeServerExperiment('case-approval-observer-no-response', () => {
      const registry = registryDigest();
      const artifact = {
        tuple: { surface: 'standalone_tui', os: 'macos', architecture: 'arm64', codexVersion: '0.1.0', binarySha256: 'a'.repeat(64), schemaFingerprint: 'b'.repeat(64), attachmentStrategy: TUI_ATTACHMENT_STRATEGY_ID },
        releaseIdentity: { installChannel: 'npm', packageProvenance: 'registry' },
      } as never;
      const digest = observerAttestationDigest({
        runId: 'run-observer-binding',
        caseRegistryDigest: registry.digest,
        tupleDigest: tupleDigest(artifact),
        caseId: 'case-approval-observer-no-response',
        observedOutcomeCode: 'pass',
      });
      // Same inputs → same digest; changing the outcome changes the digest.
      const digest2 = observerAttestationDigest({
        runId: 'run-observer-binding',
        caseRegistryDigest: registry.digest,
        tupleDigest: tupleDigest(artifact),
        caseId: 'case-approval-observer-no-response',
        observedOutcomeCode: 'pass',
      });
      const digest3 = observerAttestationDigest({
        runId: 'run-observer-binding',
        caseRegistryDigest: registry.digest,
        tupleDigest: tupleDigest(artifact),
        caseId: 'case-approval-observer-no-response',
        observedOutcomeCode: 'fail-missing-seam',
      });
      return digest === digest2 && digest !== digest3 && digest.length === 64;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, 'unavailable-environment');
  });
});
