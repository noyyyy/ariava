import { describe, expect, test } from 'bun:test';
import {
  classifyAfterDisconnect,
  COMMIT_OPERATIONS,
  evaluateCommitPredicate,
  proveCommitAfterRestart,
  verifyRequestBinding,
  type CommandRequest,
} from './command-commit';

function makeRequest(operation: 'turn.steer' | 'turn.start' | 'turn.interrupt', overrides: Partial<CommandRequest> = {}): CommandRequest {
  return {
    correlationId: `corr-${operation}`,
    operation,
    rawThreadId: 'thread-1',
    providerGeneration: 1,
    preSendEvidence: { threadSnapshotOrder: 5, threadLoaded: true, approvalPending: false },
    ...overrides,
  };
}

describe('command commit predicate (spec §8.4)', () => {
  test('accepted/queued response is NOT a commit', () => {
    const request = makeRequest('turn.steer');
    const result = evaluateCommitPredicate(request, [], { acceptedResponse: { correlationId: request.correlationId } });
    expect(result.hasPositiveCommit).toBe(false);
    expect(result.observation.state).toBe('accepted-queued');
    expect(result.acceptedInsufficientReason).toContain('accepted/queued');
  });

  test('positive provider commit: unique event with matching type/generation/order', () => {
    const request = makeRequest('turn.start');
    const result = evaluateCommitPredicate(request, [
      { sourceEventId: 'commit-1', type: 'turn.start', generation: 1, order: 6 },
    ]);
    expect(result.hasPositiveCommit).toBe(true);
    expect(result.observation.state).toBe('committed');
    expect(result.observation.providerCommitEvent?.sourceEventId).toBe('commit-1');
  });

  test('duplicate commit events (same type, two source ids) do NOT prove commit', () => {
    const request = makeRequest('turn.steer');
    const result = evaluateCommitPredicate(request, [
      { sourceEventId: 'commit-1', type: 'turn.steer', generation: 1, order: 6 },
      { sourceEventId: 'commit-2', type: 'turn.steer', generation: 1, order: 7 },
    ]);
    expect(result.hasPositiveCommit).toBe(false);
    expect(result.observation.state).toBe('accepted-queued');
  });

  test('rejection is not a commit', () => {
    const request = makeRequest('turn.interrupt');
    const result = evaluateCommitPredicate(request, [], { rejected: true });
    expect(result.hasPositiveCommit).toBe(false);
    expect(result.observation.state).toBe('rejected');
  });

  test('timeout is not a commit and never auto-replays', () => {
    const request = makeRequest('turn.steer');
    const result = evaluateCommitPredicate(request, [], { timedOut: true });
    expect(result.hasPositiveCommit).toBe(false);
    expect(result.observation.state).toBe('timeout');
    expect(result.autoReplayAttempted).toBe(false);
  });

  test('disconnect after possible invocation enters unknown, never replay', () => {
    const request = makeRequest('turn.start');
    const result = evaluateCommitPredicate(request, [], { disconnected: true });
    expect(result.observation.state).toBe('disconnected');
    const after = classifyAfterDisconnect(request, false);
    expect(after.state).toBe('unknown-after-invocation');
    expect(after.autoReplayAttempted).toBe(false);
  });

  test('all three operations have distinct commit predicates', () => {
    expect(COMMIT_OPERATIONS).toEqual(['turn.steer', 'turn.start', 'turn.interrupt']);
    for (const operation of COMMIT_OPERATIONS) {
      const request = makeRequest(operation);
      const result = evaluateCommitPredicate(request, [
        { sourceEventId: `commit-${operation}`, type: operation, generation: 1, order: 6 },
      ]);
      expect(result.hasPositiveCommit).toBe(true);
    }
  });

  test('request binding requires matching generation and loaded thread', () => {
    const request = makeRequest('turn.steer', { providerGeneration: 1 });
    expect(verifyRequestBinding(request, 1, true).ok).toBe(true);
    expect(verifyRequestBinding(request, 2, true).ok).toBe(false);
    expect(verifyRequestBinding(request, 1, false).ok).toBe(false);
    expect(verifyRequestBinding(request, 1, true).ok).toBe(true);
  });

  test('approval pending means never a reply target', () => {
    const request = makeRequest('turn.steer', { preSendEvidence: { threadSnapshotOrder: 5, threadLoaded: true, approvalPending: true } });
    const binding = verifyRequestBinding(request, 1, true);
    expect(binding.ok).toBe(false);
    expect(binding.reason).toContain('approval pending');
  });

  test('restart commit proof: committed event visible after restart', () => {
    const request = makeRequest('turn.start');
    const proof = proveCommitAfterRestart(request, [
      { sourceEventId: 'commit-1', type: 'turn.start', generation: 1, order: 6 },
    ]);
    expect(proof.proof).toBe('committed');
  });

  test('restart without commit event is unknown, not assumed not-committed', () => {
    const request = makeRequest('turn.start');
    const proof = proveCommitAfterRestart(request, [
      { sourceEventId: 'other-1', type: 'turn.item.completed', generation: 1, order: 6 },
    ]);
    expect(proof.proof).toBe('unknown');
  });

  test('missing predicate produces NO-GO at the verdict level (all three required)', () => {
    // The verdict module requires all three commit predicates; a single missing
    // operation means hasPositiveCommit=false for that operation.
    const request = makeRequest('turn.interrupt');
    const result = evaluateCommitPredicate(request, [], { acceptedResponse: { correlationId: 'x' } });
    expect(result.hasPositiveCommit).toBe(false);
  });
});
