import { describe, expect, test } from 'bun:test';
import { decideEventUpload, decideSessionUpload, RECIPIENT_SET_CHANGED_REASON, type EventUploadDecisionInput, type SessionUploadDecisionInput } from '../src/e2e/upload-decisions';
import { relayFailureCategory } from '../src/e2e/upload-failures';
import { RelayClientError } from '../src/relay-client';

/**
 * Pure decision table tests for the encrypted upload outcome model (spec §7/§11).
 * Every row asserts the exact discriminated-union decision for a publish/reconcile
 * outcome, recipient versions, and current revision. No I/O, no secrets.
 */
describe('decideSessionUpload pure decision table', () => {
  const base: SessionUploadDecisionInput = {
    publishSucceeded: false,
    attemptedRecipientVersion: 1,
    currentRevision: 4,
    failureCategory: 'http',
  };

  test('publish success commits the attempted revision', () => {
    expect(decideSessionUpload({ ...base, publishSucceeded: true }))
      .toEqual({ type: 'commit', acceptedRevision: 4 });
  });

  test('non-recipient 409 with reconcile committed commits the attempted revision', () => {
    expect(decideSessionUpload({
      ...base,
      conflictReason: 'session_snapshot_stale',
      reconcileCommitted: true,
      failureCategory: 'session-revision',
    })).toEqual({ type: 'commit', acceptedRevision: 4 });
  });

  test('non-recipient 409 without reconcile commit defers with the failure category', () => {
    expect(decideSessionUpload({
      ...base,
      conflictReason: 'session_snapshot_conflict',
      reconcileCommitted: false,
      failureCategory: 'session-revision',
    })).toEqual({ type: 'defer', reason: 'session-revision' });
  });

  test('network/non-409 failure defers with the network category', () => {
    expect(decideSessionUpload({ ...base, failureCategory: 'network' }))
      .toEqual({ type: 'defer', reason: 'network' });
  });

  test('conflict without a reconcile result requests reconcile', () => {
    expect(decideSessionUpload({
      ...base,
      conflictReason: RECIPIENT_SET_CHANGED_REASON,
      failureCategory: 'recipient-set',
    })).toEqual({ type: 'reconcile' });
  });

  test('recipient-set-changed with a bumped refreshed version and reconcile committed retries the next revision', () => {
    expect(decideSessionUpload({
      ...base,
      conflictReason: RECIPIENT_SET_CHANGED_REASON,
      reconcileCommitted: true,
      refreshedRecipientVersion: 2,
      failureCategory: 'recipient-set',
    })).toEqual({ type: 'retry-next-revision', revision: 5 });
  });

  test('recipient-set-changed with a bumped refreshed version and no reconcile commit re-encrypts the same revision', () => {
    expect(decideSessionUpload({
      ...base,
      conflictReason: RECIPIENT_SET_CHANGED_REASON,
      reconcileCommitted: false,
      refreshedRecipientVersion: 2,
      failureCategory: 'recipient-set',
    })).toEqual({ type: 'refresh-reencrypt', revision: 4 });
  });

  test('recipient-set-changed with refreshed version equal to attempted version fails closed (no-progress, §8.1)', () => {
    const decision = decideSessionUpload({
      ...base,
      conflictReason: RECIPIENT_SET_CHANGED_REASON,
      reconcileCommitted: false,
      refreshedRecipientVersion: 1,
      failureCategory: 'recipient-set',
    });
    expect(decision.type).toBe('fail-closed');
    expect((decision as { error: Error }).error.message).toMatch(/no-progress/u);
    // The fail-closed payload is a desensitized Error: no ciphertext, no reason text beyond the marker.
    expect(JSON.stringify(decision)).not.toMatch(/ciphertext|secret|encrypted upload conflict/u);
  });

  test('recipient-set-changed with same refreshed version and reconcile committed retries the next revision', () => {
    expect(decideSessionUpload({
      ...base,
      conflictReason: RECIPIENT_SET_CHANGED_REASON,
      reconcileCommitted: true,
      refreshedRecipientVersion: 1,
      failureCategory: 'recipient-set',
    })).toEqual({ type: 'retry-next-revision', revision: 5 });
  });

  test('repeated same-version reconcile-committed conflict fails closed after one retry', () => {
    const decision = decideSessionUpload({
      ...base,
      conflictReason: RECIPIENT_SET_CHANGED_REASON,
      reconcileCommitted: true,
      refreshedRecipientVersion: 1,
      sameVersionCommitRetryExhausted: true,
      failureCategory: 'recipient-set',
    });
    expect(decision.type).toBe('fail-closed');
    expect((decision as { error: Error }).error.message).toMatch(/repeated same-version/u);
  });

  test('recipient-set-changed without a refresh result defers with the recipient-set category', () => {
    expect(decideSessionUpload({
      ...base,
      conflictReason: RECIPIENT_SET_CHANGED_REASON,
      reconcileCommitted: false,
      failureCategory: 'recipient-set',
    })).toEqual({ type: 'defer', reason: 'recipient-set' });
  });
});

describe('decideEventUpload pure decision table', () => {
  const base: EventUploadDecisionInput = {
    publishSucceeded: false,
    permanentEventConflict: false,
    failureCategory: 'http',
  };

  test('publish success completes', () => {
    expect(decideEventUpload({ ...base, publishSucceeded: true }))
      .toEqual({ type: 'complete' });
  });

  test('reconcile committed completes regardless of conflict reason', () => {
    expect(decideEventUpload({
      ...base,
      conflictReason: 'session_revision_gap',
      reconcileCommitted: true,
      permanentEventConflict: true,
      failureCategory: 'session-revision',
    })).toEqual({ type: 'complete' });
  });

  test('permanent event conflict without reconcile commit quarantines with the exact baseline category', () => {
    const permanentReasons = [
      'session_revision_stale',
      'session_revision_gap',
      'session revision conflict',
      'encrypted event conflict',
      'encrypted upload conflict',
    ] as const;
    for (const reason of permanentReasons) {
      const error = new RelayClientError(409, reason, { reason });
      expect(decideEventUpload({
        ...base,
        conflictReason: reason,
        reconcileCommitted: false,
        permanentEventConflict: true,
        failureCategory: relayFailureCategory(error),
      })).toEqual({ type: 'quarantine', category: relayFailureCategory(error) });
    }
  });

  test('transient 409 not in the permanent matrix defers with its category', () => {
    expect(decideEventUpload({
      ...base,
      conflictReason: 'some_transient_conflict',
      reconcileCommitted: false,
      permanentEventConflict: false,
      failureCategory: 'http',
    })).toEqual({ type: 'defer', category: 'http' });
  });

  test('network/non-409 failure defers with the network category', () => {
    expect(decideEventUpload({ ...base, failureCategory: 'network' }))
      .toEqual({ type: 'defer', category: 'network' });
  });

  test('recipient-set-changed without reconcile commit requests refresh-session-and-reencrypt once', () => {
    expect(decideEventUpload({
      ...base,
      conflictReason: RECIPIENT_SET_CHANGED_REASON,
      reconcileCommitted: false,
      failureCategory: 'recipient-set',
    })).toEqual({ type: 'refresh-session-and-reencrypt' });
  });

  test('recipient-set-changed after an exhausted refresh defers instead of looping', () => {
    expect(decideEventUpload({
      ...base,
      conflictReason: RECIPIENT_SET_CHANGED_REASON,
      reconcileCommitted: false,
      recipientRefreshExhausted: true,
      failureCategory: 'recipient-set',
    })).toEqual({ type: 'defer', category: 'recipient-set' });
  });
});
