import type { EncryptedEventFailureCategory, UploadFailureCategory } from './upload-failures';

export const RECIPIENT_SET_CHANGED_REASON = 'e2e_recipient_set_changed';

/**
 * Pure outcome decision for one Session snapshot upload attempt.
 *
 * Inputs contain ONLY: publish/reconcile outcome, current/upload/refreshed
 * recipient versions, current revision, and a desensitized failure category.
 * No secret bytes, no encrypted payloads, no store/relay objects.
 */
export type SessionUploadDecision =
  | { type: 'commit'; acceptedRevision: number }
  | { type: 'reconcile' }
  | { type: 'refresh-reencrypt'; revision: number }
  | { type: 'retry-next-revision'; revision: number }
  | { type: 'defer'; reason: UploadFailureCategory }
  | { type: 'fail-closed'; error: Error };

/** Pure outcome decision for one encrypted Event upload attempt. */
export type EventUploadDecision =
  | { type: 'complete' }
  | { type: 'reconcile' }
  | { type: 'refresh-session-and-reencrypt' }
  | { type: 'quarantine'; category: EncryptedEventFailureCategory }
  | { type: 'defer'; category: EncryptedEventFailureCategory };

export interface SessionUploadDecisionInput {
  /** publishEncryptedSession resolved successfully. */
  publishSucceeded: boolean;
  /** Relay 409 conflict reason when the publish conflicted. */
  conflictReason?: string;
  /** reconcileEncryptedSession result when reconcile was attempted. */
  reconcileCommitted?: boolean;
  /** Recipient-set version the attempted upload was encrypted for. */
  attemptedRecipientVersion: number;
  /** Refreshed recipient-set version after an e2e_recipient_set_changed refresh. */
  refreshedRecipientVersion?: number;
  /** Revision carried by the attempted upload. */
  currentRevision: number;
  /** True after one same-version reconcile-committed retry in this invocation. */
  sameVersionCommitRetryExhausted?: boolean;
  failureCategory: UploadFailureCategory;
}

export interface EventUploadDecisionInput {
  /** publishEncryptedEvent resolved successfully. */
  publishSucceeded: boolean;
  /** Relay 409 conflict reason when the publish conflicted. */
  conflictReason?: string;
  /** reconcileEncryptedEvent result when reconcile was attempted. */
  reconcileCommitted?: boolean;
  /** Whether the conflict maps to a permanent Event conflict category. */
  permanentEventConflict: boolean;
  /** True when a recipient refresh + re-encrypt already happened for this publish pass. */
  recipientRefreshExhausted?: boolean;
  failureCategory: EncryptedEventFailureCategory;
}

/**
 * Decide the next workflow for a Session snapshot upload outcome.
 *
 * Baseline semantics (Public Repo `3a55152`) plus the single approved §8.1
 * no-progress hardening: when a recipient-set-changed conflict leaves the
 * refreshed recipient version equal to the attempted version and reconcile
 * did not prove committed, the upload must fail closed immediately --
 * preserving inflight evidence, committing no revision, removing no source,
 * and never continuing the same inner loop.
 */
export function decideSessionUpload(input: SessionUploadDecisionInput): SessionUploadDecision {
  if (input.publishSucceeded) {
    return { type: 'commit', acceptedRevision: input.currentRevision };
  }
  if (input.conflictReason === undefined) {
    return { type: 'defer', reason: input.failureCategory };
  }
  if (input.reconcileCommitted === undefined) {
    return { type: 'reconcile' };
  }
  if (input.conflictReason !== RECIPIENT_SET_CHANGED_REASON) {
    return input.reconcileCommitted
      ? { type: 'commit', acceptedRevision: input.currentRevision }
      : { type: 'defer', reason: input.failureCategory };
  }
  // e2e_recipient_set_changed
  if (input.refreshedRecipientVersion === undefined) {
    return { type: 'defer', reason: 'recipient-set' };
  }
  if (input.refreshedRecipientVersion === input.attemptedRecipientVersion) {
    if (!input.reconcileCommitted) {
      return { type: 'fail-closed', error: new Error('Session upload no-progress: refreshed recipient-set version equals attempted version') };
    }
    if (input.sameVersionCommitRetryExhausted === true) {
      return { type: 'fail-closed', error: new Error('Session upload no-progress: repeated same-version reconcile-committed conflict') };
    }
  }
  return input.reconcileCommitted
    ? { type: 'retry-next-revision', revision: input.currentRevision + 1 }
    : { type: 'refresh-reencrypt', revision: input.currentRevision };
}

/**
 * Decide the next workflow for an encrypted Event upload outcome.
 *
 * Permanent-conflict mapping, status/reason extraction and failure category
 * remain pure and exactly baseline. A recipient refresh is attempted at most
 * once per publish pass; a second recipient-set-changed conflict after the
 * refresh defers instead of looping.
 */
export function decideEventUpload(input: EventUploadDecisionInput): EventUploadDecision {
  if (input.publishSucceeded) {
    return { type: 'complete' };
  }
  if (input.conflictReason === undefined) {
    return { type: 'defer', category: input.failureCategory };
  }
  if (input.reconcileCommitted === undefined) {
    return { type: 'reconcile' };
  }
  if (input.reconcileCommitted) {
    return { type: 'complete' };
  }
  if (input.conflictReason === RECIPIENT_SET_CHANGED_REASON) {
    return input.recipientRefreshExhausted === true
      ? { type: 'defer', category: input.failureCategory }
      : { type: 'refresh-session-and-reencrypt' };
  }
  return input.permanentEventConflict
    ? { type: 'quarantine', category: input.failureCategory }
    : { type: 'defer', category: input.failureCategory };
}
