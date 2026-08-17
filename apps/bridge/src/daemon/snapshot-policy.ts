/**
 * Pure current-session snapshot failure policy (spec §7, plan Task 4).
 *
 * Only failure-count/threshold/log-throttle/action/reset decisions live here.
 * The escalation reducer (`decideSnapshotFailure`) is strictly Relay-scoped:
 * non-Relay local failures never enter it. Local crypto/store/canonicalization
 * faults keep their fail-closed behavior outside the reducer and reach only the
 * separate pure log-throttle decision (`decideSnapshotFailureLog`), so the
 * boundary is structural, not a category field a caller could misroute.
 *
 * The module never touches a clock, logger, Relay client, state store, keyring,
 * or timer. The caller collects `now` and raw active-session evidence, applies
 * the returned state transition, and executes the resulting action. Summary
 * evidence is aggregated by the separate pure `summarizeSnapshotFailures` and
 * only ever collected when a decision says `shouldLog`, so throttled failures
 * perform no state-store reads and the count/scheduling/offline behavior is
 * never preempted by summary collection.
 */

export type SnapshotFailureAction = 'retry' | 'recover-pipeline' | 'mark-offline';

/** Failure count and log throttle state owned by the policy. */
export interface SnapshotFailureState {
  /** Consecutive Relay snapshot publication failures since the last success. */
  readonly count: number;
  /** Millisecond timestamp of the last logged snapshot failure (throttle gate). */
  readonly lastLogAt: number;
}

/** Keep the frozen baseline: escalate to pipeline recovery after 2 failures. */
export const SNAPSHOT_FAILURE_ESCALATION_THRESHOLD = 2;

/** Keep the frozen baseline: publish-phase logs are coalesced within 30s. */
export const SNAPSHOT_FAILURE_LOG_THROTTLE_MS = 30_000;

/** Log summary: the full no-revision count but only the first 10 Session ids. */
export const SNAPSHOT_FAILURE_LOG_NO_REVISION_ID_CAP = 10;

export function createInitialSnapshotFailureState(): SnapshotFailureState {
  return { count: 0, lastLogAt: 0 };
}

/**
 * Success reset (spec §7): clears only the failure count. The log throttle
 * window persists across a successful publication, preserving the existing
 * 30-second coalescing behavior.
 */
export function resetSnapshotFailures(state: SnapshotFailureState): SnapshotFailureState {
  return { count: 0, lastLogAt: state.lastLogAt };
}

/** Active-session evidence aggregated into the log detail by the policy. */
export interface SnapshotActiveSessionSummary {
  readonly activeSessionCount: number;
  readonly noRevisionSessionCount: number;
  readonly noRevisionSessionIds: readonly string[];
}

/** Raw evidence collected by the caller from store inspection, never the reducer. */
export interface SnapshotFailureEvidence {
  readonly activeSessionCount: number;
  readonly sessionsWithoutRevision: readonly string[];
}

/**
 * Pure log-throttle decision for snapshot failure logging. This is the ONLY
 * policy surface for non-Relay local failures: it updates the shared throttle
 * state, but has no action and can never touch the escalation count. Recovery
 * phase always logs; publish phase honors the 30s window.
 */
export interface SnapshotLogDecision {
  readonly next: SnapshotFailureState;
  readonly shouldLog: boolean;
}

export function decideSnapshotFailureLog(
  state: SnapshotFailureState,
  now: number,
  phase: 'publish' | 'recovery',
): SnapshotLogDecision {
  if (phase === 'recovery' || now - state.lastLogAt >= SNAPSHOT_FAILURE_LOG_THROTTLE_MS) {
    return { next: { count: state.count, lastLogAt: now }, shouldLog: true };
  }
  return { next: { count: state.count, lastLogAt: state.lastLogAt }, shouldLog: false };
}

/**
 * Relay escalation reducer (spec §7 `SnapshotFailureDecision`). `type` is the
 * decision point:
 *  - `publication-failure` — a Relay/client snapshot publication failure.
 *    Increments the count and decides `retry` (below threshold, offline pass)
 *    or `recover-pipeline` (at/above threshold).
 *  - `recovery-failure` — the recovery pipeline itself failed after escalation
 *    (`count >= 2`). Always logs, marks the pass offline, and does not
 *    increment the count again.
 * `now` is clock evidence collected by the caller; this function reads no
 * clock, logger, store, or timer.
 */
export interface SnapshotFailureEvent {
  readonly type: 'publication-failure' | 'recovery-failure';
  readonly now: number;
}

export interface SnapshotFailureDecision {
  readonly next: SnapshotFailureState;
  readonly action: SnapshotFailureAction;
  readonly shouldLog: boolean;
}

export function decideSnapshotFailure(
  state: SnapshotFailureState,
  event: SnapshotFailureEvent,
): SnapshotFailureDecision {
  if (event.type === 'recovery-failure') {
    // Escalation was already decided by the two Relay failures that entered the
    // recovery pipeline. A failed recovery attempt marks this pass offline and
    // always logs; the count is not incremented again.
    return { next: { count: state.count, lastLogAt: event.now }, action: 'mark-offline', shouldLog: true };
  }

  const throttled = event.now - state.lastLogAt < SNAPSHOT_FAILURE_LOG_THROTTLE_MS;
  const count = state.count + 1;
  return {
    next: { count, lastLogAt: throttled ? state.lastLogAt : event.now },
    action: count >= SNAPSHOT_FAILURE_ESCALATION_THRESHOLD ? 'recover-pipeline' : 'retry',
    shouldLog: !throttled,
  };
}

/**
 * Pure active-session summary aggregation (no-revision id cap). Called by the
 * caller only when a decision says `shouldLog`, so throttled failures perform
 * no state-store reads.
 */
export function summarizeSnapshotFailures(evidence: SnapshotFailureEvidence): SnapshotActiveSessionSummary {
  return {
    activeSessionCount: evidence.activeSessionCount,
    noRevisionSessionCount: evidence.sessionsWithoutRevision.length,
    noRevisionSessionIds: evidence.sessionsWithoutRevision.slice(0, SNAPSHOT_FAILURE_LOG_NO_REVISION_ID_CAP),
  };
}