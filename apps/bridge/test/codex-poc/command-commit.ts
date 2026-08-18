/**
 * Command commit predicate model for the Codex Exact-Release Capability PoC
 * (spec §8.4).
 *
 * Watch has one `reply` world (same as pi `sendUserMessage`) plus `interrupt`.
 * question/done are Alert presentation, not two commands. Watch `working` is
 * interrupt-only; this PoC does not add a Steer feature. Codex may still expose
 * `turn/steer` on the wire (schema inventory), but Watch reply never uses it:
 *   - Watch reply, idle thread -> RPC `turn/start`     -> `turn/started`
 *   - Watch reply, live turn   -> pre-RPC reject (not `turn/steer`)
 *   - Watch interrupt          -> RPC `turn/interrupt` -> `turn/completed`
 *
 * The model encodes the spec's requirements:
 *   - request correlation pre-assignment;
 *   - target raw thread + provider generation binding;
 *   - pre-send evidence;
 *   - why ordinary accepted/queued response is insufficient;
 *   - the unique positive provider commit observation;
 *   - rejection/timeout/disconnect;
 *   - throw/disconnect after possible invocation -> unknown (no auto-replay);
 *   - restart commit proof;
 *   - no automatic replay.
 *
 * Research-only harness code; never part of the production import graph.
 */

/** Watch-mapped operations that must have commit predicates (spec §8.4). */
export const COMMIT_OPERATIONS = ['turn/start', 'turn/interrupt'] as const;
export type CommitOperation = (typeof COMMIT_OPERATIONS)[number];

/** Codex wire methods, including `turn/steer` which is not a Watch command. */
export const CODEX_TURN_METHODS = ['turn/start', 'turn/steer', 'turn/interrupt'] as const;
export type CodexTurnMethod = (typeof CODEX_TURN_METHODS)[number];

/**
 * Exact-release notification type that proves a positive commit for one RPC.
 * The wire does not emit `turn/start`, `turn/steer`, or `turn/interrupt` as
 * event types; those names are request methods only. `turn/steer` stays in this
 * map for schema/fake coverage only.
 */
export const COMMIT_EVENT_TYPE = Object.freeze({
  'turn/start': 'turn/started',
  'turn/steer': 'item/started',
  'turn/interrupt': 'turn/completed',
} as const satisfies Record<CodexTurnMethod, string>);

export type CommitEventType = (typeof COMMIT_EVENT_TYPE)[CommitOperation];

export function commitEventType(operation: CodexTurnMethod): (typeof COMMIT_EVENT_TYPE)[CodexTurnMethod] {
  return COMMIT_EVENT_TYPE[operation];
}

export type WatchCommandType = 'reply' | 'interrupt';

/** Watch → Codex mapping. Live reply is fail-closed; `turn/steer` is never a Watch RPC. */
export function mapWatchCommand(input: {
  type: WatchCommandType;
  turnLive: boolean;
}): { rpc: CommitOperation } | { reject: true; reason: 'live-reply-no-steer' | 'idle-interrupt' } {
  if (input.type === 'interrupt') {
    if (!input.turnLive) return { reject: true, reason: 'idle-interrupt' };
    return { rpc: 'turn/interrupt' };
  }
  if (input.turnLive) return { reject: true, reason: 'live-reply-no-steer' };
  return { rpc: 'turn/start' };
}

export interface CommandRequest {
  /** Pre-assigned request correlation id. */
  correlationId: string;
  operation: CommitOperation;
  /** Target raw thread identity. */
  rawThreadId: string;
  /** Provider generation the request is bound to. */
  providerGeneration: number;
  /** Evidence recorded before the request was sent. */
  preSendEvidence: PreSendEvidence;
}

export interface PreSendEvidence {
  /** Authoritative thread read snapshot before the command. */
  threadSnapshotOrder: number;
  /** Whether the thread was loaded at send time. */
  threadLoaded: boolean;
  /** Whether an approval/blocking request was pending (never a reply target). */
  approvalPending: boolean;
}

export type CommitState =
  | 'accepted-queued'
  | 'committed'
  | 'rejected'
  | 'timeout'
  | 'disconnected'
  | 'unknown-after-invocation';

export interface CommitObservation {
  /** The one positive provider commit observation (event that proves commit). */
  providerCommitEvent?: { sourceEventId: string; type: string; generation: number; order: number };
  /** Ordinary accepted/queued response is NOT commit evidence. */
  acceptedResponse?: { correlationId: string };
  state: CommitState;
  /** Whether restart can prove committed-or-not. */
  restartProof?: 'committed' | 'not-committed' | 'unknown';
}

export interface CommitPredicateResult {
  operation: CommitOperation;
  /** True only when a unique positive provider commit observation exists. */
  hasPositiveCommit: boolean;
  observation: CommitObservation;
  /** Why accepted/queued alone is insufficient (bounded reason). */
  acceptedInsufficientReason?: string;
  /** Whether an automatic replay was attempted (forbidden). */
  autoReplayAttempted: boolean;
}

/** Verify the pre-send binding: thread + generation must be stable. */
export function verifyRequestBinding(request: CommandRequest, currentThreadGeneration: number, currentThreadLoaded: boolean): { ok: boolean; reason?: string } {
  if (request.providerGeneration !== currentThreadGeneration) {
    return { ok: false, reason: `generation mismatch ${request.providerGeneration} != ${currentThreadGeneration}` };
  }
  if (!currentThreadLoaded) {
    return { ok: false, reason: 'thread not loaded at send time' };
  }
  if (request.preSendEvidence.approvalPending) {
    return { ok: false, reason: 'approval pending: never a reply target' };
  }
  return { ok: true };
}

/**
 * Evaluate the commit predicate for one operation.
 *
 * `providerEvents` are the authoritative events observed after the request was
 * sent. A positive commit is ONLY a provider event whose type matches the
 * operation's expected commit event AND whose sourceEventId is unique and
 * whose generation/order match the request's binding.
 *
 * An ordinary accepted/queued response is recorded but never counts as commit.
 */
export function evaluateCommitPredicate(
  request: CommandRequest,
  providerEvents: Array<{ sourceEventId: string; type: string; generation: number; order: number }>,
  options: { acceptedResponse?: { correlationId: string }; disconnected?: boolean; timedOut?: boolean; rejected?: boolean } = {},
): CommitPredicateResult {
  const expectedCommitType = commitEventType(request.operation);
  const matching = providerEvents.filter((event) =>
    event.type === expectedCommitType &&
    event.generation === request.providerGeneration &&
    event.order >= request.preSendEvidence.threadSnapshotOrder);
  const unique = new Set(matching.map((event) => event.sourceEventId));
  const hasPositiveCommit = unique.size === 1 && matching.length === 1;

  let state: CommitState = 'accepted-queued';
  if (options.rejected) state = 'rejected';
  else if (options.timedOut) state = 'timeout';
  else if (options.disconnected) state = 'disconnected';
  else if (hasPositiveCommit) state = 'committed';
  else if (options.acceptedResponse && !hasPositiveCommit) state = 'accepted-queued';
  else if (!hasPositiveCommit && providerEvents.length === 0) state = 'unknown-after-invocation';

  const acceptedInsufficientReason = options.acceptedResponse && !hasPositiveCommit
    ? 'accepted/queued response does not prove provider commit'
    : undefined;

  return {
    operation: request.operation,
    hasPositiveCommit,
    observation: {
      providerCommitEvent: hasPositiveCommit ? matching[0] : undefined,
      acceptedResponse: options.acceptedResponse,
      state,
    },
    acceptedInsufficientReason,
    autoReplayAttempted: false,
  };
}

/** Restart commit proof: after restart, thread/read must show the commit event. */
export function proveCommitAfterRestart(
  request: CommandRequest,
  authoritativeAfterRestart: Array<{ sourceEventId: string; type: string; generation: number; order: number }>,
): { proof: 'committed' | 'not-committed' | 'unknown' } {
  const commitEvent = authoritativeAfterRestart.find((event) =>
    event.type === commitEventType(request.operation) &&
    event.generation === request.providerGeneration &&
    event.order >= request.preSendEvidence.threadSnapshotOrder);
  if (commitEvent) return { proof: 'committed' };
  // No auto-replay: if the request may have been invoked but no commit event
  // exists, the result is unknown, never assumed committed or not.
  return { proof: 'unknown' };
}

/** Throw/disconnect after possible invocation must enter unknown, never replay. */
export function classifyAfterDisconnect(request: CommandRequest, sawProviderEvents: boolean): { state: 'unknown-after-invocation'; autoReplayAttempted: boolean } {
  return {
    state: 'unknown-after-invocation',
    autoReplayAttempted: false,
  };
}
