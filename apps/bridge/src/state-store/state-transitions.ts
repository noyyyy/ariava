import type { PersistedBridgeState } from '../types';

/**
 * Result of a pure state transition (spec §6.1).
 *
 * Convention: when no durable write is required, `state` is the SAME input
 * object reference (never mutated); when a write is required, `state` is a
 * new object derived from the input. Shell methods compare references to
 * decide whether to commit.
 */
export interface StateTransition<Result = void> {
  readonly state: PersistedBridgeState;
  readonly result: Result;
}

/**
 * Minimal imperative shell surface `commitState` needs (spec §6.3).
 *
 * Only clone-first / persist-before-swap methods proven by the §3.3 inventory
 * may be routed through `commitState`. Mutate-first methods and cross-medium
 * journal workflows keep their dedicated shell code.
 */
export interface StateStoreShell {
  /** Current in-memory runtime state (guarded getter; read once per commit). */
  readonly state: PersistedBridgeState;
  /** Persist-before-swap durable commit of a derived next state. */
  commit(nextState: PersistedBridgeState): void;
}

/**
 * Optional commit boundary for inventory-proven clone-first methods (spec §6.3).
 *
 * Computes `transition(current)`, persists the derived state first, then swaps
 * it in (persist-before-swap). On write failure the live in-memory state is
 * unchanged and the error propagates. Same-reference no-op transitions skip
 * the durable write.
 */
export function commitState<Result>(
  shell: StateStoreShell,
  transition: (state: PersistedBridgeState) => StateTransition<Result>,
): Result {
  const current = shell.state;
  const next = transition(current);
  if (next.state !== current) shell.commit(next.state);
  return next.result;
}
