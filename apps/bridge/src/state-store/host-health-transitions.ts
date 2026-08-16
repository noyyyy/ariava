import type {
  BridgeRuntimeHealth,
  DriverRuntimeHealth,
  HostProjection,
  PersistedBridgeState,
} from '../types';
import type { StateTransition } from './state-transitions';

/** Deterministic Host and runtime-health next-state calculations (spec §6.1). */

export function emptyRuntimeHealth(): BridgeRuntimeHealth {
  return { status: 'healthy', drivers: [] };
}

export function sanitizePersistedHost(host: HostProjection | null): HostProjection | null {
  if (!host) return null;
  const value = { ...host } as HostProjection & Record<string, unknown>;
  delete value.claimCode; delete value.claimCodeExpiresAt; delete value.ownerUserId;
  return value;
}

/** Composed runtime health view with deterministic driver ordering; always a fresh clone. */
export function readRuntimeHealth(state: PersistedBridgeState): BridgeRuntimeHealth {
  const health = state.runtimeHealth ?? emptyRuntimeHealth();
  return structuredClone({
    ...health,
    drivers: [...health.drivers].sort((left, right) => left.driver.localeCompare(right.driver)),
  });
}

/** Mutate-first Host projection replacement (write-failure live value is mutated). */
export function setHostTransition(state: PersistedBridgeState, host: HostProjection): StateTransition<void> {
  return { state: { ...state, host: sanitizePersistedHost(host) }, result: undefined };
}

export function recordDriverReconciliationFailureTransition(
  state: PersistedBridgeState,
  driver: string,
  seenAt: string,
  nextRetryAt: string,
): StateTransition<DriverRuntimeHealth> {
  const nextState = structuredClone(state);
  const health = nextState.runtimeHealth ?? emptyRuntimeHealth();
  const existing = health.drivers.find((item) => item.driver === driver);
  const degradation: DriverRuntimeHealth = existing
    ? { ...existing, count: existing.count + 1, lastSeenAt: seenAt, nextRetryAt }
    : { driver, code: 'driver_reconciliation_failed', count: 1, firstSeenAt: seenAt, lastSeenAt: seenAt, nextRetryAt };
  health.drivers = [...health.drivers.filter((item) => item.driver !== driver), degradation]
    .sort((left, right) => left.driver.localeCompare(right.driver));
  health.status = 'degraded';
  nextState.runtimeHealth = health;
  return { state: nextState, result: structuredClone(degradation) };
}

export function recordDriverReconciliationSuccessTransition(
  state: PersistedBridgeState,
  driver: string,
): StateTransition<{ count: number } | undefined> {
  const nextState = structuredClone(state);
  const health = nextState.runtimeHealth ?? emptyRuntimeHealth();
  const recovered = health.drivers.find((item) => item.driver === driver);
  if (!recovered) return { state, result: undefined };
  health.drivers = health.drivers.filter((item) => item.driver !== driver);
  health.status = health.drivers.length > 0 || health.relayPresence ? 'degraded' : 'healthy';
  nextState.runtimeHealth = health;
  return { state: nextState, result: { count: recovered.count } };
}

export function recordRelayPresenceFailureTransition(
  state: PersistedBridgeState,
  seenAt: string,
  nextRetryAt: string,
): StateTransition<void> {
  const nextState = structuredClone(state);
  const health = nextState.runtimeHealth ?? emptyRuntimeHealth();
  const existing = health.relayPresence;
  health.relayPresence = existing
    ? { ...existing, count: existing.count + 1, lastSeenAt: seenAt, nextRetryAt }
    : { code: 'relay_presence_refresh_failed', count: 1, firstSeenAt: seenAt, lastSeenAt: seenAt, nextRetryAt };
  health.status = 'degraded';
  nextState.runtimeHealth = health;
  return { state: nextState, result: undefined };
}

export function recordRelayPresenceSuccessTransition(
  state: PersistedBridgeState,
): StateTransition<{ count: number } | undefined> {
  const nextState = structuredClone(state);
  const health = nextState.runtimeHealth ?? emptyRuntimeHealth();
  const recovered = health.relayPresence;
  if (!recovered) return { state, result: undefined };
  delete health.relayPresence;
  health.status = health.drivers.length > 0 ? 'degraded' : 'healthy';
  nextState.runtimeHealth = health;
  return { state: nextState, result: { count: recovered.count } };
}
