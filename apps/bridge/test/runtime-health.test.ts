import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeStateStore } from '../src/state-store';

const roots: string[] = [];
const firstSeenAt = '2026-08-10T00:00:00.000Z';
const lastSeenAt = '2026-08-10T00:00:15.000Z';
const nextRetryAt = '2026-08-10T00:00:30.000Z';

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): { root: string; statePath: string; store: BridgeStateStore } {
  const root = join(tmpdir(), `bridge-runtime-health-${Date.now()}-${roots.length}`);
  roots.push(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const statePath = join(root, 'state.json');
  return { root, statePath, store: new BridgeStateStore(statePath) };
}

describe('durable Bridge runtime health', () => {
  test('persists bounded driver and Relay-presence degradation across current-schema restart', () => {
    const { statePath, store } = fixture();
    expect(store.getRuntimeHealth()).toEqual({ status: 'healthy', drivers: [] });

    store.recordDriverReconciliationFailure('pi', firstSeenAt, nextRetryAt);
    store.recordDriverReconciliationFailure('pi', lastSeenAt, nextRetryAt);
    store.recordRelayPresenceFailure(firstSeenAt, nextRetryAt);

    expect(store.getRuntimeHealth()).toEqual({
      status: 'degraded',
      drivers: [{
        driver: 'pi', code: 'driver_reconciliation_failed', count: 2,
        firstSeenAt, lastSeenAt, nextRetryAt,
      }],
      relayPresence: {
        code: 'relay_presence_refresh_failed', count: 1,
        firstSeenAt, lastSeenAt: firstSeenAt, nextRetryAt,
      },
    });
    expect(readFileSync(statePath, 'utf8')).not.toMatch(/error|stack|ciphertext|token|credential|path/iu);

    store.dispose();
    const restarted = new BridgeStateStore(statePath);
    expect(restarted.getRuntimeHealth()).toEqual({
      status: 'degraded',
      drivers: [{
        driver: 'pi', code: 'driver_reconciliation_failed', count: 2,
        firstSeenAt, lastSeenAt, nextRetryAt,
      }],
      relayPresence: {
        code: 'relay_presence_refresh_failed', count: 1,
        firstSeenAt, lastSeenAt: firstSeenAt, nextRetryAt,
      },
    });
    restarted.dispose();
  });

  test('successful reconciliation and presence refresh clear only their degradation', () => {
    const { store } = fixture();
    store.recordDriverReconciliationFailure('zeta', firstSeenAt, nextRetryAt);
    store.recordDriverReconciliationFailure('alpha', firstSeenAt, nextRetryAt);
    store.recordRelayPresenceFailure(firstSeenAt, nextRetryAt);
    expect(store.getRuntimeHealth().drivers.map((item) => item.driver)).toEqual(['alpha', 'zeta']);

    expect(store.recordDriverReconciliationSuccess('alpha')).toEqual({ count: 1 });
    expect(store.getRuntimeHealth()).toMatchObject({
      status: 'degraded',
      drivers: [{ driver: 'zeta' }],
      relayPresence: { code: 'relay_presence_refresh_failed' },
    });
    expect(store.recordRelayPresenceSuccess()).toEqual({ count: 1 });
    expect(store.recordDriverReconciliationSuccess('zeta')).toEqual({ count: 1 });
    expect(store.getRuntimeHealth()).toEqual({ status: 'healthy', drivers: [] });
  });

  test('fails closed on malformed or unbounded current health evidence', () => {
    const { statePath, store } = fixture();
    store.recordDriverReconciliationFailure('pi', firstSeenAt, nextRetryAt);
    store.dispose();
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    state.runtimeHealth.drivers[0].error = 'Bearer protected-token';
    writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
  });
});
