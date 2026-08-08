import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeDaemon, RuntimeHealthLogger, loadBridgeConfig } from '../src/daemon';
import type { CanonicalSessionState } from '@ariava/protocol';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function session(sessionId: string, provider: string): CanonicalSessionState {
  return {
    sessionId, hostId: 'host-health', provider, projectName: 'project', nameText: sessionId,
    status: 'working', updatedAt: '2026-08-10T00:00:00.000Z',
  };
}

function daemonFixture(drivers: Array<{ name: string; listSessions(hostId: string): Promise<CanonicalSessionState[]> }>) {
  const root = join(tmpdir(), `bridge-health-daemon-${Date.now()}-${roots.length}`);
  roots.push(root); mkdirSync(root, { recursive: true, mode: 0o700 });
  const config = loadBridgeConfig();
  Object.assign(config, {
    hostId: 'host-health', hostPlatform: 'linux', runtimePlatform: 'linux', pollIntervalMs: 15_000,
    statePath: join(root, 'state.json'), configPath: join(root, 'config.json'), identityPath: join(root, 'identity.json'),
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  const daemon = new BridgeDaemon(config, drivers as never);
  (daemon as any).startupValidated = true;
  (daemon as any).registerHostPresence = async () => {};
  let manifests = 0;
  (daemon as any).flushCurrentSessionsSnapshot = async () => { manifests += 1; return true; };
  (daemon as any).flushPendingEvents = async () => 0;
  (daemon as any).flushPendingHandles = async () => 0;
  (daemon as any).pullAndHandleCommands = async () => [];
  return { daemon, store: (daemon as any).stateStore, manifests: () => manifests };
}

describe('Bridge daemon runtime health separation', () => {
  test('one failed driver retains its complete set and suppresses authoritative publication and work', async () => {
    let fail = false;
    const driver = { name: 'pi', async listSessions() { if (fail) throw new Error('Bearer credential-secret'); return [session('session-a', 'pi')]; } };
    const fx = daemonFixture([driver]);
    await fx.daemon.syncOnce();
    expect(fx.manifests()).toBe(1);

    fail = true;
    const result = await fx.daemon.syncOnce();
    expect(result).toMatchObject({ sessions: [{ sessionId: 'session-a' }], emittedEvents: [], flushedEvents: 0, flushedReads: 0, handledCommands: [] });
    expect(fx.manifests()).toBe(1);
    expect(fx.store.peekPendingEvents()).toEqual([]);
    expect(fx.store.listSessions().some((item: CanonicalSessionState) => item.sessionId.startsWith('driver:'))).toBe(false);
    expect(fx.store.getRuntimeHealth()).toMatchObject({ status: 'degraded', drivers: [{ driver: 'pi', count: 1 }] });
    fx.daemon.stop();
  });

  test('two failed drivers retain both complete sets and produce sorted bounded health', async () => {
    let fail = false;
    const alpha = { name: 'alpha', async listSessions() { if (fail) throw new Error('alpha credential'); return [session('alpha-old', 'alpha')]; } };
    const beta = { name: 'beta', async listSessions() { if (fail) throw new Error('beta credential'); return [session('beta-old', 'beta')]; } };
    const fx = daemonFixture([beta, alpha]);
    await fx.daemon.syncOnce();
    fail = true;
    await fx.daemon.syncOnce();
    expect(fx.manifests()).toBe(1);
    expect(new Set(fx.store.listSessions().map((item: CanonicalSessionState) => item.sessionId)))
      .toEqual(new Set(['alpha-old', 'beta-old']));
    expect(fx.store.getRuntimeHealth().drivers.map((item: { driver: string }) => item.driver)).toEqual(['alpha', 'beta']);
    expect(fx.store.peekPendingEvents()).toEqual([]);
    fx.daemon.stop();
  });

  test('healthy plus failing drivers never publish a partial manifest and recovery clears health once', async () => {
    let failBeta = false;
    const alpha = { name: 'alpha', async listSessions() { return [session('alpha-new', 'alpha')]; } };
    const beta = { name: 'beta', async listSessions() { if (failBeta) throw new Error('private token'); return [session('beta-old', 'beta')]; } };
    const fx = daemonFixture([alpha, beta]);
    await fx.daemon.syncOnce();
    failBeta = true;
    await fx.daemon.syncOnce();
    await fx.daemon.syncOnce();
    expect(fx.manifests()).toBe(1);
    expect(new Set(fx.store.listSessions().map((item: CanonicalSessionState) => item.sessionId))).toEqual(new Set(['alpha-new', 'beta-old']));
    expect(fx.store.getRuntimeHealth().drivers[0].count).toBe(2);

    failBeta = false;
    await fx.daemon.syncOnce();
    expect(fx.manifests()).toBe(2);
    expect(fx.store.getRuntimeHealth()).toEqual({ status: 'healthy', drivers: [] });
    fx.daemon.stop();
  });

  test('Relay presence failure is health-only and successful refresh clears it', async () => {
    const fx = daemonFixture([{ name: 'pi', async listSessions() { return []; } }]);
    let failPresence = true;
    (fx.daemon as any).registerHostPresence = async () => { if (failPresence) throw new Error('https://user:password@relay/private?token=secret'); };
    const failed = await fx.daemon.syncOnce();
    expect(failed).toMatchObject({ offline: true, emittedEvents: [], flushedEvents: 0, flushedReads: 0, handledCommands: [] });
    expect(fx.manifests()).toBe(0);
    expect(fx.store.peekPendingEvents()).toEqual([]);
    expect(fx.store.getRuntimeHealth()).toMatchObject({ status: 'degraded', drivers: [], relayPresence: { count: 1 } });

    failPresence = false;
    await fx.daemon.syncOnce();
    expect(fx.store.getRuntimeHealth()).toEqual({ status: 'healthy', drivers: [] });
    fx.daemon.stop();
  });

  test('structured runtime health logs omit thrown details, coalesce repeats, and log one recovery', () => {
    let now = 30_000;
    const lines: string[] = [];
    const logger = new RuntimeHealthLogger((line) => lines.push(line), () => now);
    logger.failure('driver', 'pi', 1);
    logger.failure('driver', 'pi', 2);
    now += 30_000;
    logger.failure('driver', 'pi', 3);
    logger.recovery('driver', 'pi', 3);
    logger.recovery('driver', 'pi', 3);

    expect(lines).toHaveLength(3);
    expect(lines[0]).toContain('"code":"driver_reconciliation_failed"');
    expect(lines[1]).toContain('"suppressed":1');
    expect(lines[2]).toContain('"outcome":"recovered"');
    expect(lines.join('')).not.toMatch(/Bearer|credential|password|secret|stack|ciphertext|path/iu);
  });
});
