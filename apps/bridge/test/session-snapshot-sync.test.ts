import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeDaemon, loadBridgeConfig, type ReconciliationScheduler } from '../src/daemon';
import { LinuxJsonHostIdentityStore, publicIdentityMetadata } from '../src/identity';
import type { ActiveSessionSnapshot, CanonicalSessionState } from '@ariava/protocol';
import type { AgentDriver } from '../src/types';

const roots: string[] = [];
const servers: Array<{ stop(closeActiveConnections?: boolean): void }> = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function session(status: CanonicalSessionState['status'] = 'idle'): CanonicalSessionState {
  return {
    sessionId: 'sess-1', hostId: '', provider: 'test', projectName: 'project', nameText: 'Session',
    stateLabel: status === 'idle' ? 'Ready' : 'In progress', status, updatedAt: '2026-07-20T00:00:00.000Z',
  };
}

async function fixture(
  handler: (request: Request) => Response | Promise<Response>,
  driverInput?: (() => Promise<CanonicalSessionState[]>) | AgentDriver[],
  registryNow?: () => Date,
  reconciliationScheduler?: ReconciliationScheduler,
) {
  const root = join(tmpdir(), `bridge-snapshot-sync-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
  const identityPath = join(root, 'identity.json');
  const identityStore = new LinuxJsonHostIdentityStore(identityPath);
  const identity = await identityStore.createFirstRun();
  const server = Bun.serve({ port: 0, fetch: handler }); servers.push(server);
  const config = loadBridgeConfig();
  Object.assign(config, {
    runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, identity: publicIdentityMetadata(identity),
    relayBaseUrl: `http://127.0.0.1:${server.port}`, pollIntervalMs: 60_000,
    configPath: join(root, 'config.json'), statePath: join(root, 'state.json'), identityPath,
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  const drivers = Array.isArray(driverInput)
    ? driverInput
    : driverInput
      ? [{ name: 'test', listSessions: driverInput, executeCommand: async () => { throw new Error('unused'); } }]
      : undefined;
  const daemon = new BridgeDaemon(config, drivers, identityStore, registryNow, reconciliationScheduler);
  return { root, identity, config, identityStore, daemon };
}

function relay(handler: (request: Request) => Response | Promise<Response>) {
  return async (request: Request) => {
    const path = new URL(request.url).pathname;
    if (path === '/v2/bridge/enroll') {
      const body = await request.json() as { hostId: string };
      return Response.json({ host: { hostId: body.hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
    }
    if (path === '/v2/bridge/e2e/recipients') {
      return Response.json({ version: 1, hostId: 'test', recipientSetVersion: 1, recipients: [] });
    }
    if (path === '/v2/bridge/commands/pull') return Response.json({ commands: [] });
    return handler(request);
  };
}

async function waitUntil(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for condition');
    await Bun.sleep(10);
  }
}

class ManualReconciliationScheduler implements ReconciliationScheduler {
  private scheduled?: { callback: () => void; delayMs: number };

  schedule(callback: () => void, delayMs: number): unknown {
    if (this.scheduled) throw new Error('coalescing scheduled more than one timer');
    this.scheduled = { callback, delayMs };
    return this.scheduled;
  }

  cancel(handle: unknown): void {
    if (this.scheduled === handle) this.scheduled = undefined;
  }

  get pendingCount(): number { return this.scheduled ? 1 : 0; }
  get pendingDelayMs(): number | undefined { return this.scheduled?.delayMs; }

  fire(): void {
    const scheduled = this.scheduled;
    if (!scheduled) throw new Error('no reconciliation timer is scheduled');
    this.scheduled = undefined;
    scheduled.callback();
  }
}

describe('Bridge authoritative current-session reconciliation', () => {
  test('startup sends a complete snapshot and retries the exact pending request after restart', async () => {
    const bodies: unknown[] = [];
    let online = false;
    let hostId = '';
    const fx = await fixture(relay(async (request) => {
      if (new URL(request.url).pathname !== '/v2/bridge/sessions/current') return Response.json({ ok: true });
      const body = await request.json(); bodies.push(body);
      if (!online) return new Response('offline', { status: 503 });
      const snapshot = body as { hostId: string; revision: number; sessions: unknown[] };
      return Response.json({ ok: true, hostId: snapshot.hostId, revision: snapshot.revision, activeSessionCount: snapshot.sessions.length });
    }), async () => [{ ...session(), hostId }]);
    hostId = fx.identity.hostId;

    const first = await fx.daemon.syncOnce();
    expect(first.offline).toBe(true);
    const persisted = JSON.parse(readFileSync(fx.config.statePath, 'utf8')).currentSessionsSnapshot.pending.request;
    online = true;
    const restarted = new BridgeDaemon(fx.config, [{ name: 'test', listSessions: async () => [{ ...session(), hostId }], executeCommand: async () => { throw new Error('unused'); } }], fx.identityStore);
    expect((await restarted.syncOnce()).offline).toBe(false);
    expect(bodies.at(-1)).toEqual(persisted);
  });

  test('real Agent Adapter registry restart preserves the persisted Pi set until re-registration', async () => {
    const uploads: ActiveSessionSnapshot[][] = [];
    const fx = await fixture(relay(async (request) => {
      const body = await request.json() as { hostId: string; revision: number; sessions: ActiveSessionSnapshot[] };
      uploads.push(body.sessions);
      return Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: body.sessions.length });
    }));
    await fx.daemon.start();
    const { AgentAdapterClient: PiAdapterClient } = await import('../../../extensions/pi/src/adapter');
    const registration = {
      sessionId: 'sess-live-pi', provider: 'pi' as const, projectName: 'p', cwd: '/', nameText: 'Live Pi',
      stateLabel: 'In progress', status: 'working' as const, latestActivityText: 'Still running',
    };
    const piBeforeRestart = new PiAdapterClient({ baseUrl: fx.daemon.adapterUrl, secret: fx.config.agentAdapter.secret });
    await piBeforeRestart.registerSession(registration);
    await fx.daemon.syncOnce();
    expect(uploads.at(-1)?.map((item) => item.sessionId)).toEqual(['sess-live-pi']);
    fx.daemon.stop();

    const restarted = new BridgeDaemon(fx.config, undefined, fx.identityStore);
    await restarted.start();
    try {
      await restarted.syncOnce();
      expect(uploads.at(-1)?.map((item) => item.sessionId)).toEqual(['sess-live-pi']);
      expect(uploads).toHaveLength(1);

      const piAfterRestart = new PiAdapterClient({ baseUrl: restarted.adapterUrl, secret: fx.config.agentAdapter.secret });
      await piAfterRestart.heartbeat('sess-live-pi', 'working', 'Recovered after restart', registration);
      await restarted.syncOnce();
      expect(uploads.at(-1)).toMatchObject([{ sessionId: 'sess-live-pi', status: 'working', latestActivityText: 'Recovered after restart' }]);
    } finally {
      restarted.stop();
    }
  });

  test('offline mutations coalesce to the newest full set and stale response advances revision', async () => {
    let current: CanonicalSessionState[] = [];
    const uploaded: Array<{ revision: number; sessions: ActiveSessionSnapshot[] }> = [];
    let mode: 'offline' | 'stale' | 'online' = 'offline';
    let hostId = '';
    const fx = await fixture(relay(async (request) => {
      const body = await request.json() as { hostId: string; revision: number; sessions: ActiveSessionSnapshot[] };
      uploaded.push(body);
      if (mode === 'offline') return new Response('offline', { status: 503 });
      if (mode === 'stale') { mode = 'online'; return Response.json({ ok: false, code: 'session_snapshot_stale', hostId: body.hostId, acceptedRevision: 7 }, { status: 409 }); }
      return Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: body.sessions.length });
    }), async () => current.map((item) => ({ ...item, hostId })));
    hostId = fx.identity.hostId;

    current = [{ ...session(), hostId }]; await fx.daemon.syncOnce();
    current = []; await fx.daemon.syncOnce();
    mode = 'stale'; await fx.daemon.syncOnce();
    expect(uploaded.at(-1)?.revision).toBe(8);
    expect(uploaded.at(-1)?.sessions).toEqual([]);
  });

  test('preserves an established driver set when its next listing fails', async () => {
    const uploads: ActiveSessionSnapshot[][] = [];
    let fail = false; let hostId = '';
    const fx = await fixture(relay(async (request) => {
      if (new URL(request.url).pathname === '/v2/bridge/events') return Response.json({ ok: true });
      const body = await request.json() as { hostId: string; revision: number; sessions: ActiveSessionSnapshot[] };
      uploads.push(body.sessions);
      return Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: body.sessions.length });
    }), async () => { if (fail) throw new Error('driver unavailable'); return [{ ...session(), hostId }]; });
    hostId = fx.identity.hostId;
    await fx.daemon.syncOnce(); fail = true;
    const failed = await fx.daemon.syncOnce();
    expect(failed.sessions.map((item) => item.sessionId)).toEqual(['sess-1']);
    expect(uploads).toHaveLength(1);
    expect(uploads[0]?.map((item) => item.sessionId)).toEqual(['sess-1']);
  });

  test('first reconciliation skips publication when any driver has no established set', async () => {
    const uploads: ActiveSessionSnapshot[][] = []; let hostId = '';
    const drivers: AgentDriver[] = [
      { name: 'healthy', listSessions: async () => [{ ...session(), hostId }], executeCommand: async () => { throw new Error('unused'); } },
      { name: 'unknown-failing', listSessions: async () => { throw new Error('not yet available'); }, executeCommand: async () => { throw new Error('unused'); } },
    ];
    const fx = await fixture(relay(async (request) => {
      if (new URL(request.url).pathname === '/v2/bridge/events') return Response.json({ ok: true });
      const body = await request.json() as { sessions: ActiveSessionSnapshot[] }; uploads.push(body.sessions); return Response.json({ ok: true });
    }), drivers);
    hostId = fx.identity.hostId;
    const result = await fx.daemon.syncOnce();
    expect(result.sessions.map((item) => item.sessionId)).toEqual(['sess-1']);
    expect(uploads).toEqual([]);
    const state = JSON.parse(readFileSync(fx.config.statePath, 'utf8'));
    expect(state.currentSessionsSnapshot.pending).toBeUndefined();
  });

  test('excludes diagnostic sessions from the Bridge authoritative snapshot', async () => {
    let uploaded: ActiveSessionSnapshot[] = []; let hostId = '';
    const fx = await fixture(relay(async (request) => {
      const body = await request.json() as { hostId: string; revision: number; sessions: ActiveSessionSnapshot[] }; uploaded = body.sessions;
      return Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: body.sessions.length });
    }), async () => [{ ...session(), hostId }, { ...session(), sessionId: 'driver:test', hostId, provider: 'bridge', nameText: 'Diagnostic' }]);
    hostId = fx.identity.hostId; await fx.daemon.syncOnce();
    expect(uploaded.map((item) => item.sessionId)).toEqual(['sess-1']);
  });

  test('same-revision conflict is fail-closed and leaves the immutable request pending', async () => {
    const fx = await fixture(relay(async (request) => {
      const body = await request.json() as { hostId: string; revision: number };
      return Response.json({ ok: false, code: 'session_snapshot_conflict', hostId: body.hostId, acceptedRevision: body.revision }, { status: 409 });
    }), async () => []);
    await expect(fx.daemon.syncOnce()).rejects.toThrow('snapshot revision as conflicting');
    const pending = JSON.parse(readFileSync(fx.config.statePath, 'utf8')).currentSessionsSnapshot.pending;
    expect(pending.request.revision).toBe(1);
    expect(typeof pending.digest).toBe('string');
  });

  test('actual adapter mutations deterministically coalesce into one 300ms runForever wake and pure heartbeat stays quiet', async () => {
    const uploads: ActiveSessionSnapshot[][] = [];
    const scheduler = new ManualReconciliationScheduler();
    const fx = await fixture(relay(async (request) => {
      const body = await request.json() as { hostId: string; revision: number; sessions: ActiveSessionSnapshot[] }; uploads.push(body.sessions);
      return Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: body.sessions.length });
    }), undefined, undefined, scheduler);
    await fx.daemon.start(); const run = fx.daemon.runForever();
    try {
      await waitUntil(() => uploads.length === 1);
      const headers = { authorization: `Bearer ${fx.config.agentAdapter.secret}`, 'content-type': 'application/json' };
      for (const sessionId of ['sess-a', 'sess-b']) {
        const response = await fetch(`${fx.daemon.adapterUrl}/v1/agent/sessions`, { method: 'POST', headers, body: JSON.stringify({ sessionId, provider: 'pi', project: 'p', cwd: '/' }) });
        expect(response.status).toBe(201);
      }
      expect(scheduler.pendingCount).toBe(1);
      expect(scheduler.pendingDelayMs).toBe(300);
      expect(uploads).toHaveLength(1);
      scheduler.fire();
      await waitUntil(() => uploads.length === 2);
      expect(uploads[1]?.map((item) => item.sessionId).sort()).toEqual(['sess-a', 'sess-b']);
      const heartbeat = await fetch(`${fx.daemon.adapterUrl}/v1/agent/sessions/sess-a/heartbeat`, { method: 'POST', headers, body: JSON.stringify({ status: 'idle' }) });
      expect(heartbeat.status).toBe(200);
      expect(scheduler.pendingCount).toBe(0);
      expect(uploads).toHaveLength(2);
    } finally { fx.daemon.stop(); await run; }
  });

  test('authenticated DELETE uploads omission from the persisted authoritative set', async () => {
    const uploads: ActiveSessionSnapshot[][] = [];
    const fx = await fixture(relay(async (request) => {
      const body = await request.json() as { hostId: string; revision: number; sessions: ActiveSessionSnapshot[] }; uploads.push(body.sessions);
      return Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: body.sessions.length });
    }));
    await fx.daemon.start(); const run = fx.daemon.runForever();
    try {
      await waitUntil(() => uploads.length === 1);
      const headers = { authorization: `Bearer ${fx.config.agentAdapter.secret}`, 'content-type': 'application/json' };
      await fetch(`${fx.daemon.adapterUrl}/v1/agent/sessions`, { method: 'POST', headers, body: JSON.stringify({ sessionId: 'sess-delete', provider: 'pi', project: 'p', cwd: '/' }) });
      await waitUntil(() => uploads.length === 2);
      expect(uploads[1]?.map((item) => item.sessionId)).toEqual(['sess-delete']);
      const removed = await fetch(`${fx.daemon.adapterUrl}/v1/agent/sessions/sess-delete`, { method: 'DELETE', headers });
      expect(removed.status).toBe(200);
      await waitUntil(() => uploads.length === 3);
      expect(uploads[2]).toEqual([]);
    } finally { fx.daemon.stop(); await run; }
  });

  test('adapter mutation during an in-flight upload schedules a follow-up reconciliation', async () => {
    const uploads: ActiveSessionSnapshot[][] = []; let release!: () => void; let blocked = false;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const fx = await fixture(relay(async (request) => {
      const body = await request.json() as { hostId: string; revision: number; sessions: ActiveSessionSnapshot[] }; uploads.push(body.sessions);
      if (uploads.length === 2) { blocked = true; await gate; }
      return Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: body.sessions.length });
    }));
    await fx.daemon.start(); const run = fx.daemon.runForever();
    try {
      await waitUntil(() => uploads.length === 1);
      const headers = { authorization: `Bearer ${fx.config.agentAdapter.secret}`, 'content-type': 'application/json' };
      await fetch(`${fx.daemon.adapterUrl}/v1/agent/sessions`, { method: 'POST', headers, body: JSON.stringify({ sessionId: 'sess-a', provider: 'pi', project: 'p', cwd: '/' }) });
      await waitUntil(() => blocked);
      await fetch(`${fx.daemon.adapterUrl}/v1/agent/sessions`, { method: 'POST', headers, body: JSON.stringify({ sessionId: 'sess-b', provider: 'pi', project: 'p', cwd: '/' }) });
      release();
      await waitUntil(() => uploads.length === 3);
      expect(uploads[2]?.map((item) => item.sessionId).sort()).toEqual(['sess-a', 'sess-b']);
    } finally { release(); fx.daemon.stop(); await run; }
  });

  test('fake-clock TTL eviction uploads omission from the persisted authoritative set', async () => {
    const uploads: ActiveSessionSnapshot[][] = [];
    let now = new Date('2026-07-20T00:00:00.000Z');
    const fx = await fixture(relay(async (request) => {
      const body = await request.json() as { hostId: string; revision: number; sessions: ActiveSessionSnapshot[] }; uploads.push(body.sessions);
      return Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: body.sessions.length });
    }), undefined, () => now);
    await fx.daemon.start();
    try {
      await fx.daemon.syncOnce();
      const headers = { authorization: `Bearer ${fx.config.agentAdapter.secret}`, 'content-type': 'application/json' };
      await fetch(`${fx.daemon.adapterUrl}/v1/agent/sessions`, { method: 'POST', headers, body: JSON.stringify({ sessionId: 'sess-ttl', provider: 'pi', project: 'p', cwd: '/' }) });
      await fx.daemon.syncOnce();
      expect(uploads.at(-1)?.map((item) => item.sessionId)).toEqual(['sess-ttl']);
      now = new Date('2026-07-20T00:00:45.001Z');
      await fx.daemon.syncOnce();
      expect(uploads.at(-1)).toEqual([]);
    } finally { fx.daemon.stop(); }
  });

  test('concurrent sync calls are single-flight', async () => {
    let snapshotCalls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const fx = await fixture(relay(async (request) => {
      const body = await request.json() as { hostId: string; revision: number; sessions: unknown[] };
      snapshotCalls += 1; await gate;
      return Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: body.sessions.length });
    }), async () => []);
    const one = fx.daemon.syncOnce(); const two = fx.daemon.syncOnce();
    await Bun.sleep(20); expect(snapshotCalls).toBe(1);
    release(); await Promise.all([one, two]);
    expect(snapshotCalls).toBe(1);
  });
});
