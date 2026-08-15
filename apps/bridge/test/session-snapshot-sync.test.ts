import { afterEach, describe, expect, mock, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
mock.module('../src/e2e/node-crypto', () => ({
  ChaChaPolyAuthenticationError: class ChaChaPolyAuthenticationError extends Error {},
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({ nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]) }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
  generateX25519KeyMaterial: () => ({ privateKeyPkcs8: new Uint8Array(48).fill(2), publicKeyRaw: new Uint8Array(32).fill(3) }),
  x25519SharedSecret: () => new Uint8Array(32).fill(4),
  hkdfSha256: () => new Uint8Array(32).fill(5),
}));
const { BridgeDaemon, loadBridgeConfig } = await import('../src/daemon');
const { LinuxJsonHostIdentityStore, publicIdentityMetadata } = await import('../src/identity');

const roots: string[] = [];
const servers: Array<{ stop(closeActiveConnections?: boolean): void }> = [];
afterEach(() => { for (const server of servers.splice(0)) server.stop(true); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

async function fixture(handler: (request: Request) => Response | Promise<Response>, sessions: any[] = []) {
  const root = join(tmpdir(), `bridge-e2e-lifecycle-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
  const identityPath = join(root, 'identity.json'); const identityStore = new LinuxJsonHostIdentityStore(identityPath); const identity = await identityStore.createFirstRun();
  const server = Bun.serve({ port: 0, fetch: handler }); servers.push(server);
  const config = loadBridgeConfig(); Object.assign(config, { runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId,
    identity: publicIdentityMetadata(identity), relayBaseUrl: `http://127.0.0.1:${server.port}`, configPath: join(root, 'config.json'),
    statePath: join(root, 'state.json'), identityPath, agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') } });
  const driver = { name: 'pi', listSessions: async () => sessions.map((session) => ({ ...session, hostId: identity.hostId })), executeCommand: async () => { throw new Error('unused'); } };
  const daemon = new BridgeDaemon(config, [driver], identityStore);
  return { daemon, config, identity, driver };
}

const activeSession = (sessionId: string) => ({ sessionId, provider: 'pi', projectName: 'secret-project', nameText: `Session ${sessionId}`,
  latestActivityText: 'protected activity', status: 'working', updatedAt: '2026-07-29T00:00:00.000Z' });

function relay(hostId: string, lifecycle: (body: any) => Response) {
  return async (request: Request) => {
    const path = new URL(request.url).pathname;
    if (path === '/v2/bridge/enroll') return Response.json({ host: { hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
    if (path === '/v2/bridge/e2e/recipients') return Response.json({ hostId, recipientSetVersion: 1, recipients: [] });
    if (path === '/v2/bridge/e2e/sessions/current') return lifecycle(await request.json());
    if (path === '/v2/bridge/commands/pull') return Response.json({ commands: [] });
    return Response.json({ ok: true });
  };
}

describe('Bridge E2E authoritative current-session reconciliation', () => {
  test('empty startup convergence publishes a metadata-only lifecycle manifest', async () => {
    let body: any; let hostId = '';
    const fx = await fixture((request) => relay(hostId, (value) => { body = value; return Response.json({ ok: true, hostId: value.hostId, revision: value.revision, activeSessionCount: 0 }); })(request));
    hostId = fx.identity.hostId;
    expect((await fx.daemon.syncOnce()).offline).toBe(false);
    expect(body).toEqual({ hostId, revision: 1, observedAt: expect.any(String), recipientSetVersion: 1, sessions: [] });
    expect(JSON.stringify(body)).not.toMatch(/projectName|nameText|openingText|latestActivityText|actionablePrompt/);
  });

  test('process-style restart recomputes a higher revision after a network failure', async () => {
    const bodies: any[] = []; let online = false; let hostId = '';
    const fx = await fixture((request) => relay(hostId, (body) => { bodies.push(body); return online
      ? Response.json({ ok: true, hostId: body.hostId, revision: body.revision, activeSessionCount: 0 })
      : new Response('offline', { status: 503 }); })(request));
    hostId = fx.identity.hostId;
    expect((await fx.daemon.syncOnce()).offline).toBe(true);
    const afterFailure = JSON.parse(readFileSync(fx.config.statePath, 'utf8')).currentSessionsSnapshot;
    expect(afterFailure).toEqual({ version: 1, lastAllocatedRevision: 1, lastAcceptedRevision: 0 });
    online = true;
    fx.daemon.stop();
    const restartedIdentityStore = new LinuxJsonHostIdentityStore(fx.config.identityPath);
    const restarted = new BridgeDaemon(fx.config, [{ name: 'pi', listSessions: async () => [], executeCommand: async () => { throw new Error('unused'); } }], restartedIdentityStore);
    expect((await restarted.syncOnce()).offline).toBe(false);
    expect(bodies.map((body) => body.revision)).toEqual([1, 2]);
    expect(bodies[1]).toMatchObject({ hostId, recipientSetVersion: 1, sessions: [] });
  });

  test('skips encrypted publication without a recipient and publishes after readiness appears', async () => {
    let hostId = ''; let recipientReady = false; let recipientReads = 0; const manifests: any[] = [];
    const fx = await fixture(async (request) => {
      const path = new URL(request.url).pathname;
      if (path === '/v2/bridge/enroll') return Response.json({ host: { hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
      if (path === '/v2/bridge/e2e/recipients') {
        recipientReads += 1;
        return recipientReady
          ? Response.json({ hostId, recipientSetVersion: 1, recipients: [] })
          : Response.json({ error: 'e2e_recipient_not_ready' }, { status: 409 });
      }
      if (path === '/v2/bridge/e2e/sessions/current') {
        const body = await request.json() as any; manifests.push(body);
        return Response.json({ ok: true, hostId, revision: body.revision, activeSessionCount: 0 });
      }
      if (path === '/v2/bridge/commands/pull') return Response.json({ commands: [] });
      return Response.json({ ok: true });
    });
    hostId = fx.identity.hostId;

    expect((await fx.daemon.syncOnce()).offline).toBe(false);
    const waitingState = JSON.parse(readFileSync(fx.config.statePath, 'utf8')).currentSessionsSnapshot;
    expect(waitingState).toEqual({ version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 });
    expect(manifests).toEqual([]);
    expect((fx.daemon as any).reconciliationTimer).toBeUndefined();
    expect(recipientReads).toBe(3);

    recipientReady = true;
    expect((await fx.daemon.syncOnce()).offline).toBe(false);
    const publishedState = JSON.parse(readFileSync(fx.config.statePath, 'utf8')).currentSessionsSnapshot;
    expect(recipientReads).toBeGreaterThan(1);
    expect(manifests).toHaveLength(1);
    expect(manifests[0]).toEqual({ hostId, revision: 1, observedAt: expect.any(String), recipientSetVersion: 1, sessions: [] });
    expect(publishedState).toMatchObject({ version: 1, lastAllocatedRevision: 1, lastAcceptedRevision: 1 });
    expect((fx.daemon as any).currentSessionsSnapshotFailureCount).toBe(0);
  });

  test('stale Host revision rebuilds only the Host revision domain', async () => {
    const revisions: number[] = []; let first = true; let hostId = '';
    const fx = await fixture((request) => relay(hostId, (body) => { revisions.push(body.revision); if (first) { first = false; return Response.json({ ok: false, code: 'session_snapshot_stale', hostId, acceptedRevision: 7 }, { status: 409 }); }
      return Response.json({ ok: true, hostId, revision: body.revision, activeSessionCount: 0 }); })(request));
    hostId = fx.identity.hostId;
    expect((await fx.daemon.syncOnce()).offline).toBe(false);
    expect(revisions).toEqual([1, 8]);
  });

  test('uploads every distinct active encrypted Session before an exact manifest and suppresses manifest on upload failure', async () => {
    const paths: string[] = []; const uploads: Array<{ sessionId: string; revision: number }> = []; let manifest: any; let failSecond = true; let hostId = '';
    const fx = await fixture(async (request) => {
      const path = new URL(request.url).pathname; paths.push(path);
      if (path === '/v2/bridge/enroll') return Response.json({ host: { hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
      if (path === '/v2/bridge/e2e/recipients') return Response.json({ hostId, recipientSetVersion: 1, recipients: [] });
      if (path === '/v2/bridge/e2e/sessions') { const body: any = await request.json(); uploads.push({ sessionId: body.session.sessionId, revision: body.session.revision }); if (failSecond && body.session.sessionId === 'session-b') return new Response('failed', { status: 503 }); return Response.json({ ok: true }); }
      if (path === '/v2/bridge/e2e/sessions/current') { manifest = await request.json(); return Response.json({ ok: true, hostId, revision: manifest.revision, activeSessionCount: manifest.sessions.length }); }
      if (path === '/v2/bridge/commands/pull') return Response.json({ commands: [] });
      return Response.json({ ok: true });
    }, [activeSession('session-a'), activeSession('session-b')]); hostId = fx.identity.hostId;
    expect((await fx.daemon.syncOnce()).offline).toBe(true);
    expect(paths).not.toContain('/v2/bridge/e2e/sessions/current');
    failSecond = false; paths.length = 0; uploads.length = 0;
    expect((await fx.daemon.syncOnce()).offline).toBe(false);
    const manifestIndex = paths.indexOf('/v2/bridge/e2e/sessions/current');
    expect(manifestIndex).toBeGreaterThan(0);
    expect(paths.slice(0, manifestIndex).filter((path) => path === '/v2/bridge/e2e/sessions')).toHaveLength(2);
    expect(uploads).toHaveLength(2);
    expect(new Set(uploads.map((item) => item.sessionId))).toEqual(new Set(['session-a', 'session-b']));
    expect(manifest.sessions).toEqual(uploads.map((item) => ({ sessionId: item.sessionId, sessionRevision: item.revision })));
  });

  test('recipient churn revisits earlier Sessions and manifests only final-version revisions', async () => {
    const uploads: Array<{ sessionId: string; revision: number; recipientSetVersion: number }> = []; let version = 1; let churned = false; let manifest: any; let hostId = '';
    const fx = await fixture(async (request) => {
      const path = new URL(request.url).pathname;
      if (path === '/v2/bridge/enroll') return Response.json({ host: { hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
      if (path === '/v2/bridge/e2e/recipients') return Response.json({ hostId, recipientSetVersion: version, recipients: [] });
      if (path === '/v2/bridge/e2e/sessions') { const body: any = await request.json(); const item = body.session; uploads.push({ sessionId: item.sessionId, revision: item.revision, recipientSetVersion: item.recipientSetVersion });
        if (!churned && item.sessionId === 'session-b') { churned = true; version = 2; return Response.json({ ok: false, code: 'e2e_recipient_set_changed' }, { status: 409 }); } return Response.json({ ok: true }); }
      if (path === '/v2/bridge/e2e/sessions/reconcile') return Response.json({ committed: false });
      if (path === '/v2/bridge/e2e/sessions/current') { manifest = await request.json(); return Response.json({ ok: true, hostId, revision: manifest.revision, activeSessionCount: 2 }); }
      if (path === '/v2/bridge/commands/pull') return Response.json({ commands: [] }); return Response.json({ ok: true });
    }, [activeSession('session-a'), activeSession('session-b')]); hostId = fx.identity.hostId;
    expect((await fx.daemon.syncOnce()).offline).toBe(false);
    expect(uploads.filter((item) => item.sessionId === 'session-a').map((item) => item.recipientSetVersion)).toEqual([1, 2]);
    expect(manifest.recipientSetVersion).toBe(2);
    for (const member of manifest.sessions) expect(uploads).toContainEqual({ sessionId: member.sessionId, revision: member.sessionRevision, recipientSetVersion: 2 });
  });

  test('same recipient-version conflict fails closed without submitting a manifest or spinning', async () => {
    let hostId = ''; let recipientReads = 0; let uploads = 0; let reconciles = 0; let manifests = 0;
    const fx = await fixture(async (request) => {
      const path = new URL(request.url).pathname;
      if (path === '/v2/bridge/enroll') return Response.json({ host: { hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
      if (path === '/v2/bridge/e2e/recipients') { recipientReads += 1; return Response.json({ hostId, recipientSetVersion: 1, recipients: [] }); }
      if (path === '/v2/bridge/e2e/sessions') { uploads += 1; return Response.json({ ok: false, code: 'e2e_recipient_set_changed' }, { status: 409 }); }
      if (path === '/v2/bridge/e2e/sessions/reconcile') { reconciles += 1; return Response.json({ committed: false }); }
      if (path === '/v2/bridge/e2e/sessions/current') { manifests += 1; return Response.json({ ok: true }); }
      if (path === '/v2/bridge/commands/pull') return Response.json({ commands: [] }); return Response.json({ ok: true });
    }, [activeSession('session-a')]); hostId = fx.identity.hostId;
    expect((await fx.daemon.syncOnce()).offline).toBe(true);
    expect({ recipientReads, uploads, reconciles, manifests }).toEqual({ recipientReads: 3, uploads: 1, reconciles: 1, manifests: 0 });
  });

  test('invalid finalized references rebuild all active Sessions under a higher Host revision', async () => {
    const manifests: any[] = []; const uploads: any[] = []; let hostId = '';
    const fx = await fixture(async (request) => {
      const path = new URL(request.url).pathname;
      if (path === '/v2/bridge/enroll') return Response.json({ host: { hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
      if (path === '/v2/bridge/e2e/recipients') return Response.json({ hostId, recipientSetVersion: 1, recipients: [] });
      if (path === '/v2/bridge/e2e/sessions') { uploads.push((await request.json() as any).session); return Response.json({ ok: true }); }
      if (path === '/v2/bridge/e2e/sessions/current') { const body: any = await request.json(); manifests.push(body); if (manifests.length === 1) return Response.json({ ok: false, code: 'e2e_session_reference_invalid', hostId }, { status: 409 }); return Response.json({ ok: true, hostId, revision: body.revision, activeSessionCount: 1 }); }
      if (path === '/v2/bridge/commands/pull') return Response.json({ commands: [] }); return Response.json({ ok: true });
    }, [activeSession('session-a')]); hostId = fx.identity.hostId;
    expect((await fx.daemon.syncOnce()).offline).toBe(false);
    expect(manifests.map((item) => item.revision)).toEqual([1, 2]);
    expect(uploads.map((item) => item.revision)).toEqual([1, 2]);
    expect(manifests[1].sessions[0].sessionRevision).toBe(2);
  });

  test('process-style restart restores a non-empty partial-upload spool and completes the exact manifest', async () => {
    const uploads: Array<{ sessionId: string; revision: number }> = []; let manifest: any; let failSecond = true; let hostId = '';
    const fx = await fixture(async (request) => {
      const path = new URL(request.url).pathname;
      if (path === '/v2/bridge/enroll') return Response.json({ host: { hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
      if (path === '/v2/bridge/e2e/recipients') return Response.json({ hostId, recipientSetVersion: 1, recipients: [] });
      if (path === '/v2/bridge/e2e/sessions') { const body: any = await request.json(); uploads.push({ sessionId: body.session.sessionId, revision: body.session.revision }); if (failSecond && body.session.sessionId === 'session-b') return new Response('offline', { status: 503 }); return Response.json({ ok: true }); }
      if (path === '/v2/bridge/e2e/sessions/current') { manifest = await request.json(); return Response.json({ ok: true, hostId, revision: manifest.revision, activeSessionCount: manifest.sessions.length }); }
      if (path === '/v2/bridge/commands/pull') return Response.json({ commands: [] }); return Response.json({ ok: true });
    }, [activeSession('session-a'), activeSession('session-b')]); hostId = fx.identity.hostId;
    expect((await fx.daemon.syncOnce()).offline).toBe(true);
    expect((fx.daemon as any).stateStore.listInflightSessionIds()).toEqual(['session-b']);
    failSecond = false; uploads.length = 0;
    fx.daemon.stop();
    const restartedIdentityStore = new LinuxJsonHostIdentityStore(fx.config.identityPath);
    const restartedDriver = { name: 'pi', listSessions: async () => [activeSession('session-a'), activeSession('session-b')].map((session) => ({ ...session, hostId })), executeCommand: async () => { throw new Error('unused'); } };
    const restarted = new BridgeDaemon(fx.config, [restartedDriver], restartedIdentityStore);
    await (restarted as any).validateStartup();
    expect((restarted as any).stateStore.listInflightSessionIds()).toEqual(['session-b']);
    expect((await restarted.syncOnce()).offline).toBe(false);
    expect((restarted as any).encryptionIdentity).toBeDefined();
    expect((restarted as any).keyring).toBeDefined();
    expect(new Set(uploads.map((item) => item.sessionId))).toEqual(new Set(['session-a', 'session-b']));
    expect(manifest.sessions).toEqual(uploads.map((item) => ({ sessionId: item.sessionId, sessionRevision: item.revision })));
  });
});
