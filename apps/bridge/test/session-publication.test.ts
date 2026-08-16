import { afterEach, describe, expect, mock, test } from 'bun:test';
import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CanonicalEvent, CanonicalSessionState } from '@ariava/protocol';

mock.module('../src/e2e/node-crypto', () => ({
  ChaChaPolyAuthenticationError: class ChaChaPolyAuthenticationError extends Error {},
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({ nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]) }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
  generateX25519KeyMaterial: () => ({ privateKeyPkcs8: new Uint8Array(48).fill(2), publicKeyRaw: new Uint8Array(32).fill(3) }),
  x25519SharedSecret: () => new Uint8Array(32).fill(4),
  hkdfSha256: () => new Uint8Array(32).fill(5),
}));

const { EncryptedUploadOrchestrator } = await import('../src/e2e/upload-orchestrator');
const { BridgeStateStore } = await import('../src/state-store');
const { RelayClientError } = await import('../src/relay-client');
const { BridgeDaemon, SessionPublicationBlockLogger, loadBridgeConfig } = await import('../src/daemon');
const { LinuxJsonHostIdentityStore, publicIdentityMetadata } = await import('../src/identity');

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function fixture() {
  const root = join(tmpdir(), `bridge-publication-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
  const store = new BridgeStateStore(join(root, 'state.json'));
  store.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  return store;
}

function terminalSession(overrides: Partial<CanonicalSessionState> = {}): CanonicalSessionState {
  return {
    sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'secret-project', nameText: 'Session',
    latestActivityText: 'terminal activity', workingDirectory: '/secret/project',
    harnessProvider: 'pi', status: 'idle', updatedAt: '2026-08-07T00:00:01.000Z',
    lastEventId: 'event-test', ...overrides,
  };
}

function doneEvent(overrides: Partial<CanonicalEvent> = {}): CanonicalEvent {
  return {
    eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'done', status: 'idle',
    agentText: 'terminal activity', projectName: 'secret-project',
    workingDirectory: '/secret/project', harnessProvider: 'pi',
    createdAt: '2026-08-07T00:00:01.000Z', ...overrides,
  } as CanonicalEvent;
}

const snapshotV1 = { version: 1 as const, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };

/** Realistic Session upload shape (EncryptedSessionSnapshotUploadV3) for inflight fixtures. */
function sessionUploadFixture(revision: number, recipientSetVersion = 1, sessionId = 'session-test'): Record<string, unknown> {
  return { hostId: 'host-test', sessionId, provider: 'pi', status: 'idle',
    updatedAt: '2026-08-07T00:00:01.000Z', revision, recipientSetVersion,
    content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: `session-c-${revision}`, payloadKind: 'session-content-v3',
      nonce: 'A'.repeat(16), ciphertext: 'B'.repeat(24) },
    keyWraps: [] };
}

function replaceSessionInflightRaw(store: BridgeStateStore, sessionId: string, plaintext: Uint8Array): void {
  (store as any).spool.replace([`inflight:session:${sessionId}`], [{
    spoolItemId: `inflight:session:${sessionId}`, sessionId, payloadKind: 'session-upload-v3',
    createdAt: '2026-08-07T00:00:01.000Z', plaintext,
  }]);
}

function readSessionInflightRaw(store: BridgeStateStore, sessionId: string): Uint8Array {
  const spool = (store as any).spool;
  return spool.open(spool.get(`inflight:session:${sessionId}`));
}

/** Marks the manifest as accepted at `recipientSetVersion` (required for §6.2 drain). */
function acceptManifestAt(store: BridgeStateStore, recipientSetVersion: number, revision = 1): void {
  store.setRecipientSetVersion(recipientSetVersion);
  store.acceptCurrentSessionsPublication({ hostId: 'host-block', revision, observedAt: '2026-08-07T00:00:01.000Z', recipientSetVersion, sessions: [] }, 'digest', 'content-digest');
}

describe('Authoritative Session publication §6.1', () => {
  test('an invalid Session blocks the whole manifest with zero mutation: no revision, no inflight, no publish, no manifest', async () => {
    const store = fixture();
    const invalid = terminalSession({ openingText: 'a'.repeat(64 * 1024) });
    store.replaceDriverSessions('pi', [invalid]);
    let publishes = 0; let reconciles = 0;
    const client = {
      publishEncryptedSession: async () => { publishes += 1; return { ok: true as const }; },
      reconcileEncryptedSession: async () => { reconciles += 1; return true; },
    };
    const orchestrator = new EncryptedUploadOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);

    const result = await orchestrator.publishAuthoritativeSnapshots(snapshotV1, [], [invalid]);

    expect(result).toEqual({ type: 'locally-blocked', reason: 'content' });
    expect(publishes).toBe(0);
    expect(reconciles).toBe(0);
    expect(store.currentSessionRevision('session-test')).toBe(0);
    expect(store.getInflightSessionUpload('session-test')).toBeUndefined();
    expect(store.getRecipientSetVersion()).toBeUndefined();
    // No Session dead-letter was introduced.
    expect(store.getQuarantinedEventRecord('event-test')).toBeUndefined();
  });

  test('full-set preflight counts every blocked Session and still does not mutate', () => {
    const store = fixture();
    const invalid = terminalSession({ openingText: 'a'.repeat(64 * 1024) });
    const valid = terminalSession({ sessionId: 'session-ok', lastEventId: undefined });
    store.replaceDriverSessions('pi', [invalid, valid]);
    const orchestrator = new EncryptedUploadOrchestrator(store, {} as any, { reconcileRecipients: () => [] } as any);
    expect(orchestrator.preflightAuthoritativeSessionSet([invalid, valid])).toBe(1);
    expect(store.currentSessionRevision('session-test')).toBe(0);
    expect(store.currentSessionRevision('session-ok')).toBe(0);
    expect(store.listInflightSessionIds()).toEqual([]);
  });

  test('keyring/crypto-style internal faults propagate and are never classified as a content block', async () => {
    const store = fixture();
    const invalid = terminalSession({ openingText: 'a'.repeat(64 * 1024) });
    store.replaceDriverSessions('pi', [invalid]);
    const client = { publishEncryptedSession: async () => { throw new Error('unexpected publish'); } };
    const orchestrator = new EncryptedUploadOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);
    // The immutable snapshot is authoritative: an internal source-access fault on
    // the supplied Session tuple propagates (fail-closed), never a content block.
    const faulty = terminalSession();
    Object.defineProperty(faulty, 'projectName', {
      get() { throw new TypeError('internal source access fault'); },
    });
    await expect(orchestrator.publishAuthoritativeSnapshots(snapshotV1, [], [faulty])).rejects.toThrow(TypeError);
    expect(store.listInflightSessionIds()).toEqual([]);
  });

  test('publication uses the single immutable snapshot even when the mutable store changes mid-pass', async () => {
    const store = fixture();
    const terminal = terminalSession({ openingText: 'snapshot-content' });
    store.replaceDriverSessions('pi', [terminal]);
    let publishes = 0; let reconciles = 0;
    const client = {
      publishEncryptedSession: async () => {
        // A heartbeat lands mid-pass: the store now holds different content than
        // the immutable snapshot the daemon supplied.
        store.updateSession('session-test', { openingText: 'newer-heartbeat-content', updatedAt: '2026-08-07T00:00:02.000Z' });
        publishes += 1;
        return { ok: true as const };
      },
      reconcileEncryptedSession: async () => { reconciles += 1; return false; },
    };
    const orchestrator = new EncryptedUploadOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);

    const result = await orchestrator.publishAuthoritativeSnapshots(snapshotV1, [], [terminal]);
    expect(result).toMatchObject({ type: 'published', recipientSetVersion: 1 });
    // Revision 1 was encrypted from the immutable snapshot and committed; the
    // mid-pass store mutation did not split the snapshot (no inflight existed,
    // so no reconcile round-trip was needed).
    expect({ publishes, reconciles }).toEqual({ publishes: 1, reconciles: 0 });
    expect(store.currentSessionRevision('session-test')).toBe(1);
  });

  test('§4.4 reconcile-first: a committed Session inflight completes the old revision before continuing with the current source', async () => {
    const store = fixture();
    const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]);
    // Simulate a crash window: an inflight at revision 1 that the Relay already accepted.
    store.persistInflightSessionUpload('session-test', sessionUploadFixture(1), 'A'.repeat(43));
    let publishes = 0; let reconciles = 0;
    const client = {
      publishEncryptedSession: async () => { publishes += 1; return { ok: true as const }; },
      reconcileEncryptedSession: async () => { reconciles += 1; return true; },
    };
    const orchestrator = new EncryptedUploadOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);

    const result = await orchestrator.publishAuthoritativeSnapshots(snapshotV1, [], [terminal]);

    expect(result).toMatchObject({ type: 'published', recipientSetVersion: 1 });
    expect(result?.type === 'published' && result.revisions.get('session-test')).toBe(2);
    expect({ publishes, reconciles }).toEqual({ publishes: 1, reconciles: 1 });
    // Old evidence completed first: revision 1 committed, inflight removed, then revision 2 published.
    expect(store.currentSessionRevision('session-test')).toBe(2);
    expect(store.getInflightSessionUpload('session-test')).toBeUndefined();
  });

  test('§4.4 reconcile-first: an uncommitted inflight that no longer matches the source digest is rebuilt keeping its approved revision', async () => {
    const store = fixture();
    const terminal = terminalSession({ openingText: 'changed content' });
    store.replaceDriverSessions('pi', [terminal]);
    store.commitSessionRevision('session-test', 1);
    store.commitSessionRevision('session-test', 2);
    store.persistInflightSessionUpload('session-test', sessionUploadFixture(3), 'B'.repeat(43));
    let publishes = 0; let reconciles = 0;
    const client = {
      publishEncryptedSession: async () => { publishes += 1; return { ok: true as const }; },
      reconcileEncryptedSession: async () => { reconciles += 1; return false; },
    };
    const orchestrator = new EncryptedUploadOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);

    const result = await orchestrator.publishAuthoritativeSnapshots(snapshotV1, [], [terminal]);

    expect(result).toMatchObject({ type: 'published', recipientSetVersion: 1 });
    // Digest mismatch (B*43 != current source) forces a rebuild at the inflight's revision 3 — never below it.
    expect(result?.type === 'published' && result.revisions.get('session-test')).toBe(3);
    expect({ publishes, reconciles }).toEqual({ publishes: 1, reconciles: 1 });
    expect(store.currentSessionRevision('session-test')).toBe(3);
  });

  test('§4.4 reconcile-first: an uncommitted inflight matching the current source digest is reused without re-encryption', async () => {
    const store = fixture();
    const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]);
    for (let revision = 1; revision <= 4; revision += 1) store.commitSessionRevision('session-test', revision);
    const { sessionSourceDigest } = await import('../src/e2e/upload-preflight');
    const digest = sessionSourceDigest(terminal);
    store.persistInflightSessionUpload('session-test', sessionUploadFixture(5), digest);
    let publishes = 0; let reconciles = 0;
    const client = {
      publishEncryptedSession: async () => { publishes += 1; return { ok: true as const }; },
      reconcileEncryptedSession: async () => { reconciles += 1; return false; },
    };
    const orchestrator = new EncryptedUploadOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);

    const result = await orchestrator.publishAuthoritativeSnapshots(snapshotV1, [], [terminalSession()]);

    expect(result).toMatchObject({ type: 'published', recipientSetVersion: 1 });
    expect(result?.type === 'published' && result.revisions.get('session-test')).toBe(5);
    expect({ publishes, reconciles }).toEqual({ publishes: 1, reconciles: 1 });
    expect(store.currentSessionRevision('session-test')).toBe(5);
  });

  test('reconciles active and orphan V2 Session evidence, committing exact accepted revisions', async () => {
    const store = fixture();
    const active = terminalSession();
    store.commitSessionRevision('session-test', 1);
    for (let revision = 1; revision <= 6; revision += 1) store.commitSessionRevision('session-orphan', revision);
    store.persistInflightSessionUpload('session-test', sessionUploadFixture(2), 'A'.repeat(43));
    store.persistInflightSessionUpload('session-orphan', sessionUploadFixture(7, 1, 'session-orphan'), 'B'.repeat(43));
    const seen: string[] = [];
    const orchestrator = new EncryptedUploadOrchestrator(store, {
      reconcileEncryptedSession: async (upload: any) => { seen.push(upload.sessionId); return true; },
    } as any, {} as any);
    expect(await orchestrator.reconcileSessionInflights([active])).toEqual({ deferred: false });
    expect(seen.sort()).toEqual(['session-orphan', 'session-test']);
    expect(store.currentSessionRevision('session-test')).toBe(2);
    expect(store.currentSessionRevision('session-orphan')).toBe(7);
    expect(store.listInflightSessionIds()).toEqual([]);
  });

  test('preserves explicitly uncommitted active evidence for publication but fails closed on orphan evidence', async () => {
    const store = fixture();
    store.persistInflightSessionUpload('session-test', sessionUploadFixture(2), 'A'.repeat(43));
    store.persistInflightSessionUpload('session-orphan', sessionUploadFixture(7, 1, 'session-orphan'), 'B'.repeat(43));
    const beforeActive = readSessionInflightRaw(store, 'session-test');
    const beforeOrphan = readSessionInflightRaw(store, 'session-orphan');
    const orchestrator = new EncryptedUploadOrchestrator(store, { reconcileEncryptedSession: async () => false } as any, {} as any);
    expect(await orchestrator.reconcileSessionInflights([terminalSession()])).toEqual({ deferred: true });
    expect(readSessionInflightRaw(store, 'session-test')).toEqual(beforeActive);
    expect(readSessionInflightRaw(store, 'session-orphan')).toEqual(beforeOrphan);
  });

  test('unknown Session V2 wrapper keys are recovery-required and byte-preserved', async () => {
    const store = fixture();
    store.persistInflightSessionUpload('session-test', sessionUploadFixture(2), 'A'.repeat(43));
    const wrapper = JSON.parse(new TextDecoder().decode(readSessionInflightRaw(store, 'session-test')));
    wrapper.unknown = true;
    const malformed = new TextEncoder().encode(JSON.stringify(wrapper));
    const expectedMalformed = malformed.slice();
    replaceSessionInflightRaw(store, 'session-test', malformed);
    let reconciles = 0;
    const orchestrator = new EncryptedUploadOrchestrator(store, { reconcileEncryptedSession: async () => { reconciles += 1; return true; } } as any, {} as any);
    expect(await orchestrator.reconcileSessionInflights([terminalSession()])).toEqual({ deferred: true });
    expect(reconciles).toBe(0);
    expect(readSessionInflightRaw(store, 'session-test')).toEqual(expectedMalformed);
  });
});

describe('SessionPublicationBlockLogger §6.3', () => {
  test('writes only the allow-listed fields, coalesces within the window, and recovers exactly once', () => {
    let now = 0; const lines: string[] = [];
    const logger = new SessionPublicationBlockLogger((line) => lines.push(line), () => now);

    logger.blocked(1);
    expect(JSON.parse(lines[0]!)).toEqual({ component: 'session_publication', outcome: 'blocked', code: 'protected_content_invalid', blockedSessionCount: 1, suppressed: 0 });
    logger.blocked(2);
    expect(lines).toHaveLength(1); // coalesced
    now = 30_001;
    logger.blocked(2);
    expect(JSON.parse(lines[1]!)).toMatchObject({ outcome: 'blocked', blockedSessionCount: 2, suppressed: 1 });
    // No disallowed fields ever appear.
    expect(JSON.stringify(lines)).not.toMatch(/sessionId|sessionId:|byte|exception|message|stack|ciphertext|keyWrap|driver|openingText/u);

    logger.recovered();
    expect(JSON.parse(lines[2]!)).toEqual({ component: 'session_publication', outcome: 'recovered', code: 'protected_content_invalid' });
    // A second recovered after no new block is suppressed (exactly once).
    logger.recovered();
    expect(lines).toHaveLength(3);
    // After recovery the suppression state is cleared; the next block logs immediately with suppressed 0.
    logger.blocked(1);
    expect(JSON.parse(lines[3]!)).toMatchObject({ outcome: 'blocked', blockedSessionCount: 1, suppressed: 0 });
  });
});

/** Daemon fixture with stubbed publication/event surfaces (like daemon-runtime-health). */
function daemonFixture(drivers: Array<{ name: string; listSessions(hostId: string): Promise<CanonicalSessionState[]> }>) {
  const root = join(tmpdir(), `bridge-block-daemon-${Date.now()}-${roots.length}`);
  roots.push(root); mkdirSync(root, { recursive: true, mode: 0o700 });
  const config = loadBridgeConfig();
  Object.assign(config, {
    hostId: 'host-block', hostPlatform: 'linux', runtimePlatform: 'linux', pollIntervalMs: 15_000,
    statePath: join(root, 'state.json'), configPath: join(root, 'config.json'), identityPath: join(root, 'identity.json'),
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  const daemon = new BridgeDaemon(config, drivers as never);
  (daemon as any).stateStore.initializeEncryptedSpool(config.hostId, config.identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  (daemon as any).startupValidated = true;
  (daemon as any).registerHostPresence = async () => {};
  (daemon as any).flushPendingHandles = async () => 0;
  (daemon as any).pullAndHandleCommands = async () => [];
  (daemon as any).reconcileRecipientsAndDrainReceipts = async () => 0;
  return { daemon, store: (daemon as any).stateStore };
}

describe('Bridge Event drain decoupling §6.2', () => {
  const driver = { name: 'pi', listSessions: async () => [terminalSession()] };

  async function drainProbe(outcome: any, prepare: (store: any) => void): Promise<number> {
    const fx = daemonFixture([driver]);
    let eventFlushes = 0;
    (fx.daemon as any).flushCurrentSessionsSnapshot = async () => outcome;
    (fx.daemon as any).flushPendingEvents = async () => { eventFlushes += 1; return 7; };
    prepare(fx.store);
    const result = await fx.daemon.syncOnce();
    fx.daemon.stop();
    expect(result.offline).toBe(outcome.type === 'deferred' && outcome.reason === 'network');
    return eventFlushes;
  }

  test('locally-blocked + stable accepted recipient version + no Session inflight lets legal Events drain', async () => {
    const flushes = await drainProbe({ type: 'locally-blocked', reason: 'content', blockedSessionCount: 1, recipientSetVersion: 1 },
      (store) => acceptManifestAt(store, 1));
    expect(flushes).toBe(1);
  });

  test('locally-blocked with recipient churn defers Events (fail closed)', async () => {
    const flushes = await drainProbe({ type: 'locally-blocked', reason: 'content', blockedSessionCount: 1, recipientSetVersion: 2 },
      (store) => acceptManifestAt(store, 1));
    expect(flushes).toBe(0);
  });

  test('locally-blocked with unconverged Session inflight defers Events', async () => {
    const flushes = await drainProbe({ type: 'locally-blocked', reason: 'content', blockedSessionCount: 1, recipientSetVersion: 1 },
      (store) => { acceptManifestAt(store, 1); store.persistInflightSessionUpload('session-test', sessionUploadFixture(1)); });
    expect(flushes).toBe(0);
  });

  test('locally-blocked after ciphertext commit but stale accepted manifest defers Events (no proven coverage)', async () => {
    // The Bridge adopted recipient version 2 (Session ciphertexts committed) but
    // the v2 manifest was never accepted — the last accepted manifest still proves
    // version 1 coverage only, so Events must not drain under the content block.
    const flushes = await drainProbe({ type: 'locally-blocked', reason: 'content', blockedSessionCount: 1, recipientSetVersion: 2 },
      (store) => { acceptManifestAt(store, 1); store.setRecipientSetVersion(2); });
    expect(flushes).toBe(0);
  });


  test('deferred and fail-closed outcomes never drain Events', async () => {
    expect(await drainProbe({ type: 'deferred', reason: 'network' }, () => {})).toBe(0);
    expect(await drainProbe({ type: 'deferred', reason: 'recipient-set' }, () => {})).toBe(0);
    expect(await drainProbe({ type: 'fail-closed' }, () => {})).toBe(0);
  });

  test('unexpected local publication faults fail closed without marking the Host offline', async () => {
    const fx = daemonFixture([driver]);
    let eventFlushes = 0; let handleFlushes = 0; let commandPulls = 0;
    (fx.daemon as any).flushCurrentSessionsSnapshot = async () => { throw new TypeError('local spool fault'); };
    (fx.daemon as any).flushPendingEvents = async () => { eventFlushes += 1; return 1; };
    (fx.daemon as any).flushPendingHandles = async () => { handleFlushes += 1; return 0; };
    (fx.daemon as any).pullAndHandleCommands = async () => { commandPulls += 1; return []; };
    const result = await fx.daemon.syncOnce();
    expect(result.offline).toBe(false);
    expect(eventFlushes).toBe(0);
    expect(handleFlushes).toBe(1);
    expect(commandPulls).toBe(1);
    fx.daemon.stop();
  });

  test('published outcomes drain Events (normal path unchanged)', async () => {
    expect(await drainProbe({ type: 'published' }, () => {})).toBe(1);
    expect(await drainProbe({ type: 'unchanged' }, () => {})).toBe(1);
  });

  test('unchanged content with active uncommitted inflight forces replacement publication before Event drain', async () => {
    const active = terminalSession({ hostId: 'host-block' });
    const fx = daemonFixture([{ name: 'pi', listSessions: async () => [active] }]);
    fx.store.commitSessionRevision(active.sessionId, 1);
    const accepted = await fx.store.createCurrentSessionsPublication(
      'host-block', [active], 1, '2026-08-07T00:00:01.000Z',
    );
    if (!accepted) throw new Error('expected initial publication');
    fx.store.setRecipientSetVersion(1);
    fx.store.acceptCurrentSessionsPublication(accepted.request, accepted.digest, accepted.contentDigest);
    const { sessionSourceDigest } = await import('../src/e2e/upload-preflight');
    fx.store.persistInflightSessionUpload(active.sessionId, sessionUploadFixture(2), sessionSourceDigest(active));
    const publishedSessions: any[] = []; const manifests: any[] = [];
    (fx.daemon as any).relayClient = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-block', recipientSetVersion: 1, recipients: [] }),
      reconcileEncryptedSession: async () => false,
      publishEncryptedSession: async (upload: any) => { publishedSessions.push(upload); },
      replaceE2ECurrentSessions: async (request: any) => { manifests.push(request); return { ok: true, hostId: request.hostId, revision: request.revision, activeSessionCount: request.sessions.length }; },
    };
    (fx.daemon as any).keyring = { reconcileRecipients: () => [] };
    (fx.daemon as any).encryptionIdentity = {};
    expect(await (fx.daemon as any).flushCurrentSessionsSnapshot([active])).toEqual({ type: 'published' });
    expect(publishedSessions).toHaveLength(1);
    expect(publishedSessions[0].revision).toBe(2);
    expect(manifests).toHaveLength(1);
    expect(manifests[0]).toMatchObject({ revision: 2, sessions: [{ sessionId: active.sessionId, sessionRevision: 2 }] });
    expect(fx.store.listInflightSessionIds()).toEqual([]);
    fx.daemon.stop();
  });
});

const servers: Array<{ stop(closeActiveConnections?: boolean): void }> = [];
afterEach(() => { for (const server of servers.splice(0)) server.stop(true); });

/** Real daemon against a fake Relay: content block → Event drain → recovery. */
describe('Bridge authoritative publication lifecycle §9.4', () => {
  test('an invalid Session suppresses the manifest, drains legal Events, and auto-recovers with monotonic revisions and one recovered log', async () => {
    const root = join(tmpdir(), `bridge-publication-e2e-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const identityStore = new LinuxJsonHostIdentityStore(identityPath);
    const identity = await identityStore.createFirstRun();
    let hostId = '';
    const sessionUploads: Array<{ sessionId: string; revision: number }> = [];
    const manifests: Array<{ revision: number; sessions: Array<{ sessionId: string; sessionRevision: number }> }> = [];
    const server = Bun.serve({ port: 0, fetch: async (request) => {
      const path = new URL(request.url).pathname;
      if (path === '/v2/bridge/enroll') return Response.json({ host: { hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
      if (path === '/v2/bridge/e2e/recipients') return Response.json({ hostId, recipientSetVersion: 1, recipients: [] });
      if (path === '/v2/bridge/e2e/sessions') { const body: any = await request.json(); sessionUploads.push({ sessionId: body.session.sessionId, revision: body.session.revision }); return Response.json({ ok: true }); }
      if (path === '/v2/bridge/e2e/sessions/current') { const body: any = await request.json(); manifests.push(body); return Response.json({ ok: true, hostId, revision: body.revision, activeSessionCount: body.sessions.length }); }
      if (path === '/v2/bridge/e2e/events') return Response.json({ ok: true });
      if (path === '/v2/bridge/commands/pull') return Response.json({ commands: [] });
      return Response.json({ ok: true });
    } });
    servers.push(server);
    const config = loadBridgeConfig();
    Object.assign(config, { runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId,
      identity: publicIdentityMetadata(identity), relayBaseUrl: `http://127.0.0.1:${server.port}`, configPath: join(root, 'config.json'),
      statePath: join(root, 'state.json'), identityPath, agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') } });
    hostId = identity.hostId;

    let sessionMode: 'first' | 'invalid' | 'fixed' = 'first';
    const driver = {
      name: 'pi',
      listSessions: async () => {
        if (sessionMode === 'invalid') return [{ ...active('session-a'), openingText: 'a'.repeat(64 * 1024) }];
        return [active('session-a', sessionMode === 'fixed' ? 'fixed activity' : 'first activity')];
      },
      executeCommand: async () => { throw new Error('unused'); },
    };
    function active(sessionId: string, latestActivityText = 'first activity'): CanonicalSessionState {
      return { sessionId, hostId, provider: 'pi', projectName: 'secret-project', nameText: `Session ${sessionId}`,
        latestActivityText, status: 'working', updatedAt: '2026-07-29T00:00:00.000Z' };
    }
    const daemon = new BridgeDaemon(config, [driver], identityStore);

    // Intercept stderr to observe the §6.3 logger lines.
    const stderrLines: string[] = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((line: unknown) => { stderrLines.push(String(line)); return true; }) as typeof process.stderr.write;
    try {
      // 1) First publication with valid content.
      const first = await daemon.syncOnce();
      expect(first.offline).toBe(false);
      expect(manifests).toHaveLength(1);
      expect(manifests[0]!.revision).toBe(1);

      // 2) Content becomes invalid: manifest suppressed, revision NOT allocated, Events still drain.
      sessionMode = 'invalid';
      (daemon as any).stateStore.queuePendingEvent(
        doneEvent({ hostId, createdAt: '2026-08-07T00:00:02.000Z' }),
        terminalSession({ hostId, updatedAt: '2026-08-07T00:00:02.000Z' }),
      );
      const manifestsBeforeBlock = manifests.length;
      const uploadsBeforeBlock = sessionUploads.length;
      const blocked = await daemon.syncOnce();
      expect(blocked.offline).toBe(false);
      expect(manifests.length).toBe(manifestsBeforeBlock);            // no manifest sent
      expect(sessionUploads.length).toBe(uploadsBeforeBlock);         // no Session upload
      const stateAfterBlock = JSON.parse(await (await import('node:fs/promises')).readFile(config.statePath, 'utf8'));
      expect(stateAfterBlock.currentSessionsSnapshot.lastAllocatedRevision).toBe(1); // no new allocation
      expect(blocked.flushedEvents).toBe(1);                           // legal Event drained under the block
      expect(manifests).toHaveLength(1);
      const blockedLogs = stderrLines.filter((line) => line.includes('"session_publication"') && line.includes('"blocked"'));
      expect(blockedLogs).toHaveLength(1);
      expect(JSON.parse(blockedLogs[0]!)).toMatchObject({ component: 'session_publication', outcome: 'blocked', code: 'protected_content_invalid', blockedSessionCount: 1 });
      expect(JSON.stringify(blockedLogs)).not.toMatch(/sessionId|byte|exception|message|ciphertext|key|driver|openingText/u);

      // 3) Content fixed with a changed digest: full publication auto-recovers, revision monotonic, one recovered log.
      sessionMode = 'fixed';
      const fixed = await daemon.syncOnce();
      expect(fixed.offline).toBe(false);
      expect(manifests).toHaveLength(2);
      expect(manifests[1]!.revision).toBe(2);
      expect(manifests[1]!.sessions[0]!.sessionRevision).toBe(2);
      const recoveredLogs = stderrLines.filter((line) => line.includes('"session_publication"') && line.includes('"recovered"'));
      expect(recoveredLogs).toHaveLength(1);
      // The next sync with unchanged content is 'unchanged' — no further recovered/blocked logs.
      await daemon.syncOnce();
      expect(stderrLines.filter((line) => line.includes('"session_publication"'))).toHaveLength(2);
    } finally {
      process.stderr.write = originalWrite as typeof process.stderr.write;
      daemon.stop();
    }
  });
});
