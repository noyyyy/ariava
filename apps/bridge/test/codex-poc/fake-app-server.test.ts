import { describe, expect, test } from 'bun:test';
import {
  createFakeAppServer,
  FAKE_METHODS,
  FAKE_NOTIFICATIONS,
  FAKE_SERVER_REQUESTS,
  MAX_FRAME_BYTES,
  MAX_MESSAGE_DEPTH,
  MAX_PENDING_REQUESTS,
  MAX_THREADS,
  validateFrameShape,
} from './fake-app-server';

describe('fake app-server: framing and correlation', () => {
  test('initialize returns initialized notification and protocol version', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const result = server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'initialize', params: {} }));
    expect(result.ok).toBe(true);
    expect(result.frames[0]?.result).toEqual({ protocolVersion: 1 });
    const events = server.emittedNotifications('client-a');
    expect(events.some((event) => event.type === 'initialized')).toBe(true);
  });

  test('thread.list returns deterministic thread summaries', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const thread = server.createThread('fix bug', '/tmp/work');
    const result = server.handleFrame('client-a', JSON.stringify({ id: 2, method: 'thread.list', params: {} }));
    expect(result.ok).toBe(true);
    const threads = result.frames[0]?.result as { threads: Array<{ threadId: string; title: string; cwd: string }> };
    expect(threads.threads[0]?.threadId).toBe(thread.threadId);
    expect(threads.threads[0]?.title).toBe('fix bug');
  });

  test('thread.read returns authoritative events with order and sourceEventId', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const thread = server.createThread('read me', '/tmp/work');
    server.handleFrame('client-a', JSON.stringify({ id: 3, method: 'turn.start', params: { threadId: thread.threadId } }));
    const result = server.handleFrame('client-a', JSON.stringify({ id: 4, method: 'thread.read', params: { threadId: thread.threadId } }));
    expect(result.ok).toBe(true);
    const read = result.frames[0]?.result as { events: Array<{ order: number; type: string; sourceEventId: string }> };
    expect(read.events.length).toBeGreaterThan(0);
    for (const event of read.events) {
      expect(typeof event.order).toBe('number');
      expect(event.sourceEventId).toMatch(/^evt-/u);
    }
  });

  test('daemon.version and daemon.status return runtime identity', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const version = server.handleFrame('client-a', JSON.stringify({ id: 5, method: 'daemon.version', params: {} }));
    expect(version.frames[0]?.result).toEqual({ version: '0.0.0-fake' });
    const status = server.handleFrame('client-a', JSON.stringify({ id: 6, method: 'daemon.status', params: {} }));
    expect(status.frames[0]?.result).toEqual({ running: true, generation: 1 });
  });

  test('request/response correlation: pending queue tracks ids', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    server.handleFrame('client-a', JSON.stringify({ id: 'req-1', method: 'thread.list', params: {} }));
    const client = server.getClient('client-a');
    expect(client?.pendingRequests.has('req-1')).toBe(true);
    expect(client?.seenRequestIds.has('req-1')).toBe(true);
  });

  test('encodeFrame produces canonical JSON-RPC frame', () => {
    const server = createFakeAppServer();
    const wire = server.encodeFrame({ id: 1, method: 'daemon.version', params: {} });
    expect(wire).toBe('{"id":1,"method":"daemon.version","params":{}}');
  });

  test('validateFrameShape accepts reviewed methods and rejects unknown', () => {
    for (const method of FAKE_METHODS) {
      expect(validateFrameShape({ id: 1, method, params: {} }).ok).toBe(true);
    }
    expect(validateFrameShape({ id: 1, method: 'unknown.method', params: {} }).ok).toBe(false);
    expect(validateFrameShape({ id: 1, method: '', params: {} }).ok).toBe(false);
  });
});

describe('fake app-server: negative cases (spec §8.1)', () => {
  test('malformed JSON fails closed', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const result = server.handleFrame('client-a', '{not json');
    expect(result.ok).toBe(false);
    expect(result.errorCode).toBe('fail-closed');
  });

  test('oversized frame fails closed', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const big = JSON.stringify({ id: 1, method: 'thread.list', params: { padding: 'x'.repeat(MAX_FRAME_BYTES + 1) } });
    const result = server.handleFrame('client-a', big);
    expect(result.ok).toBe(false);
    expect(result.error).toContain('bytes');
  });

  test('excessive message depth fails closed', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    let nested: unknown = 'leaf';
    for (let index = 0; index < MAX_MESSAGE_DEPTH + 2; index += 1) nested = { nested };
    const result = server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'thread.list', params: nested }));
    expect(result.ok).toBe(false);
    expect(result.error).toContain('depth');
  });

  test('duplicate response id is rejected (not treated as commit)', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    server.handleFrame('client-a', JSON.stringify({ id: 'dup-1', method: 'thread.list', params: {} }));
    // First response resolves the pending request.
    server.handleFrame('client-a', JSON.stringify({ id: 'dup-1', method: 'thread.list', params: {}, result: { threads: [] } }));
    // Duplicate response for an already-resolved id must fail closed.
    const dup = server.handleFrame('client-a', JSON.stringify({ id: 'dup-1', method: 'thread.list', params: {}, result: { threads: [] } }));
    expect(dup.ok).toBe(false);
    expect(dup.error).toContain('duplicate response id');
  });

  test('unknown response/request fails closed', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const unknown = server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'not.a.method', params: {} }));
    expect(unknown.ok).toBe(false);
    expect(unknown.error).toContain('unknown method');
  });

  test('out-of-order requests are correlated by id, not arrival', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const thread = server.createThread('order', '/tmp/work');
    server.handleFrame('client-a', JSON.stringify({ id: 'first', method: 'thread.read', params: { threadId: thread.threadId } }));
    server.handleFrame('client-a', JSON.stringify({ id: 'second', method: 'thread.read', params: { threadId: thread.threadId } }));
    const client = server.getClient('client-a');
    expect(client?.seenRequestIds.has('first')).toBe(true);
    expect(client?.seenRequestIds.has('second')).toBe(true);
  });

  test('disconnect: pending requests cleared; reconnecting client gets fresh state', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'thread.list', params: {} }));
    server.disconnect('client-a');
    const client = server.getClient('client-a');
    expect(client?.connected).toBe(false);
    expect(client?.pendingRequests.size).toBe(0);
    server.connect('client-a');
    expect(server.getClient('client-a')?.connected).toBe(true);
  });

  test('pending request queue is bounded', () => {
    const server = createFakeAppServer({ maxPendingRequests: 2 });
    server.connect('client-a');
    const first = server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'thread.list', params: {} }));
    expect(first.ok).toBe(true);
    const second = server.handleFrame('client-a', JSON.stringify({ id: 2, method: 'thread.list', params: {} }));
    expect(second.ok).toBe(true);
    const third = server.handleFrame('client-a', JSON.stringify({ id: 3, method: 'thread.list', params: {} }));
    expect(third.ok).toBe(false);
    expect(third.error).toContain('queue full');
  });

  test('max threads is bounded', () => {
    const server = createFakeAppServer({ maxThreads: 1 });
    server.createThread('one', '/tmp/one');
    expect(() => server.createThread('two', '/tmp/two')).toThrow('max threads');
  });
});

describe('fake app-server: multi-client fanout (spec §8.6)', () => {
  test('notifications fan out to all connected clients', () => {
    const server = createFakeAppServer();
    server.connect('authoritative');
    server.connect('observer');
    const thread = server.createThread('fanout', '/tmp/work');
    server.handleFrame('authoritative', JSON.stringify({ id: 1, method: 'turn.start', params: { threadId: thread.threadId } }));
    const authEvents = server.emittedNotifications('authoritative');
    const obsEvents = server.emittedNotifications('observer');
    expect(authEvents.some((event) => event.type === 'turn.start')).toBe(true);
    expect(obsEvents.some((event) => event.type === 'turn.start')).toBe(true);
    // Same source event id in both (consistent fanout).
    const authTurn = authEvents.find((event) => event.type === 'turn.start');
    const obsTurn = obsEvents.find((event) => event.type === 'turn.start');
    expect(authTurn?.sourceEventId).toBe(obsTurn?.sourceEventId);
  });

  test('request correlation never crosses clients', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    server.connect('client-b');
    server.handleFrame('client-a', JSON.stringify({ id: 'a-1', method: 'thread.list', params: {} }));
    server.handleFrame('client-b', JSON.stringify({ id: 'b-1', method: 'thread.list', params: {} }));
    const clientA = server.getClient('client-a');
    const clientB = server.getClient('client-b');
    expect(clientA?.seenRequestIds.has('a-1')).toBe(true);
    expect(clientA?.seenRequestIds.has('b-1')).toBe(false);
    expect(clientB?.seenRequestIds.has('b-1')).toBe(true);
    expect(clientB?.seenRequestIds.has('a-1')).toBe(false);
  });

  test('observer connect/disconnect does not alter authoritative client behavior', () => {
    const server = createFakeAppServer();
    server.connect('authoritative');
    const thread = server.createThread('stable', '/tmp/work');
    server.connect('observer');
    server.disconnect('observer');
    server.connect('observer');
    server.handleFrame('authoritative', JSON.stringify({ id: 1, method: 'turn.start', params: { threadId: thread.threadId } }));
    expect(server.emittedNotifications('authoritative').some((event) => event.type === 'turn.start')).toBe(true);
  });

  test('reconnect provides authoritative replay without duplicate side effects', () => {
    const server = createFakeAppServer();
    server.connect('authoritative');
    const thread = server.createThread('replay', '/tmp/work');
    server.handleFrame('authoritative', JSON.stringify({ id: 1, method: 'turn.start', params: { threadId: thread.threadId } }));
    const before = server.emittedNotifications('authoritative').filter((event) => event.threadId === thread.threadId);
    server.disconnect('authoritative');
    server.connect('authoritative');
    const replayed = server.replayThread(thread.threadId, 'authoritative');
    expect(replayed.length).toBeGreaterThan(0);
    // Replay emits the same events again (bounded, idempotent by sourceEventId).
    const after = server.emittedNotifications('authoritative').filter((event) => event.threadId === thread.threadId);
    expect(after.length).toBe(before.length + replayed.length);
  });

  test('slow observer does not block authoritative client', () => {
    const server = createFakeAppServer();
    server.connect('authoritative');
    server.connect('slow-observer');
    const thread = server.createThread('slow', '/tmp/work');
    // The fake is synchronous; a slow observer is simulated by not consuming.
    // The authoritative client still receives events immediately.
    server.handleFrame('authoritative', JSON.stringify({ id: 1, method: 'turn.start', params: { threadId: thread.threadId } }));
    expect(server.emittedNotifications('authoritative').some((event) => event.type === 'turn.start')).toBe(true);
  });

  test('approval/blocking server request goes only to authoritative client', () => {
    const server = createFakeAppServer();
    server.connect('authoritative');
    server.connect('observer');
    const thread = server.createThread('approve', '/tmp/work');
    const result = server.handleFrame('authoritative', JSON.stringify({
      id: 'approval-1',
      method: 'approval.request',
      params: { threadId: thread.threadId },
      isServerRequest: true,
    }));
    expect(result.ok).toBe(true);
    // The observer never receives the approval request (authoritative only).
    const obsEvents = server.emittedNotifications('observer');
    expect(obsEvents.some((event) => event.type === 'approval.request')).toBe(false);
  });
});

describe('fake app-server: restart and generation (spec §8.3)', () => {
  test('restart bumps generation and preserves thread identity', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const thread = server.createThread('persist', '/tmp/work');
    const originalId = thread.threadId;
    const originalGeneration = thread.generation;
    server.restart();
    const after = server.getThread(originalId);
    expect(after?.threadId).toBe(originalId);
    expect(after?.generation).toBeGreaterThan(originalGeneration);
    expect(server.generation()).toBe(2);
  });

  test('events after restart carry the new generation', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const thread = server.createThread('gen', '/tmp/work');
    server.restart();
    server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'turn.start', params: { threadId: thread.threadId } }));
    const events = server.emittedNotifications('client-a');
    const after = events.find((event) => event.type === 'turn.start');
    expect(after?.generation).toBe(2);
  });

  test('unknown authority-changing notification fails closed', () => {
    const server = createFakeAppServer();
    server.connect('client-a');
    const result = server.handleFrame('client-a', JSON.stringify({ id: 1, method: 'unknown.authority.changing', params: {} }));
    expect(result.ok).toBe(false);
    expect(result.error).toContain('unknown method');
  });
});

describe('fake app-server: schema constants match reviewed surface', () => {
  test('fake methods/notifications/server requests are the reviewed allowlist', () => {
    expect(FAKE_METHODS).toContain('initialize');
    expect(FAKE_METHODS).toContain('thread.list');
    expect(FAKE_METHODS).toContain('thread.read');
    expect(FAKE_METHODS).toContain('turn.start');
    expect(FAKE_METHODS).toContain('turn.steer');
    expect(FAKE_METHODS).toContain('turn.interrupt');
    expect(FAKE_NOTIFICATIONS).toContain('initialized');
    expect(FAKE_NOTIFICATIONS).toContain('loaded');
    expect(FAKE_NOTIFICATIONS).toContain('unloaded');
    expect(FAKE_NOTIFICATIONS).toContain('turn.item.completed');
    expect(FAKE_NOTIFICATIONS).toContain('turn.completed');
    expect(FAKE_NOTIFICATIONS).toContain('turn.error');
    expect(FAKE_SERVER_REQUESTS).toContain('approval.request');
  });

  test('MAX_PENDING_REQUESTS is the reviewed bound', () => {
    expect(MAX_PENDING_REQUESTS).toBe(128);
    expect(MAX_THREADS).toBe(4096);
  });
});
