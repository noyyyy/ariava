import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LinuxJsonHostIdentityStore, resetHostIdentity, rotateHostIdentity } from '../src/identity';
import { RelayClientError } from '../src/relay-client';

const roots: string[] = [];
afterEach(() => { globalThis.fetch = originalFetch; roots.splice(0).forEach((r) => rmSync(r, { recursive: true, force: true })); });
const originalFetch = globalThis.fetch;

describe('Host rotation and reset lifecycle', () => {
  test('stages rotation before POST and recovers a lost response with pending key', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-rotation-')); roots.push(root);
    const store = new LinuxJsonHostIdentityStore(join(root, 'identity.json'));
    const current = await store.createFirstRun();
    let postSeen = false; let operationId = '';
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init); const url = new URL(request.url);
      if (request.method === 'POST') {
        postSeen = true;
        expect((await store.inspect()).status).toBe('rotation-pending');
        operationId = (await request.clone().json()).rotation.operationId;
        throw new Error('response lost');
      }
      if (url.pathname.endsWith(operationId) && postSeen) {
        const pending = await store.loadPending();
        expect(request.headers.get('x-ariava-key-id')).toBe(pending!.identity.keyId);
        return Response.json({ operationId, entityId: current.hostId, oldKeyId: current.keyId,
          newKeyId: pending!.identity.keyId, status: 'completed', completedAt: new Date().toISOString() });
      }
      return new Response('not found', { status: 404 });
    }) as typeof fetch;
    const result = await rotateHostIdentity(store, 'https://relay.test');
    expect(result.status).toBe('completed');
    expect((await store.inspect()).status).toBe('ready');
    expect((await store.load())!.hostId).toBe(current.hostId);
  });

  test('replays the old-key POST only after new-key recovery returns 404', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-recovery-replay-')); roots.push(root);
    const store = new LinuxJsonHostIdentityStore(join(root, 'identity.json'));
    const current = await store.createFirstRun();
    const seen: Array<{ method: string; keyId: string | null }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      seen.push({ method: request.method, keyId: request.headers.get('x-ariava-key-id') });
      if (request.method === 'GET') return new Response('not found', { status: 404 });
      const pending = await store.loadPending();
      return Response.json({ operationId: pending!.operationId, entityId: current.hostId, oldKeyId: current.keyId,
        newKeyId: pending!.identity.keyId, status: 'completed', completedAt: new Date().toISOString() });
    }) as typeof fetch;
    await rotateHostIdentity(store, 'https://relay.test');
    expect(seen[0]!.method).toBe('GET');
    expect(seen[0]!.keyId).not.toBe(current.keyId);
    expect(seen[1]).toEqual({ method: 'POST', keyId: current.keyId });
  });

  test('recovers a committed rotation after local promotion failure', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-promotion-recovery-')); roots.push(root);
    const durable = new LinuxJsonHostIdentityStore(join(root, 'identity.json'));
    const current = await durable.createFirstRun();
    let promotionFailuresRemaining = 2; let committed: any;
    const store = new Proxy(durable, { get(target, property) {
      if (property === 'promoteRotation') return async (operationId: string) => {
        if (promotionFailuresRemaining > 0) { promotionFailuresRemaining -= 1; throw new Error('disk full'); }
        return target.promoteRotation(operationId);
      };
      const value = (target as any)[property];
      return typeof value === 'function' ? value.bind(target) : value;
    } }) as typeof durable;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const pending = await durable.loadPending();
      if (request.method === 'POST') {
        committed = { operationId: pending!.operationId, entityId: current.hostId, oldKeyId: current.keyId,
          newKeyId: pending!.identity.keyId, status: 'completed', completedAt: new Date().toISOString() };
        return Response.json(committed);
      }
      return committed ? Response.json(committed) : new Response('not found', { status: 404 });
    }) as typeof fetch;
    await expect(rotateHostIdentity(store, 'https://relay.test')).rejects.toThrow('disk full');
    expect((await durable.inspect()).status).toBe('rotation-pending');
    const recovered = await rotateHostIdentity(store, 'https://relay.test');
    expect(recovered).toEqual(committed);
    expect((await durable.inspect()).status).toBe('ready');
  });

  test.each([
    ['operationId', (result: any) => ({ ...result, operationId: 'op_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })],
    ['entityId', (result: any) => ({ ...result, entityId: `host_${'Z'.repeat(43)}` })],
    ['oldKeyId', (result: any) => ({ ...result, oldKeyId: `key_${'Z'.repeat(43)}` })],
    ['newKeyId', (result: any) => ({ ...result, newKeyId: `key_${'Z'.repeat(43)}` })],
    ['status', (result: any) => ({ ...result, status: 'pending' })],
    ['missing completedAt', (result: any) => { const { completedAt: _, ...withoutCompletedAt } = result; return withoutCompletedAt; }],
    ['empty completedAt', (result: any) => ({ ...result, completedAt: '' })],
    ['completedAt without milliseconds', (result: any) => ({ ...result, completedAt: '2026-07-15T00:00:00Z' })],
    ['completedAt with offset', (result: any) => ({ ...result, completedAt: '2026-07-15T00:00:00.000+00:00' })],
  ])('fails closed on malformed rotation %s and preserves both keys', async (_field, mutate) => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-malformed-rotation-')); roots.push(root);
    const store = new LinuxJsonHostIdentityStore(join(root, 'identity.json'));
    const current = await store.createFirstRun();
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (request.method === 'GET') return new Response('missing', { status: 404 });
      const pending = await store.loadPending();
      const result = { operationId: pending!.operationId, entityId: current.hostId, oldKeyId: current.keyId,
        newKeyId: pending!.identity.keyId, status: 'completed', completedAt: new Date().toISOString() };
      return Response.json(mutate(result));
    }) as typeof fetch;
    await expect(rotateHostIdentity(store, 'https://relay.test')).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect((await store.load())!.keyId).toBe(current.keyId);
    expect(await store.loadPending()).not.toBeNull();
    expect((await store.inspect()).status).toBe('rotation-pending');
  });

  test.each([
    ['missing', undefined],
    ['empty', ''],
    ['noncanonical', '2026-07-15T00:00:00Z'],
  ])('rejects %s revokedAt and preserves the usable identity', async (_case, revokedAt) => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-malformed-revoke-')); roots.push(root);
    const store = new LinuxJsonHostIdentityStore(join(root, 'identity.json'));
    const current = await store.createFirstRun();
    globalThis.fetch = (async () => Response.json({ entityId: current.hostId, status: 'revoked', ...(revokedAt === undefined ? {} : { revokedAt }) })) as typeof fetch;
    await expect(resetHostIdentity(store, 'https://relay.test')).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect((await store.load())!.keyId).toBe(current.keyId);
    expect((await store.inspect()).status).toBe('ready');
  });

  test('never resets a usable identity on network or HTTP revoke errors', async () => {
    for (const response of ['network', 'http'] as const) {
      const root = mkdtempSync(join(tmpdir(), 'ariava-reset-')); roots.push(root);
      const store = new LinuxJsonHostIdentityStore(join(root, 'identity.json'));
      const before = await store.createFirstRun();
      globalThis.fetch = (async () => {
        if (response === 'network') throw new Error('offline');
        return new Response('denied', { status: 401 });
      }) as typeof fetch;
      await expect(resetHostIdentity(store, 'https://relay.test')).rejects.toBeInstanceOf(response === 'http' ? RelayClientError : Error);
      expect((await store.load())!.keyId).toBe(before.keyId);
    }
  });

  test('explicit reset repairs corrupt identity with warning and enrolls as a new zero-link host', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-reset-corrupt-')); roots.push(root);
    const path = join(root, 'identity.json');
    await new LinuxJsonHostIdentityStore(path).createFirstRun();
    await Bun.write(path, '{bad json');
    const store = new LinuxJsonHostIdentityStore(path);
    const result = await resetHostIdentity(store, 'https://relay.test');
    expect(result.revokedOldIdentity).toBe(false);
    expect(result.warning).toContain('ERR_IDENTITY_INVALID');
    expect(result.identity.hostId).toStartWith('host_');
    expect((await store.inspect()).status).toBe('ready');
  });
});
