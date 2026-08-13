import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CanonicalSessionState } from '@ariava/protocol';
import { BridgeStateStore } from '../src/state-store';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function makeSession(status: CanonicalSessionState['status'] = 'idle'): CanonicalSessionState {
  return {
    sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Session',
    status, updatedAt: '2026-07-20T00:00:00.000Z',
  };
}

describe('Bridge current session snapshot state', () => {
  test('persists only the revision cursor while publication data stays in memory', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const path = join(root, 'state.json');
    const store = new BridgeStateStore(path);
    const first = await store.createCurrentSessionsPublication('host-1', [makeSession()], 1, '2026-07-20T00:00:01.000Z');
    expect(first?.request.revision).toBe(1);
    expect(first?.contentDigest).toBeString();
    expect(JSON.parse(readFileSync(path, 'utf8')).currentSessionsSnapshot).toEqual({
      version: 1, lastAllocatedRevision: 1, lastAcceptedRevision: 0,
    });

    store.dispose();
    const reloaded = new BridgeStateStore(path);
    const second = await reloaded.createCurrentSessionsPublication('host-1', [makeSession('working')], 1, '2026-07-20T00:00:02.000Z');
    expect(second?.request.revision).toBe(2);
    const persisted = JSON.parse(readFileSync(path, 'utf8')).currentSessionsSnapshot;
    expect(persisted).toEqual({ version: 1, lastAllocatedRevision: 2, lastAcceptedRevision: 0 });
    expect(persisted).not.toHaveProperty('pending');
    expect(persisted).not.toHaveProperty('request');
  });

  test('does not allocate for accepted identical semantic content and honors stale lower bounds', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    const first = (await store.createCurrentSessionsPublication('host-1', [makeSession()], 1, '2026-07-20T00:00:01.000Z'))!;
    store.setRecipientSetVersion(1);
    expect(store.acceptCurrentSessionsPublication(first.request, 'digest-1', first.contentDigest)).toBe(true);
    expect(await store.createCurrentSessionsPublication('host-1', [makeSession()], 1, '2026-07-20T00:00:10.000Z')).toBeUndefined();

    store.noteCurrentSessionsSnapshotRevisionLowerBound(8);
    expect(store.getCurrentSessionsSnapshotState()).toMatchObject({
      lastAllocatedRevision: 8, lastAcceptedRevision: 1, lastAcceptedDigest: 'digest-1',
      lastAcceptedContentDigest: first.contentDigest, lastAcceptedRecipientSetVersion: 1,
    });
    const next = await store.createCurrentSessionsPublication('host-1', [makeSession('working')], 1, '2026-07-20T00:00:11.000Z', 8);
    expect(next?.request.revision).toBe(9);
  });

  test('rejects accepted publication evidence before its recipient set is locally committed', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    const publication = (await store.createCurrentSessionsPublication(
      'host-1', [makeSession()], 1, '2026-07-20T00:00:01.000Z',
    ))!;
    expect(() => store.acceptCurrentSessionsPublication(publication.request, 'digest-1', publication.contentDigest))
      .toThrow('recipient set is not locally committed');
    expect(store.getCurrentSessionsSnapshotState().lastAcceptedRevision).toBe(0);
  });

  test('a lost publication result allocates a higher revision after restart', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const path = join(root, 'state.json');
    const firstStore = new BridgeStateStore(path);
    const first = (await firstStore.createCurrentSessionsPublication(
      'host-1', [makeSession()], 1, '2026-07-20T00:00:01.000Z',
    ))!;
    firstStore.dispose();
    const retriedStore = new BridgeStateStore(path);
    const retried = await retriedStore.createCurrentSessionsPublication(
      'host-1', [makeSession()], 1, '2026-07-20T00:00:02.000Z',
    );
    expect(retried?.request.revision).toBe(first.request.revision + 1);
    expect(retried?.contentDigest).toBe(first.contentDigest);
  });

  test('stale lower bounds never fabricate accepted evidence on fresh or restarted state', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const path = join(root, 'state.json');
    const fresh = new BridgeStateStore(path);
    fresh.noteCurrentSessionsSnapshotRevisionLowerBound(7);
    expect(fresh.getCurrentSessionsSnapshotState()).toEqual({
      version: 1, lastAllocatedRevision: 7, lastAcceptedRevision: 0,
    });
    fresh.dispose();
    const restarted = new BridgeStateStore(path);
    expect(restarted.getCurrentSessionsSnapshotState()).toEqual({
      version: 1, lastAllocatedRevision: 7, lastAcceptedRevision: 0,
    });
    const retry = await restarted.createCurrentSessionsPublication(
      'host-1', [makeSession()], 1, '2026-07-20T00:00:12.000Z',
    );
    expect(retry?.request.revision).toBe(8);
    expect(restarted.getCurrentSessionsSnapshotState().lastAcceptedRevision).toBe(0);
  });

  test('recipient version alone allocates a higher lifecycle revision', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    const first = (await store.createCurrentSessionsPublication('host-1', [makeSession()], 1, '2026-07-20T00:00:01.000Z'))!;
    store.setRecipientSetVersion(1);
    expect(store.acceptCurrentSessionsPublication(first.request, 'digest-1', first.contentDigest)).toBe(true);
    const changed = await store.createCurrentSessionsPublication('host-1', [makeSession()], 2, '2026-07-20T00:00:02.000Z');
    expect(changed?.request).toMatchObject({ revision: 2, recipientSetVersion: 2 });
  });
});
