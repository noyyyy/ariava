import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ActiveSessionSnapshot } from '@ariava/protocol';
import { BridgeStateStore } from '../src/state-store';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function makeSession(status: ActiveSessionSnapshot['status'] = 'idle'): ActiveSessionSnapshot {
  return {
    sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Session',
    stateLabel: status === 'idle' ? 'Ready' : 'In progress', status, updatedAt: '2026-07-20T00:00:00.000Z', presence: 'active',
  };
}

describe('Bridge current session snapshot state', () => {
  test('persists immutable pending request and monotonic revision across restart', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const path = join(root, 'state.json');
    const store = new BridgeStateStore(path);
    const first = await store.stageCurrentSessionsSnapshot('host-1', [makeSession()], '2026-07-20T00:00:01.000Z');
    expect(first?.request.revision).toBe(1);

    const reloaded = new BridgeStateStore(path);
    expect(reloaded.getPendingCurrentSessionsSnapshot()).toEqual(first);
    expect(JSON.parse(readFileSync(path, 'utf8')).currentSessionsSnapshot.pending.request).toEqual(first?.request);

    const second = await reloaded.stageCurrentSessionsSnapshot('host-1', [makeSession('working')], '2026-07-20T00:00:02.000Z');
    expect(second?.request.revision).toBe(2);
    expect(new BridgeStateStore(path).getPendingCurrentSessionsSnapshot()).toEqual(second);
  });

  test('does not allocate for accepted identical semantic content and honors stale lower bounds', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    const first = (await store.stageCurrentSessionsSnapshot('host-1', [makeSession()], '2026-07-20T00:00:01.000Z'))!;
    expect(store.acceptCurrentSessionsSnapshot(first.request.revision, first.digest)).toBe(true);
    expect(await store.stageCurrentSessionsSnapshot('host-1', [makeSession()], '2026-07-20T00:00:10.000Z')).toBeUndefined();

    store.noteCurrentSessionsSnapshotRevisionLowerBound(8);
    const next = await store.stageCurrentSessionsSnapshot('host-1', [makeSession('working')], '2026-07-20T00:00:11.000Z', 8);
    expect(next?.request.revision).toBe(9);
  });

  test('matching acceptance cannot clear a newer coalesced pending snapshot', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    const first = (await store.stageCurrentSessionsSnapshot('host-1', [makeSession()], '2026-07-20T00:00:01.000Z'))!;
    const latest = (await store.stageCurrentSessionsSnapshot('host-1', [makeSession('working')], '2026-07-20T00:00:02.000Z'))!;
    expect(store.acceptCurrentSessionsSnapshot(first.request.revision, first.digest)).toBe(false);
    expect(store.getPendingCurrentSessionsSnapshot()).toEqual(latest);
  });
});
