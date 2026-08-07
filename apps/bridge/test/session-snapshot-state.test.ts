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
    stateLabel: status === 'idle' ? 'Ready' : 'In progress', status, updatedAt: '2026-07-20T00:00:00.000Z',
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
    expect(store.acceptCurrentSessionsPublication(first.request, 'digest-1', first.contentDigest)).toBe(true);
    expect(await store.createCurrentSessionsPublication('host-1', [makeSession()], 1, '2026-07-20T00:00:10.000Z')).toBeUndefined();

    store.noteCurrentSessionsSnapshotRevisionLowerBound(8);
    const next = await store.createCurrentSessionsPublication('host-1', [makeSession('working')], 1, '2026-07-20T00:00:11.000Z', 8);
    expect(next?.request.revision).toBe(9);
  });

  test('a lost publication result allocates a higher revision after restart', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const path = join(root, 'state.json');
    const first = (await new BridgeStateStore(path).createCurrentSessionsPublication(
      'host-1', [makeSession()], 1, '2026-07-20T00:00:01.000Z',
    ))!;
    const retried = await new BridgeStateStore(path).createCurrentSessionsPublication(
      'host-1', [makeSession()], 1, '2026-07-20T00:00:02.000Z',
    );
    expect(retried?.request.revision).toBe(first.request.revision + 1);
    expect(retried?.contentDigest).toBe(first.contentDigest);
  });

  test('recipient version alone allocates a higher lifecycle revision', async () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-snapshot-state-')); roots.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    const first = (await store.createCurrentSessionsPublication('host-1', [makeSession()], 1, '2026-07-20T00:00:01.000Z'))!;
    expect(store.acceptCurrentSessionsPublication(first.request, 'digest-1', first.contentDigest)).toBe(true);
    const changed = await store.createCurrentSessionsPublication('host-1', [makeSession()], 2, '2026-07-20T00:00:02.000Z');
    expect(changed?.request).toMatchObject({ revision: 2, recipientSetVersion: 2 });
  });
});
