import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeStateStore } from '../dist/state-store.js';

function legacyEvent(id) {
  return { eventId: id, hostId: 'host-test', sessionId: 'session', provider: 'pi', type: 'blocked', status: 'blocked',
    typeLabel: 'Blocked', assistantText: `MIGRATION_SECRET_${id}`, contextText: `MIGRATION_CONTEXT_${id}`, createdAt: '2026-07-20T00:00:00.000Z' };
}
function setup(events) {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-spool-migration-')); const statePath = join(dir, 'state.json');
  writeFileSync(statePath, JSON.stringify({ pendingEvents: events }), { mode: 0o600 }); chmodSync(statePath, 0o600);
  return { dir, statePath };
}

test('legacy pendingEvents migrate atomically to the independent encrypted spool', () => {
  const { dir, statePath } = setup([legacyEvent('event')]);
  try {
    const store = new BridgeStateStore(statePath); store.initializeEncryptedSpool('host-test', join(dir, 'identity.json'), 'linux');
    const state = readFileSync(statePath, 'utf8'); const spool = readFileSync(`${statePath}.spool.json`, 'utf8');
    assert.doesNotMatch(state, /pendingEvents|MIGRATION_SECRET|MIGRATION_CONTEXT/);
    assert.doesNotMatch(spool, /MIGRATION_SECRET|MIGRATION_CONTEXT/);
    assert.deepEqual(store.peekPendingEvents(), [legacyEvent('event')]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

for (const boundary of ['journaled', 'item-encrypted', 'item-journaled']) {
  test(`plaintext spool migration resumes after ${boundary} interruption without loss or duplication`, () => {
    const events = [legacyEvent('one'), legacyEvent('two')]; const { dir, statePath } = setup(events); let interrupted = false;
    try {
      const store = new BridgeStateStore(statePath);
      assert.throws(() => store.initializeEncryptedSpool('host-test', join(dir, 'identity.json'), 'linux', undefined, (phase) => {
        if (!interrupted && phase === boundary) { interrupted = true; throw new Error(`crash:${phase}`); }
      }), new RegExp(`crash:${boundary}`));
      const recovered = new BridgeStateStore(statePath);
      recovered.initializeEncryptedSpool('host-test', join(dir, 'identity.json'), 'linux');
      assert.deepEqual(recovered.peekPendingEvents().map((event) => event.eventId).sort(), ['one', 'two']);
      const state = readFileSync(statePath, 'utf8'); const spool = readFileSync(`${statePath}.spool.json`, 'utf8');
      assert.doesNotMatch(state, /pendingEvents|spoolMigration|MIGRATION_SECRET|MIGRATION_CONTEXT/);
      assert.doesNotMatch(spool, /MIGRATION_SECRET|MIGRATION_CONTEXT/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}
