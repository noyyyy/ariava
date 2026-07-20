import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalEncryptedSpool, LinuxSpoolKeyStore } from '../dist/e2e/local-spool.js';

test('production Node seals local retry spool without plaintext persistence', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-node-spool-'));
  try {
    const path = join(dir, 'spool.json');
    const spool = new LocalEncryptedSpool(path, 'host-test', new LinuxSpoolKeyStore(join(dir, 'key.json')));
    spool.enqueue({ spoolItemId: 'item', sessionId: 'session', eventId: 'event', payloadKind: 'event-upload-v1',
      createdAt: '2026-07-20T00:00:00.000Z', plaintext: new TextEncoder().encode('NODE_SPOOL_SECRET_MARKER') });
    assert.doesNotMatch(readFileSync(path, 'utf8'), /NODE_SPOOL_SECRET_MARKER/);
    assert.equal(new TextDecoder().decode(spool.open(spool.list()[0])), 'NODE_SPOOL_SECRET_MARKER');
    assert.throws(() => spool.open({ ...spool.list()[0], sessionId: 'moved' }));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
