import test from 'node:test';
import assert from 'node:assert/strict';
import vectors from '../../../packages/protocol/test/fixtures/e2e-v2-vectors.json' with { type: 'json' };
import { base64UrlDecode, E2E_SUITE_V1 } from '../../../packages/protocol/dist/index.js';
import { decryptReplyForPin, encryptEventUpload } from '../dist/e2e/envelope.js';

const hostIdentity = { version: 1, hostId: vectors.link.hostId,
  encryptionKeyId: vectors.bindings.host.encryptionKeyId, publicKey: vectors.keys.hostPublicKey,
  privateKeyPkcs8: base64UrlDecode(vectors.keys.hostPrivateKeyPkcs8), sequence: 1,
  createdAt: '2026-07-20T00:00:00.000Z' };

test('decrypts the reviewed encrypted reply vector only with matching AAD and pin material', () => {
    const command = { commandId: 'command_vector_01', hostId: vectors.link.hostId,
      sessionId: 'session_vector_01', type: 'reply', targetAlertEventId: 'event_vector_01',
      issuedAt: '2026-07-20T00:00:02.000Z', expiresAt: '2026-07-20T00:05:02.000Z', nonce: 'nonce_vector_01',
      watchDeviceId: vectors.link.watchDeviceId, linkId: vectors.link.linkId, linkGeneration: vectors.link.linkGeneration,
      epoch: vectors.link.epoch, payload: { content: { version: 1, suite: E2E_SUITE_V1,
        contentId: vectors.reply.contentId, payloadKind: 'reply-content-v1', nonce: vectors.reply.contentNonce,
        ciphertext: vectors.reply.ciphertext }, keyWrap: { version: 1, suite: E2E_SUITE_V1,
        contentId: vectors.reply.contentId, linkId: vectors.link.linkId, linkGeneration: vectors.link.linkGeneration,
        epoch: vectors.link.epoch, senderEncryptionKeyId: vectors.bindings.watch.encryptionKeyId,
        recipientEncryptionKeyId: vectors.bindings.host.encryptionKeyId,
        nonce: vectors.reply.wrapNonce, ciphertext: vectors.reply.wrappedDek } } };
    assert.equal(decryptReplyForPin(command, { hostIdentity, watchPublicKey: vectors.keys.watchPublicKey,
      transcriptDigest: vectors.transcript.digest }), 'continue');
    assert.throws(() => decryptReplyForPin({ ...command, epoch: 4 }, { hostIdentity,
      watchPublicKey: vectors.keys.watchPublicKey, transcriptDigest: vectors.transcript.digest }));
    for (const malformed of [
      { ...command, payload: { ...command.payload, content: { ...command.payload.content, version: 2 } } },
      { ...command, payload: { ...command.payload, content: { ...command.payload.content, payloadKind: 'event-content-v1' } } },
      { ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, contentId: 'other' } } },
      { ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, linkId: 'other' } } },
      { ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, suite: 'other' } } },
    ]) assert.throws(() => decryptReplyForPin(malformed, { hostIdentity, watchPublicKey: vectors.keys.watchPublicKey, transcriptDigest: vectors.transcript.digest }));
  });

test('uses fresh DEKs/content and wrap nonces for every upload attempt', () => {
    const input = { event: { eventId: 'event', hostId: vectors.link.hostId, sessionId: 'session', provider: 'pi',
      type: 'need_human', status: 'need_human', correlationId: 'correlation', createdAt: '2026-07-20T00:00:00.000Z' },
      protectedEvent: { version: 2, agentText: 'secret', needHuman: { reason: 'blocked' } },
      session: { hostId: vectors.link.hostId, sessionId: 'session', provider: 'pi', status: 'need_human',
        updatedAt: '2026-07-20T00:00:01.000Z', lastEventId: 'event', snoozedUntil: '2026-07-20T00:10:00.000Z' },
      protectedSession: { version: 2, projectName: 'p', nameText: 'n' },
      revision: 1, recipientSetVersion: 1, hostIdentity, recipients: [{ linkId: vectors.link.linkId,
        linkGeneration: vectors.link.linkGeneration, watchDeviceId: vectors.link.watchDeviceId, epoch: vectors.link.epoch,
        state: 'active', transcriptDigest: vectors.transcript.digest, watchBinding: vectors.bindings.watch }] };
    const first = encryptEventUpload(input); const second = encryptEventUpload(input);
    assert.notEqual(first.event.content.ciphertext, second.event.content.ciphertext);
    assert.notEqual(first.event.keyWraps[0].nonce, second.event.keyWraps[0].nonce);
    assert.notEqual(first.session.content.ciphertext, second.session.content.ciphertext);
  });
