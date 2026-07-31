import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, diffieHellman, hkdfSync, verify } from 'node:crypto';
import vectors from './fixtures/e2e-v1-vectors.json';
import previewVector from './fixtures/notification-preview-v1-vector.json';

function openChaChaPoly(key: Uint8Array, nonce: string, ciphertext: string, aad: Uint8Array): Uint8Array {
  const script = `
    const { createDecipheriv } = require('node:crypto');
    const [key, nonce, wire, aad] = process.argv.slice(1).map((value) => Buffer.from(value, 'base64url'));
    const body = wire.subarray(0, wire.length - 16);
    const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: body.length });
    decipher.setAuthTag(wire.subarray(wire.length - 16));
    process.stdout.write(Buffer.concat([decipher.update(body), decipher.final()]).toString('base64url'));
  `;
  const result = spawnSync('node', ['-e', script, base64UrlEncode(key), nonce, ciphertext, base64UrlEncode(aad)], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr || 'ChaChaPoly authentication failed');
  return base64UrlDecode(result.stdout);
}

function corrupt(value: string): string {
  const bytes = base64UrlDecode(value);
  bytes[Math.floor(bytes.length / 2)]! ^= 1;
  return base64UrlEncode(bytes);
}
import {
  COMMAND_TYPES,
  E2E_EPOCH_STATES,
  E2E_SUITE_V1,
  base64UrlDecode,
  base64UrlEncode,
  buildEventContentAAD,
  buildEncryptionBindingBytes,
  buildNotificationPreviewAAD,
  buildNotificationPreviewPlaintextBytes,
  buildProtectedEventContentBytes,
  buildProtectedReplyContentBytes,
  buildProtectedSessionContentBytes,
  buildLinkTranscriptBytes,
  buildReplyContentAAD,
  buildSafetyCodeInput,
  buildSessionContentAAD,
  buildWrapAAD,
  isEpochOperationAllowed,
  pairRootInfo,
  validateEncryptedContentV1,
  validateEncryptionKeyBindingV1,
  validateNotificationPreviewEnvelopeV1,
  validateNotificationPreviewPlaintextV1,
  deriveEncryptionKeyId,
  encryptionKeyIdMatchesPublicKey,
  validateRecipientKeyWrapV1,
  type E2EPendingLinkProjectionV1,
  type EncryptedCommandEnvelopeV1,
} from '../src';

const fixed = vectors;

describe('E2E protocol v1', () => {
  test('freezes generation-bound transcript, pair-root info, and AAD bytes', () => {
    expect(base64UrlEncode(buildLinkTranscriptBytes({
      ...fixed.link,
      hostBindingDigest: fixed.transcript.hostBindingDigest,
      watchBindingDigest: fixed.transcript.watchBindingDigest,
    }))).toBe(fixed.transcript.bytes);
    expect(base64UrlEncode(pairRootInfo(fixed.link.linkId, fixed.link.linkGeneration, fixed.link.epoch))).toBe(fixed.transcript.pairRootInfo);
    expect(base64UrlEncode(buildSafetyCodeInput(fixed.transcript.digest, fixed.link.linkGeneration, fixed.link.epoch))).toBe(fixed.transcript.safetyCodeInput);
    expect(base64UrlEncode(buildEventContentAAD({
      hostId: fixed.link.hostId, sessionId: 'session_vector_01', provider: 'pi', eventId: 'event_vector_01',
      type: 'question_requested', status: 'blocked', createdAt: '2026-07-20T00:00:00.000Z', contentId: fixed.event.contentId,
    }))).toBe(fixed.event.contentAAD);
    expect(base64UrlEncode(buildSessionContentAAD({
      hostId: fixed.link.hostId, sessionId: 'session_vector_01', provider: 'pi', status: 'blocked',
      updatedAt: '2026-07-20T00:00:01.000Z', revision: 4, contentId: fixed.session.contentId,
    }))).toBe(fixed.session.contentAAD);
    expect(base64UrlEncode(buildReplyContentAAD({
      hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId, sessionId: 'session_vector_01',
      commandId: 'command_vector_01', targetAlertEventId: 'event_vector_01', issuedAt: '2026-07-20T00:00:02.000Z',
      expiresAt: '2026-07-20T00:05:02.000Z', nonce: 'nonce_vector_01', contentId: fixed.reply.contentId,
    }))).toBe(fixed.reply.contentAAD);
    expect(base64UrlEncode(buildWrapAAD({
      direction: 'bridge-to-watch', linkId: fixed.link.linkId, linkGeneration: fixed.link.linkGeneration,
      epoch: fixed.link.epoch, hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId,
      senderEncryptionKeyId: 'ekey_host_vector', recipientEncryptionKeyId: 'ekey_watch_vector',
      contentId: fixed.event.contentId, payloadKind: 'event-content-v1',
    }))).toBe(fixed.event.wrapAAD);
  });

  test('freezes and verifies canonical encryption binding signature bytes', () => {
    const { canonicalBytes, bindingSignature, ...binding } = fixed.binding;
    const bytes = buildEncryptionBindingBytes(binding);
    expect(base64UrlEncode(bytes)).toBe(canonicalBytes);
    const publicKey = createPrivateKey({
      key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex')]),
      type: 'pkcs8', format: 'der',
    });
    expect(verify(null, bytes, publicKey, Buffer.from(bindingSignature, 'base64url'))).toBe(true);
    expect(verify(null, buildEncryptionBindingBytes({ ...binding, sequence: 2 }), publicKey, Buffer.from(bindingSignature, 'base64url'))).toBe(false);
  });

  test('encodes protected plaintext with dedicated deterministic key order', () => {
    expect(new TextDecoder().decode(buildProtectedEventContentBytes({
      contextText: 'context', version: 1, agentText: 'answer', humanText: 'question',
      actionablePrompt: { type: 'question', promptId: 'prompt_1', label: 'Choose', options: ['A'], expiresAt: '2026-07-20T00:01:00.000Z' },
    }))).toBe('{"version":1,"agentText":"answer","humanText":"question","contextText":"context","actionablePrompt":{"promptId":"prompt_1","type":"question","label":"Choose","options":["A"],"expiresAt":"2026-07-20T00:01:00.000Z"}}');
    expect(new TextDecoder().decode(buildProtectedSessionContentBytes({ latestActivityText: 'latest', version: 1, projectName: 'ariava', nameText: 'session' })))
      .toBe('{"version":1,"projectName":"ariava","nameText":"session","latestActivityText":"latest"}');
    expect(new TextDecoder().decode(buildProtectedReplyContentBytes({ text: 'continue', version: 1 })))
      .toBe('{"version":1,"text":"continue"}');
    expect(() => buildProtectedReplyContentBytes({ version: 1, text: 'continue', extra: true } as any)).toThrow();
    expect(() => buildProtectedEventContentBytes({ version: 1, agentText: 'answer', extra: true } as any)).toThrow();
  });

  test('changes canonical bytes when generation, epoch, or direction changes', () => {
    const baseline = fixed.event.wrapAAD;
    const input = {
      direction: 'bridge-to-watch' as const, linkId: fixed.link.linkId, linkGeneration: fixed.link.linkGeneration,
      epoch: fixed.link.epoch, hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId,
      senderEncryptionKeyId: 'ekey_host_vector', recipientEncryptionKeyId: 'ekey_watch_vector',
      contentId: fixed.event.contentId, payloadKind: 'event-content-v1' as const,
    };
    expect(base64UrlEncode(buildWrapAAD({ ...input, linkGeneration: input.linkGeneration + 1 }))).not.toBe(baseline);
    expect(base64UrlEncode(buildWrapAAD({ ...input, epoch: input.epoch + 1 }))).not.toBe(baseline);
    expect(base64UrlEncode(buildWrapAAD({ ...input, direction: 'watch-to-bridge' }))).not.toBe(baseline);
  });

  test('derives encryption key IDs from the raw X25519 public key', async () => {
    const expected = await deriveEncryptionKeyId(fixed.keys.hostPublicKey);
    expect(expected).toMatch(/^ekey_[A-Za-z0-9_-]{43}$/u);
    expect(await encryptionKeyIdMatchesPublicKey(expected, fixed.keys.hostPublicKey)).toBe(true);
    expect(await encryptionKeyIdMatchesPublicKey(`ekey_${'A'.repeat(43)}`, fixed.keys.hostPublicKey)).toBe(false);
  });

  test('strict validators reject padding, extra keys, wrong lengths, and oversize ciphertext', () => {
    const binding = {
      version: 1, entityType: 'host', entityId: `host_${'A'.repeat(43)}`, identityKeyId: `key_${'A'.repeat(43)}`,
      encryptionKeyId: `ekey_${'A'.repeat(43)}`, suite: E2E_SUITE_V1, publicKey: fixed.keys.hostPublicKey,
      sequence: 1, createdAt: '2026-07-20T00:00:00.000Z', bindingSignature: base64UrlEncode(new Uint8Array(64)),
    } as const;
    expect(validateEncryptionKeyBindingV1(binding)).toBe(true);
    expect(validateEncryptionKeyBindingV1({ ...binding, publicKey: `${binding.publicKey}=` })).toBe(false);
    expect(validateEncryptionKeyBindingV1({ ...binding, extra: true })).toBe(false);
    expect(validateEncryptionKeyBindingV1({ ...binding, entityId: 'host_vector' })).toBe(false);
    expect(validateEncryptionKeyBindingV1({ ...binding, identityKeyId: 'key_vector' })).toBe(false);
    expect(validateEncryptionKeyBindingV1({ ...binding, createdAt: '2026-07-20T00:00:00Z' })).toBe(false);
    expect(() => buildEncryptionBindingBytes({ ...binding, entityId: 'host_vector' })).toThrow();
    const content = { version: 1, suite: E2E_SUITE_V1, contentId: fixed.event.contentId, payloadKind: 'event-content-v1', nonce: fixed.event.contentNonce, ciphertext: fixed.event.ciphertext } as const;
    expect(validateEncryptedContentV1(content)).toBe(true);
    expect(validateEncryptedContentV1({ ...content, nonce: base64UrlEncode(new Uint8Array(11)) })).toBe(false);
    expect(validateEncryptedContentV1({ ...content, ciphertext: base64UrlEncode(new Uint8Array(32 * 1024 + 17)) })).toBe(false);
    const wrap = { version: 1, suite: E2E_SUITE_V1, contentId: fixed.event.contentId, linkId: fixed.link.linkId, linkGeneration: 7, epoch: 3, senderEncryptionKeyId: 'ekey_host_vector', recipientEncryptionKeyId: 'ekey_watch_vector', nonce: fixed.event.wrapNonce, ciphertext: fixed.event.wrappedDek } as const;
    expect(validateRecipientKeyWrapV1(wrap)).toBe(true);
    expect(validateRecipientKeyWrapV1({ ...wrap, ciphertext: base64UrlEncode(new Uint8Array(47)) })).toBe(false);
    expect(() => base64UrlDecode(`${fixed.keys.hostPublicKey}=`)).toThrow();
  });

  test('pending link projection carries both exact identity verification keys', () => {
    const projection = {
      linkId: fixed.link.linkId, hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId,
      linkGeneration: fixed.link.linkGeneration, epoch: fixed.link.epoch, hostBinding: {} as never,
      hostIdentityPublicKey: fixed.keys.hostPublicKey, watchBinding: {} as never,
      watchIdentityPublicKey: fixed.keys.watchPublicKey, transcriptDigest: fixed.transcript.digest,
      confirmationExpiresAt: '2026-07-20T00:05:00.000Z', state: 'pending_confirmation',
    } satisfies E2EPendingLinkProjectionV1;
    expect(projection.hostIdentityPublicKey).toBe(fixed.keys.hostPublicKey);
    expect(projection.watchIdentityPublicKey).toBe(fixed.keys.watchPublicKey);
  });

  test('enforces explicit active/retiring operation permissions', () => {
    expect(E2E_EPOCH_STATES).toContain('confirmations_complete');
    expect(isEpochOperationAllowed('active', 'create_command')).toBe(true);
    expect(isEpochOperationAllowed('retiring', 'create_command')).toBe(false);
    expect(isEpochOperationAllowed('retiring', 'read_historical_content')).toBe(true);
    expect(isEpochOperationAllowed('retiring', 'deliver_existing_command')).toBe(true);
    expect(isEpochOperationAllowed('confirmations_complete', 'read_historical_content')).toBe(false);
  });

  test('cryptographically verifies the complete preview fixture and rejects every binding mutation', () => {
    const vector = previewVector;
    const preview = vector.preview;
    const hostPrivateKey = createPrivateKey({ key: Buffer.from(vector.keys.hostPrivateKeyPkcs8, 'base64url'), type: 'pkcs8', format: 'der' });
    const watchPublicKey = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: vector.keys.watchPublicKey }, format: 'jwk' });
    const senderShared = new Uint8Array(diffieHellman({ privateKey: hostPrivateKey, publicKey: watchPublicKey }));
    expect(base64UrlEncode(senderShared)).toBe(vector.keys.sharedSecret);

    const watchPrivateKey = createPrivateKey({ key: Buffer.from(vector.keys.watchPrivateKeyPkcs8, 'base64url'), type: 'pkcs8', format: 'der' });
    const hostPublicKey = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: vector.keys.hostPublicKey }, format: 'jwk' });
    const recipientShared = new Uint8Array(diffieHellman({ privateKey: watchPrivateKey, publicKey: hostPublicKey }));
    expect(recipientShared).toEqual(senderShared);
    expect(base64UrlEncode(recipientShared)).toBe(vector.keys.sharedSecret);

    const salt = base64UrlDecode(vector.transcript.digest);
    const pairRootInfoBytes = pairRootInfo(vector.link.linkId, vector.link.linkGeneration, vector.link.epoch);
    const senderPairRoot = new Uint8Array(hkdfSync('sha256', senderShared, salt, pairRootInfoBytes, 32));
    const recipientPairRoot = new Uint8Array(hkdfSync('sha256', recipientShared, salt, pairRootInfoBytes, 32));
    expect(recipientPairRoot).toEqual(senderPairRoot);
    expect(base64UrlEncode(senderPairRoot)).toBe(vector.derived.pairRoot);
    expect(base64UrlEncode(pairRootInfoBytes)).toBe(vector.transcript.pairRootInfo);
    const wrapInfo = new TextEncoder().encode('ariava:e2e:v1:wrap:bridge-to-watch');
    const senderWrapKey = new Uint8Array(hkdfSync('sha256', senderPairRoot, salt, wrapInfo, 32));
    const recipientWrapKey = new Uint8Array(hkdfSync('sha256', recipientPairRoot, salt, wrapInfo, 32));
    expect(recipientWrapKey).toEqual(senderWrapKey);
    expect(base64UrlEncode(senderWrapKey)).toBe(vector.derived.bridgeToWatchWrapKey);

    const aadInput = {
      hostId: vector.link.hostId, watchDeviceId: vector.link.watchDeviceId, eventId: 'event_vector_01',
      sessionId: 'session_vector_01', linkId: vector.link.linkId, linkGeneration: vector.link.linkGeneration,
      epoch: vector.link.epoch, senderEncryptionKeyId: 'ekey_host_vector', recipientEncryptionKeyId: 'ekey_watch_vector',
      contentId: preview.contentId, payloadKind: 'notification-preview-v1' as const,
    };
    const contentAAD = buildNotificationPreviewAAD(aadInput);
    const wrapAAD = buildWrapAAD({ direction: 'bridge-to-watch', ...aadInput });
    expect(base64UrlEncode(contentAAD)).toBe(preview.contentAAD);
    expect(base64UrlEncode(wrapAAD)).toBe(preview.wrapAAD);
    const senderDek = openChaChaPoly(senderWrapKey, preview.wrapNonce, preview.wrappedDek, wrapAAD);
    const recipientDek = openChaChaPoly(recipientWrapKey, preview.wrapNonce, preview.wrappedDek, wrapAAD);
    expect(recipientDek).toEqual(senderDek);
    expect(base64UrlEncode(recipientDek)).toBe(preview.dek);
    const plaintext = {
      version: 1, projectName: 'ariava', state: 'block', bodyText: 'Choose a deployment target.',
      source: 'agentText', truncated: false,
    } as const;
    expect(base64UrlEncode(buildNotificationPreviewPlaintextBytes(plaintext))).toBe(preview.plaintext);
    expect(base64UrlEncode(openChaChaPoly(recipientDek, preview.contentNonce, preview.ciphertext, contentAAD))).toBe(preview.plaintext);
    expect(() => openChaChaPoly(recipientDek, preview.contentNonce, preview.ciphertext, base64UrlDecode(fixed.event.contentAAD))).toThrow();
    expect(() => openChaChaPoly(recipientDek, preview.contentNonce, preview.ciphertext, base64UrlDecode(fixed.session.contentAAD))).toThrow();
    expect(() => openChaChaPoly(recipientDek, preview.contentNonce, corrupt(preview.ciphertext), contentAAD)).toThrow();
    expect(() => openChaChaPoly(recipientWrapKey, preview.wrapNonce, corrupt(preview.wrappedDek), wrapAAD)).toThrow();

    for (const mutation of [
      { hostId: 'host_other' }, { watchDeviceId: 'watch_other' }, { eventId: 'event_other' },
      { sessionId: 'session_other' }, { linkId: 'link_other' }, { linkGeneration: 8 }, { epoch: 4 },
      { senderEncryptionKeyId: 'ekey_sender_other' }, { recipientEncryptionKeyId: 'ekey_recipient_other' },
      { contentId: 'content_other' },
    ]) expect(() => openChaChaPoly(recipientDek, preview.contentNonce, preview.ciphertext, buildNotificationPreviewAAD({ ...aadInput, ...mutation }))).toThrow();
    for (const mutation of [
      { direction: 'watch-to-bridge' as const }, { hostId: 'host_other' }, { watchDeviceId: 'watch_other' },
      { linkId: 'link_other' }, { linkGeneration: 8 }, { epoch: 4 }, { senderEncryptionKeyId: 'ekey_sender_other' },
      { recipientEncryptionKeyId: 'ekey_recipient_other' }, { contentId: 'content_other' }, { payloadKind: 'event-content-v1' as const },
    ]) expect(() => openChaChaPoly(recipientWrapKey, preview.wrapNonce, preview.wrappedDek, buildWrapAAD({ direction: 'bridge-to-watch', ...aadInput, ...mutation }))).toThrow();
  }, 20_000);

  test('rejects non-canonical notification preview AAD inputs before encoding', () => {
    const valid = {
      hostId: 'host_vector_01', watchDeviceId: `watch_${'A'.repeat(43)}`, eventId: 'event_vector_01', sessionId: 'session_vector_01',
      linkId: 'link_vector_01', linkGeneration: 7, epoch: 3, senderEncryptionKeyId: 'ekey_host_vector',
      recipientEncryptionKeyId: 'ekey_watch_vector', contentId: 'content_vector_preview_01', payloadKind: 'notification-preview-v1' as const,
    };
    for (const field of ['hostId', 'watchDeviceId', 'eventId', 'sessionId', 'linkId', 'senderEncryptionKeyId', 'recipientEncryptionKeyId', 'contentId'] as const) {
      expect(() => buildNotificationPreviewAAD({ ...valid, [field]: '' })).toThrow();
      expect(() => buildNotificationPreviewAAD({ ...valid, [field]: 'x'.repeat(257) })).toThrow();
      expect(() => buildNotificationPreviewAAD({ ...valid, [field]: '\ud800' })).toThrow();
    }
    for (const field of ['linkGeneration', 'epoch'] as const) {
      for (const invalid of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1])
        expect(() => buildNotificationPreviewAAD({ ...valid, [field]: invalid })).toThrow();
    }
  });

  test('strictly bounds preview plaintext and opaque recipient envelope', () => {
    const valid = { version: 1, projectName: 'ariava', state: 'done', bodyText: 'Finished.', source: 'fallback', truncated: false } as const;
    expect(validateNotificationPreviewPlaintextV1(valid)).toBe(true);
    expect(validateNotificationPreviewPlaintextV1({ ...valid, version: 2 })).toBe(false);
    expect(validateNotificationPreviewPlaintextV1({ ...valid, state: 'working' })).toBe(false);
    expect(validateNotificationPreviewPlaintextV1({ ...valid, source: 'relay' })).toBe(false);
    expect(validateNotificationPreviewPlaintextV1({ ...valid, projectName: 'x'.repeat(257) })).toBe(false);
    expect(validateNotificationPreviewPlaintextV1({ ...valid, bodyText: 'x'.repeat(4_001) })).toBe(false);
    expect(validateNotificationPreviewPlaintextV1({ ...valid, bodyText: '\ud800' })).toBe(false);
    expect(validateNotificationPreviewPlaintextV1({ ...valid, extra: true })).toBe(false);

    const preview = previewVector.preview;
    const envelope = {
      eventId: 'event_vector_01', sessionId: 'session_vector_01', watchDeviceId: previewVector.link.watchDeviceId,
      content: { version: 1, suite: E2E_SUITE_V1, contentId: preview.contentId, payloadKind: 'notification-preview-v1', nonce: preview.contentNonce, ciphertext: preview.ciphertext },
      keyWrap: { version: 1, suite: E2E_SUITE_V1, contentId: preview.contentId, linkId: previewVector.link.linkId, linkGeneration: 7, epoch: 3, senderEncryptionKeyId: 'ekey_host_vector', recipientEncryptionKeyId: 'ekey_watch_vector', nonce: preview.wrapNonce, ciphertext: preview.wrappedDek },
    } as const;
    expect(validateNotificationPreviewEnvelopeV1(envelope)).toBe(true);
    expect(validateNotificationPreviewEnvelopeV1({ ...envelope, content: { ...envelope.content, payloadKind: 'event-content-v1' } })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV1({ ...envelope, keyWrap: { ...envelope.keyWrap, contentId: 'other' } })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV1({ ...envelope, eventId: '\ud800' })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV1({ ...envelope, sessionId: 'x'.repeat(257) })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV1({ ...envelope, content: { ...envelope.content, contentId: '' }, keyWrap: { ...envelope.keyWrap, contentId: '' } })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV1({ ...envelope, keyWrap: { ...envelope.keyWrap, senderEncryptionKeyId: 'x'.repeat(257) } })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV1({ ...envelope, extra: true })).toBe(false);
  });

  test('keeps reply encrypted and interrupt exactly payload-free at the type boundary', () => {
    expect(COMMAND_TYPES).toEqual(['reply', 'interrupt']);
    const interrupt: EncryptedCommandEnvelopeV1 = {
      commandId: 'cmd_1', hostId: 'host_1', sessionId: 'session_1', type: 'interrupt', payload: {},
      issuedAt: '2026-07-20T00:00:00.000Z', expiresAt: '2026-07-20T00:05:00.000Z', nonce: 'nonce_1',
      watchDeviceId: 'watch_1', linkId: 'link_1', linkGeneration: 1, epoch: 1,
    };
    expect(Object.keys(interrupt.payload)).toEqual([]);
  });
});
