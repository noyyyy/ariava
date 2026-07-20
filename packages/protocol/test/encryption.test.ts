import { describe, expect, test } from 'bun:test';
import { createPrivateKey, verify } from 'node:crypto';
import vectors from './fixtures/e2e-v1-vectors.json';
import {
  COMMAND_TYPES,
  E2E_EPOCH_STATES,
  E2E_SUITE_V1,
  base64UrlDecode,
  base64UrlEncode,
  buildEventContentAAD,
  buildEncryptionBindingBytes,
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
  deriveEncryptionKeyId,
  encryptionKeyIdMatchesPublicKey,
  validateRecipientKeyWrapV1,
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
      contextText: 'context', version: 1, assistantText: 'answer', userMessageText: 'question',
      actionablePrompt: { type: 'question', promptId: 'prompt_1', label: 'Choose', options: ['A'], expiresAt: '2026-07-20T00:01:00.000Z' },
    }))).toBe('{"version":1,"assistantText":"answer","userMessageText":"question","contextText":"context","actionablePrompt":{"promptId":"prompt_1","type":"question","label":"Choose","options":["A"],"expiresAt":"2026-07-20T00:01:00.000Z"}}');
    expect(new TextDecoder().decode(buildProtectedSessionContentBytes({ latestActivityText: 'latest', version: 1, projectName: 'ariava', nameText: 'session' })))
      .toBe('{"version":1,"projectName":"ariava","nameText":"session","latestActivityText":"latest"}');
    expect(new TextDecoder().decode(buildProtectedReplyContentBytes({ text: 'continue', version: 1 })))
      .toBe('{"version":1,"text":"continue"}');
    expect(() => buildProtectedReplyContentBytes({ version: 1, text: 'continue', extra: true } as any)).toThrow();
    expect(() => buildProtectedEventContentBytes({ version: 1, assistantText: 'answer', extra: true } as any)).toThrow();
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

  test('enforces explicit active/retiring operation permissions', () => {
    expect(E2E_EPOCH_STATES).toContain('confirmations_complete');
    expect(isEpochOperationAllowed('active', 'create_command')).toBe(true);
    expect(isEpochOperationAllowed('retiring', 'create_command')).toBe(false);
    expect(isEpochOperationAllowed('retiring', 'read_historical_content')).toBe(true);
    expect(isEpochOperationAllowed('retiring', 'deliver_existing_command')).toBe(true);
    expect(isEpochOperationAllowed('confirmations_complete', 'read_historical_content')).toBe(false);
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
