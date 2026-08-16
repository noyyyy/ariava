import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, verify } from 'node:crypto';
import vectors from './fixtures/e2e-v3-vectors.json';
import legacyVectors from './fixtures/e2e-v2-vectors.json';
import previewVector from './fixtures/notification-preview-v2-vector.json';
import commandVectors from './fixtures/command-e2e-v1-vectors.json';

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

function captureError(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error('expected function to throw');
}
import {
  COMMAND_TYPES,
  E2E_EPOCH_STATES,
  E2E_SUITE_V1,
  E2E_LIMITS,
  base64UrlDecode,
  base64UrlEncode,
  buildConfirmationProofBytes,
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
  ProtectedContentValidationError,
  validateEncryptedContentV1,
  validateEncryptionKeyBindingV1,
  validateNotificationPreviewEnvelopeV2,
  validateNotificationPreviewPlaintextV2,
  deriveEncryptionKeyId,
  encryptionKeyIdMatchesPublicKey,
  validateRecipientKeyWrapV1,
  type E2EPendingLinkProjectionV1,
  type EncryptedCommandEnvelopeV1,
} from '../src';

const fixed = vectors;

describe('E2E runtime protocol v3 and key ceremony v1', () => {
  test('ties link identities and transcript digests to both canonical bindings', () => {
    expect(fixed.link.hostId).toBe(fixed.bindings.host.entityId);
    expect(fixed.link.watchDeviceId).toBe(fixed.bindings.watch.entityId);
    for (const [binding, expectedDigest] of [
      [fixed.bindings.host, fixed.transcript.hostBindingDigest],
      [fixed.bindings.watch, fixed.transcript.watchBindingDigest],
    ] as const) {
      const { canonicalBytes, bindingSignature: _, ...unsigned } = binding;
      const bytes = buildEncryptionBindingBytes(unsigned);
      expect(base64UrlEncode(bytes)).toBe(canonicalBytes);
      expect(base64UrlEncode(createHash('sha256').update(bytes).digest())).toBe(expectedDigest);
    }
  });

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
      type: 'need_human', status: 'need_human',
      createdAt: '2026-07-20T00:00:00.000Z', contentId: fixed.event.contentId,
    }))).toBe(fixed.event.contentAAD);
    expect(base64UrlEncode(buildSessionContentAAD({
      hostId: fixed.link.hostId, sessionId: 'session_vector_01', provider: 'pi', status: 'need_human',
      updatedAt: '2026-07-20T00:00:01.000Z', lastEventId: 'event_vector_01',
      snoozedUntil: '2026-07-20T00:10:00.000Z', revision: 4, contentId: fixed.session.contentId,
    }))).toBe(fixed.session.contentAAD);
    expect(base64UrlEncode(buildReplyContentAAD({
      hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId, sessionId: 'session_vector_01',
      commandId: 'command_vector_01', targetAlertEventId: 'event_vector_01', issuedAt: '2026-07-20T00:00:02.000Z',
      expiresAt: '2026-07-20T00:05:02.000Z', nonce: 'nonce_vector_01', contentId: fixed.reply.contentId,
    }))).toBe(fixed.reply.contentAAD);
    expect(base64UrlEncode(buildWrapAAD({
      direction: 'bridge-to-watch', linkId: fixed.link.linkId, linkGeneration: fixed.link.linkGeneration,
      epoch: fixed.link.epoch, hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId,
      senderEncryptionKeyId: fixed.bindings.host.encryptionKeyId,
      recipientEncryptionKeyId: fixed.bindings.watch.encryptionKeyId,
      contentId: fixed.event.contentId, payloadKind: 'event-content-v3',
    }))).toBe(fixed.event.wrapAAD);
  });

  test('cryptographically verifies v3 event/session vectors and all metadata bindings', () => {
    const wrapKey = base64UrlDecode(fixed.derived.bridgeToWatchWrapKey);
    const eventAADInput = {
      hostId: fixed.link.hostId, sessionId: 'session_vector_01', provider: 'pi', eventId: 'event_vector_01',
      type: 'need_human' as const, status: 'need_human' as const,
      createdAt: '2026-07-20T00:00:00.000Z', contentId: fixed.event.contentId,
    };
    const eventWrapInput = {
      direction: 'bridge-to-watch' as const, linkId: fixed.link.linkId, linkGeneration: fixed.link.linkGeneration,
      epoch: fixed.link.epoch, hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId,
      senderEncryptionKeyId: fixed.bindings.host.encryptionKeyId,
      recipientEncryptionKeyId: fixed.bindings.watch.encryptionKeyId,
      contentId: fixed.event.contentId, payloadKind: 'event-content-v3' as const,
    };
    const eventAAD = buildEventContentAAD(eventAADInput);
    const eventWrapAAD = buildWrapAAD(eventWrapInput);
    const eventDek = openChaChaPoly(wrapKey, fixed.event.wrapNonce, fixed.event.wrappedDek, eventWrapAAD);
    expect(base64UrlEncode(eventDek)).toBe(fixed.event.dek);
    expect(base64UrlEncode(openChaChaPoly(eventDek, fixed.event.contentNonce, fixed.event.ciphertext, eventAAD))).toBe(fixed.event.plaintext);
    for (const mutation of [
      { hostId: 'host_other' }, { sessionId: 'session_other' }, { provider: 'other' }, { eventId: 'event_other' },
      { type: 'done' as const, status: 'idle' as const },
      { createdAt: '2026-07-20T00:00:02.000Z' }, { contentId: 'content_other' },
    ]) expect(() => openChaChaPoly(eventDek, fixed.event.contentNonce, fixed.event.ciphertext, buildEventContentAAD({ ...eventAADInput, ...mutation }))).toThrow();
    for (const mutation of [
      { direction: 'watch-to-bridge' as const }, { hostId: 'host_other' }, { watchDeviceId: 'watch_other' },
      { linkId: 'link_other' }, { linkGeneration: 8 }, { epoch: 4 }, { senderEncryptionKeyId: 'ekey_other' },
      { recipientEncryptionKeyId: 'ekey_other' }, { contentId: 'content_other' },
      { payloadKind: 'session-content-v3' as const },
    ]) expect(() => openChaChaPoly(wrapKey, fixed.event.wrapNonce, fixed.event.wrappedDek, buildWrapAAD({ ...eventWrapInput, ...mutation }))).toThrow();

    const sessionAADInput = {
      hostId: fixed.link.hostId, sessionId: 'session_vector_01', provider: 'pi', status: 'need_human' as const,
      updatedAt: '2026-07-20T00:00:01.000Z', lastEventId: 'event_vector_01',
      snoozedUntil: '2026-07-20T00:10:00.000Z', revision: 4, contentId: fixed.session.contentId,
    };
    const sessionWrapInput = { ...eventWrapInput, contentId: fixed.session.contentId, payloadKind: 'session-content-v3' as const };
    const sessionAAD = buildSessionContentAAD(sessionAADInput);
    const sessionWrapAAD = buildWrapAAD(sessionWrapInput);
    const sessionDek = openChaChaPoly(wrapKey, fixed.session.wrapNonce, fixed.session.wrappedDek, sessionWrapAAD);
    expect(base64UrlEncode(sessionDek)).toBe(fixed.session.dek);
    expect(base64UrlEncode(openChaChaPoly(sessionDek, fixed.session.contentNonce, fixed.session.ciphertext, sessionAAD))).toBe(fixed.session.plaintext);
    for (const mutation of [
      { hostId: 'host_other' }, { sessionId: 'session_other' }, { provider: 'other' }, { status: 'working' as const },
      { updatedAt: '2026-07-20T00:00:02.000Z' }, { lastEventId: undefined }, { lastEventId: 'event_other' },
      { snoozedUntil: undefined }, { snoozedUntil: '2026-07-20T00:20:00.000Z' }, { revision: 5 }, { contentId: 'content_other' },
    ]) expect(() => openChaChaPoly(sessionDek, fixed.session.contentNonce, fixed.session.ciphertext, buildSessionContentAAD({ ...sessionAADInput, ...mutation }))).toThrow();

    const replyWrapInput = {
      direction: 'watch-to-bridge' as const, linkId: fixed.link.linkId, linkGeneration: fixed.link.linkGeneration,
      epoch: fixed.link.epoch, hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId,
      senderEncryptionKeyId: fixed.bindings.watch.encryptionKeyId,
      recipientEncryptionKeyId: fixed.bindings.host.encryptionKeyId,
      contentId: fixed.reply.contentId, payloadKind: 'reply-content-v1' as const,
    };
    const replyContentAAD = buildReplyContentAAD({
      hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId, sessionId: 'session_vector_01',
      commandId: 'command_vector_01', targetAlertEventId: 'event_vector_01', issuedAt: '2026-07-20T00:00:02.000Z',
      expiresAt: '2026-07-20T00:05:02.000Z', nonce: 'nonce_vector_01', contentId: fixed.reply.contentId,
    });
    const replyDek = openChaChaPoly(
      base64UrlDecode(fixed.derived.watchToBridgeWrapKey), fixed.reply.wrapNonce, fixed.reply.wrappedDek,
      buildWrapAAD(replyWrapInput),
    );
    expect(base64UrlEncode(replyDek)).toBe(fixed.reply.dek);
    expect(base64UrlEncode(openChaChaPoly(
      replyDek, fixed.reply.contentNonce, fixed.reply.ciphertext, replyContentAAD,
    ))).toBe(fixed.reply.plaintext);
  }, 20_000);

  test('freezes and verifies both canonical encryption binding signatures', () => {
    for (const [binding, identityPublicKey] of [
      [fixed.bindings.host, fixed.keys.hostIdentityPublicKey],
      [fixed.bindings.watch, fixed.keys.watchIdentityPublicKey],
    ] as const) {
      const { canonicalBytes, bindingSignature, ...unsigned } = binding;
      const bytes = buildEncryptionBindingBytes(unsigned);
      expect(base64UrlEncode(bytes)).toBe(canonicalBytes);
      const publicKey = createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x: identityPublicKey }, format: 'jwk',
      });
      expect(verify(null, bytes, publicKey, Buffer.from(bindingSignature, 'base64url'))).toBe(true);
      expect(verify(null, buildEncryptionBindingBytes({ ...unsigned, sequence: 2 }), publicKey, Buffer.from(bindingSignature, 'base64url'))).toBe(false);
    }
  });

  test('verifies transcript-bound HKDF outputs and confirmation proofs', () => {
    const salt = base64UrlDecode(fixed.transcript.digest);
    const sharedSecret = base64UrlDecode(fixed.keys.sharedSecret);
    const pairRootBytes = new Uint8Array(hkdfSync(
      'sha256', sharedSecret, salt,
      pairRootInfo(fixed.link.linkId, fixed.link.linkGeneration, fixed.link.epoch), 32,
    ));
    expect(base64UrlEncode(pairRootBytes)).toBe(fixed.derived.pairRoot);
    for (const [direction, expected] of [
      ['bridge-to-watch', fixed.derived.bridgeToWatchWrapKey],
      ['watch-to-bridge', fixed.derived.watchToBridgeWrapKey],
    ] as const) {
      const key = new Uint8Array(hkdfSync(
        'sha256', pairRootBytes, salt, new TextEncoder().encode(`ariava:e2e:v1:wrap:${direction}`), 32,
      ));
      expect(base64UrlEncode(key)).toBe(expected);
    }
    const confirmationKey = new Uint8Array(hkdfSync(
      'sha256', sharedSecret, salt, new TextEncoder().encode('ariava:e2e:v1:confirmation'), 32,
    ));
    expect(base64UrlEncode(confirmationKey)).toBe(fixed.derived.confirmationKey);
    for (const [role, expected] of [
      ['host', fixed.derived.hostProof], ['watch', fixed.derived.watchProof],
    ] as const) {
      const proof = createHmac('sha256', confirmationKey)
        .update(buildConfirmationProofBytes(role, fixed.transcript.digest)).digest();
      expect(base64UrlEncode(proof)).toBe(expected);
    }
    const safetyHmac = createHmac('sha256', confirmationKey)
      .update(buildSafetyCodeInput(fixed.transcript.digest, fixed.link.linkGeneration, fixed.link.epoch)).digest();
    expect(base64UrlEncode(safetyHmac)).toBe(fixed.derived.safetyCodeHmac);
  });

  test('encodes protected v3 plaintext in exact key order and rejects retired keys', () => {
    expect(new TextDecoder().decode(buildProtectedEventContentBytes({
      projectName: 'ariava', version: 3, agentText: 'answer', humanText: 'question',
      workingDirectory: '/workspace/ariava', harnessProvider: 'pi', needHuman: { reason: 'question' },
    }))).toBe('{"version":3,"agentText":"answer","humanText":"question","projectName":"ariava","workingDirectory":"/workspace/ariava","harnessProvider":"pi","needHuman":{"reason":"question"}}');
    expect(new TextDecoder().decode(buildProtectedSessionContentBytes({
      latestActivityText: 'latest', openingText: 'opening', version: 3, projectName: 'ariava', nameText: 'session',
      workingDirectory: '/workspace/ariava', harnessProvider: 'pi',
    }))).toBe('{"version":3,"projectName":"ariava","nameText":"session","openingText":"opening","latestActivityText":"latest","workingDirectory":"/workspace/ariava","harnessProvider":"pi"}');
    expect(new TextDecoder().decode(buildProtectedReplyContentBytes({ text: 'continue', version: 1 })))
      .toBe('{"version":1,"text":"continue"}');
    expect(() => buildProtectedReplyContentBytes({ version: 1, text: 'continue', extra: true } as any)).toThrow();
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: 'answer', extra: true } as any)).toThrow();
    for (const retired of ['actionablePrompt', 'contextText', 'correlationId', 'hbaseSessionKey'] as const) {
      expect(() => buildProtectedEventContentBytes({ version: 3, agentText: 'answer', [retired]: 'retired' } as never)).toThrow();
    }
    expect(() => buildProtectedSessionContentBytes({
      version: 3, projectName: 'ariava', nameText: 'session', hbaseSessionKey: 'retired',
    } as never)).toThrow();
  });

  test('rejects inherited protected invariant fields before building v3 bytes', () => {
    const inheritedNeedHuman = Object.assign(Object.create({ needHuman: { reason: 'blocked' } }), {
      version: 3, agentText: 'answer',
    });
    const inheritedContextError = Object.assign(Object.create({
      error: { kind: 'provider_failure', message: 'Provider failed.', retryExhausted: true },
    }), { reason: 'blocked' });
    const inheritedProviderCode = Object.assign(Object.create({ providerCode: '' }), {
      kind: 'provider_failure', message: 'Provider failed.', retryExhausted: true,
    });

    expect(() => buildProtectedEventContentBytes(inheritedNeedHuman)).toThrow();
    expect(() => buildProtectedEventContentBytes({
      version: 3, agentText: 'answer', needHuman: inheritedContextError,
    } as never)).toThrow();
    expect(() => buildProtectedEventContentBytes({
      version: 3, agentText: 'answer',
      needHuman: { reason: 'error', error: inheritedProviderCode },
    } as never)).toThrow();
  });
  test('uses byte-exact v2 Event and Session fixtures as current-v3 rejection evidence', () => {
    expect(new TextDecoder().decode(base64UrlDecode(legacyVectors.event.plaintext)))
      .toBe('{"version":2,"agentText":"E2E vector marker","needHuman":{"reason":"blocked"}}');
    expect(new TextDecoder().decode(base64UrlDecode(legacyVectors.session.plaintext)))
      .toBe('{"version":2,"projectName":"vector","nameText":"session"}');
    expect(() => buildProtectedEventContentBytes(
      JSON.parse(new TextDecoder().decode(base64UrlDecode(legacyVectors.event.plaintext))),
    )).toThrow();
    expect(() => buildProtectedSessionContentBytes(
      JSON.parse(new TextDecoder().decode(base64UrlDecode(legacyVectors.session.plaintext))),
    )).toThrow();
    expect(validateEncryptedContentV1({
      version: 1, suite: E2E_SUITE_V1, contentId: legacyVectors.event.contentId, payloadKind: 'event-content-v2',
      nonce: legacyVectors.event.contentNonce, ciphertext: legacyVectors.event.ciphertext,
    })).toBe(false);
    expect(validateEncryptedContentV1({
      version: 1, suite: E2E_SUITE_V1, contentId: legacyVectors.session.contentId, payloadKind: 'session-content-v2',
      nonce: legacyVectors.session.contentNonce, ciphertext: legacyVectors.session.ciphertext,
    })).toBe(false);
    expect(() => openChaChaPoly(
      base64UrlDecode(legacyVectors.event.dek), legacyVectors.event.contentNonce, legacyVectors.event.ciphertext,
      buildEventContentAAD({
        hostId: legacyVectors.link.hostId, sessionId: 'session_vector_01', provider: 'pi', eventId: 'event_vector_01',
        type: 'need_human', status: 'need_human', createdAt: '2026-07-20T00:00:00.000Z', contentId: legacyVectors.event.contentId,
      }),
    )).toThrow();
    expect(() => openChaChaPoly(
      base64UrlDecode(legacyVectors.session.dek), legacyVectors.session.contentNonce, legacyVectors.session.ciphertext,
      buildSessionContentAAD({
        hostId: legacyVectors.link.hostId, sessionId: 'session_vector_01', provider: 'pi', status: 'need_human',
        updatedAt: '2026-07-20T00:00:01.000Z', lastEventId: 'event_vector_01',
        snoozedUntil: '2026-07-20T00:10:00.000Z', revision: 4, contentId: legacyVectors.session.contentId,
      }),
    )).toThrow();
  });



  test('enforces limits on emitted canonical bytes and rejects descriptor bypasses', () => {
    const eventOverhead = buildProtectedEventContentBytes({ version: 3, agentText: 'x' }).byteLength - 1;
    const maximumEvent = buildProtectedEventContentBytes({
      version: 3, agentText: 'x'.repeat(E2E_LIMITS.eventPlaintextBytes - eventOverhead),
    });
    expect(maximumEvent.byteLength).toBe(E2E_LIMITS.eventPlaintextBytes);
    const oversizeEventError = captureError(() => buildProtectedEventContentBytes({
      version: 3, agentText: 'x'.repeat(E2E_LIMITS.eventPlaintextBytes - eventOverhead + 1),
    }));
    expect(oversizeEventError).toBeInstanceOf(ProtectedContentValidationError);
    expect((oversizeEventError as ProtectedContentValidationError).code).toBe('protected-event-invalid');

    const sessionOverhead = buildProtectedSessionContentBytes({ version: 3, projectName: 'x', nameText: 'x' }).byteLength - 1;
    const maximumSession = buildProtectedSessionContentBytes({
      version: 3, projectName: 'x', nameText: 'x'.repeat(E2E_LIMITS.sessionPlaintextBytes - sessionOverhead),
    });
    expect(maximumSession.byteLength).toBe(E2E_LIMITS.sessionPlaintextBytes);
    const oversizeSessionError = captureError(() => buildProtectedSessionContentBytes({
      version: 3, projectName: 'x', nameText: 'x'.repeat(E2E_LIMITS.sessionPlaintextBytes - sessionOverhead + 1),
    }));
    expect(oversizeSessionError).toBeInstanceOf(ProtectedContentValidationError);
    expect((oversizeSessionError as ProtectedContentValidationError).code).toBe('protected-session-invalid');

    let getterCalls = 0;
    const accessorEvent = Object.defineProperty({ version: 3 }, 'agentText', {
      enumerable: true, get: () => { getterCalls += 1; return 'hidden'; },
    });
    const accessorError = captureError(() => buildProtectedEventContentBytes(accessorEvent as never));
    expect(accessorError).toBeInstanceOf(ProtectedContentValidationError);
    expect((accessorError as ProtectedContentValidationError).code).toBe('protected-event-invalid');
    expect(getterCalls).toBe(0);

    const hiddenSession = { version: 3, projectName: 'ariava', nameText: 'session' };
    Object.defineProperty(hiddenSession, 'latestActivityText', { enumerable: false, value: 'hidden' });
    expect(() => buildProtectedSessionContentBytes(hiddenSession)).toThrow();
    const disguisedOversizeEvent = Object.create({ toJSON: () => ({ version: 3, agentText: '' }) }) as { version: 3; agentText: string };
    disguisedOversizeEvent.version = 3;
    disguisedOversizeEvent.agentText = 'x'.repeat(E2E_LIMITS.eventPlaintextBytes);
    expect(JSON.stringify(disguisedOversizeEvent).length).toBeLessThan(E2E_LIMITS.eventPlaintextBytes);
    expect(() => buildProtectedEventContentBytes(disguisedOversizeEvent)).toThrow();
  });

  test('rejects empty protected strings in Event and Session content (Watch-consistent bounded text)', () => {
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: '' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: 'ok', humanText: '' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: 'ok', projectName: '' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: '', nameText: 'ok' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: 'ok', nameText: '' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: 'ok', nameText: 'ok', openingText: '' } as never)).toThrow(ProtectedContentValidationError);
    // Every required string must stay non-empty.
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: 'ok' })).not.toThrow();
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: 'ok', nameText: 'ok' })).not.toThrow();
  });

  test('rejects lone surrogates in protected Event and Session text fields (well-formed Unicode)', () => {
    // Lone high surrogate in required event text.
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: '\ud800' } as never)).toThrow(ProtectedContentValidationError);
    // Lone low surrogate in optional event text fields.
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: 'ok', humanText: '\udc00' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: 'ok', projectName: 'a\ud800b' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: 'ok', workingDirectory: '\udc00' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: 'ok', harnessProvider: '\ud800' } as never)).toThrow(ProtectedContentValidationError);
    // Session text fields.
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: '\ud800', nameText: 'ok' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: 'ok', nameText: '\udc00' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: 'ok', nameText: 'ok', openingText: '\ud800' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: 'ok', nameText: 'ok', latestActivityText: '\udc00' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: 'ok', nameText: 'ok', workingDirectory: '\ud800' } as never)).toThrow(ProtectedContentValidationError);
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: 'ok', nameText: 'ok', harnessProvider: '\udc00' } as never)).toThrow(ProtectedContentValidationError);
    // Valid astral pairs (well-formed surrogate pairs) must still pass.
    expect(() => buildProtectedEventContentBytes({ version: 3, agentText: '\u{1F600}' })).not.toThrow();
    expect(() => buildProtectedSessionContentBytes({ version: 3, projectName: '\u{1F600}', nameText: 'ok' })).not.toThrow();
  });

  test('derives ciphertext bounds as plaintext + 16 for session and event and keeps reply/preview unchanged', () => {
    expect(E2E_LIMITS.sessionPlaintextBytes).toBe(64 * 1024);
    expect(E2E_LIMITS.eventPlaintextBytes).toBe(64 * 1024);
    expect(E2E_LIMITS.replyPlaintextBytes).toBe(4_000);
    expect(E2E_LIMITS.notificationPreviewPlaintextBytes).toBe(4_000);

    const eventCipher = {
      version: 1, suite: E2E_SUITE_V1, contentId: fixed.event.contentId, payloadKind: 'event-content-v3' as const,
      nonce: fixed.event.contentNonce, ciphertext: fixed.event.ciphertext,
    } as const;
    const sessionCipher = { ...eventCipher, payloadKind: 'session-content-v3' as const } as const;

    expect(validateEncryptedContentV1({ ...eventCipher, ciphertext: base64UrlEncode(new Uint8Array(E2E_LIMITS.eventPlaintextBytes + E2E_LIMITS.authenticationTagBytes)) })).toBe(true);
    expect(validateEncryptedContentV1({ ...eventCipher, ciphertext: base64UrlEncode(new Uint8Array(E2E_LIMITS.eventPlaintextBytes + E2E_LIMITS.authenticationTagBytes + 1)) })).toBe(false);
    expect(validateEncryptedContentV1({ ...sessionCipher, ciphertext: base64UrlEncode(new Uint8Array(E2E_LIMITS.sessionPlaintextBytes + E2E_LIMITS.authenticationTagBytes)) })).toBe(true);
    expect(validateEncryptedContentV1({ ...sessionCipher, ciphertext: base64UrlEncode(new Uint8Array(E2E_LIMITS.sessionPlaintextBytes + E2E_LIMITS.authenticationTagBytes + 1)) })).toBe(false);
  });

  test('changes canonical bytes when generation, epoch, or direction changes', () => {
    const baseline = fixed.event.wrapAAD;
    const input = {
      direction: 'bridge-to-watch' as const, linkId: fixed.link.linkId, linkGeneration: fixed.link.linkGeneration,
      epoch: fixed.link.epoch, hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId,
      senderEncryptionKeyId: fixed.bindings.host.encryptionKeyId,
      recipientEncryptionKeyId: fixed.bindings.watch.encryptionKeyId,
      contentId: fixed.event.contentId, payloadKind: 'event-content-v3' as const,
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
    const content = { version: 1, suite: E2E_SUITE_V1, contentId: fixed.event.contentId, payloadKind: 'event-content-v3', nonce: fixed.event.contentNonce, ciphertext: fixed.event.ciphertext } as const;
    expect(validateEncryptedContentV1(content)).toBe(true);
    expect(validateEncryptedContentV1({ ...content, payloadKind: 'event-content-v1' })).toBe(false);
    expect(validateEncryptedContentV1({ ...content, nonce: base64UrlEncode(new Uint8Array(11)) })).toBe(false);
    expect(validateEncryptedContentV1({ ...content, ciphertext: base64UrlEncode(new Uint8Array(E2E_LIMITS.eventPlaintextBytes + E2E_LIMITS.authenticationTagBytes + 1)) })).toBe(false);
    const wrap = { version: 1, suite: E2E_SUITE_V1, contentId: fixed.event.contentId, linkId: fixed.link.linkId, linkGeneration: 7, epoch: 3, senderEncryptionKeyId: 'ekey_host_vector', recipientEncryptionKeyId: 'ekey_watch_vector', nonce: fixed.event.wrapNonce, ciphertext: fixed.event.wrappedDek } as const;
    expect(validateRecipientKeyWrapV1(wrap)).toBe(true);
    expect(validateRecipientKeyWrapV1({ ...wrap, ciphertext: base64UrlEncode(new Uint8Array(47)) })).toBe(false);
    expect(() => base64UrlDecode(`${fixed.keys.hostPublicKey}=`)).toThrow();
    expect(() => buildEventContentAAD({
      hostId: fixed.link.hostId, sessionId: 'session_vector_01', provider: 'pi', eventId: 'event_vector_01',
      type: 'done', status: 'need_human' as never, createdAt: '2026-07-20T00:00:00.000Z', contentId: fixed.event.contentId,
    })).toThrow();
    expect(() => buildSessionContentAAD({
      hostId: fixed.link.hostId, sessionId: 'session_vector_01', provider: 'pi', status: 'unknown' as never,
      updatedAt: '2026-07-20T00:00:01.000Z', revision: 4, contentId: fixed.session.contentId,
    })).toThrow();

    const symbolKey = Symbol('unsupported');
    expect(validateEncryptedContentV1({ ...content, [symbolKey]: true })).toBe(false);
    for (const invalid of ['', '\ud800', 'x'.repeat(E2E_LIMITS.notificationPreviewIdentifierBytes + 1)]) {
      expect(validateEncryptedContentV1({ ...content, contentId: invalid })).toBe(false);
      expect(() => buildReplyContentAAD({
        hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId, sessionId: 'session_vector_01',
        commandId: 'command_vector_01', targetAlertEventId: 'event_vector_01', issuedAt: '2026-07-20T00:00:02.000Z',
        expiresAt: '2026-07-20T00:05:02.000Z', nonce: 'nonce_vector_01', contentId: invalid,
      })).toThrow();
      for (const field of ['contentId', 'linkId', 'senderEncryptionKeyId', 'recipientEncryptionKeyId'] as const) {
        expect(validateRecipientKeyWrapV1({ ...wrap, [field]: invalid })).toBe(false);
      }
      for (const field of ['contentId', 'linkId', 'hostId', 'watchDeviceId', 'senderEncryptionKeyId', 'recipientEncryptionKeyId'] as const) {
        expect(() => buildWrapAAD({
          direction: 'bridge-to-watch', linkId: wrap.linkId, linkGeneration: wrap.linkGeneration, epoch: wrap.epoch,
          hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId,
          senderEncryptionKeyId: wrap.senderEncryptionKeyId, recipientEncryptionKeyId: wrap.recipientEncryptionKeyId,
          contentId: wrap.contentId, payloadKind: 'event-content-v3', [field]: invalid,
        })).toThrow();
      }
    }
  });

  test('pending link projection carries both exact identity verification keys', () => {
    const projection = {
      linkId: fixed.link.linkId, hostId: fixed.link.hostId, watchDeviceId: fixed.link.watchDeviceId,
      linkGeneration: fixed.link.linkGeneration, epoch: fixed.link.epoch, hostBinding: fixed.bindings.host,
      hostIdentityPublicKey: fixed.keys.hostIdentityPublicKey, watchBinding: fixed.bindings.watch,
      watchIdentityPublicKey: fixed.keys.watchIdentityPublicKey, transcriptDigest: fixed.transcript.digest,
      confirmationExpiresAt: '2026-07-20T00:05:00.000Z', state: 'pending_confirmation',
    } satisfies E2EPendingLinkProjectionV1;
    expect(projection.hostIdentityPublicKey).toBe(fixed.keys.hostIdentityPublicKey);
    expect(projection.watchIdentityPublicKey).toBe(fixed.keys.watchIdentityPublicKey);
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

    expect(vector.link.hostId).toBe(vector.bindings.host.entityId);
    expect(vector.link.watchDeviceId).toBe(vector.bindings.watch.entityId);
    const hostBindingBytes = buildEncryptionBindingBytes(vector.bindings.host);
    const watchBindingBytes = buildEncryptionBindingBytes(vector.bindings.watch);
    expect(base64UrlEncode(createHash('sha256').update(hostBindingBytes).digest())).toBe(vector.transcript.hostBindingDigest);
    expect(base64UrlEncode(createHash('sha256').update(watchBindingBytes).digest())).toBe(vector.transcript.watchBindingDigest);
    const transcriptBytes = buildLinkTranscriptBytes({
      ...vector.link,
      hostBindingDigest: vector.transcript.hostBindingDigest,
      watchBindingDigest: vector.transcript.watchBindingDigest,
    });
    expect(base64UrlEncode(transcriptBytes)).toBe(vector.transcript.bytes);
    expect(base64UrlEncode(createHash('sha256').update(transcriptBytes).digest())).toBe(vector.transcript.digest);

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
      epoch: vector.link.epoch, senderEncryptionKeyId: vector.bindings.host.encryptionKeyId,
      recipientEncryptionKeyId: vector.bindings.watch.encryptionKeyId,
      contentId: preview.contentId, payloadKind: 'notification-preview-v2' as const, eventType: 'need_human' as const,
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
      version: 2, projectName: 'ariava', eventType: 'need_human', bodyText: 'Choose a deployment target.',
      truncated: false,
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
      { contentId: 'content_other' }, { eventType: 'done' as const },
    ]) expect(() => openChaChaPoly(recipientDek, preview.contentNonce, preview.ciphertext, buildNotificationPreviewAAD({ ...aadInput, ...mutation }))).toThrow();
    for (const mutation of [
      { direction: 'watch-to-bridge' as const }, { hostId: 'host_other' }, { watchDeviceId: 'watch_other' },
      { linkId: 'link_other' }, { linkGeneration: 8 }, { epoch: 4 }, { senderEncryptionKeyId: 'ekey_sender_other' },
      { recipientEncryptionKeyId: 'ekey_recipient_other' }, { contentId: 'content_other' }, { payloadKind: 'event-content-v2' as const },
    ]) expect(() => openChaChaPoly(recipientWrapKey, preview.wrapNonce, preview.wrappedDek, buildWrapAAD({ direction: 'bridge-to-watch', ...aadInput, ...mutation }))).toThrow();
  }, 20_000);

  test('rejects non-canonical notification preview AAD inputs before encoding', () => {
    const valid = {
      hostId: 'host_vector_01', watchDeviceId: `watch_${'A'.repeat(43)}`, eventId: 'event_vector_01', sessionId: 'session_vector_01',
      linkId: 'link_vector_01', linkGeneration: 7, epoch: 3, senderEncryptionKeyId: 'ekey_host_vector',
      recipientEncryptionKeyId: 'ekey_watch_vector', contentId: 'content_vector_preview_01', payloadKind: 'notification-preview-v2' as const,
      eventType: 'need_human' as const,
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
    const valid = { version: 2, projectName: 'ariava', eventType: 'done', bodyText: 'Finished.', truncated: false } as const;
    expect(validateNotificationPreviewPlaintextV2(valid)).toBe(true);
    expect(validateNotificationPreviewPlaintextV2({ ...valid, version: 1 })).toBe(false);
    expect(validateNotificationPreviewPlaintextV2({ ...valid, eventType: 'working' })).toBe(false);
    expect(validateNotificationPreviewPlaintextV2({ ...valid, projectName: 'x'.repeat(257) })).toBe(false);
    expect(validateNotificationPreviewPlaintextV2({ ...valid, bodyText: 'x'.repeat(4_001) })).toBe(false);
    expect(validateNotificationPreviewPlaintextV2({ ...valid, bodyText: '\ud800' })).toBe(false);
    expect(validateNotificationPreviewPlaintextV2({ ...valid, extra: true })).toBe(false);
    const preview = previewVector.preview;
    const envelope = {
      eventId: 'event_vector_01', sessionId: 'session_vector_01', eventType: 'need_human',
      watchDeviceId: previewVector.link.watchDeviceId,
      content: { version: 1, suite: E2E_SUITE_V1, contentId: preview.contentId, payloadKind: 'notification-preview-v2', nonce: preview.contentNonce, ciphertext: preview.ciphertext },
      keyWrap: {
        version: 1, suite: E2E_SUITE_V1, contentId: preview.contentId, linkId: previewVector.link.linkId,
        linkGeneration: 7, epoch: 3, senderEncryptionKeyId: previewVector.bindings.host.encryptionKeyId,
        recipientEncryptionKeyId: previewVector.bindings.watch.encryptionKeyId, nonce: preview.wrapNonce, ciphertext: preview.wrappedDek,
      },
    } as const;
    expect(validateNotificationPreviewEnvelopeV2(envelope)).toBe(true);
    expect(validateNotificationPreviewEnvelopeV2({ ...envelope, eventType: 'done' })).toBe(true);
    expect(() => openChaChaPoly(
      base64UrlDecode(preview.dek), preview.contentNonce, preview.ciphertext,
      buildNotificationPreviewAAD({
        hostId: previewVector.link.hostId, watchDeviceId: previewVector.link.watchDeviceId,
        eventId: envelope.eventId, sessionId: envelope.sessionId, eventType: 'done',
        linkId: previewVector.link.linkId, linkGeneration: 7, epoch: 3,
        senderEncryptionKeyId: previewVector.bindings.host.encryptionKeyId,
        recipientEncryptionKeyId: previewVector.bindings.watch.encryptionKeyId,
        contentId: preview.contentId, payloadKind: 'notification-preview-v2',
      }),
    )).toThrow();
    expect(validateNotificationPreviewEnvelopeV2({ ...envelope, content: { ...envelope.content, payloadKind: 'event-content-v2' } })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV2({ ...envelope, keyWrap: { ...envelope.keyWrap, contentId: 'other' } })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV2({ ...envelope, eventId: '\ud800' })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV2({ ...envelope, sessionId: 'x'.repeat(257) })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV2({ ...envelope, content: { ...envelope.content, contentId: '' }, keyWrap: { ...envelope.keyWrap, contentId: '' } })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV2({ ...envelope, keyWrap: { ...envelope.keyWrap, senderEncryptionKeyId: 'x'.repeat(257) } })).toBe(false);
    expect(validateNotificationPreviewEnvelopeV2({ ...envelope, extra: true })).toBe(false);
  });

  test('sizes preview v2 from exact emitted canonical bytes despite prototype and descriptor tricks', () => {
    const valid = { version: 2, projectName: 'ariava', eventType: 'done', bodyText: 'Finished.', truncated: false } as const;
    const canonical = buildNotificationPreviewPlaintextBytes(valid);
    const inheritedToJSON = Object.assign(Object.create({
      toJSON: () => ({ version: 2, projectName: 'x', eventType: 'done', bodyText: '', truncated: false }),
    }), valid) as typeof valid;
    expect(validateNotificationPreviewPlaintextV2(inheritedToJSON)).toBe(false);
    expect(() => buildNotificationPreviewPlaintextBytes(inheritedToJSON)).toThrow();

    const oneByte = { ...valid, projectName: 'p', bodyText: 'x' };
    const overhead = buildNotificationPreviewPlaintextBytes(oneByte).byteLength - 1;
    const maximumBody = 'x'.repeat(E2E_LIMITS.notificationPreviewPlaintextBytes - overhead);
    const maximum = { ...oneByte, bodyText: maximumBody };
    expect(buildNotificationPreviewPlaintextBytes(maximum).byteLength).toBe(E2E_LIMITS.notificationPreviewPlaintextBytes);
    const disguisedOversize = Object.assign(Object.create({ toJSON: () => valid }), {
      ...oneByte, bodyText: `${maximumBody}x`,
    });
    expect(JSON.stringify(disguisedOversize)).toBe(JSON.stringify(valid));
    expect(validateNotificationPreviewPlaintextV2(disguisedOversize)).toBe(false);
    expect(() => buildNotificationPreviewPlaintextBytes(disguisedOversize)).toThrow();

    let getterCalls = 0;
    const accessor = Object.defineProperty({ ...valid }, 'bodyText', {
      enumerable: true, get: () => { getterCalls += 1; return 'Finished.'; },
    });
    expect(validateNotificationPreviewPlaintextV2(accessor)).toBe(false);
    expect(() => buildNotificationPreviewPlaintextBytes(accessor as never)).toThrow();
    expect(getterCalls).toBe(0);
  });

  test('keeps reply encrypted and requires interrupt encrypted content', () => {
    expect(COMMAND_TYPES).toEqual(['reply', 'interrupt']);
    const interrupt: EncryptedCommandEnvelopeV1 = commandVectors.interrupt.envelope as EncryptedCommandEnvelopeV1;
    expect(interrupt.type).toBe('interrupt');
    expect(interrupt.payload.content.payloadKind).toBe('interrupt-content-v1');
    expect(interrupt.payload.keyWrap.contentId).toBe(interrupt.payload.content.contentId);
  });
});
