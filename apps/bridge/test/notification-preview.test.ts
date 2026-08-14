import { describe, expect, mock, test } from 'bun:test';
import type { CanonicalEvent, CanonicalSessionState } from '@ariava/protocol';
import { buildNotificationPreview, normalizeNotificationPreviewBody } from '../src/e2e/notification-preview';

mock.module('../src/e2e/node-crypto', () => ({
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({ nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]) }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
  generateX25519KeyMaterial: () => ({ privateKeyPkcs8: new Uint8Array(48).fill(2), publicKeyRaw: new Uint8Array(32).fill(3) }),
  x25519SharedSecret: () => new Uint8Array(32).fill(4),
  hkdfSha256: () => new Uint8Array(32).fill(5),
}));

const session = {
  sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'Ariava', nameText: 'Session',
  status: 'idle', updatedAt: '2026-08-01T00:00:01.000Z',
} satisfies CanonicalSessionState;

function doneEvent(overrides: Partial<CanonicalEvent> = {}): CanonicalEvent {
  return {
    eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'done', status: 'idle',
    agentText: 'Finished successfully', createdAt: '2026-08-01T00:00:01.000Z', ...overrides,
  } as CanonicalEvent;
}

function needHumanEvent(overrides: Partial<CanonicalEvent> = {}): CanonicalEvent {
  return {
    eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'need_human', status: 'need_human',
    agentText: 'Review the result', needHuman: { reason: 'blocked' },
    createdAt: '2026-08-01T00:00:01.000Z', ...overrides,
  } as CanonicalEvent;
}

function recipient(index: number) {
  const hostIdentity = { version: 1 as const, hostId: 'host-test', encryptionKeyId: 'ekey-host', publicKey: '',
    privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' };
  return {
    linkId: `link-${index}`, linkGeneration: 1, watchDeviceId: `watch-${index}`, epoch: index, state: 'active' as const,
    transcriptDigest: 'A'.repeat(43), hostIdentity,
    hostBinding: { version: 1 as const, entityType: 'host' as const, entityId: hostIdentity.hostId, identityKeyId: 'key-host',
      encryptionKeyId: hostIdentity.encryptionKeyId, publicKey: hostIdentity.publicKey, sequence: hostIdentity.sequence,
      createdAt: hostIdentity.createdAt, bindingSignature: 'B'.repeat(86) },
    watchBinding: { version: 1 as const, entityType: 'watch' as const, entityId: `watch-${index}`, identityKeyId: `key-${index}`,
      encryptionKeyId: `ekey-watch-${index}`, publicKey: 'A'.repeat(43), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z',
      bindingSignature: 'B'.repeat(86) },
  };
}

describe('notification preview v2', () => {
  test('uses the exact canonical fields and eventType without protected reason/error', () => {
    const preview = buildNotificationPreview(needHumanEvent({
      needHuman: { reason: 'error', error: { kind: 'provider_failure', message: 'Private provider cause.', providerCode: 'E_PRIVATE', retryExhausted: true } },
    }), { ...session, status: 'need_human' });
    expect(preview).toEqual({
      version: 2, projectName: 'Ariava', eventType: 'need_human', bodyText: 'Review the result', truncated: false,
    });
    expect(Object.keys(preview!)).toEqual(['version', 'projectName', 'eventType', 'bodyText', 'truncated']);
    expect(JSON.stringify(preview)).not.toMatch(/reason|error|provider|Private/u);
  });

  test('builds previews only for canonical terminal Events', () => {
    expect(buildNotificationPreview(doneEvent(), session)?.eventType).toBe('done');
    expect(buildNotificationPreview(needHumanEvent(), { ...session, status: 'need_human' })?.eventType).toBe('need_human');
    expect(buildNotificationPreview({ ...doneEvent(), type: 'working', status: 'working' } as never, session)).toBeUndefined();
  });

  test.each([
    'Bearer token-value',
    'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==',
    'Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==',
    'Authorization: Bearer token-value',
    'sk-AAAAAAAAAAAAAAAA',
    'AKIAABCDEFGHIJKLMNOP',
  ])('fully sanitizes credential form %s', (credential) => {
    const body = buildNotificationPreview(doneEvent({
      agentText: `Provider failed with ${credential}; safe tail.`,
    }), session)?.bodyText;
    expect(body).toContain('[redacted credential]');
    expect(body).toContain('safe tail');
    expect(body).not.toContain(credential.split(/\s+/u).at(-1)!);
  });

  test('normalizes and truncates at exactly 200 Unicode grapheme clusters', () => {
    expect(normalizeNotificationPreviewBody('  first  \n \n\t\n second  ')).toEqual({ bodyText: 'first\n\nsecond', truncated: false });
    const exact = 'a'.repeat(197) + ['👩🏽‍💻', '🇨🇦', 'e\u0301'].join('');
    expect(normalizeNotificationPreviewBody(exact)).toEqual({ bodyText: exact, truncated: false });
    expect(normalizeNotificationPreviewBody(exact + 'Z')).toEqual({ bodyText: `${exact}…`, truncated: true });
  });

  test('rejects per-pin sender identity substitution before generating notification wraps', async () => {
    const { encryptNotificationPreviews } = await import('../src/e2e/envelope');
    const plaintext = buildNotificationPreview(doneEvent(), session)!;
    const material = recipient(1);
    material.hostIdentity = { ...material.hostIdentity, encryptionKeyId: 'ekey-substituted' };
    expect(() => encryptNotificationPreviews({ event: doneEvent(), plaintext, recipients: [material] }))
      .toThrow(/sender identity/);
  });

  test('binds outer preview eventType and v2 payload kind for each recipient', async () => {
    const { encryptNotificationPreviews } = await import('../src/e2e/envelope');
    const plaintext = buildNotificationPreview(doneEvent(), session)!;
    const envelopes = encryptNotificationPreviews({
      event: doneEvent(), plaintext, recipients: [recipient(1), recipient(2)],
    });
    expect(envelopes.map((item) => item.eventType)).toEqual(['done', 'done']);
    expect(envelopes.every((item) => item.content.payloadKind === 'notification-preview-v2')).toBe(true);
    expect(envelopes.every((item) => item.content.contentId === item.keyWrap.contentId)).toBe(true);
    expect(JSON.stringify(envelopes)).not.toContain(plaintext.bodyText);
  });
});
