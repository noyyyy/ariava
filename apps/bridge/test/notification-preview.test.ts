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
  stateLabel: 'Done', status: 'done', updatedAt: '2026-08-01T00:00:00.000Z',
} satisfies CanonicalSessionState;

function event(overrides: Partial<CanonicalEvent>): CanonicalEvent {
  return {
    eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'done', status: 'done',
    typeLabel: 'Done', agentText: 'Finished successfully', createdAt: '2026-08-01T00:00:01.000Z', ...overrides,
  };
}

function recipient(index: number) {
  return {
    linkId: `link-${index}`, linkGeneration: 1, watchDeviceId: `watch-${index}`, epoch: index, state: 'active' as const,
    transcriptDigest: 'A'.repeat(43),
    watchBinding: { version: 1 as const, entityType: 'watch' as const, entityId: `watch-${index}`, identityKeyId: `key-${index}`,
      encryptionKeyId: `ekey-watch-${index}`, publicKey: 'A'.repeat(43), sequence: 1, issuedAt: '2026-08-01T00:00:00.000Z',
      bindingSignature: 'B'.repeat(86) },
  };
}

describe('notification preview selection', () => {
  test.each([
    ['done', 'done', 'done'],
    ['need_human', 'blocked', 'need_human'],
  ] as const)('maps canonical %s events to %s', (type, status, expected) => {
    expect(buildNotificationPreview(event({ type, status }), session)?.state).toBe(expected);
  });

  test('uses agent text before the bounded fallback text', () => {
    expect(buildNotificationPreview(event({ type: 'done', status: 'done', agentText: ' agent detail ' }), session)).toMatchObject({ bodyText: 'agent detail', source: 'agentText' });
    expect(buildNotificationPreview(event({ type: 'done', status: 'done', agentText: '  ', contextText: 'private context' }), session)).toMatchObject({ bodyText: 'Task completed.', source: 'fallback' });
  });

  test('trims outer whitespace and collapses excessive blank lines to one blank line', () => {
    expect(normalizeNotificationPreviewBody('  first  \n \n\t\n second  ')).toEqual({ bodyText: 'first\n\nsecond', truncated: false });
  });

  test('truncates at exactly 200 Unicode grapheme clusters without splitting complex graphemes', () => {
    const complex = ['👩🏽‍💻', '🇨🇦', 'e\u0301'];
    const exact = 'a'.repeat(197) + complex.join('');
    expect(Array.from(new Intl.Segmenter('en', { granularity: 'grapheme' }).segment(exact))).toHaveLength(200);
    expect(normalizeNotificationPreviewBody(exact)).toEqual({ bodyText: exact, truncated: false });
    expect(normalizeNotificationPreviewBody(exact + 'Z')).toEqual({ bodyText: `${exact}…`, truncated: true });
  });

  test('omits previews that exceed protocol UTF-8 or total serialized-byte limits', () => {
    expect(buildNotificationPreview(event({}), { ...session, projectName: '界'.repeat(100) })).toBeUndefined();
    expect(buildNotificationPreview(event({ agentText: '👨‍👩‍👧‍👦'.repeat(200) }), session)).toBeUndefined();
    expect(buildNotificationPreview(event({ agentText: `e${'\u0301'.repeat(4_000)}` }), session)).toBeUndefined();
  });

  test('creates an independent opaque envelope and matching wrap for each eligible recipient', async () => {
    const { encryptNotificationPreviews } = await import('../src/e2e/envelope');
    const plaintext = buildNotificationPreview(event({}), session)!;
    const envelopes = encryptNotificationPreviews({
      event: event({}), plaintext, recipients: [recipient(1), recipient(2)],
      hostIdentity: { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-host', publicKey: '',
        privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' },
    });
    expect(envelopes).toHaveLength(2);
    expect(envelopes.map((item) => item.watchDeviceId)).toEqual(['watch-1', 'watch-2']);
    expect(new Set(envelopes.map((item) => item.content.contentId)).size).toBe(2);
    expect(envelopes.every((item) => item.content.contentId === item.keyWrap.contentId)).toBe(true);
    expect(envelopes.map((item) => item.keyWrap.recipientEncryptionKeyId)).toEqual(['ekey-watch-1', 'ekey-watch-2']);
    expect(JSON.stringify(envelopes)).not.toContain(plaintext.bodyText);
  });
});
