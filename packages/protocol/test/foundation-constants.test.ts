import { describe, expect, test } from 'bun:test';
import {
  PAIRING_CODE_ALPHABET,
  PAIRING_CODE_LIMITS,
  REQUEST_SIGNATURE_DOMAIN,
  SIGNED_REQUEST_HEADER_NAMES,
  SIGNED_REQUEST_LIMITS,
  base64UrlEncode,
  formatPairingCode,
  isRotationOperationId,
  normalizePairingCode,
  validateSignedRequestHeaders,
  type SignedRequestHeaders,
} from '../src';

function encodedBytes(length: number): string {
  return base64UrlEncode(new Uint8Array(length));
}

describe('frozen v2 foundation constants', () => {
  test('exports every signed-request header name and domain', () => {
    const expected = [
      ['entityId', 'x-ariava-entity-id'],
      ['keyId', 'x-ariava-key-id'],
      ['timestamp', 'x-ariava-timestamp'],
      ['nonce', 'x-ariava-nonce'],
      ['contentSha256', 'x-ariava-content-sha256'],
      ['signature', 'x-ariava-signature'],
    ] as const;

    expect(REQUEST_SIGNATURE_DOMAIN).toBe('ariava-request-v1');
    for (const [field, header] of expected) expect(SIGNED_REQUEST_HEADER_NAMES[field]).toBe(header);
    expect(Object.keys(SIGNED_REQUEST_HEADER_NAMES).length).toBe(expected.length);
  });

  test('exports every clock, encoded-size, ID, target, body, and header bound', () => {
    const expected = [
      ['clockSkewMs', 300_000],
      ['nonceRetentionMs', 600_000],
      ['timestampCharacters', 24],
      ['nonceBytes', 16],
      ['nonceCharacters', 22],
      ['sha256Bytes', 32],
      ['sha256Characters', 43],
      ['signatureBytes', 64],
      ['signatureCharacters', 86],
      ['publicKeyBytes', 32],
      ['publicKeyCharacters', 43],
      ['hostIdCharacters', 48],
      ['watchIdCharacters', 49],
      ['keyIdCharacters', 47],
      ['methodCharacters', 7],
      ['pathSegmentCharacters', 255],
      ['canonicalPathCharacters', 1_024],
      ['queryCharacters', 2_048],
      ['queryPairs', 64],
      ['queryNameCharacters', 256],
      ['queryValueCharacters', 256],
      ['targetCharacters', 3_073],
      ['bodyBytes', 1_048_576],
      ['headerCharacters', 256],
    ] as const;

    for (const [name, value] of expected) expect(SIGNED_REQUEST_LIMITS[name]).toBe(value);
    expect(Object.keys(SIGNED_REQUEST_LIMITS).length).toBe(expected.length);
  });

  test('exports public pairing syntax and client TTL only', () => {
    expect(PAIRING_CODE_ALPHABET).toBe('0123456789ABCDEFGHJKMNPQRSTVWXYZ');
    expect(PAIRING_CODE_LIMITS).toEqual({ codeSymbols: 8, codeDisplayCharacters: 9, ttlMs: 300_000 });
    expect(formatPairingCode('ABCDEFGH')).toBe('ABCD-EFGH');
    expect(normalizePairingCode('abcd-efgh')).toBe('ABCDEFGH');
  });

  test('freezes rotation operation ID format and length', () => {
    const valid = 'op_123e4567-e89b-12d3-a456-426614174000';
    expect(valid.length).toBe(39);
    expect(isRotationOperationId(valid)).toBe(true);
    for (const invalid of [
      valid.slice(0, -1),
      `${valid}0`,
      valid.replace('op_', ''),
      'op_123E4567-e89b-12d3-a456-426614174000',
      'op_123e4567-e89b-02d3-a456-426614174000',
      'op_123e4567-e89b-12d3-c456-426614174000',
    ]) expect(isRotationOperationId(invalid)).toBe(false);
  });
});

describe('frozen encoded request-header lengths', () => {
  const headers: SignedRequestHeaders = {
    'x-ariava-entity-id': `host_${'A'.repeat(43)}`,
    'x-ariava-key-id': `key_${'A'.repeat(43)}`,
    'x-ariava-timestamp': '2026-07-15T12:34:56.789Z',
    'x-ariava-nonce': encodedBytes(SIGNED_REQUEST_LIMITS.nonceBytes),
    'x-ariava-content-sha256': encodedBytes(SIGNED_REQUEST_LIMITS.sha256Bytes),
    'x-ariava-signature': encodedBytes(SIGNED_REQUEST_LIMITS.signatureBytes),
  };

  test('accepts the exact unpadded byte and encoded lengths', () => {
    expect(headers['x-ariava-nonce'].length).toBe(SIGNED_REQUEST_LIMITS.nonceCharacters);
    expect(headers['x-ariava-content-sha256'].length).toBe(SIGNED_REQUEST_LIMITS.sha256Characters);
    expect(headers['x-ariava-signature'].length).toBe(SIGNED_REQUEST_LIMITS.signatureCharacters);
    expect(validateSignedRequestHeaders(headers).success).toBe(true);
  });

  test('rejects every wrong-length or padded binary header', () => {
    const cases = [
      ['x-ariava-nonce', SIGNED_REQUEST_LIMITS.nonceBytes],
      ['x-ariava-content-sha256', SIGNED_REQUEST_LIMITS.sha256Bytes],
      ['x-ariava-signature', SIGNED_REQUEST_LIMITS.signatureBytes],
    ] as const;

    for (const [header, bytes] of cases) {
      expect(validateSignedRequestHeaders({ ...headers, [header]: encodedBytes(bytes - 1) }).success).toBe(false);
      expect(validateSignedRequestHeaders({ ...headers, [header]: `${encodedBytes(bytes)}=` }).success).toBe(false);
    }
  });
});
