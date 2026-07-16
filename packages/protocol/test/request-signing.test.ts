import { describe, expect, test } from 'bun:test';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import fixture from './fixtures/ed25519-request-vectors.json';
const vector = fixture.vectors[0];
import {
  REQUEST_SIGNATURE_DOMAIN,
  SIGNED_REQUEST_LIMITS,
  base64UrlDecode,
  base64UrlEncode,
  buildCanonicalRequest,
  buildRequestTarget,
  canonicalizePath,
  canonicalizeQuery,
  contentSha256,
  createSignedRequestHeaders,
  validateSignedRequestHeaders,
  type CanonicalRequestInput,
} from '../src';

const querySchema = {
  parameters: {
    mode: (value: string) => value === 'first' || value === 'again',
    platform: (value: string) => value === 'macos' || value === 'linux',
    host: (value: string) => value.length > 0,
    q: (value: string) => value.length > 0,
    text: (value: string) => value.length > 0,
  },
} as const;

const input: CanonicalRequestInput = {
  entityType: 'host',
  entityId: vector.entityId,
  keyId: vector.keyId,
  method: vector.method,
  path: vector.path,
  query: vector.query,
  querySchema,
  contentSha256: vector.contentSha256,
  timestamp: vector.timestamp,
  nonce: vector.nonce,
};

function privateKey() {
  const prefix = '302e020100300506032b657004220420';
  return createPrivateKey({ key: Buffer.from(prefix + fixture.privateKeySeedHex, 'hex'), format: 'der', type: 'pkcs8' });
}

function inputFor(vectorInput: (typeof fixture.vectors)[number]): CanonicalRequestInput {
  return {
    entityType: vectorInput.entityType as CanonicalRequestInput['entityType'],
    entityId: vectorInput.entityId,
    keyId: vectorInput.keyId,
    method: vectorInput.method,
    path: vectorInput.path,
    query: vectorInput.query,
    querySchema,
    contentSha256: vectorInput.contentSha256,
    timestamp: vectorInput.timestamp,
    nonce: vectorInput.nonce,
  };
}

describe('restricted-ASCII canonical request signing', () => {
  test('matches the fixed Ed25519 vector', async () => {
    expect(REQUEST_SIGNATURE_DOMAIN).toBe('ariava-request-v1');
    expect(await contentSha256(vector.bodyUtf8)).toBe(vector.contentSha256);
    const canonical = buildCanonicalRequest(input);
    expect(canonical.query).toBe(vector.canonicalQuery);
    expect(canonical.text).toBe(vector.canonicalText);

    const signature = sign(null, canonical.bytes, privateKey());
    expect(base64UrlEncode(signature)).toBe(vector.signature);
    expect(verify(null, canonical.bytes, createPublicKey(privateKey()), signature)).toBe(true);
  });

  test('matches the fixed Unicode JSON body vector', async () => {
    const unicodeVector = fixture.vectors[1];
    expect(await contentSha256(unicodeVector.bodyUtf8)).toBe(unicodeVector.contentSha256);
    const canonical = buildCanonicalRequest(inputFor(unicodeVector));
    expect(canonical.text).toBe(unicodeVector.canonicalText);
    expect(base64UrlEncode(sign(null, canonical.bytes, privateKey()))).toBe(unicodeVector.signature);
    expect(() => canonicalizePath('/v2/session/继续')).toThrow('printable ASCII');
    expect(() => canonicalizeQuery('text=继续', querySchema)).toThrow('printable ASCII');
  });

  test('sorts supported name=value pairs and builds the final target', () => {
    expect(canonicalizeQuery('platform=macos&mode=first', querySchema)).toBe('mode=first&platform=macos');
    expect(buildRequestTarget('/v2/bridge/enroll', [
      { name: 'platform', value: 'linux' },
      { name: 'mode', value: 'first' },
    ], querySchema)).toBe('/v2/bridge/enroll?mode=first&platform=linux');
  });

  test('rejects lowercase HTTP methods instead of normalizing signed bytes', () => {
    expect(() => buildCanonicalRequest({ ...input, method: 'post' })).toThrow('method must be uppercase');
  });

  test('rejects unsupported Worker-visible target forms', () => {
    const operations: Array<() => unknown> = [
      () => canonicalizePath('/v2/hosts/a%2Fb'),
      () => canonicalizePath('/v2/hosts/../watch'),
      () => canonicalizePath('/v2/hosts/%2E%2E/watch'),
      () => canonicalizePath('/v2//hosts'),
      () => canonicalizePath('/v2/hosts/'),
      () => canonicalizeQuery('host=a&host=b', querySchema),
      () => canonicalizeQuery('host=a%2Fb', querySchema),
      () => canonicalizeQuery('q=a+b', querySchema),
      () => canonicalizeQuery('host', querySchema),
      () => canonicalizeQuery('host=', querySchema),
      () => canonicalizeQuery('host=a=b', querySchema),
      () => canonicalizeQuery('unknown=value', querySchema),
      () => canonicalizeQuery('platform=windows', querySchema),
      () => canonicalizePath('/v2/hosts/a\n'),
    ];
    expect(canonicalizePath('/')).toBe('/');
    for (const operation of operations) expect(operation).toThrow();
  });

  test('tampering every signed component changes verification bytes', () => {
    const canonical = buildCanonicalRequest(input);
    const publicKey = createPublicKey(privateKey());
    const signature = base64UrlDecode(vector.signature, 64);
    const variants: CanonicalRequestInput[] = [
      { ...input, entityType: 'watch' },
      { ...input, entityId: `host_${'A'.repeat(43)}` },
      { ...input, keyId: `key_${'A'.repeat(43)}` },
      { ...input, method: 'PUT' },
      { ...input, path: '/v2/bridge/registration' },
      { ...input, query: 'mode=again&platform=macos' },
      { ...input, contentSha256: 'A'.repeat(43) },
      { ...input, timestamp: '2026-07-15T12:34:57.789Z' },
      { ...input, nonce: 'AQECAwQFBgcICQoLDA0ODw' },
    ];
    expect(verify(null, canonical.bytes, publicKey, signature)).toBe(true);
    for (const variant of variants) {
      expect(verify(null, buildCanonicalRequest(variant).bytes, publicKey, signature)).toBe(false);
    }
  });

  test('creates and validates exact signed headers and constants', () => {
    expect(SIGNED_REQUEST_LIMITS.nonceBytes).toBe(16);
    expect(SIGNED_REQUEST_LIMITS.signatureBytes).toBe(64);
    const headers = createSignedRequestHeaders(input, vector.signature);
    expect(validateSignedRequestHeaders(headers)).toEqual({ success: true, value: headers, issues: [] });
    expect(validateSignedRequestHeaders({ ...headers, 'x-ariava-nonce': `${vector.nonce}=` }).success).toBe(false);
    expect(validateSignedRequestHeaders({ ...headers, 'x-ariava-timestamp': '2026-07-15T12:34:56Z' }).success).toBe(false);
  });
});
