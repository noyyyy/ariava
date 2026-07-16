import type { EntityType } from './identity.js';

export const REQUEST_SIGNATURE_DOMAIN = 'ariava-request-v1' as const;

export const SIGNED_REQUEST_HEADER_NAMES = {
  entityId: 'x-ariava-entity-id',
  keyId: 'x-ariava-key-id',
  timestamp: 'x-ariava-timestamp',
  nonce: 'x-ariava-nonce',
  contentSha256: 'x-ariava-content-sha256',
  signature: 'x-ariava-signature',
} as const;

export const SIGNED_REQUEST_LIMITS = {
  clockSkewMs: 300_000,
  nonceRetentionMs: 600_000,
  timestampCharacters: 24,
  nonceBytes: 16,
  nonceCharacters: 22,
  sha256Bytes: 32,
  sha256Characters: 43,
  signatureBytes: 64,
  signatureCharacters: 86,
  publicKeyBytes: 32,
  publicKeyCharacters: 43,
  hostIdCharacters: 48,
  watchIdCharacters: 49,
  keyIdCharacters: 47,
  methodCharacters: 7,
  pathSegmentCharacters: 255,
  canonicalPathCharacters: 1_024,
  queryCharacters: 2_048,
  queryPairs: 64,
  queryNameCharacters: 256,
  queryValueCharacters: 256,
  targetCharacters: 3_073,
  bodyBytes: 1_048_576,
  headerCharacters: 256,
} as const;

export type QueryValueValidator = (value: string) => boolean;

export interface QuerySchema {
  /** Exact allowed query names and their route-specific value validators. */
  readonly parameters: Readonly<Record<string, QueryValueValidator>>;
}

export interface CanonicalRequestInput {
  entityType: EntityType;
  entityId: string;
  keyId: string;
  method: string;
  path: string;
  query?: string | readonly QueryPair[];
  querySchema: QuerySchema;
  contentSha256: string;
  timestamp: string;
  nonce: string;
}

export interface CanonicalRequest {
  method: string;
  path: string;
  query: string;
  text: string;
  bytes: Uint8Array;
}

export interface QueryPair {
  name: string;
  value: string;
}

export interface SignedRequestHeaders {
  'x-ariava-entity-id': string;
  'x-ariava-key-id': string;
  'x-ariava-timestamp': string;
  'x-ariava-nonce': string;
  'x-ariava-content-sha256': string;
  'x-ariava-signature': string;
}

export class RequestCanonicalizationError extends TypeError {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'RequestCanonicalizationError';
    this.code = code;
  }
}

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const DYNAMIC_VALUE_RE = /^[A-Za-z0-9_~-]+$/;
const METHOD_RE = /^[A-Z]+$/;
const encoder = new TextEncoder();

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

export function base64UrlDecode(value: string, expectedBytes?: number, label = 'base64url value'): Uint8Array {
  if (!value || !BASE64URL_RE.test(value) || value.includes('=')) {
    throw new TypeError(`${label} must be canonical unpadded base64url`);
  }
  const padding = (4 - (value.length % 4)) % 4;
  if (value.length % 4 === 1) throw new TypeError(`${label} has an invalid base64url length`);
  let binary: string;
  try {
    binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padding));
  } catch {
    throw new TypeError(`${label} is not valid base64url`);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (expectedBytes !== undefined && bytes.byteLength !== expectedBytes) {
    throw new TypeError(`${label} must contain exactly ${expectedBytes} bytes`);
  }
  if (base64UrlEncode(bytes) !== value) throw new TypeError(`${label} is not canonical base64url`);
  return bytes;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const source = new Uint8Array(bytes);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', source.buffer));
}

export async function contentSha256(body: Uint8Array | string): Promise<string> {
  const bytes = typeof body === 'string' ? encoder.encode(body) : body;
  if (bytes.byteLength > SIGNED_REQUEST_LIMITS.bodyBytes) throw new TypeError('signed body exceeds the global limit');
  return base64UrlEncode(await sha256(bytes));
}

export function isRestrictedDynamicValue(value: string): boolean {
  return value.length > 0 && DYNAMIC_VALUE_RE.test(value) && value !== '.' && value !== '..';
}

export function assertRestrictedDynamicValue(value: string, label = 'dynamic value'): string {
  if (!isRestrictedDynamicValue(value)) {
    throw new RequestCanonicalizationError(
      'INVALID_DYNAMIC_VALUE',
      `${label} must use unreserved ASCII without '.', '..', percent encoding, controls, or free text`,
    );
  }
  return value;
}

export function canonicalizePath(path: string): string {
  assertAscii(path, 'path');
  if (!path.startsWith('/') || path.includes('?') || path.includes('#')) {
    throw new RequestCanonicalizationError('INVALID_PATH', 'path must be an absolute Worker-visible pathname');
  }
  if (path.includes('%')) {
    throw new RequestCanonicalizationError('PERCENT_ENCODING_UNSUPPORTED', 'percent-encoded path values are unsupported');
  }
  if (path.length > SIGNED_REQUEST_LIMITS.canonicalPathCharacters) {
    throw new RequestCanonicalizationError('PATH_TOO_LONG', 'path exceeds the canonical path limit');
  }
  if (path !== '/' && (path.endsWith('/') || path.includes('//'))) {
    throw new RequestCanonicalizationError('EMPTY_PATH_SEGMENT', 'repeated or trailing empty path segments are unsupported');
  }
  const segments = path === '/' ? [] : path.slice(1).split('/');
  for (const segment of segments) {
    if (segment === '.' || segment === '..') {
      throw new RequestCanonicalizationError('DOT_SEGMENT_UNSUPPORTED', 'dot path segments are unsupported');
    }
    if (segment.length > SIGNED_REQUEST_LIMITS.pathSegmentCharacters) {
      throw new RequestCanonicalizationError('PATH_SEGMENT_TOO_LONG', 'path segment exceeds the limit');
    }
    if (!DYNAMIC_VALUE_RE.test(segment)) {
      throw new RequestCanonicalizationError('INVALID_PATH_SEGMENT', 'path segments must use restricted unreserved ASCII');
    }
  }
  return path;
}

export function canonicalizeQuery(query: string | readonly QueryPair[] = '', schema: QuerySchema): string {
  const pairs = typeof query === 'string' ? parseQuery(query) : [...query];
  if (pairs.length > SIGNED_REQUEST_LIMITS.queryPairs) {
    throw new RequestCanonicalizationError('TOO_MANY_QUERY_PAIRS', 'query has too many pairs');
  }
  const seen = new Set<string>();
  const canonical = pairs.map(({ name, value }) => {
    assertRestrictedDynamicValue(name, 'query name');
    assertRestrictedDynamicValue(value, 'query value');
    const validator = Object.prototype.hasOwnProperty.call(schema.parameters, name) ? schema.parameters[name] : undefined;
    if (!validator) {
      throw new RequestCanonicalizationError('UNSUPPORTED_QUERY_NAME', `query name ${name} is unsupported for this route`);
    }
    if (!validator(value)) {
      throw new RequestCanonicalizationError('INVALID_QUERY_VALUE', `query value for ${name} is invalid for this route`);
    }
    if (name.length > SIGNED_REQUEST_LIMITS.queryNameCharacters || value.length > SIGNED_REQUEST_LIMITS.queryValueCharacters) {
      throw new RequestCanonicalizationError('QUERY_VALUE_TOO_LONG', 'query name or value exceeds the limit');
    }
    if (seen.has(name)) {
      throw new RequestCanonicalizationError('DUPLICATE_QUERY_NAME', 'duplicate query names are unsupported');
    }
    seen.add(name);
    return { name, value };
  });
  canonical.sort((left, right) => compareAscii(left.name, right.name) || compareAscii(left.value, right.value));
  const result = canonical.map(({ name, value }) => `${name}=${value}`).join('&');
  if (result.length > SIGNED_REQUEST_LIMITS.queryCharacters) {
    throw new RequestCanonicalizationError('QUERY_TOO_LONG', 'query exceeds the canonical query limit');
  }
  return result;
}

export function buildRequestTarget(path: string, query: string | readonly QueryPair[], schema: QuerySchema): string {
  const canonicalPath = canonicalizePath(path);
  const canonicalQuery = canonicalizeQuery(query, schema);
  const target = canonicalQuery ? `${canonicalPath}?${canonicalQuery}` : canonicalPath;
  if (target.length > SIGNED_REQUEST_LIMITS.targetCharacters) {
    throw new RequestCanonicalizationError('TARGET_TOO_LONG', 'request target exceeds the limit');
  }
  return target;
}

export function buildCanonicalRequest(input: CanonicalRequestInput): CanonicalRequest {
  const method = input.method;
  if (method !== method.toUpperCase() || !METHOD_RE.test(method) || method.length > SIGNED_REQUEST_LIMITS.methodCharacters) {
    throw new RequestCanonicalizationError('INVALID_METHOD', 'method must be uppercase ASCII within the method limit');
  }
  const path = canonicalizePath(input.path);
  const query = canonicalizeQuery(input.query, input.querySchema);
  const text = [
    REQUEST_SIGNATURE_DOMAIN,
    input.entityType,
    input.entityId,
    input.keyId,
    method,
    path,
    query,
    input.contentSha256,
    input.timestamp,
    input.nonce,
  ].join('\n');
  return { method, path, query, text, bytes: encoder.encode(text) };
}

export function createSignedRequestHeaders(input: CanonicalRequestInput, signature: string): SignedRequestHeaders {
  return {
    [SIGNED_REQUEST_HEADER_NAMES.entityId]: input.entityId,
    [SIGNED_REQUEST_HEADER_NAMES.keyId]: input.keyId,
    [SIGNED_REQUEST_HEADER_NAMES.timestamp]: input.timestamp,
    [SIGNED_REQUEST_HEADER_NAMES.nonce]: input.nonce,
    [SIGNED_REQUEST_HEADER_NAMES.contentSha256]: input.contentSha256,
    [SIGNED_REQUEST_HEADER_NAMES.signature]: signature,
  };
}

function parseQuery(query: string): QueryPair[] {
  const value = query.startsWith('?') ? query.slice(1) : query;
  assertAscii(value, 'query');
  if (!value) return [];
  if (value.includes('%') || value.includes('+') || value.includes(';') || value.includes('#')) {
    throw new RequestCanonicalizationError('UNSUPPORTED_QUERY_FORM', 'query percent encoding, plus, semicolon, and fragment forms are unsupported');
  }
  return value.split('&').map((pair) => {
    if (!pair || pair.indexOf('=') <= 0 || pair.indexOf('=') !== pair.lastIndexOf('=')) {
      throw new RequestCanonicalizationError('UNSUPPORTED_QUERY_FORM', 'query pairs must use exactly one name=value form');
    }
    const [name, valuePart] = pair.split('=');
    if (!valuePart) throw new RequestCanonicalizationError('UNSUPPORTED_QUERY_FORM', 'empty query values are unsupported');
    return { name, value: valuePart };
  });
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertAscii(value: string, label: string): void {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code > 0x7e || code < 0x20 || code === 0x7f) {
      throw new RequestCanonicalizationError('NON_ASCII_OR_CONTROL', `${label} must contain printable ASCII only`);
    }
  }
}
