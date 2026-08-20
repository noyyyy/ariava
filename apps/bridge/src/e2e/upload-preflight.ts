import { createHash, timingSafeEqual } from 'node:crypto';
import {
  base64UrlEncode,
  buildProtectedEventContentBytes,
  buildProtectedSessionContentBytes,
  encodeLengthPrefixedFields,
  ProtectedContentValidationError,
  type CanonicalEvent,
  type CanonicalSessionState,
} from '@ariava/protocol';
import { eventEncryptionInput, PendingUploadBindingError, sessionEncryptionInput } from './upload-inputs';

export { PendingUploadBindingError };

/**
 * Discriminated local-upload preflight result (§4.1).
 *
 * `invalid-content` is produced ONLY by `ProtectedContentValidationError`
 * (canonical protected-content exact-shape / well-formed Unicode / byte-limit
 * validation). `invalid-source-binding` is produced ONLY by
 * `PendingUploadBindingError` thrown after a successful source decode for
 * Event↔Session binding mismatches or a `need_human` Session missing
 * `lastEventId`; recipient/keyring binding never produces it. JSON/UTF-8
 * decode failures are reported by the per-item storage API as fixed results
 * (Slice 5), never inferred from exception class names here.
 * Every other error (crypto, keyring, X25519, AEAD, randomness, IO,
 * spool/state invariants) propagates and is NOT locally isolatable.
 */
export type LocalUploadPreflight =
  | { type: 'ready'; sourceDigest: string }
  | { type: 'invalid-content'; code: 'protected-session-invalid' | 'protected-event-invalid' }
  | { type: 'invalid-source-binding'; code: 'event-session-binding-invalid' };

export const SESSION_SOURCE_DIGEST_NAMESPACE = 'ariava:session-upload-source:v1';
export const EVENT_SOURCE_DIGEST_NAMESPACE = 'ariava:event-upload-source:v1';

const textEncoder = new TextEncoder();

export function encodeSourceDigestInput(namespace: string, fields: readonly string[]): Uint8Array {
  const prefix = textEncoder.encode(`${namespace}\n`);
  const canonical = encodeLengthPrefixedFields(fields);
  const result = new Uint8Array(prefix.byteLength + canonical.byteLength);
  result.set(prefix);
  result.set(canonical, prefix.byteLength);
  return result;
}

function sha256Base64Url(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('base64url');
}

/**
 * Constant-time comparison of two 43-character base64url SHA-256 digests (§4.3).
 * Non-canonical inputs (wrong length / alphabet) are rejected as unequal so a
 * malformed persisted digest can never be treated as a match.
 */
export function digestsEqual(left: string, right: string): boolean {
  if (left.length !== right.length || !SOURCE_DIGEST_PATTERN.test(left) || !SOURCE_DIGEST_PATTERN.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'base64url'), Buffer.from(right, 'base64url'));
}

const SOURCE_DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * Deterministic canonical bytes for one Session upload source tuple (§4.3).
 * Built from the shared exact canonical encoders (length-prefixed fields +
 * canonical protected content); never from object property order or
 * ciphertext. Slice 5 reuses these bytes for the inflight V2 wrapper digests.
 */
function canonicalSessionSourceBytes(session: CanonicalSessionState): Uint8Array {
  const input = sessionEncryptionInput(session);
  return encodeSourceDigestInput(SESSION_SOURCE_DIGEST_NAMESPACE, [
    session.hostId,
    session.sessionId,
    session.provider,
    session.status,
    session.updatedAt,
    session.lastEventId ?? '',
    session.snoozedUntil ?? '',
    base64UrlEncode(buildProtectedSessionContentBytes(input.protectedSession)),
  ]);
}

/**
 * Deterministic canonical bytes for one immutable pending Event + bundled
 * terminal Session tuple (§4.3).
 */
function canonicalEventSourceBytes(event: CanonicalEvent, session: CanonicalSessionState): Uint8Array {
  const input = eventEncryptionInput(event, session);
  return encodeSourceDigestInput(EVENT_SOURCE_DIGEST_NAMESPACE, [
    event.eventId,
    event.hostId,
    event.sessionId,
    event.provider,
    event.type,
    event.status,
    event.createdAt,
    session.updatedAt,
    session.snoozedUntil ?? '',
    base64UrlEncode(buildProtectedEventContentBytes(input.protectedEvent)),
    base64UrlEncode(buildProtectedSessionContentBytes(input.protectedSession)),
  ]);
}

/** 43-character base64url SHA-256 source digest for one Session upload source. */
export function sessionSourceDigest(session: CanonicalSessionState): string {
  return sha256Base64Url(canonicalSessionSourceBytes(session));
}

/** 43-character base64url SHA-256 source digest for one immutable Event tuple. */
export function eventSourceDigest(event: CanonicalEvent, session: CanonicalSessionState): string {
  return sha256Base64Url(canonicalEventSourceBytes(event, session));
}

/**
 * Protected-content preflight for one authoritative Session snapshot.
 * Must complete before randomness, sealing, or recipient DEK wrapping.
 */
export function preflightSessionSource(session: CanonicalSessionState): LocalUploadPreflight {
  try {
    buildProtectedSessionContentBytes(sessionEncryptionInput(session).protectedSession);
  } catch (error) {
    if (error instanceof ProtectedContentValidationError) {
      return { type: 'invalid-content', code: error.code };
    }
    if (error instanceof PendingUploadBindingError) {
      return { type: 'invalid-source-binding', code: error.code };
    }
    throw error;
  }
  return { type: 'ready', sourceDigest: sessionSourceDigest(session) };
}

/**
 * Protected-content + binding preflight for one immutable pending Event and
 * its bundled terminal Session snapshot (§4.1, §4.2 entry points 3-4).
 */
export function preflightEventSource(event: CanonicalEvent, session: CanonicalSessionState): LocalUploadPreflight {
  try {
    const input = eventEncryptionInput(event, session);
    buildProtectedEventContentBytes(input.protectedEvent);
    buildProtectedSessionContentBytes(input.protectedSession);
  } catch (error) {
    if (error instanceof ProtectedContentValidationError) {
      return { type: 'invalid-content', code: error.code };
    }
    if (error instanceof PendingUploadBindingError) {
      return { type: 'invalid-source-binding', code: error.code };
    }
    throw error;
  }
  return { type: 'ready', sourceDigest: eventSourceDigest(event, session) };
}
