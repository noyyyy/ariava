import { describe, expect, test } from 'bun:test';
import { isAbortError, snapshotError, type SnapshotErrorCode } from '../src/daemon/daemon-errors';
import { buildHostEnrollmentRequest, buildHostMetadata } from '../src/daemon/daemon-inputs';
import { RelayClientError } from '../src/relay-client';

/**
 * Pure table tests for the deterministic daemon error parser and request
 * builders extracted in Task 3 (plan `2026-08-16-bridge-daemon-lifecycle-
 * decomposition.md`, spec §5/§7/§10). No I/O, no secrets.
 */
describe('buildHostMetadata deterministic evidence inputs', () => {
  test('builds the exact metadata shape from explicit evidence', () => {
    expect(buildHostMetadata({ hostName: 'MacBook', hostPlatform: 'macos', bridgeVersion: '0.3.0' }))
      .toEqual({ hostName: 'MacBook', platform: 'macos', bridgeVersion: '0.3.0' });
  });

  test('preserves every field verbatim', () => {
    expect(buildHostMetadata({ hostName: '  Host Name  ', hostPlatform: 'linux', bridgeVersion: '1.2.3' }))
      .toEqual({ hostName: '  Host Name  ', platform: 'linux', bridgeVersion: '1.2.3' });
  });
});

describe('buildHostEnrollmentRequest deterministic evidence inputs', () => {
  test('assembles the exact HostEnrollmentRequest shape from explicit evidence', () => {
    const identity = {
      hostId: 'host-1',
      keyId: 'key-1',
      algorithm: 'Ed25519' as const,
      publicKey: 'pub-key',
    };
    const request = buildHostEnrollmentRequest({
      identity,
      encryptionBinding: {
        version: 1, entityType: 'host' as const, entityId: 'host-1', identityKeyId: 'key-1', encryptionKeyId: 'enc-key-1',
        suite: 'x25519-hkdf-sha256-chachapoly-v1', publicKey: 'binding-pub', sequence: 1,
        createdAt: '2026-08-16T00:00:00.000Z', bindingSignature: 'sig',
      },
      hostMetadata: { hostName: 'MacBook', platform: 'macos', bridgeVersion: '0.3.0' },
    });
    expect(request).toEqual({
      hostId: 'host-1', keyId: 'key-1', algorithm: 'Ed25519', publicKey: 'pub-key',
      encryptionBinding: {
        version: 1, entityType: 'host', entityId: 'host-1', identityKeyId: 'key-1', encryptionKeyId: 'enc-key-1',
        suite: 'x25519-hkdf-sha256-chachapoly-v1', publicKey: 'binding-pub', sequence: 1,
        createdAt: '2026-08-16T00:00:00.000Z', bindingSignature: 'sig',
      },
      hostName: 'MacBook', platform: 'macos', bridgeVersion: '0.3.0',
    });
  });
});

describe('isAbortError pure recognition', () => {
  test('recognizes AbortError-name errors and rejects everything else', () => {
    const abortError = new Error('aborted');
    abortError.name = 'AbortError';
    expect(isAbortError(abortError)).toBe(true);
    expect(isAbortError(new Error('plain failure'))).toBe(false);
    expect(isAbortError(new TypeError('type failure'))).toBe(false);
    expect(isAbortError(new RelayClientError(503, 'relay failure'))).toBe(false);
    expect(isAbortError('aborted')).toBe(false);
    expect(isAbortError(null)).toBe(false);
    expect(isAbortError(undefined)).toBe(false);
  });
});

describe('snapshotError pure conflict parser', () => {
  const stale = 'session_snapshot_stale';
  const conflict = 'session_snapshot_conflict';
  const recipientNotReady = 'e2e_recipient_not_ready';
  const recipientChanged = 'e2e_recipient_set_changed';
  const referenceInvalid = 'e2e_session_reference_invalid';

  test('extracts acceptedRevision from valid 409 bodies across every code', () => {
    const rows: Array<{ code: SnapshotErrorCode; body: Record<string, unknown>; expected: { acceptedRevision?: number } | undefined }> = [
      { code: stale, body: { code: stale, acceptedRevision: 7 }, expected: { acceptedRevision: 7 } },
      { code: conflict, body: { error: conflict, acceptedRevision: 3 }, expected: { acceptedRevision: 3 } },
      { code: recipientNotReady, body: { reason: recipientNotReady, acceptedRevision: 5 }, expected: { acceptedRevision: 5 } },
      { code: recipientChanged, body: { code: recipientChanged, acceptedRevision: 5 }, expected: { acceptedRevision: 5 } },
      { code: referenceInvalid, body: { error: referenceInvalid }, expected: {} },
      { code: recipientNotReady, body: { reason: recipientNotReady }, expected: {} },
      { code: stale, body: { code: stale, acceptedRevision: 0 }, expected: { acceptedRevision: 0 } },
    ];
    for (const row of rows) {
      expect(snapshotError(new RelayClientError(409, 'conflict', row.body), row.code)).toEqual(row.expected);
    }
  });

  test('falls back to the RelayClientError reason without body code/error/reason', () => {
    expect(snapshotError(new RelayClientError(409, stale, { acceptedRevision: 9 }), stale))
      .toEqual({ acceptedRevision: 9 });
  });

  test('fail-closed: stale requires a safe-integer acceptedRevision', () => {
    const malformed: Array<Record<string, unknown>> = [
      { code: stale },                                   // absent
      { code: stale, acceptedRevision: '7' },            // string
      { code: stale, acceptedRevision: 7.5 },            // float
      { code: stale, acceptedRevision: Number.NaN },     // NaN
      { code: stale, acceptedRevision: Number.POSITIVE_INFINITY }, // non-finite
      { code: stale, acceptedRevision: null },           // null
      { code: stale, acceptedRevision: undefined },      // explicit undefined
    ];
    for (const body of malformed) {
      expect(snapshotError(new RelayClientError(409, 'conflict', body), stale)).toBeUndefined();
    }
  });

  test('fail-closed: ignores non-409, non-RelayClientError, and non-object bodies', () => {
    expect(snapshotError(new RelayClientError(503, 'offline', { code: stale, acceptedRevision: 7 }), stale)).toBeUndefined();
    expect(snapshotError(new Error('spurious'), stale)).toBeUndefined();
    expect(snapshotError(new RelayClientError(409, 'conflict', 'not-an-object'), stale)).toBeUndefined();
    expect(snapshotError(new RelayClientError(409, 'conflict', null), stale)).toBeUndefined();
    expect(snapshotError(new RelayClientError(409, 'conflict', undefined), stale)).toBeUndefined();
  });

  test('reason mismatch returns undefined for any queried code', () => {
    expect(snapshotError(new RelayClientError(409, 'conflict', { code: recipientNotReady }), stale)).toBeUndefined();
    expect(snapshotError(new RelayClientError(409, 'conflict', { error: recipientChanged }), stale)).toBeUndefined();
  });

  test('stale without revision evidence never yields a bare empty evidence object', () => {
    expect(snapshotError(new RelayClientError(409, 'conflict', { code: stale }), stale)).toBeUndefined();
  });
});
