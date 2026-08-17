import { describe, expect, test } from 'bun:test';
import {
  PROTOCOL_4_ERROR_CODE_LIST,
  PROTOCOL_4_ERROR_GOLDEN,
  PROTOCOL_4_PRECEDENCE_GOLDEN,
  PROTOCOL_4_RAW_BODY_LIMIT_BYTES,
  PROTOCOL_4_RETRYABLE_CODES,
  isProtocol4ErrorEnvelope,
  protocol4ErrorEnvelope,
  type AgentAdapterProtocol4ErrorCode,
} from './protocol4-error-golden.fixture';

/**
 * Phase 0 golden self-consistency tests (plan Task 00.3). The golden is exact;
 * any change to the table, envelope, or precedence here is a reviewed contract
 * change that Phase 2 implements against and Phase 1 docs mirror.
 */

describe('Protocol 4 error golden freeze (Task 00.3)', () => {
  test('golden is complete: every §6.3 code appears exactly once with exact status mapping', () => {
    const expectedCodes = new Set<string>(PROTOCOL_4_ERROR_CODE_LIST);
    const seen = new Set<string>();
    for (const row of PROTOCOL_4_ERROR_GOLDEN) {
      expect(expectedCodes.has(row.code)).toBe(true);
      expect(seen.has(row.code)).toBe(false); // no duplicate codes
      seen.add(row.code);
    }
    expect(seen.size).toBe(PROTOCOL_4_ERROR_CODE_LIST.length);
    expect(seen.size).toBe(13);

    const statusByCode = new Map<AgentAdapterProtocol4ErrorCode, number>(
      PROTOCOL_4_ERROR_GOLDEN.map((row) => [row.code, row.status]),
    );
    expect(statusByCode.get('UNAUTHORIZED')).toBe(401);
    expect(statusByCode.get('PROTOCOL_VERSION_MISMATCH')).toBe(426);
    expect(statusByCode.get('NOT_FOUND')).toBe(404);
    expect(statusByCode.get('SESSION_NOT_FOUND')).toBe(404);
    expect(statusByCode.get('INVALID_REQUEST')).toBe(400);
    for (const code of ['OWNER_CONFLICT', 'STALE_OWNER', 'IDENTITY_CONFLICT', 'ORDER_CONFLICT', 'COMMAND_CONFLICT', 'COMMAND_OUTCOME_UNKNOWN']) {
      expect(statusByCode.get(code as AgentAdapterProtocol4ErrorCode)).toBe(409);
    }
    expect(statusByCode.get('REQUEST_TOO_LARGE')).toBe(413);
    expect(statusByCode.get('INTERNAL_ERROR')).toBe(500);
  });

  test('retryable=true is reserved for OWNER_CONFLICT only', () => {
    for (const row of PROTOCOL_4_ERROR_GOLDEN) {
      const isOwnerConflict = row.code === 'OWNER_CONFLICT' && row.status === 409;
      expect(row.retryable).toBe(isOwnerConflict);
      expect(PROTOCOL_4_RETRYABLE_CODES).toEqual(['OWNER_CONFLICT']);
    }
  });

  test('envelope is exact: unknown/missing keys rejected, no detail/exception/session/provider/lease fields', () => {
    expect(isProtocol4ErrorEnvelope(protocol4ErrorEnvelope('UNAUTHORIZED', false))).toBe(true);
    expect(isProtocol4ErrorEnvelope(protocol4ErrorEnvelope('OWNER_CONFLICT', true))).toBe(true);
    expect(isProtocol4ErrorEnvelope({ error: { code: 'STALE_OWNER', retryable: false } })).toBe(true);

    const forbidden = [
      { error: { code: 'NOT_FOUND', retryable: false }, detail: 'leak' },          // extra envelope key
      { error: { code: 'NOT_FOUND', retryable: false, detail: 'leak' } },           // extra error key
      { error: { code: 'NOT_FOUND' } },                                             // missing retryable
      { error: { retryable: false } },                                              // missing code
      { error: { code: 'NOT_FOUND', retryable: 'false' } },                         // wrong retryable type
      { error: { code: 'UNKNOWN_CODE', retryable: false } },                        // unknown code
      { error: { code: 'NOT_FOUND', retryable: false }, sessionId: 'sess-1' },      // no session on envelope
      { code: 'NOT_FOUND' },                                                        // no error wrapper
      'INTERNAL_ERROR',                                                             // not an envelope
      null,
      [],
      { error: { code: 'NOT_FOUND', retryable: false, Session: 'leak' } },          // no Session in error object
      { error: { code: 'NOT_FOUND', retryable: false, provider: 'pi' } },           // no provider in error object
      { error: { code: 'NOT_FOUND', retryable: false, ownerLease: 'leak' } },       // no lease in error object
      { error: { code: 'NOT_FOUND', retryable: false, exception: 'text' } },        // no exception text
    ];
    for (const candidate of forbidden) {
      expect(isProtocol4ErrorEnvelope(candidate)).toBe(false);
    }
  });

  test('precedence goldens are exactly the three "decide-before" orderings', () => {
    expect(PROTOCOL_4_PRECEDENCE_GOLDEN.map((row) => row.id)).toEqual([
      'raw-oversize-preempts-bearer',
      'legal-raw-missing-bearer-fails-before-codec',
      'auth-ok-decoded-oversize',
    ]);
    expect(PROTOCOL_4_RAW_BODY_LIMIT_BYTES).toBe(256 * 1024);

    const [oversize, missingBearer, decodedOversize] = PROTOCOL_4_PRECEDENCE_GOLDEN;
    // (1) raw cap+1 + missing/invalid bearer → 413 REQUEST_TOO_LARGE before credential lookup
    expect(oversize!.expectedStatus).toBe(413);
    expect(oversize!.expectedCode).toBe('REQUEST_TOO_LARGE');
    // (2) legal raw + missing bearer + would-be decoded oversize → 401 UNAUTHORIZED without parse
    expect(missingBearer!.expectedStatus).toBe(401);
    expect(missingBearer!.expectedCode).toBe('UNAUTHORIZED');
    // (3) valid auth + decoded oversize → 413 REQUEST_TOO_LARGE
    expect(decodedOversize!.expectedStatus).toBe(413);
    expect(decodedOversize!.expectedCode).toBe('REQUEST_TOO_LARGE');
  });

  test('no code outside the golden is ever emitted', () => {
    for (const row of PROTOCOL_4_ERROR_GOLDEN) {
      expect(PROTOCOL_4_ERROR_CODE_LIST).toContain(row.code);
    }
    // The envelope validator rejects unknown codes, so the golden table is the
    // closed set of errors the wire can ever carry.
    expect(isProtocol4ErrorEnvelope({ error: { code: 'MADE_UP', retryable: false } })).toBe(false);
  });
});