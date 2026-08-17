/**
 * Phase 0 protocol-4 error golden freeze (spec 08-16 §6.3, plan Task 00.3).
 *
 * This is a TEST-LOCAL fixture document. It is the exact, frozen contract that
 * Phase 2 implements against. There is intentionally NO production dispatcher
 * yet: no production code imports this file.
 *
 * Frozen contract:
 *  - exact envelope `{ "error": { "code": AgentAdapterProtocol4ErrorCode, "retryable": boolean } }`;
 *  - unknown/missing envelope keys rejected;
 *  - no detail / Session / provider / lease / registeredAt / exception text;
 *  - complete §6.3 status/code/retryable table; only OWNER_CONFLICT is retryable;
 *  - precedence: raw-body cap+1 with missing/invalid bearer is 413 BEFORE any
 *    credential lookup; legal raw with missing bearer is 401 WITHOUT body parse;
 *    valid auth + decoded oversize is 413.
 */

export type AgentAdapterProtocol4ErrorCode =
  | 'UNAUTHORIZED'
  | 'PROTOCOL_VERSION_MISMATCH'
  | 'NOT_FOUND'
  | 'SESSION_NOT_FOUND'
  | 'INVALID_REQUEST'
  | 'OWNER_CONFLICT'
  | 'STALE_OWNER'
  | 'IDENTITY_CONFLICT'
  | 'ORDER_CONFLICT'
  | 'COMMAND_CONFLICT'
  | 'COMMAND_OUTCOME_UNKNOWN'
  | 'REQUEST_TOO_LARGE'
  | 'INTERNAL_ERROR';

export interface Protocol4ErrorGoldenRow {
  /** §6.3 condition that produces this error. */
  readonly condition: string;
  readonly status: number;
  readonly code: AgentAdapterProtocol4ErrorCode;
  readonly retryable: boolean;
}

/** Raw request-body cap: transport framing/raw size over this → 413 before bearer. */
export const PROTOCOL_4_RAW_BODY_LIMIT_BYTES = 256 * 1024;

/** Complete frozen §6.3 status/code/retryable table. */
export const PROTOCOL_4_ERROR_GOLDEN: readonly Protocol4ErrorGoldenRow[] = [
  {
    condition: 'transport framing/raw size legal; missing/invalid bearer (any target/current path; route existence is not leaked)',
    status: 401, code: 'UNAUTHORIZED', retryable: false,
  },
  {
    condition: 'valid credential but protocol header missing/malformed/non-4',
    status: 426, code: 'PROTOCOL_VERSION_MISMATCH', retryable: false,
  },
  {
    condition: "valid credential + header; unknown path or unsupported method on known path",
    status: 404, code: 'NOT_FOUND', retryable: false,
  },
  {
    condition: 'known owner route; canonical Session does not exist',
    status: 404, code: 'SESSION_NOT_FOUND', retryable: false,
  },
  {
    condition: 'known route: unknown/duplicate/malformed/noncanonical query; malformed JSON/body/path encoding/identifier; missing/malformed instance or lease header; unapproved provider registration',
    status: 400, code: 'INVALID_REQUEST', retryable: false,
  },
  {
    condition: 'same provider / different live instance acquisition',
    status: 409, code: 'OWNER_CONFLICT', retryable: true,
  },
  {
    condition: 'syntactically valid but expired/revoked/non-current instance or lease',
    status: 409, code: 'STALE_OWNER', retryable: false,
  },
  {
    condition: 'provider/session identity collision',
    status: 409, code: 'IDENTITY_CONFLICT', retryable: false,
  },
  {
    condition: 'Event ID/order/fingerprint/checkpoint conflict',
    status: 409, code: 'ORDER_CONFLICT', retryable: false,
  },
  {
    condition: 'command/result tuple or terminal conflict',
    status: 409, code: 'COMMAND_CONFLICT', retryable: false,
  },
  {
    condition: 'late result hits durable unknown',
    status: 409, code: 'COMMAND_OUTCOME_UNKNOWN', retryable: false,
  },
  {
    condition: 'HTTP framing invalid or raw body over 256 KiB (decided before bearer, even with missing/invalid bearer); or valid credential/header/route then decoded body over route limit',
    status: 413, code: 'REQUEST_TOO_LARGE', retryable: false,
  },
  {
    condition: 'unexpected internal failure',
    status: 500, code: 'INTERNAL_ERROR', retryable: false,
  },
];

export const PROTOCOL_4_ERROR_CODE_LIST: readonly AgentAdapterProtocol4ErrorCode[] = [
  'UNAUTHORIZED',
  'PROTOCOL_VERSION_MISMATCH',
  'NOT_FOUND',
  'SESSION_NOT_FOUND',
  'INVALID_REQUEST',
  'OWNER_CONFLICT',
  'STALE_OWNER',
  'IDENTITY_CONFLICT',
  'ORDER_CONFLICT',
  'COMMAND_CONFLICT',
  'COMMAND_OUTCOME_UNKNOWN',
  'REQUEST_TOO_LARGE',
  'INTERNAL_ERROR',
] as const;

/** retryable=true is reserved for OWNER_CONFLICT only. */
export const PROTOCOL_4_RETRYABLE_CODES: readonly AgentAdapterProtocol4ErrorCode[] = ['OWNER_CONFLICT'] as const;

/** Exact error envelope. */
export interface Protocol4ErrorEnvelopeShape {
  error: { code: AgentAdapterProtocol4ErrorCode; retryable: boolean };
}

export function protocol4ErrorEnvelope(
  code: AgentAdapterProtocol4ErrorCode,
  retryable = false,
): Protocol4ErrorEnvelopeShape {
  return { error: { code, retryable } };
}

/**
 * Exact-key envelope validator: only `error`, `error` only has `code +
 * retryable`, types exact, code known. Missing/unknown keys and unknown codes
 * are rejected.
 */
export function isProtocol4ErrorEnvelope(value: unknown): value is Protocol4ErrorEnvelopeShape {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !Object.hasOwn(record, 'error')) return false;
  const error = record.error;
  if (typeof error !== 'object' || error === null || Array.isArray(error)) return false;
  const errorRecord = error as Record<string, unknown>;
  if (Object.keys(errorRecord).length !== 2
    || !Object.hasOwn(errorRecord, 'code') || !Object.hasOwn(errorRecord, 'retryable')) return false;
  if (typeof errorRecord.retryable !== 'boolean') return false;
  return (PROTOCOL_4_ERROR_CODE_LIST as readonly string[]).includes(errorRecord.code as string);
}

export interface Protocol4PrecedenceGoldenRow {
  readonly id: string;
  readonly scenario: string;
  readonly expectedStatus: number;
  readonly expectedCode: AgentAdapterProtocol4ErrorCode;
  readonly note: string;
}

/** Frozen §6.3 precedence goldens. */
export const PROTOCOL_4_PRECEDENCE_GOLDEN: readonly Protocol4PrecedenceGoldenRow[] = [
  {
    id: 'raw-oversize-preempts-bearer',
    scenario: 'raw body > 256 KiB AND missing/invalid bearer',
    expectedStatus: 413,
    expectedCode: 'REQUEST_TOO_LARGE',
    note: '413 is decided on transport framing/raw size BEFORE bearer comparison; the same request is 413 even though the bearer is missing/invalid.',
  },
  {
    id: 'legal-raw-missing-bearer-fails-before-codec',
    scenario: 'legal raw body + missing bearer, would-be decoded body over decoded cap',
    expectedStatus: 401,
    expectedCode: 'UNAUTHORIZED',
    note: 'Auth fails first; 401 is returned WITHOUT parsing the body, so the would-be decoded oversize is never discovered.',
  },
  {
    id: 'auth-ok-decoded-oversize',
    scenario: 'valid credential/header/route + decoded body over route limit',
    expectedStatus: 413,
    expectedCode: 'REQUEST_TOO_LARGE',
    note: '413 is only reachable after the auth layer passed.',
  },
];