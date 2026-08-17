import { describe, expect, test } from 'bun:test';
import {
  AGENT_ADAPTER_COMMAND_POLL_QUERY,
  AGENT_ADAPTER_DISCOVERY_KEYS,
  AGENT_ADAPTER_EVENT_DISPOSITIONS,
  AGENT_ADAPTER_HANDLE_ACTIONS,
  AGENT_ADAPTER_HEALTH_PATH,
  AGENT_ADAPTER_LIMITS,
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
  AGENT_ADAPTER_ROUTE_PREFIX,
  PRODUCER_EVENT_ORDER_MAX,
  PROTOCOL_4_ERROR_CODE_LIST,
  PROTOCOL_4_ERROR_GOLDEN,
  PROTOCOL_4_PRECEDENCE_GOLDEN,
  PROTOCOL_4_RAW_BODY_LIMIT_BYTES,
  PROTOCOL_4_RETRYABLE_CODES,
  SESSION_HANDLE_ACTIONS,
  agentAdapterProtocol4ErrorRetryable,
  agentAdapterProtocol4ErrorStatus,
  base64UrlEncode,
  decodeAgentAdapterPathIdentifier,
  isAgentAdapterCommandPollTimeout,
  isAgentAdapterDiscovery,
  isAgentAdapterDriverInstanceId,
  isAgentAdapterIdentifier,
  isAgentAdapterOwnerLease,
  isAgentAdapterProducerEventId,
  isAgentAdapterProducerEventOrder,
  isProtocol4ErrorEnvelope,
  nextProducerEventOrder,
  parseAgentAdapterCommandPollTimeout,
  producerEventOrderAsBigInt,
  producerEventOrderFromBigInt,
  protocol4ErrorEnvelope,
  validateAgentAdapterDiscovery,
  validateAgentAdapterEventRequest,
  validateAgentAdapterEventResponse,
  validateAgentAdapterHandleRequest,
  validateAgentAdapterHandleResponse,
  validateAgentAdapterHeartbeatRequest,
  validateAgentAdapterOkResponse,
  validateAgentAdapterRegisterOwnedResponse,
  validateAgentAdapterRegisterRequest,
  validateCommandResult,
  type AgentAdapterHandleAction,
  type AgentAdapterProtocol4ErrorCode,
} from '../src';
import {
  PROTOCOL_4_ERROR_GOLDEN as FROZEN_ERROR_GOLDEN,
  PROTOCOL_4_ERROR_CODE_LIST as FROZEN_ERROR_CODE_LIST,
  PROTOCOL_4_PRECEDENCE_GOLDEN as FROZEN_PRECEDENCE_GOLDEN,
  PROTOCOL_4_RAW_BODY_LIMIT_BYTES as FROZEN_RAW_BODY_LIMIT,
  PROTOCOL_4_RETRYABLE_CODES as FROZEN_RETRYABLE_CODES,
} from '../../../apps/bridge/test/agent-adapter/protocol4-error-golden.fixture.js';

const sessionIdPlaceholder = 'session_1';
const hostIdPlaceholder = `host_${'A'.repeat(43)}`;
const canonicalTimestamp = '2026-08-17T00:00:00.000Z';

function bytes(length: number): Uint8Array {
  return new Uint8Array(length);
}

const VALID_DISCOVERY = {
  url: 'http://127.0.0.1:7272',
  secret: 'a'.repeat(64),
  protocolVersion: 4,
  provider: 'pi',
  profileId: 'default',
  hostId: hostIdPlaceholder,
} as const;

function validRegister(): Record<string, unknown> {
  return {
    sessionId: sessionIdPlaceholder,
    provider: 'pi',
    projectName: 'Project',
    cwd: '/workspace/ariava',
    nameText: 'Session title',
    driverInstanceId: base64UrlEncode(bytes(32)),
    openingText: 'opening',
    latestActivityText: 'working text',
    harnessProvider: 'pi',
    pid: 1234,
    status: 'working',
  };
}

function validEvent(): Record<string, unknown> {
  return {
    producerEventId: base64UrlEncode(bytes(16)),
    producerEventOrder: `${'0'.repeat(31)}1`,
    event: {
      eventId: 'evt_1',
      hostId: hostIdPlaceholder,
      sessionId: sessionIdPlaceholder,
      provider: 'pi',
      type: 'done',
      status: 'idle',
      agentText: 'Finished',
      createdAt: canonicalTimestamp,
    },
  };
}

describe('Protocol 4 generation constants', () => {
  test('header version is exactly 4', () => {
    expect(AGENT_ADAPTER_PROTOCOL_VERSION).toBe(4);
    expect(AGENT_ADAPTER_PROTOCOL_HEADER).toBe('x-ariava-agent-adapter-version');
  });

  test('health and agent route constants are independent of each other and of the version', () => {
    expect(AGENT_ADAPTER_HEALTH_PATH).toBe('/v2/health');
    expect(AGENT_ADAPTER_ROUTE_PREFIX).toBe('/v2/agent');
    expect(AGENT_ADAPTER_HEALTH_PATH).not.toBe(AGENT_ADAPTER_ROUTE_PREFIX);
    expect(AGENT_ADAPTER_HEALTH_PATH.includes(String(AGENT_ADAPTER_PROTOCOL_VERSION))).toBe(false);
    expect(AGENT_ADAPTER_ROUTE_PREFIX.includes(String(AGENT_ADAPTER_PROTOCOL_VERSION))).toBe(false);
    expect(AGENT_ADAPTER_HEALTH_PATH.startsWith('/v1/')).toBe(false);
    expect(AGENT_ADAPTER_ROUTE_PREFIX.startsWith('/v1/')).toBe(false);
    // The route generation is a storage-level independent constant: it is not
    // a string-mutation of the health path and carries no version probe.
    expect(AGENT_ADAPTER_HEALTH_PATH.endsWith(String(AGENT_ADAPTER_PROTOCOL_VERSION))).toBe(false);
    expect(AGENT_ADAPTER_ROUTE_PREFIX.endsWith(String(AGENT_ADAPTER_PROTOCOL_VERSION))).toBe(false);
  });

  test('shared limits own the frozen body cap', () => {
    expect(AGENT_ADAPTER_LIMITS.requestBodyBytes).toBe(256 * 1024);
    expect(PROTOCOL_4_RAW_BODY_LIMIT_BYTES).toBe(AGENT_ADAPTER_LIMITS.requestBodyBytes);
    expect(AGENT_ADAPTER_LIMITS.identifierBytes).toBe(256);
    expect(AGENT_ADAPTER_LIMITS.driverInstanceIdMinBits).toBe(128);
    expect(AGENT_ADAPTER_LIMITS.ownerLeaseBytes).toBe(32);
    expect(AGENT_ADAPTER_LIMITS.ownerLeaseCharacters).toBe(43);
    expect(AGENT_ADAPTER_LIMITS.producerEventIdBytes).toBe(16);
    expect(AGENT_ADAPTER_LIMITS.producerEventIdCharacters).toBe(22);
    expect(AGENT_ADAPTER_LIMITS.producerEventOrderCharacters).toBe(32);
    expect(AGENT_ADAPTER_LIMITS.commandPollTimeoutMinMs).toBe(0);
    expect(AGENT_ADAPTER_LIMITS.commandPollTimeoutMaxMs).toBe(120_000);
    expect(AGENT_ADAPTER_LIMITS.commandPollTimeoutDefaultMs).toBe(30_000);
    expect(AGENT_ADAPTER_LIMITS.eventCanonicalBytes).toBe(64 * 1024);
  });
});

describe('Protocol 4 discovery schema', () => {
  test('exact six keys and nothing else', () => {
    expect(AGENT_ADAPTER_DISCOVERY_KEYS).toEqual([
      'url', 'secret', 'protocolVersion', 'provider', 'profileId', 'hostId',
    ]);
  });

  test('accepts the canonical discovery', () => {
    expect(isAgentAdapterDiscovery(VALID_DISCOVERY)).toBe(true);
    const validated = validateAgentAdapterDiscovery(VALID_DISCOVERY);
    expect(validated.success).toBe(true);
    expect(validated.value).toEqual({ ...VALID_DISCOVERY, url: 'http://127.0.0.1:7272' });
  });

  test('rejects unknown or missing keys', () => {
    for (const extra of ['secret2', 'agentSecret', 'schemaVersion', 'hostName', 'scope']) {
      expect(isAgentAdapterDiscovery({ ...VALID_DISCOVERY, [extra]: 'x' }), extra).toBe(false);
    }
    for (const missing of AGENT_ADAPTER_DISCOVERY_KEYS) {
      const candidate = { ...VALID_DISCOVERY };
      delete candidate[missing];
      expect(isAgentAdapterDiscovery(candidate), `missing ${missing}`).toBe(false);
      expect(validateAgentAdapterDiscovery(candidate).success, `missing ${missing}`).toBe(false);
    }
  });

  test('rejects a non-4 protocolVersion and invalid values', () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ['version 3', { ...VALID_DISCOVERY, protocolVersion: 3 }],
      ['version string', { ...VALID_DISCOVERY, protocolVersion: '4' }],
      ['empty secret', { ...VALID_DISCOVERY, secret: '' }],
      ['whitespace secret', { ...VALID_DISCOVERY, secret: ` ${'a'.repeat(32)} ` }],
      ['empty provider', { ...VALID_DISCOVERY, provider: '' }],
      ['oversized provider', { ...VALID_DISCOVERY, provider: 'x'.repeat(257) }],
      ['lone surrogate provider', { ...VALID_DISCOVERY, provider: '\ud800' }],
      ['empty profileId', { ...VALID_DISCOVERY, profileId: '' }],
      ['empty hostId', { ...VALID_DISCOVERY, hostId: '' }],
    ];
    for (const [name, candidate] of cases) {
      expect(isAgentAdapterDiscovery(candidate), name).toBe(false);
      expect(validateAgentAdapterDiscovery(candidate).success, name).toBe(false);
    }
  });

  test('rejects non-loopback, authenticated, slash-less, port-less or query-carrying urls', () => {
    const urls = [
      'http://192.168.1.10:7272',
      'http://localhost:7272',
      'http://127.0.0.1:7272/agent',
      'https://127.0.0.1:7272',
      'http://user:pass@127.0.0.1:7272',
      'http://127.0.0.1:7272?x=1',
      'http://127.0.0.1:7272#frag',
      'http://127.0.0.1',
      'not a url',
      '',
    ];
    for (const url of urls) {
      const candidate = { ...VALID_DISCOVERY, url };
      expect(isAgentAdapterDiscovery(candidate), url).toBe(false);
      expect(validateAgentAdapterDiscovery(candidate).success, url).toBe(false);
    }
    expect(isAgentAdapterDiscovery({ ...VALID_DISCOVERY, url: 'http://[::1]:7272' })).toBe(true);
  });

  test('rejects accessor and prototype tricks', () => {
    const withInheritedProvider = Object.assign(
      Object.create({ provider: 'pi', profileId: 'default', hostId: hostIdPlaceholder }),
      { url: VALID_DISCOVERY.url, secret: VALID_DISCOVERY.secret, protocolVersion: 4 },
    );
    expect(isAgentAdapterDiscovery(withInheritedProvider)).toBe(false); // non-plain prototype
    expect(isAgentAdapterDiscovery({ ...withInheritedProvider })).toBe(false); // spread loses the inherited identity keys
  });
});

describe('Protocol 4 error contract (AAB015)', () => {
  test('the production table is byte-identical to the frozen Phase 0 bridge fixture', () => {
    expect(PROTOCOL_4_ERROR_GOLDEN).toEqual(FROZEN_ERROR_GOLDEN);
    expect(PROTOCOL_4_ERROR_CODE_LIST).toEqual(FROZEN_ERROR_CODE_LIST);
    expect(PROTOCOL_4_PRECEDENCE_GOLDEN).toEqual(FROZEN_PRECEDENCE_GOLDEN);
    expect(PROTOCOL_4_RETRYABLE_CODES).toEqual(FROZEN_RETRYABLE_CODES);
    expect(PROTOCOL_4_RAW_BODY_LIMIT_BYTES).toBe(FROZEN_RAW_BODY_LIMIT);
  });

  test('golden is complete: every §6.3 code appears exactly once with exact status mapping', () => {
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
    expect(statusByCode.size).toBe(PROTOCOL_4_ERROR_CODE_LIST.length);
    expect(statusByCode.size).toBe(13);
  });

  test('retryable=true is reserved for OWNER_CONFLICT only', () => {
    for (const row of PROTOCOL_4_ERROR_GOLDEN) {
      expect(row.retryable).toBe(row.code === 'OWNER_CONFLICT');
    }
    expect(PROTOCOL_4_RETRYABLE_CODES).toEqual(['OWNER_CONFLICT']);
    expect(agentAdapterProtocol4ErrorRetryable('OWNER_CONFLICT')).toBe(true);
    expect(agentAdapterProtocol4ErrorRetryable('INTERNAL_ERROR')).toBe(false);
    expect(agentAdapterProtocol4ErrorRetryable('REQUEST_TOO_LARGE')).toBe(false);
  });

  test('status mapper maps every code to its frozen status', () => {
    for (const row of PROTOCOL_4_ERROR_GOLDEN) {
      expect(agentAdapterProtocol4ErrorStatus(row.code)).toBe(row.status);
    }
  });

  test('envelope is exact: unknown/missing keys rejected, no detail/session/provider/lease/exception', () => {
    expect(isProtocol4ErrorEnvelope(protocol4ErrorEnvelope('UNAUTHORIZED', false))).toBe(true);
    expect(isProtocol4ErrorEnvelope(protocol4ErrorEnvelope('OWNER_CONFLICT', true))).toBe(true);
    expect(isProtocol4ErrorEnvelope({ error: { code: 'STALE_OWNER', retryable: false } })).toBe(true);

    const forbidden = [
      { error: { code: 'NOT_FOUND', retryable: false }, detail: 'leak' },
      { error: { code: 'NOT_FOUND', retryable: false, detail: 'leak' } },
      { error: { code: 'NOT_FOUND' } },
      { error: { retryable: false } },
      { error: { code: 'NOT_FOUND', retryable: 'false' } },
      { error: { code: 'UNKNOWN_CODE', retryable: false } },
      { error: { code: 'NOT_FOUND', retryable: false }, sessionId: 'sess-1' },
      { code: 'NOT_FOUND' },
      'INTERNAL_ERROR',
      null,
      [],
      { error: { code: 'NOT_FOUND', retryable: false, Session: 'leak' } },
      { error: { code: 'NOT_FOUND', retryable: false, provider: 'pi' } },
      { error: { code: 'NOT_FOUND', retryable: false, ownerLease: 'leak' } },
      { error: { code: 'NOT_FOUND', retryable: false, exception: 'text' } },
      { error: { code: 'OWNER_CONFLICT', retryable: 'true' } },
      { error: { code: 'NOT_FOUND', retryable: false, retryable2: true } },
    ];
    for (const candidate of forbidden) expect(isProtocol4ErrorEnvelope(candidate), JSON.stringify(candidate)).toBe(false);

    // accessor/prototype tricks fail closed
    const accessorEnvelope: Record<string, unknown> = {};
    Object.defineProperty(accessorEnvelope, 'error', {
      enumerable: true, get: () => ({ code: 'NOT_FOUND', retryable: false }),
    });
    expect(isProtocol4ErrorEnvelope(accessorEnvelope)).toBe(false);
  });

  test('precedence goldens are exactly the three decide-before orderings', () => {
    expect(PROTOCOL_4_PRECEDENCE_GOLDEN.map((row) => row.id)).toEqual([
      'raw-oversize-preempts-bearer',
      'legal-raw-missing-bearer-fails-before-codec',
      'auth-ok-decoded-oversize',
    ]);
    const [oversize, missingBearer, decodedOversize] = PROTOCOL_4_PRECEDENCE_GOLDEN;
    expect(oversize!.expectedStatus).toBe(413);
    expect(oversize!.expectedCode).toBe('REQUEST_TOO_LARGE');
    expect(missingBearer!.expectedStatus).toBe(401);
    expect(missingBearer!.expectedCode).toBe('UNAUTHORIZED');
    expect(decodedOversize!.expectedStatus).toBe(413);
    expect(decodedOversize!.expectedCode).toBe('REQUEST_TOO_LARGE');
    // every precedence row stays inside the closed golden table
    for (const row of PROTOCOL_4_PRECEDENCE_GOLDEN) {
      expect(PROTOCOL_4_ERROR_CODE_LIST).toContain(row.expectedCode);
      expect(isProtocol4ErrorEnvelope(protocol4ErrorEnvelope(row.expectedCode, false))).toBe(true);
    }
  });
});

describe('Protocol 4 exact codecs', () => {
  test('identifiers: non-empty, well-formed Unicode, ≤ 256 UTF-8 bytes', () => {
    expect(isAgentAdapterIdentifier('session_1')).toBe(true);
    expect(isAgentAdapterIdentifier('x'.repeat(256))).toBe(true);
    expect(isAgentAdapterIdentifier('x'.repeat(257))).toBe(false);
    expect(isAgentAdapterIdentifier('中'.repeat(85))).toBe(true); // 255 bytes
    expect(isAgentAdapterIdentifier('中'.repeat(86))).toBe(false); // 258 bytes
    expect(isAgentAdapterIdentifier('')).toBe(false);
    expect(isAgentAdapterIdentifier('\ud800')).toBe(false);
    expect(isAgentAdapterIdentifier('a\udc00b')).toBe(false);
    expect(isAgentAdapterIdentifier(123)).toBe(false);
  });

  test('producerEventId: exactly 22-char base64url-no-padding encoding 16 bytes', () => {
    const valid = base64UrlEncode(bytes(16));
    expect(valid.length).toBe(22);
    expect(isAgentAdapterProducerEventId(valid)).toBe(true);
    expect(isAgentAdapterProducerEventId(base64UrlEncode(bytes(15)))).toBe(false); // 20 chars / 15 bytes
    expect(isAgentAdapterProducerEventId(base64UrlEncode(bytes(17)))).toBe(false); // 23 chars / 17 bytes
    expect(isAgentAdapterProducerEventId(`${valid}=`)).toBe(false); // padding
    expect(isAgentAdapterProducerEventId(valid.slice(0, 21))).toBe(false);
    expect(isAgentAdapterProducerEventId(`${valid.slice(0, 21)}@`)).toBe(false); // non-base64url char
    expect(isAgentAdapterProducerEventId('')).toBe(false);
  });

  test('ownerLease: exactly 43-char base64url-no-padding encoding 32 bytes', () => {
    const valid = base64UrlEncode(bytes(32));
    expect(valid.length).toBe(43);
    expect(isAgentAdapterOwnerLease(valid)).toBe(true);
    expect(isAgentAdapterOwnerLease(base64UrlEncode(bytes(31)))).toBe(false); // 42 chars / 31 bytes
    expect(isAgentAdapterOwnerLease(`${valid}=`)).toBe(false); // padded
    expect(isAgentAdapterOwnerLease(valid.slice(0, 42))).toBe(false);
    const mixedCaseLease = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, index) => index + 60));
    expect(isAgentAdapterOwnerLease(mixedCaseLease)).toBe(true);
    expect(isAgentAdapterOwnerLease(mixedCaseLease.toUpperCase())).toBe(false); // case change breaks canonical encoding
    expect(isAgentAdapterOwnerLease(valid.slice(0, 42) + '$')).toBe(false);
  });

  test('driverInstanceId: ≥ 128-bit, ≤ 256 UTF-8 bytes, canonical unpadded base64url', () => {
    expect(isAgentAdapterDriverInstanceId(base64UrlEncode(bytes(16)))).toBe(true);
    expect(isAgentAdapterDriverInstanceId(base64UrlEncode(bytes(22)))).toBe(true); // Pi convention length
    expect(isAgentAdapterDriverInstanceId(base64UrlEncode(bytes(170)))).toBe(true); // encoded length still ≤ 256 chars
    expect(isAgentAdapterDriverInstanceId(base64UrlEncode(bytes(15)))).toBe(false); // < 128 bit
    expect(isAgentAdapterDriverInstanceId('short')).toBe(false); // not base64url
    expect(isAgentAdapterDriverInstanceId(`${'x'.repeat(255)}!`)).toBe(false); // non-base64url char
    expect(isAgentAdapterDriverInstanceId(base64UrlEncode(bytes(200)))).toBe(false); // 268 chars > 256 bytes
    expect(isAgentAdapterDriverInstanceId('')).toBe(false);
  });

  test('producerEventOrder: 32 lowercase hex, starts at 1, never zero, overflow fail-closed', () => {
    const one = `${'0'.repeat(31)}1`;
    expect(isAgentAdapterProducerEventOrder(one)).toBe(true);
    expect(isAgentAdapterProducerEventOrder(`${'0'.repeat(31)}f`)).toBe(true);
    expect(isAgentAdapterProducerEventOrder(PRODUCER_EVENT_ORDER_MAX)).toBe(true);
    expect(isAgentAdapterProducerEventOrder('0'.repeat(32))).toBe(false); // zero is not a valid order
    expect(isAgentAdapterProducerEventOrder('A'.repeat(32))).toBe(false); // uppercase hex
    expect(isAgentAdapterProducerEventOrder('1'.repeat(31))).toBe(false); // short
    expect(isAgentAdapterProducerEventOrder('1'.repeat(33))).toBe(false); // long
    expect(isAgentAdapterProducerEventOrder(`${'0'.repeat(31)}g`)).toBe(false); // non-hex

    expect(producerEventOrderAsBigInt(one)).toBe(1n);
    expect(producerEventOrderAsBigInt('0'.repeat(32))).toBe(null);
    expect(producerEventOrderFromBigInt(1n)).toBe(one);
    expect(producerEventOrderFromBigInt(0n)).toBe(null);
    expect(producerEventOrderFromBigInt(1n << 128n)).toBe(null); // overflow
    expect(producerEventOrderFromBigInt((1n << 128n) - 1n)).toBe(PRODUCER_EVENT_ORDER_MAX);

    expect(nextProducerEventOrder(one)).toBe(`${'0'.repeat(31)}2`);
    expect(nextProducerEventOrder(`${'0'.repeat(30)}ff`)).toBe(`${'0'.repeat(29)}100`);
    expect(nextProducerEventOrder(PRODUCER_EVENT_ORDER_MAX)).toBe(null); // fail closed, no wrap
    expect(nextProducerEventOrder('0'.repeat(32))).toBe(null);
  });

  test('path identifiers: single percent-decode only, fail closed otherwise', () => {
    expect(decodeAgentAdapterPathIdentifier('session_1', 'sessionId')).toBe('session_1');
    expect(decodeAgentAdapterPathIdentifier('%E4%B8%AD', 'sessionId')).toBe('中');
    expect(decodeAgentAdapterPathIdentifier('a%20b', 'sessionId')).toBe('a b');
    expect(decodeAgentAdapterPathIdentifier('%2F', 'sessionId')).toBe(null); // encoded slash
    expect(decodeAgentAdapterPathIdentifier('a%2fb', 'sessionId')).toBe(null);
    expect(decodeAgentAdapterPathIdentifier('%252F', 'sessionId')).toBe(null); // double encoding
    expect(decodeAgentAdapterPathIdentifier('%zz', 'sessionId')).toBe(null); // malformed percent
    expect(decodeAgentAdapterPathIdentifier('', 'sessionId')).toBe(null);
    expect(decodeAgentAdapterPathIdentifier('a/b', 'sessionId')).toBe(null);
    expect(decodeAgentAdapterPathIdentifier('x'.repeat(257), 'sessionId')).toBe(null); // > 256 bytes after decode
    expect(decodeAgentAdapterPathIdentifier('%', 'sessionId')).toBe(null);
  });

  test('command poll timeout: single canonical decimal 0…120000', () => {
    expect(AGENT_ADAPTER_COMMAND_POLL_QUERY).toBe('timeout');
    expect(parseAgentAdapterCommandPollTimeout('0')).toBe(0);
    expect(parseAgentAdapterCommandPollTimeout('30000')).toBe(30000);
    expect(parseAgentAdapterCommandPollTimeout('120000')).toBe(120000);
    for (const invalid of ['+1', '01', ' 1', '1 ', '1.0', '1e3', '-1', '120001', '', '0x10', '12_000']) {
      expect(parseAgentAdapterCommandPollTimeout(invalid), invalid).toBe(null);
    }
    expect(parseAgentAdapterCommandPollTimeout(30000)).toBe(null);
    expect(parseAgentAdapterCommandPollTimeout(undefined)).toBe(null);
    expect(isAgentAdapterCommandPollTimeout(0)).toBe(true);
    expect(isAgentAdapterCommandPollTimeout(30000)).toBe(true);
    expect(isAgentAdapterCommandPollTimeout(120000)).toBe(true);
    expect(isAgentAdapterCommandPollTimeout(120001)).toBe(false);
    expect(isAgentAdapterCommandPollTimeout(-1)).toBe(false);
    expect(isAgentAdapterCommandPollTimeout(0.5)).toBe(false);
    expect(isAgentAdapterCommandPollTimeout(NaN)).toBe(false);
  });
});

describe('Protocol 4 wire request/response codecs', () => {
  test('register: exact required/optional keys, unknown keys (incl. hbaseSessionKey) rejected', () => {
    expect(validateAgentAdapterRegisterRequest(validRegister()).success).toBe(true);
    expect(validateAgentAdapterRegisterRequest({
      sessionId: sessionIdPlaceholder, provider: 'pi', projectName: 'P', cwd: '/w', nameText: 'N',
      driverInstanceId: base64UrlEncode(bytes(32)),
    }).success).toBe(true);
    expect(validateAgentAdapterRegisterRequest({ ...validRegister(), hbaseSessionKey: 'sk' }).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest({ ...validRegister(), extraKey: 1 }).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest({
      ...validRegister(), sessionId: undefined,
    }).success).toBe(false);
    const { driverInstanceId, ...withoutInstanceId } = validRegister();
    void driverInstanceId;
    expect(validateAgentAdapterRegisterRequest(withoutInstanceId).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest({ ...validRegister(), driverInstanceId: 'not-base64' }).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest({ ...validRegister(), driverInstanceId: base64UrlEncode(bytes(8)) }).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest({ ...validRegister(), pid: -1 }).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest({ ...validRegister(), pid: 1.5 }).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest({ ...validRegister(), status: 'done' }).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest({ ...validRegister(), sessionId: 'x'.repeat(257) }).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest(null).success).toBe(false);
    expect(validateAgentAdapterRegisterRequest({ ...validRegister(), openingText: '中'.repeat(30_000) }).success).toBe(false); // > 64 KiB field
    const { openingText, ...validOnlyRequired } = validRegister();
    expect(validateAgentAdapterRegisterRequest(validOnlyRequired).success).toBe(true);
    void openingText;
  });

  test('register 201 response: owned + lease codec', () => {
    const ok = {
      sessionId: sessionIdPlaceholder,
      registeredAt: canonicalTimestamp,
      ownership: 'owned',
      ownerLease: base64UrlEncode(bytes(32)),
    };
    expect(validateAgentAdapterRegisterOwnedResponse(ok).success).toBe(true);
    expect(validateAgentAdapterRegisterOwnedResponse({ ...ok, ownership: 'pending' }).success).toBe(false);
    expect(validateAgentAdapterRegisterOwnedResponse({ ...ok, ownerLease: 'short' }).success).toBe(false);
    expect(validateAgentAdapterRegisterOwnedResponse({ ...ok, registeredAt: '2026-08-17T00:00:00Z' }).success).toBe(false);
    expect(validateAgentAdapterRegisterOwnedResponse({ ...ok, sessionId: '' }).success).toBe(false);
    expect(validateAgentAdapterRegisterOwnedResponse({ ...ok, extra: true }).success).toBe(false);
  });

  test('heartbeat: required status, optional null-clear or string-only fields', () => {
    expect(validateAgentAdapterHeartbeatRequest({ status: 'working' }).success).toBe(true);
    expect(validateAgentAdapterHeartbeatRequest({
      status: 'idle', latestActivityText: null, openingText: null, projectName: 'P', nameText: 'N',
    }).success).toBe(true);
    expect(validateAgentAdapterHeartbeatRequest({ status: 'need_human' }).success).toBe(true);
    expect(validateAgentAdapterHeartbeatRequest({}).success).toBe(false); // missing status
    expect(validateAgentAdapterHeartbeatRequest({ status: 'done' }).success).toBe(false);
    expect(validateAgentAdapterHeartbeatRequest({ status: 'working', projectName: null }).success).toBe(false);
    expect(validateAgentAdapterHeartbeatRequest({ status: 'working', nameText: null }).success).toBe(false);
    expect(validateAgentAdapterHeartbeatRequest({ status: 'working', latestActivityText: { text: 'x' } }).success).toBe(false);
    expect(validateAgentAdapterHeartbeatRequest({ status: 'working', latestActivityText: '\ud800' }).success).toBe(false);
    expect(validateAgentAdapterHeartbeatRequest({ status: 'working', extra: 1 }).success).toBe(false);
    expect(validateAgentAdapterHeartbeatRequest({ status: 'working', latestActivityText: 'x'.repeat(65_537) }).success).toBe(false);
  });

  test('event request: exact envelope, no bundled session, 64 KiB canonical event bound, well-formed Unicode', () => {
    expect(validateAgentAdapterEventRequest(validEvent()).success).toBe(true);
    expect(validateAgentAdapterEventRequest({ ...validEvent(), session: { sessionId: 's' } }).success).toBe(false);
    expect(validateAgentAdapterEventRequest({ ...validEvent(), bundledSession: {} }).success).toBe(false);
    expect(validateAgentAdapterEventRequest({ ...validEvent(), producerEventId: 'short' }).success).toBe(false);
    expect(validateAgentAdapterEventRequest({ ...validEvent(), producerEventOrder: '0'.repeat(32) }).success).toBe(false);
    expect(validateAgentAdapterEventRequest({ ...validEvent(), event: null }).success).toBe(false);
    expect(validateAgentAdapterEventRequest({ ...validEvent(), event: ['array'] }).success).toBe(false);
    expect(validateAgentAdapterEventRequest({ ...validEvent(), event: { a: 1n } }).success).toBe(false); // BigInt is not JSON
    expect(validateAgentAdapterEventRequest({ ...validEvent(), event: { a: '\ud800' } }).success).toBe(false); // lone surrogate
    expect(validateAgentAdapterEventRequest({ ...validEvent(), event: undefined }).success).toBe(false);

    const oversizeEvent = {
      ...(validEvent().event as Record<string, unknown>),
      agentText: '中'.repeat(30_000), // 90 000 bytes > 64 KiB
    };
    expect(validateAgentAdapterEventRequest({ ...validEvent(), event: oversizeEvent }).success).toBe(false);

    const boundaryEvent = {
      ...(validEvent().event as Record<string, unknown>),
      agentText: '',
    };
    expect(validateAgentAdapterEventRequest({ ...validEvent(), event: boundaryEvent }).success).toBe(true);
  });

  test('event response: exact committed|duplicate disposition', () => {
    const response = {
      eventId: 'evt_1',
      producerEventId: base64UrlEncode(bytes(16)),
      producerEventOrder: `${'0'.repeat(31)}1`,
      disposition: 'committed',
    };
    expect(validateAgentAdapterEventResponse(response).success).toBe(true);
    expect(validateAgentAdapterEventResponse({ ...response, disposition: 'duplicate' }).success).toBe(true);
    expect(validateAgentAdapterEventResponse({ ...response, disposition: 'pending' }).success).toBe(false);
    expect(validateAgentAdapterEventResponse({ ...response, eventId: '' }).success).toBe(false);
    expect(validateAgentAdapterEventResponse({ ...response, extra: true }).success).toBe(false);
    expect(AGENT_ADAPTER_EVENT_DISPOSITIONS).toEqual(['committed', 'duplicate']);
  });

  test('handle: wire actions are local_input|bridge_recovery only; pi_input stays persisted-token-only', () => {
    expect(AGENT_ADAPTER_HANDLE_ACTIONS).toEqual(['local_input', 'bridge_recovery']);
    expect(AGENT_ADAPTER_HANDLE_ACTIONS as readonly string[]).not.toContain('pi_input');
    // SESSION_HANDLE_ACTIONS keeps pi_input for persisted/Relay/D1 stored tokens.
    expect(SESSION_HANDLE_ACTIONS).toEqual(['pi_input', 'watch_reply', 'bridge_recovery']);
    const action: AgentAdapterHandleAction = 'local_input';

    expect(validateAgentAdapterHandleRequest({ handledThroughEventId: 'evt_1' }).success).toBe(true);
    expect(validateAgentAdapterHandleRequest({ handledThroughEventId: 'evt_1', action }).success).toBe(true);
    expect(validateAgentAdapterHandleRequest({ handledThroughEventId: 'evt_1', action: 'bridge_recovery' }).success).toBe(true);
    expect(validateAgentAdapterHandleRequest({ handledThroughEventId: 'evt_1', action: 'pi_input' }).success).toBe(false);
    expect(validateAgentAdapterHandleRequest({ handledThroughEventId: 'evt_1', action: 'watch_reply' }).success).toBe(false);
    expect(validateAgentAdapterHandleRequest({ handledThroughEventId: 'evt_1', handledThroughEventCreatedAt: canonicalTimestamp, handledAt: canonicalTimestamp }).success).toBe(true);
    expect(validateAgentAdapterHandleRequest({ handledThroughEventId: 'evt_1', handledAt: 'not-a-time' }).success).toBe(false);
    expect(validateAgentAdapterHandleRequest({}).success).toBe(false); // missing required
    expect(validateAgentAdapterHandleRequest({ handledThroughEventId: 'evt_1', actorId: 'x' }).success).toBe(false);
  });

  test('handle response and uniform ok responses are exact', () => {
    const handleResponse = {
      ok: true, hostId: hostIdPlaceholder, sessionId: sessionIdPlaceholder, handledThroughEventId: 'evt_1',
    };
    expect(validateAgentAdapterHandleResponse(handleResponse).success).toBe(true);
    expect(validateAgentAdapterHandleResponse({ ...handleResponse, ok: false }).success).toBe(false);
    expect(validateAgentAdapterHandleResponse({ ...handleResponse, extra: 1 }).success).toBe(false);
    expect(validateAgentAdapterHandleResponse({ ...handleResponse, hostId: '' }).success).toBe(false);

    expect(validateAgentAdapterOkResponse({ ok: true }).success).toBe(true);
    expect(validateAgentAdapterOkResponse({ ok: false }).success).toBe(false);
    expect(validateAgentAdapterOkResponse({}).success).toBe(false);
    expect(validateAgentAdapterOkResponse({ ok: true, extra: 1 }).success).toBe(false);
  });

  test('terminal result keeps accepted===true iff executed', () => {
    const executed = {
      commandId: 'command_1', hostId: hostIdPlaceholder, sessionId: sessionIdPlaceholder,
      accepted: true, status: 'executed', updatedAt: canonicalTimestamp,
    };
    expect(validateCommandResult(executed)).toBe(true);
    expect(validateCommandResult({ ...executed, accepted: false })).toBe(false);
    expect(validateCommandResult({ ...executed, status: 'failed' })).toBe(false);
    expect(validateCommandResult({
      ...executed, accepted: false, status: 'failed',
    })).toBe(true);
    expect(validateCommandResult({ ...executed, message: 'leak' })).toBe(false);
  });
});

describe('Protocol 4 barrel surface', () => {
  test('wire parser helpers are the only Agent Adapter runtime API (no protocol-3 parser exported)', async () => {
    const protocol = await import('../src');
    for (const legacyParser of [
      'parseAgentAdapterEventInput',
      'parseAgentAdapterHeartbeatInput',
      'parseAgentAdapterRegisterInput',
      'parseAgentAdapterHandleInput',
      'parseAgentAdapterCommandResultV3',
      'isProtocol3ErrorEnvelope',
      'validateAgentAdapterEventV3',
    ]) {
      expect(protocol[legacyParser as keyof typeof protocol], legacyParser).toBeUndefined();
    }
  });
});