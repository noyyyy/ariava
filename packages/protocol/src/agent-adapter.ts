import type { CanonicalEvent, SessionStatus } from './events.js';
import { SESSION_STATUSES } from './events.js';
import { E2E_LIMITS } from './encryption.js';
import { base64UrlDecode } from './request-signing.js';
import { isCanonicalTimestamp, type ValidationResult } from './validation.js';
import type { CommandResult } from './commands.js';

/**
 * Protocol 4 Agent Adapter contract (specs `2026-08-15-provider-neutral-agent-adapter-owner-foundation-design`
 * §4–§9 and `2026-08-16-agent-adapter-owner-bound-pi-breaking-cutover-design` §6).
 *
 * Every generation dimension is an independent constant: the protocol header
 * version, the health route generation, the agent route generation and the
 * runtime schema must never be derived from each other.
 *
 * The frozen protocol-4 error table (AAB015) lives here as production API.
 * `apps/bridge/test/agent-adapter/protocol4-error-golden.fixture.ts` keeps a
 * byte-identical frozen copy that the protocol tests re-verify at runtime so a
 * second divergent table can never be invented.
 *
 * There is intentionally no protocol-3 parser in this module and nothing here
 * is a permissive fallback: unknown/missing keys fail closed at this codec.
 */

/* -------------------------------------------------------------------------------- *
 * Independent generation constants
 * -------------------------------------------------------------------------------- */

/** Headers/body carry protocol generation 4 only. */
export const AGENT_ADAPTER_PROTOCOL_VERSION = 4 as const;

/** Request header carrying the protocol generation. */
export const AGENT_ADAPTER_PROTOCOL_HEADER = 'x-ariava-agent-adapter-version' as const;

/** Health route (independent of the header version). */
export const AGENT_ADAPTER_HEALTH_PATH = '/v2/health' as const;

/** Agent route prefix (independent of the health route and the header version). */
export const AGENT_ADAPTER_ROUTE_PREFIX = '/v2/agent' as const;

/** Single canonical query name for the command-poll route. */
export const AGENT_ADAPTER_COMMAND_POLL_QUERY = 'timeout' as const;

/* -------------------------------------------------------------------------------- *
 * Shared bounds and exact codecs
 * -------------------------------------------------------------------------------- */

/** Frozen §6.3 raw request-body cap (transport framing decides 413 before bearer). */
export const PROTOCOL_4_RAW_BODY_LIMIT_BYTES = 256 * 1024;

/**
 * Shared protocol-4 upper bounds. `requestBodyBytes` is the raw transport cap;
 * the remaining bounds define the exact wire codecs in this module.
 */
export const AGENT_ADAPTER_LIMITS = {
  /** Raw request-body cap: transport framing/raw size over this → 413 before credential lookup. */
  requestBodyBytes: PROTOCOL_4_RAW_BODY_LIMIT_BYTES,
  /** Identifiers (`sessionId`, `provider`, `producerEventId`, command/result IDs, `harnessProvider`, …) ≤ 256 UTF-8 bytes. */
  identifierBytes: 256,
  /** `driverInstanceId` must encode at least 128 bits of entropy. */
  driverInstanceIdMinBits: 128,
  driverInstanceIdMinBytes: 16,
  /** `driverInstanceId` is also an identifier: ≤ 256 UTF-8 bytes. */
  driverInstanceIdMaxBytes: 256,
  /** `ownerLease` is a 256-bit random value encoded as unpadded base64url. */
  ownerLeaseBytes: 32,
  ownerLeaseCharacters: 43,
  /** Pi/authorized-provider `producerEventId`: a 128-bit value encoded as unpadded base64url. */
  producerEventIdBytes: 16,
  producerEventIdCharacters: 22,
  /** `producerEventOrder`: unsigned 128-bit big-endian counter, 32 lowercase hex characters. */
  producerEventOrderBytes: 16,
  producerEventOrderCharacters: 32,
  /** Register/heartbeat session text fields share the canonical Session 64 KiB projection bound. */
  sessionFieldBytes: E2E_LIMITS.sessionPlaintextBytes,
  /** The canonical Event inside the Event request must fit the 64 KiB canonical event bound. */
  eventCanonicalBytes: E2E_LIMITS.eventPlaintextBytes,
  /** Command-poll `timeout` query: canonical decimal in 0…120000, default 30000. */
  commandPollTimeoutMinMs: 0,
  commandPollTimeoutMaxMs: 120_000,
  commandPollTimeoutDefaultMs: 30_000,
} as const;

const adapterTextEncoder = new TextEncoder();
const BASE64URL_ONLY_RE = /^[A-Za-z0-9_-]+$/u;
const HEX32_LOWER_ONLY_RE = /^[0-9a-f]{32}$/u;
const CANONICAL_DECIMAL_RE = /^(?:0|[1-9][0-9]*)$/u;
const PRODUCER_EVENT_ORDER_MAX_BIGINT = (1n << 128n) - 1n;

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Exact-key record gate: ordinary object, exact own enumerable data keys only,
 * no accessor/prototype tricks, required keys present as own properties.
 */
function exactDataRecord(
  value: unknown,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
  label: string,
  issues: string[],
): Record<string, unknown> | undefined {
  if (!isPlainRecord(value)) {
    issues.push(`${label} must be a plain object`);
    return undefined;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = new Set(allowedKeys);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      issues.push(`${label} contains a non-string key`);
      return undefined;
    }
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
      issues.push(`${label}.${key} must be an enumerable own data property`);
      return undefined;
    }
    if (!allowed.has(key)) {
      issues.push(`${label}.${key} is unsupported`);
      return undefined;
    }
  }
  for (const key of requiredKeys) {
    if (!Object.hasOwn(value, key)) {
      issues.push(`${label}.${key} is required`);
      return undefined;
    }
  }
  for (const key of allowedKeys) {
    if (!Object.hasOwn(value, key) && key in value) {
      issues.push(`${label}.${key} must be an own data property`);
      return undefined;
    }
  }
  return value;
}

/** Shared identifier: non-empty, well-formed Unicode, ≤ 256 UTF-8 bytes. */
export function isAgentAdapterIdentifier(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || !isWellFormedUnicode(value)) return false;
  return adapterTextEncoder.encode(value).byteLength <= AGENT_ADAPTER_LIMITS.identifierBytes;
}

/** Bounded adapter text field (projectName, cwd, nameText, session text): well-formed Unicode, ≤ 64 KiB. */
function isAgentAdapterText(value: unknown): value is string {
  return typeof value === 'string'
    && isWellFormedUnicode(value)
    && adapterTextEncoder.encode(value).byteLength <= AGENT_ADAPTER_LIMITS.sessionFieldBytes;
}

function isOptionalAdapterText(value: unknown): value is string | undefined {
  return value === undefined || isAgentAdapterText(value);
}

function isOptionalAdapterIdentifier(value: unknown): value is string | undefined {
  return value === undefined || isAgentAdapterIdentifier(value);
}

/**
 * `driverInstanceId`: a stable instance value per producer load, ≥ 128-bit random
 * or of equal strength (canonical unpadded base64url decoding to ≥ 16 bytes) and
 * still bounded as an identifier (≤ 256 UTF-8 bytes).
 */
export function isAgentAdapterDriverInstanceId(value: unknown): value is string {
  if (!isAgentAdapterIdentifier(value)) return false;
  try {
    return base64UrlDecode(value).byteLength >= AGENT_ADAPTER_LIMITS.driverInstanceIdMinBytes;
  } catch {
    return false;
  }
}

/** `ownerLease`: exactly 43 characters of unpadded base64url encoding 32 random bytes (256 bit). */
export function isAgentAdapterOwnerLease(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== AGENT_ADAPTER_LIMITS.ownerLeaseCharacters) return false;
  try {
    base64UrlDecode(value, AGENT_ADAPTER_LIMITS.ownerLeaseBytes, 'owner lease');
    return true;
  } catch {
    return false;
  }
}

/** `producerEventId`: exactly 22 characters of unpadded base64url encoding 16 bytes (128 bit). */
export function isAgentAdapterProducerEventId(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== AGENT_ADAPTER_LIMITS.producerEventIdCharacters) return false;
  try {
    base64UrlDecode(value, AGENT_ADAPTER_LIMITS.producerEventIdBytes, 'producer event id');
    return true;
  } catch {
    return false;
  }
}

/**
 * `producerEventOrder`: 32 lowercase hex characters encoding an unsigned 128-bit
 * big-endian counter that starts at 1. Zero is NOT a valid wire order.
 * Overflow (2^128 − 1 reached) is fail-closed via `nextProducerEventOrder`.
 */
export function isAgentAdapterProducerEventOrder(value: unknown): value is string {
  return typeof value === 'string'
    && HEX32_LOWER_ONLY_RE.test(value)
    && value !== '0'.repeat(AGENT_ADAPTER_LIMITS.producerEventOrderCharacters);
}

/** Largest encodable producer event order (2^128 − 1). */
export const PRODUCER_EVENT_ORDER_MAX = 'f'.repeat(AGENT_ADAPTER_LIMITS.producerEventOrderCharacters);

export function producerEventOrderAsBigInt(value: string): bigint | null {
  if (!isAgentAdapterProducerEventOrder(value)) return null;
  return BigInt(`0x${value}`);
}

export function producerEventOrderFromBigInt(order: bigint): string | null {
  if (order < 1n || order > PRODUCER_EVENT_ORDER_MAX_BIGINT) return null;
  return order.toString(16).padStart(AGENT_ADAPTER_LIMITS.producerEventOrderCharacters, '0');
}

/**
 * Successor of a producer event order, or `null` when the counter is at
 * 2^128 − 1: producers must fail closed instead of wrapping.
 */
export function nextProducerEventOrder(value: string): string | null {
  const current = producerEventOrderAsBigInt(value);
  if (current === null) return null;
  return producerEventOrderFromBigInt(current + 1n);
}

/**
 * Path-identifier codec: a single percent-decode, then the shared identifier
 * validator. Encoded slash (raw or after decode), double encoding, malformed
 * percent sequences and empty segments fail closed (return `null`).
 */
export function decodeAgentAdapterPathIdentifier(value: string, _label: string): string | null {
  if (!value || value.includes('/')) return null;
  if (/%2f/iu.test(value)) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }
  if (/%2f/iu.test(decoded) || decoded.includes('/')) return null;
  return isAgentAdapterIdentifier(decoded) ? decoded : null;
}

/** Command-poll `timeout` value bound as a parsed number. */
export function isAgentAdapterCommandPollTimeout(value: unknown): value is number {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= AGENT_ADAPTER_LIMITS.commandPollTimeoutMinMs
    && value <= AGENT_ADAPTER_LIMITS.commandPollTimeoutMaxMs;
}

/** Parses the raw query string into a bounded canonical decimal, or `null`. */
export function parseAgentAdapterCommandPollTimeout(value: unknown): number | null {
  if (typeof value !== 'string' || !CANONICAL_DECIMAL_RE.test(value)) return null;
  const parsed = Number(value);
  return isAgentAdapterCommandPollTimeout(parsed) ? parsed : null;
}

/**
 * Canonical JSON byte accounting with explicit escaping. Returns `true` when the
 * value is an ordinary JSON value (no undefined/function/symbol/bigint/getter),
 * all strings are well-formed Unicode, and the serialized byte length (including
 * structural characters and escaped strings) is within `maxBytes`.
 */
function jsonBytesWithin(value: unknown, maxBytes: number): boolean {
  const state = { bytes: 0 };
  const accountString = (text: string): boolean => {
    if (!isWellFormedUnicode(text)) return false;
    state.bytes += adapterTextEncoder.encode(JSON.stringify(text)).byteLength;
    return true;
  };
  const walk = (node: unknown): boolean => {
    if (state.bytes > maxBytes) return false;
    if (node === null) {
      state.bytes += 4;
      return true;
    }
    if (typeof node === 'boolean') {
      state.bytes += node ? 4 : 5;
      return true;
    }
    if (typeof node === 'number') {
      if (!Number.isFinite(node)) return false;
      state.bytes += String(node).length;
      return true;
    }
    if (typeof node === 'string') return accountString(node);
    if (Array.isArray(node)) {
      state.bytes += 1; // '['
      for (let index = 0; index < node.length; index += 1) {
        state.bytes += index === 0 ? 0 : 1; // ','
        if (!walk(node[index])) return false;
      }
      state.bytes += 1; // ']'
      return true;
    }
    if (!isPlainRecord(node)) return false;
    state.bytes += 1; // '{'
    let first = true;
    for (const key of Object.keys(node)) {
      state.bytes += first ? 0 : 1; // ','
      first = false;
      if (!accountString(key)) return false;
      state.bytes += 1; // ':'
      if (!walk(node[key])) return false;
    }
    state.bytes += 1; // '}'
    return true;
  };
  return walk(value) && state.bytes <= maxBytes;
}

/* -------------------------------------------------------------------------------- *
 * Discovery schema (exact six keys)
 * -------------------------------------------------------------------------------- */

export const AGENT_ADAPTER_DISCOVERY_KEYS = [
  'url', 'secret', 'protocolVersion', 'provider', 'profileId', 'hostId',
] as const;

export interface AgentAdapterDiscovery {
  url: string;
  secret: string;
  protocolVersion: typeof AGENT_ADAPTER_PROTOCOL_VERSION;
  provider: string;
  profileId: string;
  hostId: string;
}

/** Canonical unauthenticated loopback HTTP origin, or `null`. */
function canonicalDiscoveryUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || !isWellFormedUnicode(value) || value.trim() !== value) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' || url.username || url.password || url.search || url.hash) return null;
  if (url.pathname !== '/' && url.pathname !== '') return null;
  const hostname = url.hostname.toLowerCase();
  if (hostname !== '127.0.0.1' && hostname !== '::1' && hostname !== '[::1]') return null;
  if (!url.port) return null;
  const port = Number(url.port);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) return null;
  return url.origin;
}

function isAgentAdapterDiscoverySecret(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && isWellFormedUnicode(value) && value.trim() === value
    && adapterTextEncoder.encode(value).byteLength <= 256;
}

export function isAgentAdapterDiscovery(value: unknown): value is AgentAdapterDiscovery {
  if (!isPlainRecord(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== AGENT_ADAPTER_DISCOVERY_KEYS.length
    || AGENT_ADAPTER_DISCOVERY_KEYS.some((key) => !Object.hasOwn(value, key))) {
    return false;
  }
  return canonicalDiscoveryUrl(value.url) !== null
    && isAgentAdapterDiscoverySecret(value.secret)
    && value.protocolVersion === AGENT_ADAPTER_PROTOCOL_VERSION
    && isAgentAdapterIdentifier(value.provider)
    && isAgentAdapterIdentifier(value.profileId)
    && isAgentAdapterIdentifier(value.hostId);
}

/** Shared validator for the Bridge write path and the producer read path. */
export function validateAgentAdapterDiscovery(value: unknown): ValidationResult<AgentAdapterDiscovery> {
  const issues: string[] = [];
  const record = exactDataRecord(value, AGENT_ADAPTER_DISCOVERY_KEYS, AGENT_ADAPTER_DISCOVERY_KEYS, 'discovery', issues);
  if (!record) return { success: false, issues };
  const url = canonicalDiscoveryUrl(record.url);
  if (url === null) issues.push('discovery.url must be an unauthenticated loopback HTTP origin with an explicit port');
  if (!isAgentAdapterDiscoverySecret(record.secret)) issues.push('discovery.secret is invalid');
  if (record.protocolVersion !== AGENT_ADAPTER_PROTOCOL_VERSION) {
    issues.push(`discovery.protocolVersion must be exactly ${AGENT_ADAPTER_PROTOCOL_VERSION}`);
  }
  for (const key of ['provider', 'profileId', 'hostId'] as const) {
    if (!isAgentAdapterIdentifier(record[key])) issues.push(`discovery.${key} is invalid`);
  }
  if (issues.length) return { success: false, issues };
  return {
    success: true,
    issues,
    value: {
      url: url as string,
      secret: record.secret as string,
      protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
      provider: record.provider as string,
      profileId: record.profileId as string,
      hostId: record.hostId as string,
    },
  };
}

/* -------------------------------------------------------------------------------- *
 * Register (POST /v2/agent/sessions) → 201 owned acquisition
 * -------------------------------------------------------------------------------- */

const REGISTER_REQUIRED_KEYS = [
  'sessionId', 'provider', 'projectName', 'cwd', 'nameText', 'driverInstanceId',
] as const;
const REGISTER_OPTIONAL_KEYS = [
  'openingText', 'latestActivityText', 'harnessProvider', 'pid', 'status',
] as const;
const REGISTER_ALLOWED_KEYS = [...REGISTER_REQUIRED_KEYS, ...REGISTER_OPTIONAL_KEYS];

export interface AgentAdapterRegisterRequest {
  sessionId: string;
  provider: string;
  projectName: string;
  cwd: string;
  nameText: string;
  driverInstanceId: string;
  openingText?: string;
  latestActivityText?: string;
  harnessProvider?: string;
  pid?: number;
  status?: SessionStatus;
}

/**
 * Exact register codec. `hbaseSessionKey` was removed from canonical Session and
 * the whole Agent Adapter pipeline; any unknown key (including it) is rejected.
 */
export function validateAgentAdapterRegisterRequest(value: unknown): ValidationResult<AgentAdapterRegisterRequest> {
  const issues: string[] = [];
  const record = exactDataRecord(value, REGISTER_ALLOWED_KEYS, REGISTER_REQUIRED_KEYS, 'register request', issues);
  if (!record) return { success: false, issues };
  if (!isAgentAdapterIdentifier(record.sessionId)) issues.push('register request.sessionId is invalid');
  if (!isAgentAdapterIdentifier(record.provider)) issues.push('register request.provider is invalid');
  if (!isAgentAdapterText(record.projectName) || (record.projectName as string).length === 0) {
    issues.push('register request.projectName is invalid');
  }
  if (!isAgentAdapterText(record.cwd) || (record.cwd as string).length === 0) {
    issues.push('register request.cwd is invalid');
  }
  if (!isAgentAdapterText(record.nameText) || (record.nameText as string).length === 0) {
    issues.push('register request.nameText is invalid');
  }
  if (!isAgentAdapterDriverInstanceId(record.driverInstanceId)) issues.push('register request.driverInstanceId is invalid');
  if (!isOptionalAdapterText(record.openingText)) issues.push('register request.openingText is invalid');
  if (!isOptionalAdapterText(record.latestActivityText)) issues.push('register request.latestActivityText is invalid');
  if (!isOptionalAdapterIdentifier(record.harnessProvider)) issues.push('register request.harnessProvider is invalid');
  if (record.pid !== undefined && (!Number.isSafeInteger(record.pid) || (record.pid as number) < 0)) {
    issues.push('register request.pid must be a non-negative safe integer');
  }
  if (record.status !== undefined && !(SESSION_STATUSES as readonly string[]).includes(record.status as string)) {
    issues.push('register request.status must be idle, working or need_human');
  }
  if (issues.length) return { success: false, issues };
  return { success: true, issues, value: record as unknown as AgentAdapterRegisterRequest };
}

export interface AgentAdapterRegisterOwnedResponse {
  sessionId: string;
  registeredAt: string;
  ownership: 'owned';
  ownerLease: string;
}

export function validateAgentAdapterRegisterOwnedResponse(value: unknown): ValidationResult<AgentAdapterRegisterOwnedResponse> {
  const issues: string[] = [];
  const record = exactDataRecord(
    value,
    ['sessionId', 'registeredAt', 'ownership', 'ownerLease'],
    ['sessionId', 'registeredAt', 'ownership', 'ownerLease'],
    'register response',
    issues,
  );
  if (!record) return { success: false, issues };
  if (!isAgentAdapterIdentifier(record.sessionId)) issues.push('register response.sessionId is invalid');
  if (!isCanonicalTimestamp(record.registeredAt)) issues.push('register response.registeredAt must be a canonical RFC3339 timestamp');
  if (record.ownership !== 'owned') issues.push('register response.ownership must be "owned"');
  if (!isAgentAdapterOwnerLease(record.ownerLease)) issues.push('register response.ownerLease is invalid');
  if (issues.length) return { success: false, issues };
  return { success: true, issues, value: record as unknown as AgentAdapterRegisterOwnedResponse };
}

/* -------------------------------------------------------------------------------- *
 * Heartbeat (POST /v2/agent/sessions/:sessionId/heartbeat) → 200 { ok: true }
 * -------------------------------------------------------------------------------- */

const HEARTBEAT_REQUIRED_KEYS = ['status'] as const;
const HEARTBEAT_OPTIONAL_KEYS = ['latestActivityText', 'openingText', 'projectName', 'nameText'] as const;
const HEARTBEAT_ALLOWED_KEYS = [...HEARTBEAT_REQUIRED_KEYS, ...HEARTBEAT_OPTIONAL_KEYS];

export interface AgentAdapterHeartbeatRequest {
  status: SessionStatus;
  /** Explicit `null` clears; absent means "keep unchanged". */
  latestActivityText?: string | null;
  /** Explicit `null` clears; absent means "keep unchanged". */
  openingText?: string | null;
  /** String only; `null` is not allowed for identity/domain fields. */
  projectName?: string;
  /** String only; `null` is not allowed for identity/domain fields. */
  nameText?: string;
}

export function validateAgentAdapterHeartbeatRequest(value: unknown): ValidationResult<AgentAdapterHeartbeatRequest> {
  const issues: string[] = [];
  const record = exactDataRecord(value, HEARTBEAT_ALLOWED_KEYS, HEARTBEAT_REQUIRED_KEYS, 'heartbeat request', issues);
  if (!record) return { success: false, issues };
  if (!(SESSION_STATUSES as readonly string[]).includes(record.status as string)) {
    issues.push('heartbeat request.status is required and must be idle, working or need_human');
  }
  if (!(record.latestActivityText === undefined || record.latestActivityText === null || isAgentAdapterText(record.latestActivityText))) {
    issues.push('heartbeat request.latestActivityText must be a string or null');
  }
  if (!(record.openingText === undefined || record.openingText === null || isAgentAdapterText(record.openingText))) {
    issues.push('heartbeat request.openingText must be a string or null');
  }
  if (!isOptionalAdapterText(record.projectName)) issues.push('heartbeat request.projectName must be a string');
  if (!isOptionalAdapterText(record.nameText)) issues.push('heartbeat request.nameText must be a string');
  if (issues.length) return { success: false, issues };
  return { success: true, issues, value: record as unknown as AgentAdapterHeartbeatRequest };
}

/* -------------------------------------------------------------------------------- *
 * Event (POST /v2/agent/sessions/:sessionId/events) → 200 exact ack
 * -------------------------------------------------------------------------------- */

export interface AgentAdapterEventRequest {
  producerEventId: string;
  producerEventOrder: string;
  /**
   * Canonical Event. The codec enforces that it is an ordinary JSON object with
   * well-formed Unicode within the 64 KiB canonical-event byte bound; full
   * canonical-shape validation is performed by the shared canonical event
   * pipeline before the durable checkpoint.
   */
  event: CanonicalEvent;
}

export function validateAgentAdapterEventRequest(value: unknown): ValidationResult<AgentAdapterEventRequest> {
  const issues: string[] = [];
  const record = exactDataRecord(
    value,
    ['producerEventId', 'producerEventOrder', 'event'],
    ['producerEventId', 'producerEventOrder', 'event'],
    'event request',
    issues,
  );
  if (!record) return { success: false, issues };
  if (!isAgentAdapterProducerEventId(record.producerEventId)) issues.push('event request.producerEventId is invalid');
  if (!isAgentAdapterProducerEventOrder(record.producerEventOrder)) {
    issues.push('event request.producerEventOrder must be 32 lowercase hex characters starting at 1');
  }
  if (!isPlainRecord(record.event)) {
    issues.push('event request.event must be a plain object');
  } else if (!jsonBytesWithin(record.event, AGENT_ADAPTER_LIMITS.eventCanonicalBytes)) {
    issues.push(`event request.event must be well-formed JSON within ${AGENT_ADAPTER_LIMITS.eventCanonicalBytes} bytes`);
  }
  if (issues.length) return { success: false, issues };
  return { success: true, issues, value: record as unknown as AgentAdapterEventRequest };
}

export const AGENT_ADAPTER_EVENT_DISPOSITIONS = ['committed', 'duplicate'] as const;
export type AgentAdapterEventDisposition = (typeof AGENT_ADAPTER_EVENT_DISPOSITIONS)[number];

export interface AgentAdapterEventResponse {
  eventId: string;
  producerEventId: string;
  producerEventOrder: string;
  disposition: AgentAdapterEventDisposition;
}

export function validateAgentAdapterEventResponse(value: unknown): ValidationResult<AgentAdapterEventResponse> {
  const issues: string[] = [];
  const record = exactDataRecord(
    value,
    ['eventId', 'producerEventId', 'producerEventOrder', 'disposition'],
    ['eventId', 'producerEventId', 'producerEventOrder', 'disposition'],
    'event response',
    issues,
  );
  if (!record) return { success: false, issues };
  if (!isAgentAdapterIdentifier(record.eventId)) issues.push('event response.eventId is invalid');
  if (!isAgentAdapterProducerEventId(record.producerEventId)) issues.push('event response.producerEventId is invalid');
  if (!isAgentAdapterProducerEventOrder(record.producerEventOrder)) issues.push('event response.producerEventOrder is invalid');
  if (!(AGENT_ADAPTER_EVENT_DISPOSITIONS as readonly string[]).includes(record.disposition as string)) {
    issues.push('event response.disposition must be committed or duplicate');
  }
  if (issues.length) return { success: false, issues };
  return { success: true, issues, value: record as unknown as AgentAdapterEventResponse };
}

/* -------------------------------------------------------------------------------- *
 * Handle (POST /v2/agent/sessions/:sessionId/handle) → 200 exact ack
 *
 * `SESSION_HANDLE_ACTIONS` in `events.ts` keeps `pi_input` for persisted
 * Relay/D1 stored handle tokens; the protocol-4 *wire* uses the provider-neutral
 * `local_input` action (default) and `bridge_recovery`. `pi_input` is not valid
 * on the protocol-4 wire.
 * -------------------------------------------------------------------------------- */

export const AGENT_ADAPTER_HANDLE_ACTIONS = ['local_input', 'bridge_recovery'] as const;
export type AgentAdapterHandleAction = (typeof AGENT_ADAPTER_HANDLE_ACTIONS)[number];

const HANDLE_REQUIRED_KEYS = ['handledThroughEventId'] as const;
const HANDLE_OPTIONAL_KEYS = ['handledThroughEventCreatedAt', 'handledAt', 'action'] as const;
const HANDLE_ALLOWED_KEYS = [...HANDLE_REQUIRED_KEYS, ...HANDLE_OPTIONAL_KEYS];

export interface AgentAdapterHandleRequest {
  handledThroughEventId: string;
  handledThroughEventCreatedAt?: string;
  handledAt?: string;
  /** Wire action; defaults to `local_input`. */
  action?: AgentAdapterHandleAction;
}

export function validateAgentAdapterHandleRequest(value: unknown): ValidationResult<AgentAdapterHandleRequest> {
  const issues: string[] = [];
  const record = exactDataRecord(value, HANDLE_ALLOWED_KEYS, HANDLE_REQUIRED_KEYS, 'handle request', issues);
  if (!record) return { success: false, issues };
  if (!isAgentAdapterIdentifier(record.handledThroughEventId)) issues.push('handle request.handledThroughEventId is invalid');
  if (record.handledThroughEventCreatedAt !== undefined && !isCanonicalTimestamp(record.handledThroughEventCreatedAt)) {
    issues.push('handle request.handledThroughEventCreatedAt must be a canonical RFC3339 timestamp');
  }
  if (record.handledAt !== undefined && !isCanonicalTimestamp(record.handledAt)) {
    issues.push('handle request.handledAt must be a canonical RFC3339 timestamp');
  }
  if (record.action !== undefined && !(AGENT_ADAPTER_HANDLE_ACTIONS as readonly string[]).includes(record.action as string)) {
    issues.push('handle request.action must be local_input or bridge_recovery');
  }
  if (issues.length) return { success: false, issues };
  return { success: true, issues, value: record as unknown as AgentAdapterHandleRequest };
}

export interface AgentAdapterHandleResponse {
  ok: true;
  hostId: string;
  sessionId: string;
  handledThroughEventId: string;
}

export function validateAgentAdapterHandleResponse(value: unknown): ValidationResult<AgentAdapterHandleResponse> {
  const issues: string[] = [];
  const record = exactDataRecord(
    value,
    ['ok', 'hostId', 'sessionId', 'handledThroughEventId'],
    ['ok', 'hostId', 'sessionId', 'handledThroughEventId'],
    'handle response',
    issues,
  );
  if (!record) return { success: false, issues };
  if (record.ok !== true) issues.push('handle response.ok must be true');
  if (!isAgentAdapterIdentifier(record.hostId)) issues.push('handle response.hostId is invalid');
  if (!isAgentAdapterIdentifier(record.sessionId)) issues.push('handle response.sessionId is invalid');
  if (!isAgentAdapterIdentifier(record.handledThroughEventId)) issues.push('handle response.handledThroughEventId is invalid');
  if (issues.length) return { success: false, issues };
  return { success: true, issues, value: record as unknown as AgentAdapterHandleResponse };
}

/* -------------------------------------------------------------------------------- *
 * Uniform ok responses (heartbeat / unregister / command result)
 * -------------------------------------------------------------------------------- */

export interface AgentAdapterOkResponse {
  ok: true;
}

export function validateAgentAdapterOkResponse(value: unknown): ValidationResult<AgentAdapterOkResponse> {
  const issues: string[] = [];
  const record = exactDataRecord(value, ['ok'], ['ok'], 'ok response', issues);
  if (!record) return { success: false, issues };
  if (record.ok !== true) issues.push('ok response.ok must be true');
  if (issues.length) return { success: false, issues };
  return { success: true, issues, value: { ok: true } };
}

/* -------------------------------------------------------------------------------- *
 * Terminal result (POST /v2/agent/sessions/:sessionId/commands/:commandId/result)
 *
 * The exact `{commandId, hostId, sessionId, accepted, status, updatedAt}` shape
 * is the existing public `CommandResult` contract; the invariant
 * `accepted === true` iff `status === 'executed'` is enforced by
 * `validateCommandResult` from `commands.js`.
 * -------------------------------------------------------------------------------- */

export type AgentAdapterTerminalResult = CommandResult;

/* -------------------------------------------------------------------------------- *
 * Protocol-4 error contract (AAB015 — frozen §6.3 table)
 * -------------------------------------------------------------------------------- */

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

/** Complete frozen §6.3 status/code/retryable table (byte-identical to the Phase 0 bridge fixture). */
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

export function isAgentAdapterProtocol4ErrorCode(value: unknown): value is AgentAdapterProtocol4ErrorCode {
  return typeof value === 'string' && (PROTOCOL_4_ERROR_CODE_LIST as readonly string[]).includes(value);
}

export function agentAdapterProtocol4ErrorStatus(code: AgentAdapterProtocol4ErrorCode): number {
  const row = PROTOCOL_4_ERROR_GOLDEN.find((candidate) => candidate.code === code);
  return row?.status ?? 500;
}

export function agentAdapterProtocol4ErrorRetryable(code: AgentAdapterProtocol4ErrorCode): boolean {
  return (PROTOCOL_4_RETRYABLE_CODES as readonly AgentAdapterProtocol4ErrorCode[]).includes(code);
}

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
 * retryable`, types exact, code known. Missing/unknown keys, unknown codes,
 * accessor/prototype tricks and any detail/Session/provider/lease/exception
 * fields are rejected.
 */
export function isProtocol4ErrorEnvelope(value: unknown): value is Protocol4ErrorEnvelopeShape {
  const issues: string[] = [];
  const envelope = exactDataRecord(value, ['error'], ['error'], 'error envelope', issues);
  if (!envelope) return false;
  const error = exactDataRecord(envelope.error, ['code', 'retryable'], ['code', 'retryable'], 'error object', issues);
  if (!error) return false;
  if (typeof error.retryable !== 'boolean') return false;
  return isAgentAdapterProtocol4ErrorCode(error.code);
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