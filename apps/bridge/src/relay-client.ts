import { randomBytes } from 'node:crypto';
import type {
  BridgePairWatchResponse,
  CanonicalEvent,
  CanonicalSessionState,
  EncryptedCommandEnvelopeV1,
  E2EActivationAckV1,
  E2EConfirmationSubmissionV1,
  E2EPendingLinkProjectionV1,
  E2ERecipientSnapshotV1,
  EncryptedEventUploadV2,
  EncryptedSessionSnapshotUploadV2,
  HandleSessionRequest,
  HostEnrollmentRequest,
  HostEnrollmentResponse,
  HostMetadataUpdateRequest,
  IdentityRevokeResponse,
  LinkedWatchProjection,
  MarkSessionReadRequest,
  MarkSessionReadResponse,
  QueryPair,
  QuerySchema,
  ReplaceE2ECurrentSessionsRequestV1,
  ReplaceE2ECurrentSessionsResponseV1,
} from '@ariava/protocol';
import {
  assertRestrictedDynamicValue,
  base64UrlDecode,
  base64UrlEncode,
  buildRequestTarget,
  contentSha256,
  isCanonicalTimestamp,
  normalizePairingCode,
  validateEncryptedCommandEnvelopeV1,
  validateEncryptionKeyBindingV1,
} from '@ariava/protocol';
import type { HostRequestSigner } from './identity';

const EMPTY_QUERY_SCHEMA: QuerySchema = { parameters: {} };
const MAX_PULLED_COMMANDS = 100;
const encoder = new TextEncoder();

export interface RelayClientOptions {
  baseUrl: string;
  signer: HostRequestSigner;
  fetch?: typeof fetch;
  now?: () => Date;
  nonce?: () => string;
}

export type RelayRequestSignal = () => AbortSignal | undefined;

export class RelayClientError extends Error {
  readonly reason?: string;
  constructor(
    readonly status: number,
    message: string,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = 'RelayClientError';
    if (body && typeof body === 'object') {
      const parsed = body as { error?: unknown; reason?: unknown };
      this.reason = typeof parsed.reason === 'string'
        ? parsed.reason : typeof parsed.error === 'string' ? parsed.error : message;
    } else {
      this.reason = message;
    }
  }
}

export class RelayClient {
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => Date;
  private readonly nonce: () => string;

  constructor(private readonly options: RelayClientOptions, private readonly requestSignal?: RelayRequestSignal) {
    this.fetchImpl = options.fetch ?? fetch;
    this.now = options.now ?? (() => new Date());
    this.nonce = options.nonce ?? (() => base64UrlEncode(randomBytes(16)));
  }

  private request<T>(
    method: string,
    path: string,
    body: unknown,
    query: readonly QueryPair[] = [],
    querySchema: QuerySchema = EMPTY_QUERY_SCHEMA,
  ): Promise<T> {
    return this.requestBytes(method, path, body === undefined ? undefined : encoder.encode(JSON.stringify(body)), query, querySchema);
  }

  private async requestBytes<T>(
    method: string,
    path: string,
    bodyBytes: Uint8Array | undefined,
    query: readonly QueryPair[] = [],
    querySchema: QuerySchema = EMPTY_QUERY_SCHEMA,
  ): Promise<T> {
    const target = buildRequestTarget(path, query, querySchema);
    const [pathname, canonicalQuery = ''] = target.split('?');
    const headers = await this.options.signer.signRequest({
      entityType: 'host',
      entityId: this.options.signer.entityId,
      keyId: this.options.signer.keyId,
      method,
      path: pathname!,
      query: canonicalQuery,
      querySchema,
      contentSha256: await contentSha256(bodyBytes ?? new Uint8Array()),
      timestamp: this.now().toISOString(),
      nonce: this.nonce(),
    });
    const response = await this.fetchImpl(new URL(target, this.options.baseUrl), {
      method,
      headers: {
        ...headers,
        ...(bodyBytes === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(bodyBytes === undefined ? {} : { body: bodyBytes }),
      signal: this.requestSignal?.(),
    });
    if (!response.ok) {
      const text = (await response.text()).trim();
      let errorBody: unknown;
      try { errorBody = text ? JSON.parse(text) : undefined; } catch { errorBody = undefined; }
      const message = errorMessage(errorBody) ?? (text || response.statusText || 'Relay request failed.');
      throw new RelayClientError(response.status, message, errorBody);
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  enrollHost(request: HostEnrollmentRequest): Promise<HostEnrollmentResponse> {
    return this.request<unknown>('POST', '/v2/bridge/enroll', request).then(decodeHostEnrollmentResponse);
  }

  updateHost(request: HostMetadataUpdateRequest): Promise<HostEnrollmentResponse> {
    return this.request('PUT', '/v2/bridge/registration', request);
  }

  /** A signed metadata refresh is the v2 Host heartbeat. */
  heartbeat(request: HostMetadataUpdateRequest): Promise<HostEnrollmentResponse> {
    return this.updateHost(request);
  }

  pairWatch(pairingCode: string): Promise<BridgePairWatchResponse> {
    return this.request('POST', '/v2/bridge/pair-watch', { pairingCode: normalizePairingCode(pairingCode) });
  }

  async listWatches(): Promise<{ watches: LinkedWatchProjection[] }> {
    return this.request<unknown>('GET', '/v2/bridge/watches', undefined).then(decodeLinkedWatchesResponse);
  }

  removeWatch(watchDeviceId: string, linkGeneration: number): Promise<{ ok: true }> {
    assertRestrictedDynamicValue(watchDeviceId, 'watch device ID');
    if (!isPositiveSafeInteger(linkGeneration)) throw new TypeError('link generation must be a positive safe integer');
    return this.request('DELETE', `/v2/bridge/watches/${watchDeviceId}`, { linkGeneration });
  }

  publishEvent(event: CanonicalEvent, session: CanonicalSessionState): Promise<{ ok: true }> {
    return this.request('POST', '/v2/bridge/events', { event, session });
  }

  replaceE2ECurrentSessions(request: ReplaceE2ECurrentSessionsRequestV1): Promise<ReplaceE2ECurrentSessionsResponseV1> {
    return this.request('PUT', '/v2/bridge/e2e/sessions/current', request);
  }

  recipientSnapshot(): Promise<E2ERecipientSnapshotV1> {
    return this.request<unknown>('GET', '/v2/bridge/e2e/recipients', undefined).then(decodeRecipientSnapshot);
  }

  publishEncryptedEvent(event: EncryptedEventUploadV2, session: EncryptedSessionSnapshotUploadV2): Promise<{ ok: true }> {
    return this.request('POST', '/v2/bridge/e2e/events', { event, session });
  }

  reconcileEncryptedEvent(event: EncryptedEventUploadV2, session: EncryptedSessionSnapshotUploadV2): Promise<{ committed: boolean }> {
    return this.request('POST', '/v2/bridge/e2e/events/reconcile', { event, session });
  }

  reconcileEncryptedSession(session: EncryptedSessionSnapshotUploadV2): Promise<boolean> {
    return this.request<{ committed: boolean }>('POST', '/v2/bridge/e2e/sessions/reconcile', { session }).then((value) => value.committed);
  }

  publishEncryptedSession(session: EncryptedSessionSnapshotUploadV2): Promise<{ ok: true }> {
    return this.request('POST', '/v2/bridge/e2e/sessions', { session });
  }

  confirmLink(linkId: string, request: E2EConfirmationSubmissionV1): Promise<{ state: string; peerConfirmationProof?: E2EConfirmationSubmissionV1 }> {
    assertRestrictedDynamicValue(linkId, 'link ID');
    return this.request('POST', `/v2/bridge/e2e/links/${linkId}/confirm`, request);
  }

  activateLink(linkId: string, request: E2EActivationAckV1): Promise<{ state: string }> {
    assertRestrictedDynamicValue(linkId, 'link ID');
    return this.request('POST', `/v2/bridge/e2e/links/${linkId}/activate`, request);
  }

  markSessionRead(sessionId: string, request: MarkSessionReadRequest): Promise<MarkSessionReadResponse> {
    assertRestrictedDynamicValue(sessionId, 'session ID');
    return this.request('POST', `/v2/bridge/sessions/${sessionId}/read`, request);
  }

  handleSession(sessionId: string, request: HandleSessionRequest): Promise<{ ok: true; hostId: string; sessionId: string; handledThroughEventId: string }> {
    assertRestrictedDynamicValue(sessionId, 'session ID');
    return this.request('POST', `/v2/bridge/sessions/${sessionId}/handle`, request);
  }

  async pullCommands(hostId: string, limit = 20): Promise<EncryptedCommandEnvelopeV1[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PULLED_COMMANDS) {
      throw new TypeError('command pull limit must be an integer from 1 through 100');
    }
    const value = await this.request<unknown>('POST', '/v2/bridge/commands/pull', { hostId, limit });
    const commands = decodeCommandPullCollection(value, limit);
    return structuredClone(commands);
  }

  async submitCommandReceipt(canonicalBody: string): Promise<void> {
    const response = await this.requestBytes<unknown>(
      'POST', '/v2/bridge/e2e/commands/receipt', encoder.encode(canonicalBody),
    );
    if (!isExactRecord(response, ['ok']) || response.ok !== true) throw new TypeError('Relay command receipt response is invalid');
  }

  revokeIdentity(): Promise<IdentityRevokeResponse> {
    return this.request<unknown>('POST', '/v2/bridge/revoke', {}).then(decodeIdentityRevokeResponse);
  }
}

function errorMessage(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const record = body as Record<string, unknown>;
  if (typeof record.message === 'string' && record.message.trim()) return record.message;
  if (typeof record.error === 'string' && record.error.trim()) return record.error;
  if (typeof record.code === 'string' && record.code.trim()) return record.code;
  return undefined;
}

function decodeHostEnrollmentResponse(value: unknown): HostEnrollmentResponse {
  if (!isExactRecord(value, ['host'])) throw new TypeError('Relay Host enrollment response is invalid');
  const host = value.host;
  if (!isExactRecord(host, [
    'hostId', 'hostName', 'platform', 'bridgeVersion', 'registeredAt', 'lastSeenAt', 'bridgeStatus',
  ], ['status'])
    || !isNonEmptyString(host.hostId) || !isNonEmptyString(host.hostName)
    || (host.platform !== 'macos' && host.platform !== 'linux') || !isNonEmptyString(host.bridgeVersion)
    || !isCanonicalTimestamp(host.registeredAt) || !isCanonicalTimestamp(host.lastSeenAt)
    || !['online', 'offline', 'degraded'].includes(host.bridgeStatus as string)
    || (host.status !== undefined && host.status !== 'active' && host.status !== 'revoked')) {
    throw new TypeError('Relay Host enrollment response is invalid');
  }
  return value as unknown as HostEnrollmentResponse;
}

function decodeLinkedWatchesResponse(value: unknown): { watches: LinkedWatchProjection[] } {
  if (!isExactRecord(value, ['watches']) || !Array.isArray(value.watches)) {
    throw new TypeError('Relay linked Watches response is invalid');
  }
  const watchIds = new Set<string>();
  const watches: LinkedWatchProjection[] = [];
  for (const watch of value.watches) {
    if (!isExactRecord(watch, ['watchDeviceId', 'pairedAt', 'lastSeenAt', 'linkGeneration'], ['e2e'])
      || !isNonEmptyString(watch.watchDeviceId) || !isCanonicalTimestamp(watch.pairedAt)
      || !isCanonicalTimestamp(watch.lastSeenAt) || !isPositiveSafeInteger(watch.linkGeneration)
      || (watch.e2e !== undefined && !isPendingLinkProjection(watch.e2e, watch.watchDeviceId, watch.linkGeneration))
      || watchIds.has(watch.watchDeviceId)) {
      throw new TypeError('Relay linked Watches response is invalid');
    }
    watchIds.add(watch.watchDeviceId);
    watches.push(watch as unknown as LinkedWatchProjection);
  }
  return { watches: structuredClone(watches) };
}

function isPendingLinkProjection(value: unknown, watchDeviceId: string, linkGeneration: number): value is E2EPendingLinkProjectionV1 {
  if (!isExactRecord(value, [
    'linkId', 'hostId', 'watchDeviceId', 'linkGeneration', 'epoch', 'hostBinding', 'hostIdentityPublicKey',
    'watchBinding', 'watchIdentityPublicKey', 'transcriptDigest', 'confirmationExpiresAt', 'state',
  ])) return false;
  return isNonEmptyString(value.linkId) && isNonEmptyString(value.hostId)
    && value.watchDeviceId === watchDeviceId && value.linkGeneration === linkGeneration
    && isPositiveSafeInteger(value.epoch)
    && validateEncryptionKeyBindingV1(value.hostBinding) && value.hostBinding.entityType === 'host'
    && value.hostBinding.entityId === value.hostId
    && validateEncryptionKeyBindingV1(value.watchBinding) && value.watchBinding.entityType === 'watch'
    && value.watchBinding.entityId === watchDeviceId
    && isEncodedBytes(value.hostIdentityPublicKey, 32) && isEncodedBytes(value.watchIdentityPublicKey, 32)
    && isEncodedBytes(value.transcriptDigest, 32) && isCanonicalTimestamp(value.confirmationExpiresAt)
    && ['pending_confirmation', 'confirmations_complete', 'host_activated', 'watch_activated'].includes(value.state as string);
}

function isEncodedBytes(value: unknown, bytes: number): value is string {
  if (typeof value !== 'string') return false;
  try {
    base64UrlDecode(value, bytes);
    return true;
  } catch {
    return false;
  }
}

function decodeRecipientSnapshot(value: unknown): E2ERecipientSnapshotV1 {
  if (!isExactRecord(value, ['hostId', 'recipientSetVersion', 'recipients'])
    || !isNonEmptyString(value.hostId) || !isPositiveSafeInteger(value.recipientSetVersion)
    || !Array.isArray(value.recipients) || value.recipients.length > MAX_PULLED_COMMANDS) {
    throw new TypeError('Relay recipient snapshot response is invalid');
  }
  const tuples = new Set<string>();
  const watches = new Set<string>();
  for (const recipient of value.recipients) {
    if (!isExactRecord(recipient, ['linkId', 'linkGeneration', 'watchDeviceId', 'epoch', 'state', 'watchBinding'])
      || !isNonEmptyString(recipient.linkId) || !isPositiveSafeInteger(recipient.linkGeneration)
      || !isNonEmptyString(recipient.watchDeviceId) || !isPositiveSafeInteger(recipient.epoch)
      || recipient.state !== 'active' || !validateEncryptionKeyBindingV1(recipient.watchBinding)
      || recipient.watchBinding.entityType !== 'watch' || recipient.watchBinding.entityId !== recipient.watchDeviceId) {
      throw new TypeError('Relay recipient snapshot response is invalid');
    }
    const tuple = `${recipient.linkId}\n${recipient.linkGeneration}\n${recipient.epoch}`;
    if (tuples.has(tuple) || watches.has(recipient.watchDeviceId)) {
      throw new TypeError('Relay recipient snapshot response is invalid');
    }
    tuples.add(tuple);
    watches.add(recipient.watchDeviceId);
  }
  return structuredClone(value) as E2ERecipientSnapshotV1;
}

function decodeIdentityRevokeResponse(value: unknown): IdentityRevokeResponse {
  if (!isExactRecord(value, ['entityId', 'status', 'revokedAt'])
    || !isNonEmptyString(value.entityId) || value.status !== 'revoked' || !isCanonicalTimestamp(value.revokedAt)) {
    throw new TypeError('Relay identity revoke response is invalid');
  }
  return value as unknown as IdentityRevokeResponse;
}

function isExactRecord(
  value: unknown, required: readonly string[], optional: readonly string[] = [],
): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const keys = Object.keys(value);
  return required.every((key) => keys.includes(key))
    && keys.every((key) => required.includes(key) || optional.includes(key));
}

function decodeCommandPullCollection(value: unknown, limit: number): EncryptedCommandEnvelopeV1[] {
  if (!isPlainOrNullRecord(value)) throw new TypeError('Relay command pull response is invalid');
  const responseKeys = Reflect.ownKeys(value);
  if (responseKeys.length !== 1 || responseKeys[0] !== 'commands') {
    throw new TypeError('Relay command pull response is invalid');
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, 'commands');
  if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) {
    throw new TypeError('Relay command pull response is invalid');
  }
  const commands = descriptor.value;
  if (!Array.isArray(commands) || Object.getPrototypeOf(commands) !== Array.prototype) {
    throw new TypeError('Relay command pull response is invalid');
  }
  const keys = Reflect.ownKeys(commands);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(commands, 'length');
  if (!lengthDescriptor || !('value' in lengthDescriptor) || lengthDescriptor.enumerable !== false
    || lengthDescriptor.configurable !== false || lengthDescriptor.writable !== true
    || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0
    || lengthDescriptor.value > limit || lengthDescriptor.value > MAX_PULLED_COMMANDS
    || keys.length !== lengthDescriptor.value + 1 || keys.some((key) => typeof key === 'symbol')) {
    throw new TypeError('Relay command pull response is invalid');
  }
  const decoded: EncryptedCommandEnvelopeV1[] = [];
  for (let index = 0; index < lengthDescriptor.value; index += 1) {
    const itemDescriptor = Object.getOwnPropertyDescriptor(commands, String(index));
    if (!itemDescriptor || !('value' in itemDescriptor) || itemDescriptor.enumerable !== true
      || itemDescriptor.configurable !== true || itemDescriptor.writable !== true
      || !validateEncryptedCommandEnvelopeV1(itemDescriptor.value)) {
      throw new TypeError('Relay command pull response is invalid');
    }
    decoded.push(itemDescriptor.value);
  }
  return decoded;
}

function isPlainOrNullRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}
