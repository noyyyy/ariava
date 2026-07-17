import { randomBytes } from 'node:crypto';
import type {
  BridgePairWatchResponse,
  CanonicalEvent,
  CanonicalSessionState,
  CommandEnvelope,
  CommandResult,
  HandleSessionRequest,
  HostEnrollmentRequest,
  HostEnrollmentResponse,
  HostMetadataUpdateRequest,
  IdentityRevokeResponse,
  KeyRotationRequest,
  KeyRotationResponse,
  LinkedWatchProjection,
  MarkSessionReadRequest,
  MarkSessionReadResponse,
  QueryPair,
  QuerySchema,
} from '@ariava/protocol';
import {
  assertRestrictedDynamicValue,
  base64UrlEncode,
  buildRequestTarget,
  contentSha256,
  normalizePairingCode,
} from '@ariava/protocol';
import type { HostRequestSigner } from './identity';

const EMPTY_QUERY_SCHEMA: QuerySchema = { parameters: {} };
const encoder = new TextEncoder();

export interface RelayClientOptions {
  baseUrl: string;
  signer: HostRequestSigner;
  fetch?: typeof fetch;
  now?: () => Date;
  nonce?: () => string;
}

export class RelayClientError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'RelayClientError';
  }
}

export class RelayClient {
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => Date;
  private readonly nonce: () => string;

  constructor(private readonly options: RelayClientOptions) {
    this.fetchImpl = options.fetch ?? fetch;
    this.now = options.now ?? (() => new Date());
    this.nonce = options.nonce ?? (() => base64UrlEncode(randomBytes(16)));
  }

  private async request<T>(
    method: string,
    path: string,
    body: unknown,
    query: readonly QueryPair[] = [],
    querySchema: QuerySchema = EMPTY_QUERY_SCHEMA,
  ): Promise<T> {
    const bodyText = body === undefined ? '' : JSON.stringify(body);
    const bodyBytes = encoder.encode(bodyText);
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
      contentSha256: await contentSha256(bodyBytes),
      timestamp: this.now().toISOString(),
      nonce: this.nonce(),
    });
    const response = await this.fetchImpl(new URL(target, this.options.baseUrl), {
      method,
      headers: {
        ...headers,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: bodyBytes }),
    });
    if (!response.ok) {
      const message = (await response.text()).trim() || response.statusText || 'Relay request failed.';
      throw new RelayClientError(response.status, message);
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  enrollHost(request: HostEnrollmentRequest): Promise<HostEnrollmentResponse> {
    return this.request('POST', '/v2/bridge/enroll', request);
  }

  updateHost(request: HostMetadataUpdateRequest): Promise<HostEnrollmentResponse> {
    return this.request('PUT', '/v2/bridge/registration', request);
  }

  /** A signed metadata refresh is the v2 Host heartbeat. */
  heartbeat(request: HostMetadataUpdateRequest): Promise<HostEnrollmentResponse> {
    return this.updateHost(request);
  }

  pairWatch(pairingCode: string): Promise<BridgePairWatchResponse> {
    const normalizedPairingCode = normalizePairingCode(pairingCode);
    return this.request('POST', '/v2/bridge/pair-watch', { pairingCode: normalizedPairingCode });
  }

  listWatches(): Promise<{ watches: LinkedWatchProjection[] }> {
    return this.request('GET', '/v2/bridge/watches', undefined);
  }

  removeWatch(watchDeviceId: string): Promise<{ ok: true }> {
    assertRestrictedDynamicValue(watchDeviceId, 'watch device ID');
    return this.request('DELETE', `/v2/bridge/watches/${watchDeviceId}`, {});
  }

  publishEvent(event: CanonicalEvent, session: CanonicalSessionState): Promise<{ ok: true }> {
    return this.request('POST', '/v2/bridge/events', { event, session });
  }

  markSessionRead(sessionId: string, request: MarkSessionReadRequest): Promise<MarkSessionReadResponse> {
    assertRestrictedDynamicValue(sessionId, 'session ID');
    return this.request('POST', `/v2/bridge/sessions/${sessionId}/read`, request);
  }

  handleSession(sessionId: string, request: HandleSessionRequest): Promise<{ ok: true; hostId: string; sessionId: string; handledThroughEventId: string }> {
    assertRestrictedDynamicValue(sessionId, 'session ID');
    return this.request('POST', `/v2/bridge/sessions/${sessionId}/handle`, request);
  }

  pullCommands(hostId: string, limit = 20): Promise<{ commands: CommandEnvelope[] }> {
    return this.request('POST', '/v2/bridge/commands/pull', { hostId, limit });
  }

  submitCommandResult(result: CommandResult): Promise<{ ok: true }> {
    return this.request('POST', '/v2/bridge/commands/result', result);
  }

  rotateKey(request: KeyRotationRequest): Promise<KeyRotationResponse> {
    return this.request('POST', '/v2/bridge/keys/rotate', request);
  }

  recoverRotation(operationId: string): Promise<KeyRotationResponse> {
    assertRestrictedDynamicValue(operationId, 'rotation operation ID');
    return this.request('GET', `/v2/bridge/keys/rotations/${operationId}`, undefined);
  }

  revokeIdentity(): Promise<IdentityRevokeResponse> {
    return this.request('POST', '/v2/bridge/revoke', {});
  }
}
