import { timingSafeEqual } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import {
  AGENT_ADAPTER_HEALTH_PATH,
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
  AGENT_ADAPTER_ROUTE_PREFIX,
  ProtectedContentValidationError,
  isAgentAdapterDriverInstanceId,
  protocol4ErrorEnvelope,
  SESSION_STATUSES,
  type SessionStatus,
} from '@ariava/protocol';
import {
  AgentAdapterRequestValidationError,
  AgentAdapterOwnerConflictError,
  AgentAdapterStaleOwnerError,
  AgentAdapterOrderConflictError,
  AgentAdapterSessionNotFoundError,
  SessionIdCollisionError,
  type AgentAdapterRegistry,
  type RegisterSessionInput,
} from './registry';
import { AGENT_ADAPTER_LIMITS, AGENT_ADAPTER_OWNER_HEADERS, isBoundedAgentAdapterIdentifier } from './registry-types';
import type { BridgeRuntimeHealth } from '../types';
import { parseAgentAdapterCommandResult, type AgentAdapterCommandResult } from './result';

export class AgentAdapterClientInputError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AgentAdapterClientInputError';
  }
}

export class AgentAdapterRequestBodyTooLargeError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AgentAdapterRequestBodyTooLargeError';
  }
}

export interface AgentAdapterServerConfig {
  port: number;
  secret: string;
  hostId: string;
}

export class AgentAdapterServer {
  private server: Server | null = null;
  private activePort: number;

  constructor(
    private readonly config: AgentAdapterServerConfig,
    private readonly registry: AgentAdapterRegistry,
    private readonly health: () => BridgeRuntimeHealth = () => ({ status: 'healthy', drivers: [] }),
  ) {
    this.activePort = config.port;
  }

  async start(): Promise<void> {
    if (this.server) return;
    const server = createServer((request, response) => {
      void this.handle(request, response);
    });
    this.server = server;
    server.listen(this.config.port, '127.0.0.1');
    try {
      await once(server, 'listening');
    } catch (error) {
      if (this.server === server) this.server = null;
      throw error;
    }
    const address = server.address();
    if (address && typeof address === 'object') this.activePort = address.port;
  }

  stop(closeActiveConnections = false): void {
    this.registry.cancelCommandPolls();
    if (!this.server) return;
    if (closeActiveConnections && 'closeAllConnections' in this.server) {
      this.server.closeAllConnections();
    }
    this.server.close();
    this.server = null;
  }

  get url(): string {
    return `http://127.0.0.1:${this.activePort}`;
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      // §6.3 precedence: transport framing/raw body size is decided BEFORE the
      // bearer comparison, so an oversized or illegally-framed request is 413
      // even when the bearer is missing/invalid.
      const rawBody = await this.readRawBody(request);

      const auth = request.headers.authorization;
      const token = auth?.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!constantTimeSecretEquals(token, this.config.secret)) {
        this.writeJson(response, 401, protocol4ErrorEnvelope('UNAUTHORIZED'));
        return;
      }
      if (request.headers[AGENT_ADAPTER_PROTOCOL_HEADER] !== String(AGENT_ADAPTER_PROTOCOL_VERSION)) {
        this.writeJson(response, 426, protocol4ErrorEnvelope('PROTOCOL_VERSION_MISMATCH'));
        return;
      }

      const url = new URL(request.url ?? '/', this.url);
      const pathname = url.pathname;
      const method = request.method ?? 'GET';

      // Health is credential + protocol header only; the response stays the
      // existing redacted health JSON (no diagnostics).
      if (pathname === AGENT_ADAPTER_HEALTH_PATH && method === 'GET') {
        this.writeJson(response, 200, { ok: true, hostId: this.config.hostId, health: this.health() });
        return;
      }

      if (!pathname.startsWith(AGENT_ADAPTER_ROUTE_PREFIX)) {
        // Unknown path, including any legacy /v1/** route, is not leaked: 404.
        this.writeJson(response, 404, protocol4ErrorEnvelope('NOT_FOUND'));
        return;
      }
      const routePath = pathname.slice(AGENT_ADAPTER_ROUTE_PREFIX.length) || '/';

      if (routePath === '/sessions' && method === 'POST') {
        const input = parseRegisterInput(this.parseJson(rawBody));
        const session = this.registry.register(input);
        this.writeJson(response, 201, {
          sessionId: session.sessionId, registeredAt: session.registeredAt, ownership: 'owned' as const, ownerLease: session.ownerLease,
        });
        return;
      }

      const unregisterMatch = routePath.match(/^\/sessions\/([^/]+)$/);
      if (unregisterMatch && method === 'DELETE') {
        const sessionId = decodePathIdentity(unregisterMatch[1], 'sessionId');
        this.requireCurrentOwner(request, sessionId);
        this.registry.unregister(sessionId);
        this.writeJson(response, 200, { ok: true });
        return;
      }

      const eventMatch = routePath.match(/^\/sessions\/([^/]+)\/events$/);
      if (eventMatch && method === 'POST') {
        const sessionId = decodePathIdentity(eventMatch[1], 'sessionId');
        this.requireCurrentOwner(request, sessionId);
        const responseBody = this.registry.pushEventSource(sessionId, this.parseJson(rawBody));
        this.writeJson(response, 200, responseBody);
        return;
      }

      const handleMatch = routePath.match(/^\/sessions\/([^/]+)\/handle$/);
      if (handleMatch && method === 'POST') {
        const sessionId = decodePathIdentity(handleMatch[1], 'sessionId');
        this.requireCurrentOwner(request, sessionId);
        const result = this.registry.handleSession(
          sessionId,
          parseHandleInput(this.parseJson(rawBody)),
        );
        this.writeJson(response, 200, result);
        return;
      }

      const heartbeatMatch = routePath.match(/^\/sessions\/([^/]+)\/heartbeat$/);
      if (heartbeatMatch && method === 'POST') {
        const sessionId = decodePathIdentity(heartbeatMatch[1], 'sessionId');
        this.requireCurrentOwner(request, sessionId);
        const { status, latestActivityText, openingText, projectName, nameText } = parseHeartbeatInput(this.parseJson(rawBody));
        const session = this.registry.heartbeat(sessionId, status, latestActivityText, {
          openingText, projectName, nameText,
        });
        if (!session) {
          this.writeJson(response, 404, protocol4ErrorEnvelope('SESSION_NOT_FOUND'));
          return;
        }
        this.writeJson(response, 200, { ok: true });
        return;
      }

      const commandMatch = routePath.match(/^\/sessions\/([^/]+)\/commands$/);
      if (commandMatch && method === 'GET') {
        const sessionId = decodePathIdentity(commandMatch[1], 'sessionId');
        this.requireCurrentOwner(request, sessionId);
        const timeout = Math.min(Math.max(parseInt(url.searchParams.get('timeout') ?? '30000', 10), 0), 120_000);
        const command = await this.registry.dequeueCommand(sessionId, timeout);
        if (!command) {
          response.statusCode = 204;
          response.end();
          return;
        }
        this.writeJson(response, 200, { command });
        return;
      }

      const resultMatch = routePath.match(/^\/sessions\/([^/]+)\/commands\/([^/]+)\/result$/);
      if (resultMatch && method === 'POST') {
        const sessionId = decodePathIdentity(resultMatch[1], 'sessionId');
        const commandId = decodePathIdentity(resultMatch[2], 'commandId');
        this.requireCurrentOwner(request, sessionId);
        if (this.registry.isCommandOutcomeUnknown(commandId)) {
          this.writeJson(response, 409, protocol4ErrorEnvelope('COMMAND_OUTCOME_UNKNOWN'));
          return;
        }
        const result = parseResultInput(this.parseJson(rawBody), commandId);
        this.registry.resolveCommand(commandId, result, sessionId);
        this.writeJson(response, 200, { ok: true });
        return;
      }

      this.writeJson(response, 404, protocol4ErrorEnvelope('NOT_FOUND'));
    } catch (error) {
      if (error instanceof AgentAdapterOwnerConflictError) {
        this.writeJson(response, 409, protocol4ErrorEnvelope('OWNER_CONFLICT', true));
        return;
      }
      if (error instanceof SessionIdCollisionError) {
        this.writeJson(response, 409, protocol4ErrorEnvelope('IDENTITY_CONFLICT'));
        return;
      }
      if (error instanceof AgentAdapterStaleOwnerError) {
        this.writeJson(response, 409, protocol4ErrorEnvelope('STALE_OWNER'));
        return;
      }
      if (error instanceof AgentAdapterOrderConflictError) {
        this.writeJson(response, 409, protocol4ErrorEnvelope('ORDER_CONFLICT'));
        return;
      }
      if (error instanceof AgentAdapterSessionNotFoundError) {
        this.writeJson(response, 404, protocol4ErrorEnvelope('SESSION_NOT_FOUND'));
        return;
      }
      if (error instanceof AgentAdapterRequestBodyTooLargeError) {
        this.writeJson(response, 413, protocol4ErrorEnvelope('REQUEST_TOO_LARGE'));
        return;
      }
      if (error instanceof ProtectedContentValidationError
        || error instanceof AgentAdapterClientInputError
        || error instanceof AgentAdapterRequestValidationError) {
        this.writeJson(response, 400, protocol4ErrorEnvelope('INVALID_REQUEST'));
        return;
      }
      // Never leak exception text: 500 carries the exact INTERNAL_ERROR envelope.
      this.writeJson(response, 500, protocol4ErrorEnvelope('INTERNAL_ERROR'));
    }
  }

  /** Owner routes verify the caller is the current live owner with a non-expired lease. */
  private requireCurrentOwner(request: IncomingMessage, sessionId: string): void {
    const driverInstance = request.headers[AGENT_ADAPTER_OWNER_HEADERS.driverInstance];
    const ownerLease = request.headers[AGENT_ADAPTER_OWNER_HEADERS.ownerLease];
    if (typeof driverInstance !== 'string' || typeof ownerLease !== 'string'
      || !isBoundedAgentAdapterIdentifier(driverInstance) || !isBoundedAgentAdapterIdentifier(ownerLease)) {
      throw new AgentAdapterClientInputError('Owner route requires a valid X-Ariava-Driver-Instance and X-Ariava-Owner-Lease header');
    }
    this.registry.assertCurrentOwner(sessionId, driverInstance, ownerLease);
  }

  /**
   * Reads the raw request body once, enforcing the protocol-4 256 KiB cap as a
   * transport framing decision (413) before any bearer comparison. The cap is
   * applied to the declared Content-Length when present and to the actual
   * accumulated byte count mid-stream, whichever would exceed it first.
   */
  private readRawBody(request: IncomingMessage): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      let settled = false;
      const release = (): void => {
        request.removeListener('data', onData);
        request.removeListener('end', onEnd);
        request.removeListener('error', onError);
        chunks.length = 0;
      };
      // A settled-overflow reject keeps a temporary error sink while draining so
      // a client abort after the 413 has been returned cannot surface as an
      // unhandled EventEmitter error.
      const overflow = (): void => {
        if (settled) return;
        settled = true;
        release();
        const absorbDrainError = (): void => {};
        const cleanupDrain = (): void => {
          request.removeListener('error', absorbDrainError);
          request.removeListener('end', cleanupDrain);
          request.removeListener('close', cleanupDrain);
        };
        request.on('error', absorbDrainError);
        request.once('end', cleanupDrain);
        request.once('close', cleanupDrain);
        request.resume();
        reject(new AgentAdapterRequestBodyTooLargeError('Request body exceeds the Agent Adapter byte limit'));
      };

      const onData = (chunk: Buffer): void => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += buffer.byteLength;
        if (totalBytes > AGENT_ADAPTER_LIMITS.requestBodyBytes) {
          overflow();
          return;
        }
        chunks.push(buffer);
      };
      const onEnd = (): void => {
        if (settled) return;
        settled = true;
        const rawBody = Buffer.concat(chunks);
        release();
        resolve(rawBody);
      };
      const onError = (error: Error): void => { if (!settled) { settled = true; release(); reject(error); } };
      const declared = request.headers['content-length'];
      if (declared !== undefined) {
        if (!/^\d+$/u.test(declared) || Number(declared) > AGENT_ADAPTER_LIMITS.requestBodyBytes) {
          overflow();
          return;
        }
      }
      request.on('data', onData);
      request.on('end', onEnd);
      request.on('error', onError);
    });
  }

  private parseJson(rawBody: Buffer): unknown {
    if (rawBody.length === 0) return {};
    let text: string;
    try {
      // A fatal UTF-8 decoder rejects malformed byte sequences instead of
      // lossily replacing them with U+FFFD — wire garbage must be a 400.
      text = new TextDecoder('utf-8', { fatal: true }).decode(rawBody);
    } catch (error) {
      throw new AgentAdapterClientInputError('Request body must contain valid UTF-8', { cause: error });
    }
    try {
      return JSON.parse(text) as unknown;
    } catch (error) {
      throw new AgentAdapterClientInputError('Request body must contain valid JSON', { cause: error });
    }
  }

  private writeJson(response: ServerResponse, status: number, body: unknown): void {
    response.statusCode = status;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(body));
  }
}

function constantTimeSecretEquals(provided: string, expected: string): boolean {
  if (!expected) return false;
  const left = Buffer.from(provided);
  const right = Buffer.from(expected);
  if (left.byteLength !== right.byteLength) {
    timingSafeEqual(right, right);
    return false;
  }
  return timingSafeEqual(left, right);
}

function decodePathIdentity(value: string, label: 'sessionId' | 'commandId'): string {
  try {
    const decoded = decodeURIComponent(value);
    if (/%2f/iu.test(value) || /%2f/iu.test(decoded) || decoded.includes('/')) {
      throw new AgentAdapterClientInputError(`${label} path segment must not contain an encoded slash`);
    }
    if (!isBoundedAgentAdapterIdentifier(decoded)) {
      throw new AgentAdapterClientInputError(`${label} path segment is invalid`);
    }
    return decoded;
  } catch (error) {
    if (error instanceof AgentAdapterClientInputError) throw error;
    throw new AgentAdapterClientInputError(`${label} path segment contains malformed percent encoding`, { cause: error });
  }
}

function parseRegisterInput(value: unknown): RegisterSessionInput {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new AgentAdapterClientInputError('Request body must be an object');
  }

  const obj = value as Record<string, unknown>;
  assertExactKeys(obj,
    ['sessionId', 'provider', 'projectName', 'cwd', 'nameText', 'driverInstanceId'],
    ['openingText', 'latestActivityText', 'harnessProvider', 'pid', 'status'],
    'register Session',
  );
  const driverInstanceId = obj.driverInstanceId;
  if (!isAgentAdapterDriverInstanceId(driverInstanceId)) {
    throw new AgentAdapterClientInputError('register driverInstanceId is invalid');
  }
  return {
    sessionId: requireIdentifier(obj, 'sessionId'),
    provider: requireIdentifier(obj, 'provider'),
    projectName: requireString(obj, 'projectName'),
    cwd: requireString(obj, 'cwd'),
    nameText: requireString(obj, 'nameText'),
    driverInstanceId,
    openingText: optionalString(obj, 'openingText'),
    latestActivityText: optionalString(obj, 'latestActivityText'),
    harnessProvider: optionalIdentifier(obj, 'harnessProvider'),
    pid: optionalNumber(obj, 'pid'),
    status: optionalStatus(obj, 'status'),
  };
}

function parseHandleInput(value: unknown): import('@ariava/protocol').HandleSessionRequest {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new AgentAdapterClientInputError('handle body must be an object');
  }
  const obj = value as Record<string, unknown>;
  assertExactKeys(
    obj,
    ['handledThroughEventId'],
    ['handledThroughEventCreatedAt', 'handledAt', 'action'],
    'handle',
  );
  const action = optionalString(obj, 'action');
  if (action !== undefined && action !== 'local_input' && action !== 'pi_input' && action !== 'bridge_recovery') {
    throw new AgentAdapterClientInputError('handle.action is invalid');
  }
  // Wire `local_input` (and the tolerated legacy `pi_input`) both mean the
  // persisted `pi_input` handle action; only `bridge_recovery` differs.
  let handleAction: 'pi_input' | 'bridge_recovery' | undefined;
  if (action === 'bridge_recovery') {
    handleAction = 'bridge_recovery';
  } else if (action !== undefined) {
    handleAction = 'pi_input';
  }
  return {
    handledThroughEventId: requireIdentifier(obj, 'handledThroughEventId'),
    handledThroughEventCreatedAt: optionalString(obj, 'handledThroughEventCreatedAt'),
    handledAt: optionalString(obj, 'handledAt'),
    action: handleAction,
  };
}

function parseHeartbeatInput(value: unknown): {
  status: SessionStatus;
  latestActivityText?: string | null;
  openingText?: string | null;
  projectName?: string;
  nameText?: string;
} {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new AgentAdapterClientInputError('Request body must be an object');
  }

  const obj = value as Record<string, unknown>;
  assertExactKeys(obj, ['status'], [
    'latestActivityText', 'openingText', 'projectName', 'nameText',
  ], 'heartbeat');
  const statusValue = requireString(obj, 'status');
  if (!SESSION_STATUSES.includes(statusValue as SessionStatus)) {
    throw new AgentAdapterClientInputError(`Invalid status: ${statusValue}`);
  }

  return {
    status: statusValue as SessionStatus,
    latestActivityText: optionalNullableString(obj, 'latestActivityText'),
    openingText: optionalNullableString(obj, 'openingText'),
    projectName: optionalString(obj, 'projectName'),
    nameText: optionalString(obj, 'nameText'),
  };
}

function assertExactKeys(
  obj: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) throw new AgentAdapterClientInputError(`${label}.${key} is unsupported`);
  }
  for (const key of required) {
    if (!hasOwn(obj, key)) throw new AgentAdapterClientInputError(`${label}.${key} is required`);
  }
}

function optionalStatus(obj: Record<string, unknown>, key: string): SessionStatus | undefined {
  const value = optionalString(obj, key);
  if (value === undefined) return undefined;
  if (!SESSION_STATUSES.includes(value as SessionStatus)) throw new AgentAdapterClientInputError(`Invalid status: ${value}`);
  return value as SessionStatus;
}

function parseResultInput(value: unknown, expectedCommandId: string): AgentAdapterCommandResult {
  let result: AgentAdapterCommandResult;
  try {
    result = parseAgentAdapterCommandResult(value);
  } catch (error) {
    throw new AgentAdapterClientInputError('Agent Adapter command result is invalid', { cause: error });
  }
  if (result.commandId !== expectedCommandId) {
    throw new AgentAdapterClientInputError('commandId in result does not match URL');
  }
  return result;
}

function requireIdentifier(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (!isBoundedAgentAdapterIdentifier(value)) {
    throw new AgentAdapterClientInputError(`Missing or invalid field: ${key}`);
  }
  return value;
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== 'string') {
    throw new AgentAdapterClientInputError(`Missing or invalid field: ${key}`);
  }
  return value;
}

function hasOwn(obj: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function optionalNullableString(obj: Record<string, unknown>, key: string): string | null | undefined {
  const value = obj[key];
  if (value === undefined || value === null) return value;
  if (typeof value !== 'string') {
    throw new AgentAdapterClientInputError(`Invalid field: ${key}`);
  }
  return value;
}

function optionalIdentifier(obj: Record<string, unknown>, key: string): string | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (!isBoundedAgentAdapterIdentifier(value)) {
    throw new AgentAdapterClientInputError(`Invalid field: ${key}`);
  }
  return value;
}

function optionalString(obj: Record<string, unknown>, key: string): string | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') {
    throw new AgentAdapterClientInputError(`Invalid field: ${key}`);
  }
  return value;
}

function optionalNumber(obj: Record<string, unknown>, key: string): number | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'number') {
    throw new AgentAdapterClientInputError(`Invalid field: ${key}`);
  }
  return value;
}
