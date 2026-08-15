import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import {
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
  SESSION_STATUSES,
  type SessionStatus,
} from '@ariava/protocol';
import {
  AgentAdapterRequestValidationError,
  SessionIdCollisionError,
  type AgentAdapterRegistry,
  type RegisterSessionInput,
} from './registry';
import type { BridgeRuntimeHealth } from '../types';
import { parseAgentAdapterCommandResult, type AgentAdapterCommandResult } from './result';

export class AgentAdapterClientInputError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AgentAdapterClientInputError';
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
    const auth = request.headers.authorization;
    const token = auth?.startsWith('Bearer ') ? auth.slice(7) : '';
    if (token !== this.config.secret || !this.config.secret) {
      this.writeJson(response, 401, { error: 'Unauthorized' });
      return;
    }
    if (request.headers[AGENT_ADAPTER_PROTOCOL_HEADER] !== String(AGENT_ADAPTER_PROTOCOL_VERSION)) {
      this.writeJson(response, 426, { error: 'Agent Adapter protocol version mismatch' });
      return;
    }

    const url = new URL(request.url ?? '/', this.url);
    const pathname = url.pathname;
    const method = request.method ?? 'GET';

    try {
      if (pathname === '/v1/health' && method === 'GET') {
        this.writeJson(response, 200, { ok: true, hostId: this.config.hostId, health: this.health() });
        return;
      }

      if (pathname === '/v1/agent/sessions' && method === 'POST') {
        const input = parseRegisterInput(await this.readJson(request));
        const session = this.registry.register(input);
        this.writeJson(response, 201, { sessionId: session.sessionId, registeredAt: session.registeredAt });
        return;
      }

      const unregisterMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)$/);
      if (unregisterMatch && method === 'DELETE') {
        const sessionId = decodePathIdentity(unregisterMatch[1], 'sessionId');
        this.registry.unregister(sessionId);
        this.writeJson(response, 200, { ok: true });
        return;
      }

      const eventMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/events$/);
      if (eventMatch && method === 'POST') {
        const sessionId = decodePathIdentity(eventMatch[1], 'sessionId');
        const eventId = this.registry.pushEvent(sessionId, await this.readJson(request));
        this.writeJson(response, 200, { eventId });
        return;
      }

      const handleMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/handle$/);
      if (handleMatch && method === 'POST') {
        const sessionId = decodePathIdentity(handleMatch[1], 'sessionId');
        const result = this.registry.handleSession(
          sessionId,
          parseHandleInput(await this.readJson(request)),
        );
        this.writeJson(response, 200, result);
        return;
      }


      const heartbeatMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/heartbeat$/);
      if (heartbeatMatch && method === 'POST') {
        const sessionId = decodePathIdentity(heartbeatMatch[1], 'sessionId');
        const { status, latestActivityText, openingText, projectName, nameText } = parseHeartbeatInput(await this.readJson(request));
        const session = this.registry.heartbeat(sessionId, status, latestActivityText, {
          openingText, projectName, nameText,
        });
        if (!session) {
          this.writeJson(response, 404, { error: 'Session not found' });
          return;
        }
        this.writeJson(response, 200, { ok: true });
        return;
      }

      const commandMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/commands$/);
      if (commandMatch && method === 'GET') {
        const sessionId = decodePathIdentity(commandMatch[1], 'sessionId');
        if (!this.registry.hasSession(sessionId)) {
          this.writeJson(response, 404, { error: 'Session not found' });
          return;
        }
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

      const resultMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/commands\/([^/]+)\/result$/);
      if (resultMatch && method === 'POST') {
        const sessionId = decodePathIdentity(resultMatch[1], 'sessionId');
        const commandId = decodePathIdentity(resultMatch[2], 'commandId');
        const result = parseResultInput(await this.readJson(request), commandId);
        this.registry.resolveCommand(commandId, result, sessionId);
        this.writeJson(response, 200, { ok: true });
        return;
      }

      this.writeJson(response, 404, { error: 'Not found' });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (error instanceof SessionIdCollisionError) {
        this.writeJson(response, 409, { error: message, code: error.code });
        return;
      }
      if (error instanceof AgentAdapterClientInputError || error instanceof AgentAdapterRequestValidationError) {
        this.writeJson(response, 400, { error: message });
        return;
      }
      this.writeJson(response, 500, { error: message });
    }
  }

  private async readJson(request: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    if (chunks.length === 0) return {};
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
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

function decodePathIdentity(value: string, label: 'sessionId' | 'commandId'): string {
  try {
    return decodeURIComponent(value);
  } catch (error) {
    throw new AgentAdapterClientInputError(`${label} path segment contains malformed percent encoding`, { cause: error });
  }
}

function parseRegisterInput(value: unknown): RegisterSessionInput {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new AgentAdapterClientInputError('Request body must be an object');
  }

  const obj = value as Record<string, unknown>;
  assertExactKeys(obj,
    ['sessionId', 'provider', 'projectName', 'cwd', 'nameText'],
    ['openingText', 'latestActivityText', 'harnessProvider', 'pid', 'status'],
    'register Session',
  );
  return {
    sessionId: requireString(obj, 'sessionId'),
    provider: requireString(obj, 'provider'),
    projectName: requireString(obj, 'projectName'),
    cwd: requireString(obj, 'cwd'),
    nameText: requireString(obj, 'nameText'),
    openingText: optionalString(obj, 'openingText'),
    latestActivityText: optionalString(obj, 'latestActivityText'),
    harnessProvider: optionalString(obj, 'harnessProvider'),
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
  if (action !== undefined && action !== 'pi_input' && action !== 'bridge_recovery') {
    throw new AgentAdapterClientInputError('handle.action is invalid');
  }
  return {
    handledThroughEventId: requireString(obj, 'handledThroughEventId'),
    handledThroughEventCreatedAt: optionalString(obj, 'handledThroughEventCreatedAt'),
    handledAt: optionalString(obj, 'handledAt'),
    action,
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
