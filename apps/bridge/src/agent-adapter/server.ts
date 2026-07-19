import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { CommandResult, SessionStatus } from '@ariava/protocol';
import { SESSION_STATUSES } from '@ariava/protocol';
import type { AgentAdapterRegistry, RegisterSessionInput } from './registry';

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

    const url = new URL(request.url ?? '/', this.url);
    const pathname = url.pathname;
    const method = request.method ?? 'GET';

    try {
      if (pathname === '/v1/agent/sessions' && method === 'POST') {
        const input = parseRegisterInput(await this.readJson(request));
        const session = this.registry.register(input);
        this.writeJson(response, 201, { sessionId: session.sessionId, registeredAt: session.registeredAt });
        return;
      }

      const unregisterMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)$/);
      if (unregisterMatch && method === 'DELETE') {
        this.registry.unregister(unregisterMatch[1]);
        this.writeJson(response, 200, { ok: true });
        return;
      }

      const eventMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/events$/);
      if (eventMatch && method === 'POST') {
        const eventId = this.registry.pushEvent(eventMatch[1], await this.readJson(request));
        this.writeJson(response, 200, { eventId });
        return;
      }

      const handleMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/handle$/);
      if (handleMatch && method === 'POST') {
        const result = this.registry.handleSession(handleMatch[1], await this.readJson(request));
        this.writeJson(response, 200, result);
        return;
      }

      const readMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/read$/);
      if (readMatch && method === 'POST') {
        const result = this.registry.handleSessionReadAlias(readMatch[1], await this.readJson(request));
        this.writeJson(response, 200, result);
        return;
      }

      const heartbeatMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/heartbeat$/);
      if (heartbeatMatch && method === 'POST') {
        const { status, latestActivityText } = parseHeartbeatInput(await this.readJson(request));
        const session = this.registry.heartbeat(heartbeatMatch[1], status, latestActivityText);
        if (!session) {
          this.writeJson(response, 404, { error: 'Session not found' });
          return;
        }
        this.writeJson(response, 200, { ok: true });
        return;
      }

      const commandMatch = pathname.match(/^\/v1\/agent\/sessions\/([^/]+)\/commands$/);
      if (commandMatch && method === 'GET') {
        const timeout = Math.min(Math.max(parseInt(url.searchParams.get('timeout') ?? '30000', 10), 0), 120_000);
        const command = await this.registry.dequeueCommand(commandMatch[1], timeout);
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
        const result = parseResultInput(await this.readJson(request), resultMatch[2]);
        this.registry.resolveCommand(resultMatch[2], result);
        this.writeJson(response, 200, { ok: true });
        return;
      }

      this.writeJson(response, 404, { error: 'Not found' });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.writeJson(response, 500, { error: message });
    }
  }

  private async readJson(request: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    if (chunks.length === 0) return {};
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  }

  private writeJson(response: ServerResponse, status: number, body: unknown): void {
    response.statusCode = status;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(body));
  }
}

function parseRegisterInput(value: unknown): RegisterSessionInput {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Request body must be an object');
  }

  const obj = value as Record<string, unknown>;
  const sessionId = requireString(obj, 'sessionId');
  const provider = requireString(obj, 'provider');
  const projectName = optionalString(obj, 'projectName') ?? optionalString(obj, 'project') ?? 'unknown';
  const cwd = requireString(obj, 'cwd');

  return {
    sessionId,
    provider,
    projectName,
    cwd,
    nameText: optionalString(obj, 'nameText') ?? optionalString(obj, 'title') ?? projectName,
    openingText: optionalString(obj, 'openingText'),
    latestActivityText: optionalString(obj, 'latestActivityText') ?? optionalString(obj, 'summary'),
    pid: optionalNumber(obj, 'pid'),
  };
}

function parseHeartbeatInput(value: unknown): { status: SessionStatus; latestActivityText?: string } {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Request body must be an object');
  }

  const obj = value as Record<string, unknown>;
  const statusValue = requireString(obj, 'status');
  if (!SESSION_STATUSES.includes(statusValue as SessionStatus)) {
    throw new Error(`Invalid status: ${statusValue}`);
  }

  return {
    status: statusValue as SessionStatus,
    latestActivityText: optionalString(obj, 'latestActivityText') ?? optionalString(obj, 'summary'),
  };
}

function parseResultInput(value: unknown, expectedCommandId: string): CommandResult {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Request body must be an object');
  }

  const obj = value as Record<string, unknown>;
  const commandId = requireString(obj, 'commandId');
  if (commandId !== expectedCommandId) {
    throw new Error('commandId in result does not match URL');
  }

  return {
    commandId,
    hostId: requireString(obj, 'hostId'),
    sessionId: requireString(obj, 'sessionId'),
    accepted: requireBoolean(obj, 'accepted'),
    status: requireResultStatus(obj),
    message: requireString(obj, 'message'),
    correlationId: optionalString(obj, 'correlationId'),
    updatedAt: requireString(obj, 'updatedAt'),
  };
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== 'string') {
    throw new Error(`Missing or invalid field: ${key}`);
  }
  return value;
}

function optionalString(obj: Record<string, unknown>, key: string): string | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') {
    throw new Error(`Invalid field: ${key}`);
  }
  return value;
}

function optionalNumber(obj: Record<string, unknown>, key: string): number | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'number') {
    throw new Error(`Invalid field: ${key}`);
  }
  return value;
}

function requireBoolean(obj: Record<string, unknown>, key: string): boolean {
  const value = obj[key];
  if (typeof value !== 'boolean') {
    throw new Error(`Missing or invalid field: ${key}`);
  }
  return value;
}

function requireResultStatus(obj: Record<string, unknown>): CommandResult['status'] {
  const value = requireString(obj, 'status');
  const valid: CommandResult['status'][] = ['queued', 'delivered', 'executed', 'expired', 'rejected', 'failed'];
  if (!valid.includes(value as CommandResult['status'])) {
    throw new Error(`Invalid result status: ${value}`);
  }
  return value as CommandResult['status'];
}
