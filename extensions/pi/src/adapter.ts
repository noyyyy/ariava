import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import type { CanonicalEvent, CommandEnvelope, CommandResult, HandleSessionRequest, SessionStatus } from '@ariava/protocol';
import type { AgentAdapter } from './adapter-interface';
import type { PiSessionInfo } from './session';

export interface AgentAdapterDiscoveryFile {
  url: string;
  secret: string;
}

export interface AgentAdapterClientOptions {
  configPath?: string;
  baseUrl?: string;
  secret?: string;
}

const DEFAULT_CONFIG_PATH = `${homedir()}/.config/ariava/agent-adapter.json`;

export function resolveAgentAdapterConfigPath(explicitConfigPath?: string): string {
  if (explicitConfigPath !== undefined) return explicitConfigPath;
  const environmentConfigPath = process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH;
  if (environmentConfigPath?.trim()) return environmentConfigPath;
  return DEFAULT_CONFIG_PATH;
}

export class AgentAdapterClient implements AgentAdapter {
  private readonly configPath: string;
  private cachedDiscovery: AgentAdapterDiscoveryFile | null = null;
  private readonly pinnedDiscovery: boolean;

  constructor(options: AgentAdapterClientOptions = {}) {
    this.configPath = resolveAgentAdapterConfigPath(options.configPath);
    this.pinnedDiscovery = Boolean(options.baseUrl && options.secret);
    if (options.baseUrl && options.secret) {
      this.cachedDiscovery = { url: options.baseUrl, secret: options.secret };
    }
  }

  async registerSession(session: PiSessionInfo): Promise<{ sessionId: string; registeredAt: string }> {
    const response = await this.fetch('POST', '/v1/agent/sessions', session);
    return (await response.json()) as { sessionId: string; registeredAt: string };
  }

  async unregisterSession(sessionId: string): Promise<void> {
    await this.fetch('DELETE', `/v1/agent/sessions/${encodeURIComponent(sessionId)}`, undefined);
  }

  async pushEvent(event: Partial<CanonicalEvent>): Promise<{ eventId: string }> {
    const sessionId = event.sessionId;
    if (!sessionId) {
      throw new Error('pushEvent requires sessionId');
    }
    const response = await this.fetch('POST', `/v1/agent/sessions/${encodeURIComponent(sessionId)}/events`, event);
    return (await response.json()) as { eventId: string };
  }

  async handleSession(sessionId: string, request: HandleSessionRequest): Promise<{ ok: true; hostId: string; sessionId: string; handledThroughEventId: string }> {
    const response = await this.fetch('POST', `/v1/agent/sessions/${encodeURIComponent(sessionId)}/handle`, request);
    return (await response.json()) as { ok: true; hostId: string; sessionId: string; handledThroughEventId: string };
  }

  async heartbeat(sessionId: string, status: SessionStatus, latestActivityText?: string | null, session?: PiSessionInfo): Promise<void> {
    const currentSession = session ? { ...session, status, latestActivityText: latestActivityText ?? undefined } : undefined;
    const body: Record<string, unknown> = { status };
    if (latestActivityText !== undefined) body.latestActivityText = latestActivityText;
    if (currentSession) {
      body.openingText = currentSession.openingText ?? null;
      body.projectName = currentSession.projectName;
      body.nameText = currentSession.nameText;
    }
    const path = `/v1/agent/sessions/${encodeURIComponent(sessionId)}/heartbeat`;
    const response = await this.fetchResponse('POST', path, body);
    if (response.status === 404 && currentSession) {
      await this.registerSession(currentSession);
      await this.fetch('POST', path, body);
      return;
    }
    await this.requireOk(response, 'POST', path);
  }

  async pollCommands(sessionId: string, timeoutMs: number, session?: PiSessionInfo): Promise<CommandEnvelope | null> {
    const path = `/v1/agent/sessions/${encodeURIComponent(sessionId)}/commands?timeout=${timeoutMs}`;
    let response = await this.fetchResponse('GET', path, undefined);
    if (response.status === 404 && session) {
      await this.registerSession(session);
      response = await this.fetchResponse('GET', path, undefined);
    }
    await this.requireOk(response, 'GET', path);
    if (response.status === 204) return null;
    const body = (await response.json()) as { command: CommandEnvelope };
    return body.command;
  }

  async submitResult(commandId: string, result: CommandResult): Promise<void> {
    const sessionId = result.sessionId;
    await this.fetch(
      'POST',
      `/v1/agent/sessions/${encodeURIComponent(sessionId)}/commands/${encodeURIComponent(commandId)}/result`,
      result,
    );
  }

  private async fetch(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body: unknown,
  ): Promise<Response> {
    const response = await this.fetchResponse(method, path, body);
    await this.requireOk(response, method, path);
    return response;
  }

  private async fetchResponse(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body: unknown,
  ): Promise<Response> {
    let discovery = await this.getDiscovery();
    let response = await this.requestWithDiscovery(discovery, method, path, body);
    if (response.status === 401 && !this.pinnedDiscovery) {
      this.cachedDiscovery = null;
      discovery = await this.getDiscovery();
      response = await this.requestWithDiscovery(discovery, method, path, body);
    }
    return response;
  }

  private async requireOk(response: Response, method: string, path: string): Promise<void> {
    if (response.ok) return;
    const text = await response.text();
    throw new Error(`Agent Adapter ${method} ${path} failed: ${response.status} ${text}`);
  }

  private async requestWithDiscovery(
    discovery: AgentAdapterDiscoveryFile,
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body: unknown,
  ): Promise<Response> {
    const url = `${discovery.url}${path}`;
    const init: RequestInit = {
      method,
      headers: {
        authorization: `Bearer ${discovery.secret}`,
        'content-type': 'application/json',
      },
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }

    return this.withRetry(() => fetch(url, init), `${method} ${path}`);
  }

  private async getDiscovery(): Promise<AgentAdapterDiscoveryFile> {
    if (this.cachedDiscovery) return this.cachedDiscovery;

    const raw = readFileSync(this.configPath, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (!isDiscoveryFile(parsed)) {
      throw new Error(`Invalid agent adapter discovery file: ${this.configPath}`);
    }
    this.cachedDiscovery = parsed;
    return parsed;
  }

  private async withRetry<T>(operation: () => Promise<T>, _label: string, maxAttempts = 5): Promise<T> {
    let delayMs = 250;
    let lastError: unknown;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        if (attempt === maxAttempts) break;
        await sleep(delayMs);
        delayMs = Math.min(delayMs * 2, 8000);
      }
    }

    throw lastError;
  }
}

function isDiscoveryFile(value: unknown): value is AgentAdapterDiscoveryFile {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as Record<string, unknown>).url === 'string' &&
    typeof (value as Record<string, unknown>).secret === 'string'
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
