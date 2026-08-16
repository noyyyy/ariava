import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import {
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
  type CommandEnvelope,
  type HandleSessionRequest,
  type SessionStatus,
} from '@ariava/protocol';
import {
  validateAgentAdapterCommand,
  validateAgentAdapterCommandResult,
  type AgentAdapter,
  type AgentAdapterCommandResult,
  type AgentAdapterEvent,
} from './adapter-interface';
import type { PiSessionInfo } from './session';

export interface AgentAdapterDiscoveryFile {
  url: string;
  secret: string;
  protocolVersion: typeof AGENT_ADAPTER_PROTOCOL_VERSION;
}

export interface AgentAdapterClientOptions {
  configPath?: string;
  baseUrl?: string;
  secret?: string;
}

const DEFAULT_CONFIG_PATH = `${homedir()}/.config/ariava/agent-adapter.json`;
export const AGENT_ADAPTER_REQUEST_BODY_BYTES = 256 * 1024;
const adapterTextEncoder = new TextEncoder();

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
  private readonly sessionMutationTails = new Map<string, Promise<void>>();
  private readonly sessionLifecycleGenerations = new Map<string, number>();

  constructor(options: AgentAdapterClientOptions = {}) {
    this.configPath = resolveAgentAdapterConfigPath(options.configPath);
    this.pinnedDiscovery = Boolean(options.baseUrl && options.secret);
    if (options.baseUrl && options.secret) {
      this.cachedDiscovery = {
        url: options.baseUrl,
        secret: options.secret,
        protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
      };
    }
  }

  async registerSession(session: PiSessionInfo): Promise<{ sessionId: string; registeredAt: string }> {
    this.invalidatePollRecovery(session.sessionId);
    return this.enqueueSessionMutation(session.sessionId, () => this.registerSessionCore(session));
  }

  private async registerSessionCore(session: PiSessionInfo): Promise<{ sessionId: string; registeredAt: string }> {
    const {
      sessionId, provider, projectName, cwd, nameText, openingText, latestActivityText,
      harnessProvider, pid, status,
    } = session;
    const response = await this.fetch('POST', '/v1/agent/sessions', {
      sessionId, provider, projectName, cwd, nameText, openingText, latestActivityText,
      harnessProvider, pid, status,
    });
    return (await response.json()) as { sessionId: string; registeredAt: string };
  }

  async unregisterSession(sessionId: string): Promise<void> {
    this.invalidatePollRecovery(sessionId);
    await this.enqueueSessionMutation(sessionId, () => this.unregisterSessionCore(sessionId));
  }

  private async unregisterSessionCore(sessionId: string): Promise<void> {
    await this.fetch('DELETE', `/v1/agent/sessions/${encodeURIComponent(sessionId)}`, undefined);
  }

  async pushEvent(event: AgentAdapterEvent): Promise<{ eventId: string }> {
    return this.enqueueSessionMutation(event.sessionId, () => this.pushEventCore(event));
  }

  private async pushEventCore(event: AgentAdapterEvent): Promise<{ eventId: string }> {
    const response = await this.fetch(
      'POST', `/v1/agent/sessions/${encodeURIComponent(event.sessionId)}/events`, event,
    );
    return (await response.json()) as { eventId: string };
  }

  async handleSession(sessionId: string, request: HandleSessionRequest): Promise<{ ok: true; hostId: string; sessionId: string; handledThroughEventId: string }> {
    return this.enqueueSessionMutation(sessionId, () => this.handleSessionCore(sessionId, request));
  }

  private async handleSessionCore(sessionId: string, request: HandleSessionRequest): Promise<{ ok: true; hostId: string; sessionId: string; handledThroughEventId: string }> {
    const response = await this.fetch('POST', `/v1/agent/sessions/${encodeURIComponent(sessionId)}/handle`, request);
    return (await response.json()) as { ok: true; hostId: string; sessionId: string; handledThroughEventId: string };
  }

  async heartbeat(sessionId: string, status: SessionStatus, latestActivityText?: string | null, session?: PiSessionInfo): Promise<void> {
    this.invalidatePollRecovery(sessionId);
    await this.enqueueSessionMutation(
      sessionId,
      () => this.heartbeatCore(sessionId, status, latestActivityText, session),
    );
  }

  private async heartbeatCore(sessionId: string, status: SessionStatus, latestActivityText?: string | null, session?: PiSessionInfo): Promise<void> {
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
      await this.registerSessionCore(currentSession);
      await this.fetch('POST', path, body);
      return;
    }
    await this.requireOk(response, 'POST', path);
  }

  async pollCommands(sessionId: string, timeoutMs: number, session?: PiSessionInfo): Promise<CommandEnvelope | null> {
    const lifecycleGeneration = this.getLifecycleGeneration(sessionId);
    const path = `/v1/agent/sessions/${encodeURIComponent(sessionId)}/commands?timeout=${timeoutMs}`;
    let response = await this.fetchResponse('GET', path, undefined);
    if (response.status === 404 && session) {
      if (this.getLifecycleGeneration(sessionId) !== lifecycleGeneration) return null;
      const recovered = await this.enqueueSessionMutation(sessionId, async () => {
        if (this.getLifecycleGeneration(sessionId) !== lifecycleGeneration) return false;
        await this.registerSessionCore(session);
        return true;
      });
      if (!recovered) return null;
      response = await this.fetchResponse('GET', path, undefined);
    }
    await this.requireOk(response, 'GET', path);
    if (response.status === 204) return null;
    const body = await response.json() as unknown;
    if (!isExactCommandResponse(body) || !validateAgentAdapterCommand(body.command)) {
      throw new TypeError('Agent Adapter command response is invalid');
    }
    return structuredClone(body.command);
  }

  async submitResult(commandId: string, result: AgentAdapterCommandResult): Promise<void> {
    if (commandId !== result.commandId || !validateAgentAdapterCommandResult(result)) {
      throw new TypeError('Agent Adapter command result is invalid');
    }
    await this.fetch(
      'POST',
      `/v1/agent/sessions/${encodeURIComponent(result.sessionId)}/commands/${encodeURIComponent(commandId)}/result`,
      structuredClone(result),
    );
  }

  private invalidatePollRecovery(sessionId: string): void {
    this.sessionLifecycleGenerations.set(sessionId, this.getLifecycleGeneration(sessionId) + 1);
  }

  private getLifecycleGeneration(sessionId: string): number {
    return this.sessionLifecycleGenerations.get(sessionId) ?? 0;
  }

  private enqueueSessionMutation<Result>(sessionId: string, operation: () => Promise<Result>): Promise<Result> {
    const previous = this.sessionMutationTails.get(sessionId) ?? Promise.resolve();
    const result = previous.catch(() => undefined).then(operation);
    const tail = result.then(() => undefined, () => undefined);
    this.sessionMutationTails.set(sessionId, tail);
    void tail.finally(() => {
      if (this.sessionMutationTails.get(sessionId) === tail) this.sessionMutationTails.delete(sessionId);
    });
    return result;
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
        [AGENT_ADAPTER_PROTOCOL_HEADER]: String(discovery.protocolVersion),
      },
    };
    if (body !== undefined) {
      const serialized = JSON.stringify(body);
      if (adapterTextEncoder.encode(serialized).byteLength > AGENT_ADAPTER_REQUEST_BODY_BYTES) {
        throw new Error('Agent Adapter request body exceeds the 256 KiB byte limit');
      }
      init.body = serialized;
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

function isExactCommandResponse(value: unknown): value is { command: unknown } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 1 || keys[0] !== 'command') return false;
  const descriptor = Object.getOwnPropertyDescriptor(value, 'command');
  return Boolean(descriptor?.enumerable && 'value' in descriptor);
}

function isDiscoveryFile(value: unknown): value is AgentAdapterDiscoveryFile {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  return keys.length === 3
    && keys.includes('url')
    && keys.includes('secret')
    && keys.includes('protocolVersion')
    && typeof record.url === 'string'
    && typeof record.secret === 'string'
    && record.protocolVersion === AGENT_ADAPTER_PROTOCOL_VERSION;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
