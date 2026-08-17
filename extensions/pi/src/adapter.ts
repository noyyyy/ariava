import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import {
  AGENT_ADAPTER_LIMITS,
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
  AGENT_ADAPTER_ROUTE_PREFIX,
  isAgentAdapterDiscovery,
  isProtocol4ErrorEnvelope,
  nextProducerEventOrder,
  producerEventOrderFromBigInt,
  validateAgentAdapterEventResponse,
  validateAgentAdapterHandleResponse,
  validateAgentAdapterRegisterOwnedResponse,
  type AgentAdapterHandleRequest,
  type AgentAdapterHandleResponse,
  type AgentAdapterProtocol4ErrorCode,
  type CommandEnvelope,
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
  provider: 'pi';
  profileId: string;
  hostId: string;
}

export interface AgentAdapterClientOptions {
  configPath?: string;
  baseUrl?: string;
  secret?: string;
}

const DEFAULT_CONFIG_PATH = `${homedir()}/.config/ariava/agent-adapter.json`;
export const AGENT_ADAPTER_REQUEST_BODY_BYTES = AGENT_ADAPTER_LIMITS.requestBodyBytes;
const adapterTextEncoder = new TextEncoder();

export const AGENT_ADAPTER_OWNER_HEADERS = {
  driverInstance: 'x-ariava-driver-instance' as const,
  ownerLease: 'x-ariava-owner-lease' as const,
} as const;

const PINNED_DISCOVERY_PROFILE_ID = 'default';
const PINNED_DISCOVERY_HOST_ID = 'pinned-host';

export function resolveAgentAdapterConfigPath(explicitConfigPath?: string): string {
  if (explicitConfigPath !== undefined) return explicitConfigPath;
  const environmentConfigPath = process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH;
  if (environmentConfigPath?.trim()) return environmentConfigPath;
  return DEFAULT_CONFIG_PATH;
}

export class AgentAdapterClient implements AgentAdapter {
  readonly eventPublicationEnabled = true as const;

  private readonly configPath: string;
  private readonly driverInstanceId = randomBytes(AGENT_ADAPTER_LIMITS.driverInstanceIdMinBytes).toString('base64url');
  private readonly sessionLeases = new Map<string, string>();
  private readonly commandLeases = new Map<string, { sessionId: string; ownerLease: string }>();
  private readonly producerEventOrders = new Map<string, string>();
  private cachedDiscovery: AgentAdapterDiscoveryFile | null = null;
  private readonly pinnedDiscovery: boolean;
  private readonly sessionMutationTails = new Map<string, Promise<void>>();

  constructor(options: AgentAdapterClientOptions = {}) {
    this.configPath = resolveAgentAdapterConfigPath(options.configPath);
    this.pinnedDiscovery = Boolean(options.baseUrl && options.secret);
    if (options.baseUrl && options.secret) {
      this.cachedDiscovery = {
        url: options.baseUrl,
        secret: options.secret,
        protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
        provider: 'pi',
        profileId: PINNED_DISCOVERY_PROFILE_ID,
        hostId: PINNED_DISCOVERY_HOST_ID,
      };
    }
  }

  async registerSession(session: PiSessionInfo): Promise<{ sessionId: string; registeredAt: string }> {
    return this.enqueueSessionMutation(session.sessionId, () => this.registerSessionCore(session));
  }

  private async registerSessionCore(session: PiSessionInfo): Promise<{ sessionId: string; registeredAt: string }> {
    const {
      sessionId, provider, projectName, cwd, nameText, openingText, latestActivityText,
      harnessProvider, pid, status,
    } = session;
    const response = await this.requestRegister({
      sessionId, provider, projectName, cwd, nameText, driverInstanceId: this.driverInstanceId,
      openingText, latestActivityText, harnessProvider, pid, status,
    });
    const parsed = await response.json() as unknown;
    const validation = validateAgentAdapterRegisterOwnedResponse(parsed);
    if (!validation.success || !validation.value || validation.value.sessionId !== sessionId) {
      throw new TypeError('Agent Adapter register response is invalid');
    }
    this.sessionLeases.set(sessionId, validation.value.ownerLease);
    return { sessionId: validation.value.sessionId, registeredAt: validation.value.registeredAt };
  }

  async unregisterSession(sessionId: string): Promise<void> {
    await this.enqueueSessionMutation(sessionId, async () => {
      const lease = this.requireSessionLease(sessionId);
      try {
        const path = `${AGENT_ADAPTER_ROUTE_PREFIX}/sessions/${encodeURIComponent(sessionId)}`;
        const response = await this.requestOwnerRoute('DELETE', path, undefined, lease);
        await this.requireOk(response, 'DELETE', path);
      } finally {
        if (this.sessionLeases.get(sessionId) === lease) this.sessionLeases.delete(sessionId);
        for (const [commandId, commandLease] of this.commandLeases) {
          if (commandLease.sessionId === sessionId) this.commandLeases.delete(commandId);
        }
      }
    });
  }

  async pushEvent(event: AgentAdapterEvent): Promise<{ eventId: string }> {
    const producerEventId = randomBytes(AGENT_ADAPTER_LIMITS.producerEventIdBytes).toString('base64url');
    const producerEventOrder = this.allocateProducerEventOrder(event.sessionId);
    const path = `${AGENT_ADAPTER_ROUTE_PREFIX}/sessions/${encodeURIComponent(event.sessionId)}/events`;
    const response = await this.requestOwnerRoute('POST', path, {
      producerEventId,
      producerEventOrder,
      event: structuredClone(event),
    }, this.requireSessionLease(event.sessionId));
    await this.requireOk(response, 'POST', path);
    const parsed = await response.json() as unknown;
    const validation = validateAgentAdapterEventResponse(parsed);
    if (!validation.success || !validation.value
      || validation.value.producerEventId !== producerEventId
      || validation.value.producerEventOrder !== producerEventOrder) {
      throw new TypeError('Agent Adapter Event response is invalid');
    }
    return { eventId: validation.value.eventId };
  }

  async handleSession(sessionId: string, request: AgentAdapterHandleRequest): Promise<AgentAdapterHandleResponse> {
    return this.enqueueSessionMutation(sessionId, async () => {
      const path = `${AGENT_ADAPTER_ROUTE_PREFIX}/sessions/${encodeURIComponent(sessionId)}/handle`;
      const response = await this.requestOwnerRoute('POST', path, {
        ...request,
        action: request.action ?? 'local_input',
      }, this.requireSessionLease(sessionId));
      await this.requireOk(response, 'POST', path);
      const parsed = await response.json() as unknown;
      const validation = validateAgentAdapterHandleResponse(parsed);
      if (!validation.success || !validation.value) {
        throw new TypeError('Agent Adapter handle response is invalid');
      }
      return validation.value;
    });
  }

  async heartbeat(
    sessionId: string,
    status: SessionStatus,
    latestActivityText?: string | null,
    session?: PiSessionInfo,
  ): Promise<void> {
    await this.enqueueSessionMutation(
      sessionId,
      () => this.heartbeatCore(sessionId, status, latestActivityText, session),
    );
  }

  private async heartbeatCore(
    sessionId: string,
    status: SessionStatus,
    latestActivityText?: string | null,
    session?: PiSessionInfo,
  ): Promise<void> {
    const currentSession = session ? { ...session, status, latestActivityText: latestActivityText ?? undefined } : undefined;
    const body: Record<string, unknown> = { status };
    if (latestActivityText !== undefined) body.latestActivityText = latestActivityText;
    if (currentSession) {
      body.openingText = currentSession.openingText ?? null;
      body.projectName = currentSession.projectName;
      body.nameText = currentSession.nameText;
    }
    const path = `${AGENT_ADAPTER_ROUTE_PREFIX}/sessions/${encodeURIComponent(sessionId)}/heartbeat`;
    let response = await this.requestOwnerRoute('POST', path, body, this.requireSessionLease(sessionId), true);
    if (currentSession && await this.needsSessionReacquire(response)) {
      // A 401 on a discovery-backed config means the persisted secret rotated.
      if (response.status === 401) this.cachedDiscovery = null;
      await this.registerSessionCore(currentSession);
      response = await this.requestOwnerRoute('POST', path, body, this.requireSessionLease(sessionId), true);
    }
    await this.requireOk(response, 'POST', path);
  }

  async pollCommands(sessionId: string, timeoutMs: number): Promise<CommandEnvelope | null> {
    const lease = this.requireSessionLease(sessionId);
    const path = `${AGENT_ADAPTER_ROUTE_PREFIX}/sessions/${encodeURIComponent(sessionId)}/commands?timeout=${timeoutMs}`;
    const response = await this.requestOwnerRoute('GET', path, undefined, lease);
    await this.requireOk(response, 'GET', path);
    if (response.status === 204) return null;
    const body = await response.json() as unknown;
    if (!isExactCommandResponse(body) || !validateAgentAdapterCommand(body.command)
      || body.command.sessionId !== sessionId || this.commandLeases.has(body.command.commandId)) {
      throw new TypeError('Agent Adapter command response is invalid');
    }
    this.commandLeases.set(body.command.commandId, { sessionId, ownerLease: lease });
    return structuredClone(body.command);
  }

  async submitResult(commandId: string, result: AgentAdapterCommandResult): Promise<void> {
    if (commandId !== result.commandId || !validateAgentAdapterCommandResult(result)) {
      throw new TypeError('Agent Adapter command result is invalid');
    }
    const commandLease = this.commandLeases.get(commandId);
    if (!commandLease || commandLease.sessionId !== result.sessionId) {
      throw new Error('Agent Adapter command result has no matching dequeue lease');
    }
    const path = `${AGENT_ADAPTER_ROUTE_PREFIX}/sessions/${encodeURIComponent(result.sessionId)}/commands/${encodeURIComponent(commandId)}/result`;
    try {
      const response = await this.requestOwnerRoute('POST', path, structuredClone(result), commandLease.ownerLease);
      if (await this.hasProtocol4ErrorCode(response, 'COMMAND_OUTCOME_UNKNOWN')) return;
      await this.requireOk(response, 'POST', path);
    } finally {
      this.commandLeases.delete(commandId);
    }
  }

  abandonCommand(commandId: string): void {
    this.commandLeases.delete(commandId);
  }

  private allocateProducerEventOrder(sessionId: string): string {
    const previous = this.producerEventOrders.get(sessionId);
    const order = previous === undefined
      ? producerEventOrderFromBigInt(randomNonZero128BitInteger())
      : nextProducerEventOrder(previous);
    if (order === null) throw new Error('Agent Adapter producer event order exhausted');
    this.producerEventOrders.set(sessionId, order);
    return order;
  }

  private requireSessionLease(sessionId: string): string {
    const lease = this.sessionLeases.get(sessionId);
    if (!lease) throw new Error(`Agent Adapter session ${sessionId} is not registered`);
    return lease;
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

  private async requestRegister(body: unknown): Promise<Response> {
    const path = `${AGENT_ADAPTER_ROUTE_PREFIX}/sessions`;
    let discovery = await this.getDiscovery();
    try {
      const response = await this.requestWithDiscovery(discovery, 'POST', path, body, undefined, true);
      if (response.status !== 401 || this.pinnedDiscovery) {
        await this.requireOk(response, 'POST', path);
        return response;
      }
    } catch (error) {
      if (this.pinnedDiscovery || error instanceof AgentAdapterHttpError) throw error;
    }
    this.cachedDiscovery = null;
    discovery = await this.getDiscovery();
    const response = await this.requestWithDiscovery(discovery, 'POST', path, body, undefined, true);
    await this.requireOk(response, 'POST', path);
    return response;
  }

  private async requestOwnerRoute(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body: unknown,
    ownerLease: string,
    retryOnTransport = false,
  ): Promise<Response> {
    return this.requestWithDiscovery(await this.getDiscovery(), method, path, body, ownerLease, retryOnTransport);
  }

  private async requireOk(response: Response, method: string, path: string): Promise<void> {
    if (response.ok) return;
    throw new AgentAdapterHttpError(`Agent Adapter ${method} ${path} failed: ${response.status}`);
  }

  private async requestWithDiscovery(
    discovery: AgentAdapterDiscoveryFile,
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body: unknown,
    ownerLease?: string,
    retryOnTransport = false,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${discovery.secret}`,
      'content-type': 'application/json',
      [AGENT_ADAPTER_PROTOCOL_HEADER]: String(discovery.protocolVersion),
    };
    if (ownerLease !== undefined) {
      headers[AGENT_ADAPTER_OWNER_HEADERS.driverInstance] = this.driverInstanceId;
      headers[AGENT_ADAPTER_OWNER_HEADERS.ownerLease] = ownerLease;
    }
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      const serialized = JSON.stringify(body);
      if (adapterTextEncoder.encode(serialized).byteLength > AGENT_ADAPTER_REQUEST_BODY_BYTES) {
        throw new Error('Agent Adapter request body exceeds the 256 KiB byte limit');
      }
      init.body = serialized;
    }
    const attempt = () => fetch(`${discovery.url}${path}`, init);
    return retryOnTransport ? this.withRetry(attempt) : attempt();
  }

  private async getDiscovery(): Promise<AgentAdapterDiscoveryFile> {
    if (this.cachedDiscovery) return this.cachedDiscovery;
    const parsed = JSON.parse(readFileSync(this.configPath, 'utf8')) as unknown;
    if (!isAgentAdapterDiscovery(parsed) || parsed.provider !== 'pi') {
      throw new Error(`Invalid agent adapter discovery file: ${this.configPath}`);
    }
    const discovery: AgentAdapterDiscoveryFile = { ...parsed, provider: 'pi' };
    this.cachedDiscovery = discovery;
    return discovery;
  }

  private async hasProtocol4ErrorCode(response: Response, code: AgentAdapterProtocol4ErrorCode): Promise<boolean> {
    const envelope = await parseProtocol4Error(response);
    return envelope?.error.code === code;
  }

  /** A live owner re-registers when the discovery secret rotated (401) or the session was lost or expired. */
  private async needsSessionReacquire(response: Response): Promise<boolean> {
    if (response.status === 401 && !this.pinnedDiscovery) return true;
    return await this.hasProtocol4ErrorCode(response, 'SESSION_NOT_FOUND')
      || await this.hasProtocol4ErrorCode(response, 'STALE_OWNER');
  }

  private async withRetry<T>(operation: () => Promise<T>, maxAttempts = 5): Promise<T> {
    let delayMs = 250;
    let lastError: unknown;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        if (attempt === maxAttempts) break;
        await sleep(delayMs);
        delayMs = Math.min(delayMs * 2, 8_000);
      }
    }
    throw lastError;
  }
}

class AgentAdapterHttpError extends Error {}

async function parseProtocol4Error(response: Response) {
  if (response.ok) return null;
  try {
    const parsed = await response.clone().json() as unknown;
    return isProtocol4ErrorEnvelope(parsed) ? parsed : null;
  } catch {
    return null;
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

function randomNonZero128BitInteger(): bigint {
  const highBit = 1n << 127n;
  const wallClockPrefix = (BigInt(Date.now()) & ((1n << 47n) - 1n)) << 80n;
  const randomSuffix = BigInt(`0x${randomBytes(10).toString('hex')}`);
  return highBit | wallClockPrefix | randomSuffix;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
