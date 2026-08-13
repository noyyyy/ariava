import {
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
} from '@ariava/protocol';
import { readAgentAdapterConfig, type AgentAdapterDiscoveryFile } from '../../../agent-adapter/config';
import type { HostIdentity } from '../../../identity/types';
import type { BridgeRuntimeHealth } from '../../../types';
import type { ResolvedAriavaConfig } from '../../config';
import type { ServiceStatus } from '../../service/types';
import { boundedPositive, fetchBounded, throwIfAborted } from './bounded-fetch';
import { errorCode, errorMessage, readinessError } from './remediation';
import { parseAgentAdapterHealth } from './runtime-health-codec';

export interface ReadinessClock {
  now(): number;
  sleep(milliseconds: number): Promise<void>;
}

export interface LocalBridgeDependencies {
  fetch: typeof fetch;
  clock: ReadinessClock;
  readDiscovery(path: string): AgentAdapterDiscoveryFile | null;
  serviceStatus(): ServiceStatus;
}

export interface LocalBridgeInput {
  config: Pick<ResolvedAriavaConfig, 'agentAdapterConfigPath' | 'agentAdapterPort'>;
  identity: Pick<HostIdentity, 'hostId'>;
  timeoutMs?: number;
  pollIntervalMs?: number;
  requestTimeoutMs?: number;
  signal?: AbortSignal;
}

const defaultClock: ReadinessClock = {
  now: () => Date.now(),
  sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
};

export const defaultLocalBridgeDependencies: LocalBridgeDependencies = {
  fetch,
  clock: defaultClock,
  readDiscovery: readAgentAdapterConfig,
  serviceStatus: () => { throw new Error('A service status dependency is required'); },
};

export async function pollForService(
  input: Pick<LocalBridgeInput, 'timeoutMs' | 'pollIntervalMs' | 'signal'>,
  overrides: Partial<LocalBridgeDependencies> = {},
): Promise<ServiceStatus> {
  const deps = { ...defaultLocalBridgeDependencies, ...overrides };
  const timeoutMs = boundedPositive(input.timeoutMs, 10_000);
  const intervalMs = boundedPositive(input.pollIntervalMs, 100);
  const deadline = deps.clock.now() + timeoutMs;
  let status = deps.serviceStatus();
  throwIfAborted(input.signal);
  while (status.support.supported && status.installed && !status.processRunning && deps.clock.now() < deadline) {
    throwIfAborted(input.signal);
    await deps.clock.sleep(Math.min(intervalMs, Math.max(1, deadline - deps.clock.now())));
    status = deps.serviceStatus();
  }
  return status;
}

export async function pollForDiscoveryAndHealth(
  input: LocalBridgeInput,
  overrides: Partial<LocalBridgeDependencies> = {},
): Promise<{ discovery: AgentAdapterDiscoveryFile; health: BridgeRuntimeHealth }> {
  const deps = { ...defaultLocalBridgeDependencies, ...overrides };
  const timeoutMs = boundedPositive(input.timeoutMs, 10_000);
  const intervalMs = boundedPositive(input.pollIntervalMs, 100);
  const deadline = deps.clock.now() + timeoutMs;
  let lastCode: 'ERR_AGENT_ADAPTER_DISCOVERY' | 'ERR_AGENT_ADAPTER_NOT_LOOPBACK' = 'ERR_AGENT_ADAPTER_DISCOVERY';
  let lastMessage = 'Timed out waiting for authenticated Agent Adapter health.';
  let sawProbeFailure = false;

  throwIfAborted(input.signal);
  while (true) {
    try {
      const discovery = deps.readDiscovery(input.config.agentAdapterConfigPath);
      if (discovery) {
        const parsed = new URL(discovery.url);
        if (!isLoopbackUrl(parsed)) {
          throw readinessError('ERR_AGENT_ADAPTER_NOT_LOOPBACK', 'Agent Adapter discovery URL is not a loopback HTTP origin.');
        }
        if (Number(parsed.port) !== input.config.agentAdapterPort) {
          throw readinessError('ERR_AGENT_ADAPTER_DISCOVERY', 'Agent Adapter discovery port does not match persisted configuration.');
        }
        const response = await fetchBounded(new URL('/v1/health', parsed.origin), {
          headers: {
            authorization: `Bearer ${discovery.secret}`,
            [AGENT_ADAPTER_PROTOCOL_HEADER]: String(AGENT_ADAPTER_PROTOCOL_VERSION),
          },
        }, boundedPositive(input.requestTimeoutMs, Math.min(timeoutMs, 2_000)), deps.fetch);
        if (response.status === 401 || response.status === 403) {
          throw readinessError('ERR_AGENT_ADAPTER_DISCOVERY', 'Agent Adapter authentication failed.');
        }
        if (!response.ok) throw readinessError('ERR_AGENT_ADAPTER_DISCOVERY', 'Agent Adapter health probe failed.');
        const body = await response.json() as unknown;
        const health = parseAgentAdapterHealth(body, input.identity.hostId);
        if (!health) {
          throw readinessError('ERR_AGENT_ADAPTER_DISCOVERY', 'Agent Adapter returned mismatched health evidence.');
        }
        return { discovery, health };
      }
    } catch (error) {
      const code = errorCode(error, 'ERR_AGENT_ADAPTER_DISCOVERY');
      lastCode = code === 'ERR_AGENT_ADAPTER_NOT_LOOPBACK' ? 'ERR_AGENT_ADAPTER_NOT_LOOPBACK' : 'ERR_AGENT_ADAPTER_DISCOVERY';
      lastMessage = errorMessage(error, lastMessage);
      sawProbeFailure = true;
    }
    throwIfAborted(input.signal);
    if (deps.clock.now() >= deadline) {
      throw readinessError(
        lastCode,
        sawProbeFailure ? lastMessage : 'Timed out waiting for authenticated Agent Adapter health.',
      );
    }
    await deps.clock.sleep(Math.min(intervalMs, Math.max(1, deadline - deps.clock.now())));
  }
}

function isLoopbackUrl(url: URL): boolean {
  const hostname = url.hostname.toLowerCase();
  return url.protocol === 'http:' && !url.username && !url.password && !url.search && !url.hash
    && (url.pathname === '/' || url.pathname === '')
    && (hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1');
}
