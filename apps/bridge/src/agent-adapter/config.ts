import {
  type AgentAdapterDiscovery,
  validateAgentAdapterDiscovery as validateProtocolAgentAdapterDiscovery,
} from '@ariava/protocol';
import { pathHasFilesystemEvidence, readSecureJson, writeSecureJson } from '../host-manager/secure-files';

/** Exact six-key discovery evidence shared with the producer (spec 08-16 §6). */
export type AgentAdapterDiscoveryFile = AgentAdapterDiscovery;

export function readAgentAdapterConfig(path: string, expectedPort?: number): AgentAdapterDiscoveryFile | null {
  if (!pathHasFilesystemEvidence(path)) {
    return null;
  }

  const parsed = readSecureJson<unknown>(path);
  return validateAgentAdapterDiscovery(parsed, expectedPort);
}

export function writeAgentAdapterConfig(path: string, config: AgentAdapterDiscoveryFile): void {
  writeSecureJson(path, config);
}

export function validateAgentAdapterDiscovery(
  value: unknown,
  expectedPort?: number,
): AgentAdapterDiscoveryFile {
  const result = validateProtocolAgentAdapterDiscovery(value);
  if (!result.success) {
    throw new Error('Agent Adapter discovery file is invalid');
  }
  const discovery = result.value!;

  if (expectedPort !== undefined) {
    // discovery.url is already a canonical loopback origin; only the port can disagree.
    const url = new URL(discovery.url);
    if (Number(url.port) !== expectedPort) {
      throw new Error('Agent Adapter discovery URL port is invalid');
    }
  }
  return discovery;
}
