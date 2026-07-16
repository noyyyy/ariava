import { pathHasFilesystemEvidence, readSecureJson, writeSecureJson } from '../host-manager/secure-files';

export interface AgentAdapterDiscoveryFile {
  url: string;
  secret: string;
}

export function readAgentAdapterConfig(path: string): AgentAdapterDiscoveryFile | null {
  if (!pathHasFilesystemEvidence(path)) {
    return null;
  }

  const parsed = readSecureJson<unknown>(path);
  if (!isDiscoveryFile(parsed)) {
    throw new Error('Agent Adapter discovery file is invalid');
  }
  return parsed;
}

export function writeAgentAdapterConfig(path: string, config: AgentAdapterDiscoveryFile): void {
  writeSecureJson(path, config);
}

function isDiscoveryFile(value: unknown): value is AgentAdapterDiscoveryFile {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return typeof record.url === 'string' && typeof record.secret === 'string';
}
