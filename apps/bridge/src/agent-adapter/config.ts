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
  return validateAgentAdapterDiscovery(parsed);
}

export function writeAgentAdapterConfig(path: string, config: AgentAdapterDiscoveryFile): void {
  writeSecureJson(path, config);
}

export function validateAgentAdapterDiscovery(
  value: unknown,
  expectedPort?: number,
): AgentAdapterDiscoveryFile {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Agent Adapter discovery file is invalid');
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const hasExpectedKeys = keys.length === 2 && keys.includes('url') && keys.includes('secret');
  if (!hasExpectedKeys
    || typeof record.url !== 'string'
    || typeof record.secret !== 'string'
    || record.secret.trim().length === 0) {
    throw new Error('Agent Adapter discovery file is invalid');
  }

  let url: URL;
  try {
    url = new URL(record.url);
  } catch {
    throw new Error('Agent Adapter discovery URL is invalid');
  }
  if (url.protocol !== 'http:' || url.username || url.password || url.search || url.hash
    || (url.pathname !== '/' && url.pathname !== '') || !isLoopbackHostname(url.hostname)) {
    throw new Error('Agent Adapter discovery URL must be an unauthenticated loopback HTTP origin');
  }
  const port = Number(url.port);
  if (!url.port || port < 1 || port > 65_535
    || (expectedPort !== undefined && port !== expectedPort)) {
    throw new Error('Agent Adapter discovery URL port is invalid');
  }
  return { url: url.origin, secret: record.secret };
}

export function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === '127.0.0.1' || normalized === '[::1]' || normalized === '::1';
}
