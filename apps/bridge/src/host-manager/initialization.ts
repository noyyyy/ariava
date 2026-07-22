import { hostname } from 'node:os';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  ensureFirstRunIdentity,
  publicIdentityMetadata,
  type HostIdentityStore,
} from '../identity';
import {
  ARIAVA_AGENT_ADAPTER_CONFIG_PATH,
  ARIAVA_HOST_IDENTITY_PATH,
  ARIAVA_STATE_PATH,
} from './paths';
import {
  ARIAVA_PRODUCTION_RELAY_BASE_URL,
  type AriavaUserConfig,
} from './config';

export interface HostInitializationOptions {
  relayBaseUrl?: string;
}

export interface HostInitializationDependencies {
  loadUserConfig(): AriavaUserConfig;
  saveUserConfig(config: AriavaUserConfig): void;
  createIdentityStore(identityPath: string): HostIdentityStore;
  hostName(): string;
  generateSecret(): string;
  environment: NodeJS.ProcessEnv;
}

export interface HostInitializationResult {
  config: AriavaUserConfig;
  identityCreated: boolean;
}

export function buildInitializedConfig(
  existing: AriavaUserConfig,
  options: HostInitializationOptions = {},
  dependencies: Pick<HostInitializationDependencies, 'hostName' | 'generateSecret' | 'environment'> = {
    hostName: hostname,
    generateSecret: () => randomBytes(32).toString('hex'),
    environment: process.env,
  },
): AriavaUserConfig {
  const persistedRelay = existing.relayBaseUrl?.trim();
  const explicitRelay = options.relayBaseUrl?.trim();
  return {
    ...existing,
    relayBaseUrl: persistedRelay || explicitRelay || ARIAVA_PRODUCTION_RELAY_BASE_URL,
    hostName: existing.hostName ?? dependencies.environment.ARIAVA_HOST_NAME?.trim() ?? dependencies.hostName(),
    agentAdapterPort: existing.agentAdapterPort ?? 7272,
    agentAdapterSecret: existing.agentAdapterSecret ?? dependencies.generateSecret(),
    identityPath: existing.identityPath ?? resolve(dependencies.environment.ARIAVA_HOST_IDENTITY_PATH ?? ARIAVA_HOST_IDENTITY_PATH),
    agentAdapterConfigPath: resolve(existing.agentAdapterConfigPath ?? ARIAVA_AGENT_ADAPTER_CONFIG_PATH),
    statePath: resolve(existing.statePath ?? ARIAVA_STATE_PATH),
  };
}

/**
 * Initializes production Host state without recursively invoking the CLI.
 * The caller must establish platform support and any onboarding locks first.
 */
export async function initializeHost(
  options: HostInitializationOptions,
  dependencies: HostInitializationDependencies,
): Promise<HostInitializationResult> {
  const base = buildInitializedConfig(dependencies.loadUserConfig(), options, dependencies);
  dependencies.saveUserConfig(base);
  const identityPath = base.identityPath;
  if (!identityPath) throw new Error('Host identity path was not initialized');
  const ensured = await ensureFirstRunIdentity(dependencies.createIdentityStore(identityPath));
  const config = { ...base, identity: publicIdentityMetadata(ensured.identity) };
  dependencies.saveUserConfig(config);
  return { config, identityCreated: ensured.created };
}
