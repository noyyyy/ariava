import { hostname } from 'node:os';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  createRuntimeHostEncryptionIdentityStore,
  type HostEncryptionIdentityStore,
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
import { createDefaultProfile } from '../cli/profiles/default';
import { createProfileCliContext } from '../cli/context';
import { initializeProfile } from '../cli/operations/initialize';
import type { AriavaProfileDescriptor } from '../cli/profile';

export interface HostInitializationOptions {
  relayBaseUrl?: string;
  /** Honor ARIAVA_HOST_IDENTITY_PATH when present; production onboarding disables this. */
  useEnvironmentIdentityPath?: boolean;
}

export interface HostInitializationDependencies {
  loadUserConfig(): AriavaUserConfig;
  saveUserConfig(config: AriavaUserConfig): void;
  createIdentityStore(identityPath: string): HostIdentityStore;
  createEncryptionIdentityStore?(identityPath: string): HostEncryptionIdentityStore;
  hostName(): string;
  generateSecret(): string;
  environment: NodeJS.ProcessEnv;
  profile?: AriavaProfileDescriptor;
  platform?: NodeJS.Platform | string;
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
    identityPath: existing.identityPath ?? resolve(
      options.useEnvironmentIdentityPath === false
        ? ARIAVA_HOST_IDENTITY_PATH
        : dependencies.environment.ARIAVA_HOST_IDENTITY_PATH ?? ARIAVA_HOST_IDENTITY_PATH,
    ),
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
  const profile = dependencies.profile ?? createDefaultProfile();
  const result = await initializeProfile(createProfileCliContext({
    profile,
    platform: dependencies.platform ?? process.platform,
    hostName: dependencies.hostName,
    generateSecret: dependencies.generateSecret,
    environment: dependencies.environment,
    allowProductionEnvironmentDefaults: profile.id === 'default',
    saveBaseBeforeIdentity: profile.id === 'default',
    config: {
      load: () => dependencies.loadUserConfig(),
      save: (config) => dependencies.saveUserConfig(config),
    },
    identity: {
      create: (resources) => dependencies.createIdentityStore(resources.identityMetadataPath),
    },
    encryptionIdentity: {
      create: (resources) => dependencies.createEncryptionIdentityStore
        ? dependencies.createEncryptionIdentityStore(resources.identityMetadataPath)
        : createRuntimeHostEncryptionIdentityStore(
          resources.identityMetadataPath,
          dependencies.platform ?? process.platform,
          resources.identityProfile,
        ),
    },
  }), options);
  return { config: result.config, identityCreated: result.identityCreated };
}
