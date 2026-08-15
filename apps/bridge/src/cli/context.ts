import { withHostIdentityOperationLock, type HostIdentityOperationLease } from './operations/host-identity-operation-lock';
import { unmanagedHostDomainResetLifecycle, type HostDomainResetLifecycleAdapter } from './operations/host-domain-reset';
import { createRuntimeHostReplacementSpoolKeyStore, type HostReplacementSpoolKeyStore } from '../e2e/local-spool';
import { acquireRuntimeCoordinator, type RuntimeCoordinator } from '../runtime-lock';
import {
  assertProfileDescriptorForEffects,
  assertSelectedProfileResourcesForEffects,
  type AriavaProfileDescriptor,
} from './profile';
import {
  resolveProfileUserConfig,
  type AriavaUserConfig,
  type ResolvedAriavaConfig,
} from '../host-manager/config';
import {
  createRuntimeHostEncryptionIdentityStore,
  createRuntimeHostIdentityStore,
  type HostEncryptionIdentity,
  type HostEncryptionIdentityStore,
  type HostIdentity,
  type HostIdentityStore,
} from '../identity';
import type { AriavaCliOutput } from './output';
import { AriavaCliError } from '../host-manager/service/errors';

export interface ProfileConfigMutationPolicy {
  assertSetAllowed(key: string): asserts key is keyof AriavaUserConfig;
}

const COMMON_MUTABLE_CONFIG_KEYS = new Set<keyof AriavaUserConfig>([
  'relayBaseUrl',
  'hostName',
  'agentAdapterSecret',
  'pollIntervalMs',
]);

const DEFAULT_MUTABLE_RESOURCE_KEYS = new Set<keyof AriavaUserConfig>([
  'statePath',
  'agentAdapterConfigPath',
  'agentAdapterPort',
]);

function createProfileConfigMutationPolicy(
  profileId: AriavaProfileDescriptor['id'],
): ProfileConfigMutationPolicy {
  return {
    assertSetAllowed(key): asserts key is keyof AriavaUserConfig {
      const configKey = key as keyof AriavaUserConfig;
      const allowed = COMMON_MUTABLE_CONFIG_KEYS.has(configKey)
        || (profileId === 'default' && DEFAULT_MUTABLE_RESOURCE_KEYS.has(configKey));
      if (!allowed) {
        throw new AriavaCliError(
          'ERR_IDENTITY_MANAGED_CONFIG',
          `${key} is managed by the profile or identity subsystem and cannot be set manually.`,
        );
      }
    },
  };
}

export interface AriavaCliExecutionOptions {
  json: boolean;
}

export interface AriavaCliAdapter {
  execute(argv: string[], options: AriavaCliExecutionOptions): Promise<number>;
}

export interface AriavaLifecycleAdapter extends AriavaCliAdapter {}

export interface AriavaCliCommandSuccess {
  envelope: {
    ok: boolean;
    code: string;
    message: string;
    data: unknown;
  };
  human?: string;
  exitCode?: number;
}

export interface AriavaSharedCommandAdapter {
  execute(argv: string[], options: AriavaCliExecutionOptions): Promise<AriavaCliCommandSuccess>;
}

export interface AriavaCliApplicationContext {
  profileId: AriavaProfileDescriptor['id'];
  profile(): AriavaProfileDescriptor;
  preflight?(argv: readonly string[]): void;
  validateDescriptor?(argv: readonly string[]): void;
  lifecycle: AriavaLifecycleAdapter;
  legacy: AriavaCliAdapter;
  shared: AriavaSharedCommandAdapter;
  output: AriavaCliOutput;
  version(): string;
  helpData?(): Record<string, unknown>;
}

export type ProfileAccessKind =
  | 'filesystemReads'
  | 'filesystemWrites'
  | 'keychainProbes'
  | 'keychainReads'
  | 'keychainWrites'
  | 'keychainDeletes'
  | 'relaySigners'
  | 'relayRequests'
  | 'childSpawns'
  | 'serviceRunnerCalls';

export interface ProfileConfigBoundary {
  load(path: string): AriavaUserConfig;
  save(config: AriavaUserConfig, path: string): void;
}

export interface ProfileIdentityFactory {
  create(resources: ResolvedProfileResources, platform: NodeJS.Platform | string): HostIdentityStore;
}

export interface ProfileEncryptionIdentityFactory {
  create(resources: ResolvedProfileResources, platform: NodeJS.Platform | string): HostEncryptionIdentityStore;
}

export interface ProfileLinkKeyringFactory {
  create(resources: ResolvedProfileResources, identity: HostEncryptionIdentity): unknown;
}

export interface ProfileRelayFactory {
  create(config: ResolvedAriavaConfig, identity: HostIdentity): unknown;
}

export type ResolvedProfileResources = ReturnType<AriavaProfileDescriptor['resolveResources']>;

export interface ProfileRuntimeCoordinatorFactory {
  acquire(resources: ResolvedProfileResources): RuntimeCoordinator;
}

export interface ProfileHostReplacementSpoolKeyFactory {
  create(resources: ResolvedProfileResources, platform: NodeJS.Platform | string): HostReplacementSpoolKeyStore;
}

export interface ProfileHostIdentityOperationLock {
  run<T>(resources: ResolvedProfileResources, operation: (lease: HostIdentityOperationLease) => Promise<T>): Promise<T>;
}

export interface AriavaProfileCliContext {
  profile: AriavaProfileDescriptor;
  platform: NodeJS.Platform | string;
  hostName(): string;
  generateSecret(): string;
  environment: NodeJS.ProcessEnv;
  allowProductionEnvironmentDefaults: boolean;
  saveBaseBeforeIdentity: boolean;
  config: ProfileConfigBoundary;
  configMutation: ProfileConfigMutationPolicy;
  resolveForDisplay?(fileConfig: AriavaUserConfig): ResolvedAriavaConfig;
  identity: ProfileIdentityFactory;
  encryptionIdentity: ProfileEncryptionIdentityFactory;
  linkKeyring?: ProfileLinkKeyringFactory;
  relay?: ProfileRelayFactory;
  runtimeCoordinator: ProfileRuntimeCoordinatorFactory;
  hostReplacementSpoolKey: ProfileHostReplacementSpoolKeyFactory;
  hostDomainResetLifecycle: HostDomainResetLifecycleAdapter;
  hostIdentityOperationLock: ProfileHostIdentityOperationLock;
  validation: {
    descriptor(): void;
    selected(): void;
    resolved(config: ResolvedAriavaConfig): ResolvedProfileResources;
  };
  access?(kind: ProfileAccessKind, path?: string): void;
}

export interface CreateProfileCliContextInput {
  profile: AriavaProfileDescriptor;
  platform: NodeJS.Platform | string;
  hostName(): string;
  generateSecret(): string;
  environment?: NodeJS.ProcessEnv;
  allowProductionEnvironmentDefaults?: boolean;
  saveBaseBeforeIdentity?: boolean;
  config: ProfileConfigBoundary;
  configMutation?: ProfileConfigMutationPolicy;
  resolveForDisplay?(fileConfig: AriavaUserConfig): ResolvedAriavaConfig;
  identity?: ProfileIdentityFactory;
  encryptionIdentity?: ProfileEncryptionIdentityFactory;
  linkKeyring?: ProfileLinkKeyringFactory;
  relay?: ProfileRelayFactory;
  runtimeCoordinator?: ProfileRuntimeCoordinatorFactory;
  hostReplacementSpoolKey?: ProfileHostReplacementSpoolKeyFactory;
  hostDomainResetLifecycle?: HostDomainResetLifecycleAdapter;
  hostIdentityOperationLock?: ProfileHostIdentityOperationLock;
  observeValidation?(phase: 'descriptor' | 'selected' | 'resolved'): void;
  observeFilesystemProbe?(path: string): void;
  access?(kind: ProfileAccessKind, path?: string): void;
}

export function createProfileCliContext(input: CreateProfileCliContextInput): AriavaProfileCliContext {
  return {
    profile: input.profile,
    platform: input.platform,
    hostName: input.hostName,
    generateSecret: input.generateSecret,
    environment: input.environment ?? {},
    allowProductionEnvironmentDefaults: input.allowProductionEnvironmentDefaults ?? input.profile.id === 'default',
    saveBaseBeforeIdentity: input.saveBaseBeforeIdentity ?? input.profile.id === 'default',
    config: input.config,
    configMutation: input.configMutation ?? createProfileConfigMutationPolicy(input.profile.id),
    resolveForDisplay: input.resolveForDisplay,
    identity: input.identity ?? {
      create: (resources, platform) => createRuntimeHostIdentityStore(
        resources.identityMetadataPath,
        platform,
        resources.identityProfile,
      ),
    },
    encryptionIdentity: input.encryptionIdentity ?? {
      create: (resources, platform) => createRuntimeHostEncryptionIdentityStore(
        resources.identityMetadataPath,
        platform,
        resources.identityProfile,
      ),
    },
    linkKeyring: input.linkKeyring,
    relay: input.relay,
    runtimeCoordinator: input.runtimeCoordinator ?? {
      acquire: (resources) => acquireRuntimeCoordinator(resources.statePath, resources.encryptedSpoolPath),
    },
    hostReplacementSpoolKey: input.hostReplacementSpoolKey ?? {
      create: (resources, platform) => createRuntimeHostReplacementSpoolKeyStore(
        resources.identityMetadataPath, platform,
      ),
    },
    hostDomainResetLifecycle: input.hostDomainResetLifecycle ?? unmanagedHostDomainResetLifecycle(),
    hostIdentityOperationLock: input.hostIdentityOperationLock ?? {
      run: (resources, operation) => withHostIdentityOperationLock(resources, operation),
    },
    validation: {
      descriptor: () => {
        input.observeValidation?.('descriptor');
        assertProfileDescriptorForEffects(input.profile);
      },
      selected: () => {
        input.observeValidation?.('selected');
        assertSelectedProfileResourcesForEffects(input.profile, input.observeFilesystemProbe);
      },
      resolved: (config) => {
        input.observeValidation?.('resolved');
        return input.profile.resolveResources(config, input.observeFilesystemProbe);
      },
    },
    access: input.access,
  };
}

export function loadResolvedProfileConfig(context: AriavaProfileCliContext): {
  fileConfig: AriavaUserConfig;
  resolved: ResolvedAriavaConfig;
  resources: ResolvedProfileResources;
} {
  context.validation.selected();
  context.access?.('filesystemReads', context.profile.resources.configPath);
  const fileConfig = context.config.load(context.profile.resources.configPath);
  const resolved = resolveProfileUserConfig(context.profile, fileConfig);
  const resources = context.validation.resolved(resolved);
  return { fileConfig, resolved, resources };
}
