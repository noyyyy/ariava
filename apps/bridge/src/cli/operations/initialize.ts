import type { HostIdentityInspection } from '../../identity';
import { ensureFirstRunIdentity, inspectPublicIdentity, publicIdentityMetadata } from '../../identity';
import type { AriavaUserConfig, ResolvedAriavaConfig } from '../../host-manager/config';
import { loadResolvedProfileConfig, type AriavaProfileCliContext } from '../context';

export interface ProfileInitializationOptions {
  relayBaseUrl?: string;
  useEnvironmentIdentityPath?: boolean;
}

export interface ProfileInitializationResult {
  config: AriavaUserConfig;
  resolved: ResolvedAriavaConfig;
  inspection: HostIdentityInspection;
  identityCreated: boolean;
}

export async function initializeProfile(
  context: AriavaProfileCliContext,
  options: ProfileInitializationOptions = {},
): Promise<ProfileInitializationResult> {
  context.validation.descriptor();
  const loaded = loadResolvedProfileConfig(context);
  const base = buildProfileInitializedConfig(context, loaded.fileConfig, options);
  const { resolved, resources } = resolveInitializedResources(context, base);

  if (context.saveBaseBeforeIdentity) saveConfig(context, base);

  const store = context.identity.create(resources, context.platform);
  const ensured = await ensureFirstRunIdentity(store);
  const config = { ...base, identity: publicIdentityMetadata(ensured.identity) };
  if (context.saveBaseBeforeIdentity || JSON.stringify(loaded.fileConfig) !== JSON.stringify(config)) {
    saveConfig(context, config);
  }
  context.encryptionIdentity.create(resources, context.platform).loadOrCreate(ensured.identity.hostId);
  const inspection = await inspectPublicIdentity(store);
  return { config, resolved, inspection, identityCreated: ensured.created };
}

export function buildProfileInitializedConfig(
  context: AriavaProfileCliContext,
  existing: AriavaUserConfig,
  options: ProfileInitializationOptions = {},
): AriavaUserConfig {
  const profile = context.profile;
  const resources = profile.resources;
  const persistedRelay = existing.relayBaseUrl?.trim();
  const explicitRelay = options.relayBaseUrl?.trim();
  const environmentHostName = context.allowProductionEnvironmentDefaults
    ? context.environment.ARIAVA_HOST_NAME?.trim()
    : undefined;
  const environmentIdentityPath = context.allowProductionEnvironmentDefaults
    && options.useEnvironmentIdentityPath !== false
    ? context.environment.ARIAVA_HOST_IDENTITY_PATH?.trim()
    : undefined;
  const identityPath = existing.identityPath
    ?? environmentIdentityPath
    ?? resources.identityMetadataPath;
  return {
    ...existing,
    relayBaseUrl: persistedRelay || explicitRelay || profile.defaultRelayBaseUrl,
    hostName: existing.hostName ?? environmentHostName ?? profile.defaultHostName(context.hostName()),
    agentAdapterPort: existing.agentAdapterPort ?? resources.agentAdapterPort,
    agentAdapterSecret: existing.agentAdapterSecret ?? context.generateSecret(),
    identityPath,
    agentAdapterConfigPath: existing.agentAdapterConfigPath ?? resources.agentAdapterConfigPath,
    statePath: existing.statePath ?? resources.statePath,
  };
}

function resolveInitializedResources(
  context: AriavaProfileCliContext,
  config: AriavaUserConfig,
): { resolved: ResolvedAriavaConfig; resources: ReturnType<AriavaProfileCliContext['validation']['resolved']> } {
  const profileResources = context.profile.resources;
  const resolved: ResolvedAriavaConfig = {
    ...config,
    relayBaseUrl: config.relayBaseUrl ?? context.profile.defaultRelayBaseUrl,
    hostName: config.hostName ?? '',
    agentAdapterPort: config.agentAdapterPort ?? profileResources.agentAdapterPort,
    agentAdapterConfigPath: config.agentAdapterConfigPath ?? profileResources.agentAdapterConfigPath,
    statePath: config.statePath ?? profileResources.statePath,
    identityPath: config.identityPath ?? profileResources.identityMetadataPath,
    configPath: profileResources.configPath,
    installPath: `${profileResources.root}/install.json`,
    logDir: `${profileResources.root}/logs`,
    stdoutLogPath: `${profileResources.root}/logs/bridge.stdout.log`,
    stderrLogPath: `${profileResources.root}/logs/bridge.stderr.log`,
    tmpDir: `${profileResources.root}/tmp`,
    environmentOverrides: [],
  };
  return { resolved, resources: context.validation.resolved(resolved) };
}

function saveConfig(context: AriavaProfileCliContext, config: AriavaUserConfig): void {
  context.access?.('filesystemWrites', context.profile.resources.configPath);
  context.config.save(config, context.profile.resources.configPath);
}
