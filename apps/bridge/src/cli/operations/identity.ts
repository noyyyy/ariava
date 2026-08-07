import {
  enrollCurrentIdentity,
  inspectPublicIdentity,
  publicIdentityMetadata,
  resetHostIdentity,
  rotateHostIdentity,
  HostIdentityError,
  type HostEncryptionIdentity,
  type HostIdentity,
  type HostIdentityInspection,
  type HostIdentityStore,
} from '../../identity';
import type { HostPlatform, KeyRotationResponse } from '@ariava/protocol';
import { probeHostPlatform } from '../../host-platform';
import { buildProfileInitializedConfig } from './initialize';
import { loadResolvedProfileConfig, type AriavaProfileCliContext } from '../context';

export async function inspectProfileIdentity(
  context: AriavaProfileCliContext,
): Promise<HostIdentityInspection> {
  context.validation.descriptor();
  const { resources } = loadResolvedProfileConfig(context);
  return inspectPublicIdentity(context.identity.create(resources, context.platform));
}

export interface ProfileIdentityRotationDependencies {
  rotate(store: HostIdentityStore, relayBaseUrl: string): Promise<KeyRotationResponse>;
}

const defaultRotationDependencies: ProfileIdentityRotationDependencies = {
  rotate: rotateHostIdentity,
};

export async function rotateProfileIdentity(
  context: AriavaProfileCliContext,
  dependencies: ProfileIdentityRotationDependencies = defaultRotationDependencies,
): Promise<KeyRotationResponse> {
  context.validation.descriptor();
  const { fileConfig, resolved, resources } = loadResolvedProfileConfig(context);
  const store = context.identity.create(resources, context.platform);
  const result = await dependencies.rotate(store, resolved.relayBaseUrl);
  const identity = await store.load();
  if (!identity) throw new HostIdentityError('ERR_IDENTITY_MISSING', 'Rotated identity could not be loaded');
  saveProfileConfig(context, { ...fileConfig, identity: publicIdentityMetadata(identity) });
  return result;
}

export interface ProfileIdentityResetDependencies {
  bridgeVersion: string;
  reset(store: HostIdentityStore, relayBaseUrl: string): Promise<{
    identity: HostIdentity;
    revokedOldIdentity: boolean;
    warning?: string;
  }>;
  enroll(
    relayBaseUrl: string,
    identity: HostIdentity,
    metadata: { hostName: string; platform: HostPlatform; bridgeVersion: string },
    encryptionIdentity: HostEncryptionIdentity,
  ): Promise<void>;
}

export interface ProfileIdentityResetResult {
  hostId: string;
  keyId: string;
  revokedOldIdentity: boolean;
  links: [];
  warning?: string;
}

export async function resetProfileIdentity(
  context: AriavaProfileCliContext,
  dependencies: ProfileIdentityResetDependencies,
): Promise<ProfileIdentityResetResult> {
  context.validation.descriptor();
  const loaded = loadResolvedProfileConfig(context);
  const baseConfig = buildProfileInitializedConfig(context, loaded.fileConfig);
  const resolved = { ...loaded.resolved, ...baseConfig };
  const resources = context.validation.resolved(resolved);
  const store = context.identity.create(resources, context.platform);
  const result = await dependencies.reset(store, resolved.relayBaseUrl);
  const encryptionIdentity = context.encryptionIdentity
    .create(resources, context.platform)
    .replaceForReset(result.identity.hostId);
  const config = {
    ...baseConfig,
    identity: publicIdentityMetadata(result.identity),
  };
  saveProfileConfig(context, config);
  await dependencies.enroll(
    resolved.relayBaseUrl,
    result.identity,
    {
      hostName: resolved.hostName,
      platform: probeHostPlatform(context.platform),
      bridgeVersion: dependencies.bridgeVersion,
    },
    encryptionIdentity,
  );
  return {
    hostId: result.identity.hostId,
    keyId: result.identity.keyId,
    revokedOldIdentity: result.revokedOldIdentity,
    links: [],
    ...(result.warning ? { warning: result.warning } : {}),
  };
}

export function createDefaultProfileIdentityResetDependencies(
  bridgeVersion: string,
): ProfileIdentityResetDependencies {
  return {
    bridgeVersion,
    reset: resetHostIdentity,
    enroll: enrollCurrentIdentity,
  };
}

function saveProfileConfig(context: AriavaProfileCliContext, config: Parameters<AriavaProfileCliContext['config']['save']>[0]): void {
  context.access?.('filesystemWrites', context.profile.resources.configPath);
  context.config.save(config, context.profile.resources.configPath);
}
