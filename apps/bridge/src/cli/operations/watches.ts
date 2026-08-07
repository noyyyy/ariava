import type { HostPlatform, LinkedWatchProjection } from '@ariava/protocol';
import { createHostEncryptionBinding, HostIdentityError, type HostIdentity } from '../../identity';
import { probeHostPlatform } from '../../host-platform';
import { RelayClient } from '../../relay-client';
import { loadResolvedProfileConfig, type AriavaProfileCliContext } from '../context';

export type WatchesProfileInput =
  | { action: 'list' }
  | { action: 'remove'; watchDeviceId: string };

export type WatchesProfileResult =
  | { action: 'list'; watches: LinkedWatchProjection[] }
  | { action: 'remove'; watchDeviceId: string };

export interface WatchesProfileRelay {
  enrollHost(input: {
    hostId: string;
    keyId: string;
    algorithm: HostIdentity['algorithm'];
    publicKey: string;
    encryptionBinding: Awaited<ReturnType<typeof createHostEncryptionBinding>>;
    hostName: string;
    platform: HostPlatform;
    bridgeVersion: string;
  }): Promise<unknown>;
  listWatches(): Promise<{ watches: LinkedWatchProjection[] }>;
  removeWatch(watchDeviceId: string): Promise<{ ok: true }>;
}

export interface WatchesProfileDependencies {
  bridgeVersion: string;
  createHostBinding: typeof createHostEncryptionBinding;
  createRelay(relayBaseUrl: string, identity: HostIdentity): WatchesProfileRelay;
}

export function createDefaultWatchesProfileDependencies(bridgeVersion: string): WatchesProfileDependencies {
  return {
    bridgeVersion,
    createHostBinding: createHostEncryptionBinding,
    createRelay: (relayBaseUrl, identity) => new RelayClient({
      baseUrl: relayBaseUrl,
      signer: identity.signer,
    }),
  };
}

export async function watchesProfile(
  context: AriavaProfileCliContext,
  input: WatchesProfileInput,
  dependencies: WatchesProfileDependencies,
): Promise<WatchesProfileResult> {
  context.validation.descriptor();
  const { resolved, resources } = loadResolvedProfileConfig(context);
  const identity = await context.identity.create(resources, context.platform).load();
  if (!identity) {
    const message = context.profile.id === 'dev'
      ? `Dev profile is not initialized at ${context.profile.resources.configPath}; run npm run dev:cli -- init first`
      : 'Host identity is not initialized; run `ariava init`.';
    throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', message);
  }
  const encryptionIdentity = context.encryptionIdentity
    .create(resources, context.platform)
    .loadOrCreate(identity.hostId);
  const relay = dependencies.createRelay(resolved.relayBaseUrl, identity);
  await relay.enrollHost({
    hostId: identity.hostId,
    keyId: identity.keyId,
    algorithm: identity.algorithm,
    publicKey: identity.publicKey,
    encryptionBinding: await dependencies.createHostBinding(identity, encryptionIdentity),
    hostName: resolved.hostName,
    platform: probeHostPlatform(context.platform),
    bridgeVersion: dependencies.bridgeVersion,
  });
  if (input.action === 'list') {
    const result = await relay.listWatches();
    return { action: 'list', watches: result.watches };
  }
  await relay.removeWatch(input.watchDeviceId);
  return { action: 'remove', watchDeviceId: input.watchDeviceId };
}
