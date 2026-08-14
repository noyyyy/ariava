import type { EncryptionKeyBindingV1, HostPlatform, LinkedWatchProjection } from '@ariava/protocol';
import { createHostEncryptionBinding, HostIdentityError, type HostIdentity } from '../../identity';
import { LocalLinkKeyring } from '../../e2e/link-keyring';
import { probeHostPlatform } from '../../host-platform';
import { RelayClient } from '../../relay-client';
import {
  loadResolvedProfileConfig,
  type AriavaProfileCliContext,
  type ResolvedProfileResources,
} from '../context';

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
  removeWatch(watchDeviceId: string, linkGeneration: number): Promise<{ ok: true }>;
}

export interface WatchesProfileDependencies {
  bridgeVersion: string;
  createHostBinding: typeof createHostEncryptionBinding;
  createRelay(relayBaseUrl: string, identity: HostIdentity): WatchesProfileRelay;
  createKeyring(
    resources: ResolvedProfileResources,
    identities: ReturnType<AriavaProfileCliContext['encryptionIdentity']['create']>,
    migrationContext: { currentHostIdentity: HostIdentity; signedCurrentHostBinding: EncryptionKeyBindingV1 },
  ): Pick<LocalLinkKeyring, 'revokeWatchGeneration'>;
}

export function createDefaultWatchesProfileDependencies(bridgeVersion: string): WatchesProfileDependencies {
  return {
    bridgeVersion,
    createHostBinding: createHostEncryptionBinding,
    createRelay: (relayBaseUrl, identity) => new RelayClient({
      baseUrl: relayBaseUrl,
      signer: identity.signer,
    }),
    createKeyring: (resources, identities, migrationContext) => new LocalLinkKeyring(
      resources.linkKeyringPath, identities, migrationContext,
    ),
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
  const encryptionStore = context.encryptionIdentity.create(resources, context.platform);
  const encryptionIdentity = encryptionStore.loadOrCreate(identity.hostId);
  const hostBinding = await dependencies.createHostBinding(identity, encryptionIdentity);
  const relay = dependencies.createRelay(resolved.relayBaseUrl, identity);
  await relay.enrollHost({
    hostId: identity.hostId,
    keyId: identity.keyId,
    algorithm: identity.algorithm,
    publicKey: identity.publicKey,
    encryptionBinding: hostBinding,
    hostName: resolved.hostName,
    platform: probeHostPlatform(context.platform),
    bridgeVersion: dependencies.bridgeVersion,
  });
  if (input.action === 'list') {
    const result = await relay.listWatches();
    return { action: 'list', watches: result.watches };
  }
  const linked = await relay.listWatches();
  const selected = linked.watches.find((watch) => watch.watchDeviceId === input.watchDeviceId);
  if (!selected) throw new TypeError('Selected Watch is not linked to this Host');
  const keyring = dependencies.createKeyring(resources, encryptionStore, {
    currentHostIdentity: identity,
    signedCurrentHostBinding: hostBinding,
  });
  const unlink = await relay.removeWatch(input.watchDeviceId, selected.linkGeneration);
  if (!isExactSuccessfulUnlink(unlink)) {
    throw new TypeError('Relay returned a malformed Watch unlink response');
  }
  keyring.revokeWatchGeneration(input.watchDeviceId, selected.linkGeneration);
  return { action: 'remove', watchDeviceId: input.watchDeviceId };
}

function isExactSuccessfulUnlink(value: unknown): value is { ok: true } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null)
    && Reflect.ownKeys(value).length === 1
    && Object.hasOwn(value, 'ok')
    && (value as { ok?: unknown }).ok === true;
}
