import {
  base64UrlDecode,
  isBridgeStatus,
  isCanonicalTimestamp,
  isHostPlatform,
  normalizePairingCode,
  validateEncryptionKeyBindingV1,
  type BridgePairWatchResponse,
  type EncryptionKeyBindingV1,
  type E2EPendingLinkProjectionV1,
  type HostPlatform,
} from '@ariava/protocol';
import {
  createHostEncryptionBinding,
  enrollCurrentIdentity,
  HostIdentityError,
  type HostEncryptionIdentity,
  type HostIdentity,
} from '../../identity';
import { probeHostPlatform } from '../../host-platform';
import { LocalLinkKeyring, type HostActivationTransport } from '../../e2e/link-keyring';
import {
  runHostSafetyCodeActivation,
  type HostSafetyCodeActivationInput,
  type HostSafetyCodeActivationOutcome,
} from '../../e2e/host-safety-code-activation';
import { RelayClient } from '../../relay-client';
import { loadResolvedProfileConfig, type AriavaProfileCliContext, type ResolvedProfileResources } from '../context';
import { sanitizePairFailure } from '../failure';

export interface PairProfileInput {
  pairingCode: string;
  confirmMatch(): Promise<boolean>;
  write?(line: string): void;
  presentAccepted?(pairing: BridgePairWatchResponse): void;
  sleep?(ms: number): Promise<void>;
}

export type PairProfileResult = {
  status: 'paired' | 'cancelled';
  safetyCodeActivation: HostSafetyCodeActivationOutcome;
  pairing: BridgePairWatchResponse;
  messages: string[];
};

export interface PairProfileRelay extends HostActivationTransport {}

export interface PairProfileDependencies {
  bridgeVersion: string;
  normalizePairingCode(value: string): string;
  enroll(
    relayBaseUrl: string,
    identity: HostIdentity,
    metadata: { hostName: string; platform: HostPlatform; bridgeVersion: string },
    encryptionIdentity: HostEncryptionIdentity,
  ): Promise<void>;
  createRelay(relayBaseUrl: string, identity: HostIdentity): PairProfileRelay;
  pairWatch(relay: PairProfileRelay, pairingCode: string): Promise<BridgePairWatchResponse>;
  createKeyring(
    resources: ResolvedProfileResources,
    identities: ReturnType<AriavaProfileCliContext['encryptionIdentity']['create']>,
    migrationContext: { currentHostIdentity: HostIdentity; signedCurrentHostBinding: EncryptionKeyBindingV1 },
  ): LocalLinkKeyring;
  createHostBinding: typeof createHostEncryptionBinding;
  activate(input: HostSafetyCodeActivationInput): Promise<HostSafetyCodeActivationOutcome>;
}

export function createDefaultPairProfileDependencies(bridgeVersion: string): PairProfileDependencies {
  return {
    bridgeVersion,
    normalizePairingCode,
    enroll: enrollCurrentIdentity,
    createRelay: (relayBaseUrl, identity) => new RelayClient({ baseUrl: relayBaseUrl, signer: identity.signer }),
    pairWatch: (relay, pairingCode) => (relay as RelayClient).pairWatch(pairingCode),
    createKeyring: (resources, identities, migrationContext) => new LocalLinkKeyring(resources.linkKeyringPath, identities, migrationContext),
    createHostBinding: createHostEncryptionBinding,
    activate: runHostSafetyCodeActivation,
  };
}

export async function pairProfile(
  context: AriavaProfileCliContext,
  input: PairProfileInput,
  dependencies: PairProfileDependencies,
): Promise<PairProfileResult> {
  const pairingCode = dependencies.normalizePairingCode(input.pairingCode);
  context.validation.descriptor();
  const { resolved, resources } = loadResolvedProfileConfig(context);
  let identity: HostIdentity | null = null;
  try {
    identity = await context.identity.create(resources, context.platform).load();
    if (!identity) {
      const message = context.profile.id === 'dev'
        ? `Dev profile is not initialized at ${context.profile.resources.configPath}; run npm run dev:cli -- init first`
        : 'Host identity is not initialized; run `ariava init`.';
      throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', message);
    }
    const encryptionStore = context.encryptionIdentity.create(resources, context.platform);
    const encryptionIdentity = encryptionStore.loadOrCreate(identity.hostId);
    await dependencies.enroll(
      resolved.relayBaseUrl,
      identity,
      {
        hostName: resolved.hostName,
        platform: probeHostPlatform(context.platform),
        bridgeVersion: dependencies.bridgeVersion,
      },
      encryptionIdentity,
    );
    const relay = dependencies.createRelay(resolved.relayBaseUrl, identity);
    const pairing = await dependencies.pairWatch(relay, pairingCode);
    assertPairingResponse(pairing, identity);
    const messages: string[] = [];
    const write = (line: string) => {
      messages.push(line);
      input.write?.(line);
    };
    input.presentAccepted?.(pairing);
    const hostBinding = await dependencies.createHostBinding(identity, encryptionIdentity);
    const keyring = dependencies.createKeyring(resources, encryptionStore, {
      currentHostIdentity: identity,
      signedCurrentHostBinding: hostBinding,
    });
    const safetyCodeActivation = await dependencies.activate({
      projection: pairing.e2e,
      alreadyPaired: pairing.alreadyPaired,
      hostIdentity: encryptionIdentity,
      hostBinding,
      keyring,
      transport: relay,
      write,
      confirmMatch: input.confirmMatch,
      ...(input.sleep ? { sleep: input.sleep } : {}),
    });
    return {
      status: safetyCodeActivation === 'cancelled' ? 'cancelled' : 'paired',
      safetyCodeActivation,
      pairing,
      messages,
    };
  } catch (error) {
    throw sanitizePairFailure(error, [
      resolved.agentAdapterSecret ?? '',
      resolved.identity?.privateKeyStorage.account ?? '',
      identity?.privateKeyStorage.account ?? '',
    ]);
  }
}

function assertPairingResponse(pairing: BridgePairWatchResponse, identity: HostIdentity): void {
  if (!isRecord(pairing) || !isHostProjection(pairing.host)
    || !isWatchProjection(pairing.watchDevice) || !isHostWatchLink(pairing.link)
    || typeof pairing.alreadyPaired !== 'boolean'
    || (pairing.e2e !== undefined && !isPendingE2EProjection(pairing.e2e))) {
    throw new TypeError('Relay returned a malformed pairing response');
  }
  if (pairing.host.hostId !== identity.hostId || pairing.link.hostId !== identity.hostId) {
    throw new TypeError('Pairing response Host does not match the selected profile identity');
  }
  if (pairing.link.watchDeviceId !== pairing.watchDevice.watchDeviceId) {
    throw new TypeError('Pairing response Watch does not match the created link');
  }
  if (!pairing.watchDevice.selectedHostIds.includes(identity.hostId)) {
    throw new TypeError('Relay returned a malformed pairing response');
  }
  if (pairing.e2e && (pairing.e2e.hostId !== identity.hostId
    || pairing.e2e.watchDeviceId !== pairing.watchDevice.watchDeviceId
    || pairing.e2e.linkGeneration !== pairing.link.generation)) {
    throw new TypeError('Relay returned a malformed pairing response');
  }
}

function isHostProjection(value: unknown): value is BridgePairWatchResponse['host'] {
  if (!isRecord(value)) return false;
  return hasExactKeys(value, [
    'hostId', 'hostName', 'platform', 'bridgeVersion', 'registeredAt', 'lastSeenAt', 'bridgeStatus', 'status',
  ])
    && isEntityId(value.hostId, 'host')
    && isNonEmptyString(value.hostName)
    && isHostPlatform(value.platform)
    && isNonEmptyString(value.bridgeVersion)
    && isCanonicalTimestamp(value.registeredAt)
    && isCanonicalTimestamp(value.lastSeenAt)
    && isBridgeStatus(value.bridgeStatus)
    && value.status === 'active';
}

function isWatchProjection(value: unknown): value is BridgePairWatchResponse['watchDevice'] {
  if (!isRecord(value)) return false;
  return isEntityId(value.watchDeviceId, 'watch')
    && Array.isArray(value.selectedHostIds)
    && value.selectedHostIds.every((hostId) => isEntityId(hostId, 'host'))
    && isCanonicalTimestamp(value.registeredAt)
    && isCanonicalTimestamp(value.lastSeenAt)
    && value.pairingStatus === 'paired';
}

function isHostWatchLink(value: unknown): value is BridgePairWatchResponse['link'] {
  if (!isRecord(value) || !hasExactKeys(value, [
    'hostId', 'watchDeviceId', 'pairedAt', 'generation', 'updatedAt',
  ])) return false;
  return isEntityId(value.hostId, 'host')
    && isEntityId(value.watchDeviceId, 'watch')
    && isCanonicalTimestamp(value.pairedAt)
    && isPositiveInteger(value.generation)
    && isCanonicalTimestamp(value.updatedAt);
}

function isPendingE2EProjection(value: unknown): value is E2EPendingLinkProjectionV1 {
  if (!isRecord(value)) return false;
  return isNonEmptyString(value.linkId)
    && isEntityId(value.hostId, 'host')
    && isEntityId(value.watchDeviceId, 'watch')
    && isPositiveInteger(value.linkGeneration)
    && isPositiveInteger(value.epoch)
    && validateEncryptionKeyBindingV1(value.hostBinding)
    && value.hostBinding.entityType === 'host'
    && value.hostBinding.entityId === value.hostId
    && isEncoded(value.hostIdentityPublicKey, 32)
    && validateEncryptionKeyBindingV1(value.watchBinding)
    && value.watchBinding.entityType === 'watch'
    && value.watchBinding.entityId === value.watchDeviceId
    && isEncoded(value.watchIdentityPublicKey, 32)
    && isEncoded(value.transcriptDigest, 32)
    && isCanonicalTimestamp(value.confirmationExpiresAt)
    && (value.state === 'pending_confirmation' || value.state === 'confirmations_complete'
      || value.state === 'host_activated' || value.state === 'watch_activated');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && Boolean(value.trim());
}

function isEntityId(value: unknown, type: 'host' | 'watch'): value is string {
  return typeof value === 'string' && new RegExp(`^${type}_[A-Za-z0-9_-]{43}$`, 'u').test(value);
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function isEncoded(value: unknown, bytes: number): value is string {
  if (typeof value !== 'string') return false;
  try {
    base64UrlDecode(value, bytes);
    return true;
  } catch {
    return false;
  }
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}
