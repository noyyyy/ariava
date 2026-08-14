import { deriveEntityIdentity, isCanonicalTimestamp, type HostPlatform } from '@ariava/protocol';
import { HostIdentityError } from './errors';
import type { HostIdentity, HostIdentityInspection, HostIdentityMetadata, HostIdentityStore } from './types';
import { createHostEncryptionBinding, type HostEncryptionIdentity } from './host-encryption-key';
import { RelayClient, RelayClientError } from '../relay-client';

export function publicIdentityMetadata(identity: HostIdentity): HostIdentityMetadata {
  const { signer: _signer, ...metadata } = identity;
  return metadata;
}

export async function ensureFirstRunIdentity(store: HostIdentityStore): Promise<{ identity: HostIdentity; created: boolean }> {
  const inspection = await store.inspect();
  if (inspection.status === 'not-initialized') return { identity: await store.createFirstRun(), created: true };
  if (inspection.status !== 'ready') throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'Host identity evidence requires explicit reset');
  const identity = await store.load();
  if (!identity) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not initialized');
  return { identity, created: false };
}

export async function inspectPublicIdentity(store: HostIdentityStore): Promise<HostIdentityInspection> { return store.inspect(); }

export interface HostMetadataContext { hostName: string; platform: HostPlatform; bridgeVersion: string; }

export async function enrollCurrentIdentity(relayBaseUrl: string, identity: HostIdentity, metadata: HostMetadataContext, encryptionIdentity?: HostEncryptionIdentity): Promise<void> {
  await assertCanonicalIdentity(identity);
  const result = await new RelayClient({ baseUrl: relayBaseUrl, signer: identity.signer }).enrollHost({
    hostId: identity.hostId, keyId: identity.keyId, algorithm: identity.algorithm, publicKey: identity.publicKey,
    ...metadata, ...(encryptionIdentity ? { encryptionBinding: await createHostEncryptionBinding(identity, encryptionIdentity) } : {}),
  });
  if (!isExactEnrollmentResponse(result, identity, metadata)) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Relay returned a malformed Host enrollment result');
  }
}

export async function revokeHostIdentityForReset(identity: HostIdentity, relayBaseUrl: string): Promise<'revoked' | 'identity-already-revoked'> {
  await assertCanonicalIdentity(identity);
  try {
    const result = await new RelayClient({ baseUrl: relayBaseUrl, signer: identity.signer }).revokeIdentity();
    if (!isExactRecord(result, ['entityId', 'status', 'revokedAt'])
      || result.entityId !== identity.hostId || result.status !== 'revoked' || !isCanonicalTimestamp(result.revokedAt)) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Relay returned a malformed Host identity revoke result');
    }
    return 'revoked';
  } catch (error) {
    if (error instanceof RelayClientError && error.status === 401 && isConclusiveRevoked(error.body, identity)) return 'identity-already-revoked';
    throw error;
  }
}

export async function replaceHostIdentityAfterRevoke(store: HostIdentityStore, operationId?: string): Promise<HostIdentity> {
  return store.resetAfterExplicitConfirmation(operationId);
}

function isConclusiveRevoked(body: unknown, identity: HostIdentity): boolean {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.getPrototypeOf(body) !== Object.prototype) return false;
  const record = body as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(',');
  return (keys === 'code' && record.code === 'identity_revoked')
    || (keys === 'code,entityId,keyId' && record.code === 'unknown_or_revoked_key'
      && record.entityId === identity.hostId && record.keyId === identity.keyId);
}

function isExactEnrollmentResponse(value: unknown, identity: HostIdentity, metadata: HostMetadataContext): boolean {
  if (!isExactRecord(value, ['host'])) return false;
  const host = value.host;
  if (!isExactRecord(host, [
    'hostId', 'hostName', 'platform', 'bridgeVersion', 'registeredAt', 'lastSeenAt', 'bridgeStatus', 'status',
  ])) return false;
  return host.hostId === identity.hostId && host.hostName === metadata.hostName && host.platform === metadata.platform
    && host.bridgeVersion === metadata.bridgeVersion && isCanonicalTimestamp(host.registeredAt)
    && isCanonicalTimestamp(host.lastSeenAt) && ['online', 'offline', 'degraded'].includes(host.bridgeStatus as string)
    && host.status === 'active';
}

async function assertCanonicalIdentity(identity: HostIdentity): Promise<void> {
  const derived = await deriveEntityIdentity('host', identity.publicKey);
  if (identity.algorithm !== 'Ed25519' || identity.publicKeyFingerprint !== derived.fingerprint
    || identity.hostId !== derived.entityId || identity.keyId !== derived.keyId
    || identity.signer.entityId !== derived.entityId || identity.signer.keyId !== derived.keyId) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity is not canonical');
  }
}

function isExactRecord(
  value: unknown, required: readonly string[], optional: readonly string[] = [],
): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const keys = Object.keys(value);
  return required.every((key) => keys.includes(key))
    && keys.every((key) => required.includes(key) || optional.includes(key));
}
