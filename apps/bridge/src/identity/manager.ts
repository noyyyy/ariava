import { randomUUID } from 'node:crypto';
import { isCanonicalTimestamp, type HostPlatform, type KeyRotationRequest, type KeyRotationResponse, type RotationPayload } from '@ariava/protocol';
import { HostIdentityError } from './errors';
import { generateHostRotationIdentity } from './host-identity';
import type { HostIdentity, HostIdentityInspection, HostIdentityMetadata, HostIdentityStore, PendingHostIdentity } from './types';
import { createHostEncryptionBinding, type HostEncryptionIdentity } from './host-encryption-key';
import { RelayClient, RelayClientError } from '../relay-client';

const encoder = new TextEncoder();

export function publicIdentityMetadata(identity: HostIdentity): HostIdentityMetadata {
  const { signer: _signer, ...metadata } = identity;
  return metadata;
}

export async function ensureFirstRunIdentity(store: HostIdentityStore): Promise<{ identity: HostIdentity; created: boolean }> {
  const inspection = await store.inspect();
  if (inspection.status === 'not-initialized') return { identity: await store.createFirstRun(), created: true };
  const identity = await store.load();
  if (!identity) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not initialized');
  return { identity, created: false };
}

export async function inspectPublicIdentity(store: HostIdentityStore): Promise<HostIdentityInspection> {
  return store.inspect();
}

export interface HostMetadataContext {
  hostName: string;
  platform: HostPlatform;
  bridgeVersion: string;
}

export async function enrollCurrentIdentity(
  relayBaseUrl: string,
  identity: HostIdentity,
  metadata: HostMetadataContext,
  encryptionIdentity?: HostEncryptionIdentity,
 ): Promise<void> {
  await new RelayClient({ baseUrl: relayBaseUrl, signer: identity.signer }).enrollHost({
    hostId: identity.hostId,
    keyId: identity.keyId,
    algorithm: identity.algorithm,
    publicKey: identity.publicKey,
    ...metadata,
    ...(encryptionIdentity ? { encryptionBinding: await createHostEncryptionBinding(identity, encryptionIdentity) } : {}),
  });
}

export async function rotateHostIdentity(
  store: HostIdentityStore,
  relayBaseUrl: string,
): Promise<KeyRotationResponse> {
  const current = await requireIdentity(store);
  let pending = await store.loadPending();
  if (!pending) {
    const operationId = `op_${randomUUID()}`;
    const issuedAt = new Date().toISOString();
    const generated = await generateHostRotationIdentity(current.hostId, current.privateKeyStorage, issuedAt);
    pending = { operationId, issuedAt, identity: generated.identity };
    await store.stageRotation(pending);
  }

  const recovered = await tryRecoverRotation(pending, current, relayBaseUrl);
  if (recovered) {
    assertRotationResult(recovered, current, pending);
    await store.promoteRotation(pending.operationId);
    return recovered;
  }

  const request = await buildRotationRequest(current, pending);
  try {
    const result = await new RelayClient({ baseUrl: relayBaseUrl, signer: current.signer }).rotateKey(request);
    assertRotationResult(result, current, pending);
    await store.promoteRotation(pending.operationId);
    return result;
  } catch (error) {
    // A failed POST may have committed remotely before its response was lost. Retain both keys;
    // recovery on this or the next invocation queries with the pending key before replaying old-key POST.
    const afterFailure = await tryRecoverRotation(pending, current, relayBaseUrl).catch(() => null);
    if (afterFailure) {
      assertRotationResult(afterFailure, current, pending);
      await store.promoteRotation(pending.operationId);
      return afterFailure;
    }
    throw error;
  }
}

export async function resetHostIdentity(
  store: HostIdentityStore,
  relayBaseUrl: string,
): Promise<{ identity: HostIdentity; revokedOldIdentity: boolean; warning?: string }> {
  let current: HostIdentity | null = null;
  let warning: string | undefined;
  try { current = await store.load(); } catch (error) {
    warning = `Old Host identity could not be loaded or revoked: ${error instanceof HostIdentityError ? error.code : 'ERR_IDENTITY_INVALID'}`;
  }
  let revokedOldIdentity = false;
  if (current) {
    // Never replace a usable identity if revoke was rejected or its outcome is unknown.
    const result = await new RelayClient({ baseUrl: relayBaseUrl, signer: current.signer }).revokeIdentity();
    if (result.entityId !== current.hostId || result.status !== 'revoked' || !isCanonicalTimestamp(result.revokedAt)) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Relay returned a malformed Host identity revoke result');
    }
    revokedOldIdentity = true;
  }
  return { identity: await store.resetAfterExplicitConfirmation(), revokedOldIdentity, ...(warning ? { warning } : {}) };
}

async function tryRecoverRotation(pending: PendingHostIdentity, current: HostIdentity, relayBaseUrl: string): Promise<KeyRotationResponse | null> {
  try {
    const result = await new RelayClient({ baseUrl: relayBaseUrl, signer: pending.identity.signer }).recoverRotation(pending.operationId);
    assertRotationResult(result, current, pending);
    return result;
  } catch (error) {
    if (error instanceof RelayClientError && error.status === 404) return null;
    throw error;
  }
}

function assertRotationResult(result: KeyRotationResponse, current: HostIdentity, pending: PendingHostIdentity): void {
  if (
    result.operationId !== pending.operationId
    || result.entityId !== current.hostId
    || result.oldKeyId !== current.keyId
    || result.newKeyId !== pending.identity.keyId
    || result.status !== 'completed'
    || !isCanonicalTimestamp(result.completedAt)
  ) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Relay returned a mismatched Host key rotation result');
  }
}

async function buildRotationRequest(current: HostIdentity, pending: PendingHostIdentity): Promise<KeyRotationRequest> {
  const rotation: RotationPayload = {
    operationId: pending.operationId,
    entityId: current.hostId,
    oldKeyId: current.keyId,
    newKeyId: pending.identity.keyId,
    newPublicKey: pending.identity.publicKey,
    issuedAt: pending.issuedAt,
  };
  const bytes = rotationPayloadBytes(rotation);
  return {
    rotation,
    oldKeyAuthorizationSignature: await current.signer.sign(bytes),
    newKeyProofSignature: await pending.identity.signer.sign(bytes),
  };
}

function rotationPayloadBytes(payload: RotationPayload): Uint8Array {
  return encoder.encode(JSON.stringify({
    operationId: payload.operationId,
    entityId: payload.entityId,
    oldKeyId: payload.oldKeyId,
    newKeyId: payload.newKeyId,
    newPublicKey: payload.newPublicKey,
    issuedAt: payload.issuedAt,
  }));
}

async function requireIdentity(store: HostIdentityStore): Promise<HostIdentity> {
  const identity = await store.load();
  if (!identity) throw new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'Host identity is not initialized; run `ariava init`');
  return identity;
}
