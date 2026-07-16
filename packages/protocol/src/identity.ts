import { base64UrlDecode, base64UrlEncode, sha256 } from './request-signing.js';

export const ENTITY_TYPES = ['host', 'watch'] as const;
export type EntityType = (typeof ENTITY_TYPES)[number];

export const IDENTITY_ALGORITHM = 'Ed25519' as const;
export type IdentityAlgorithm = typeof IDENTITY_ALGORITHM;

export const IDENTITY_STATUSES = ['active', 'superseded', 'revoked'] as const;
export type IdentityStatus = (typeof IDENTITY_STATUSES)[number];

export const KEY_STATUSES = ['active', 'revoked'] as const;
export type KeyStatus = (typeof KEY_STATUSES)[number];

export interface PublicIdentity {
  entityType: EntityType;
  entityId: string;
  keyId: string;
  algorithm: IdentityAlgorithm;
  publicKey: string;
  publicKeyFingerprint: string;
}

export interface EntityKeyProjection {
  keyId: string;
  algorithm: IdentityAlgorithm;
  publicKey: string;
  publicKeyFingerprint: string;
  status: KeyStatus;
  createdAt: string;
  revokedAt?: string;
}

export interface RotationPayload {
  operationId: string;
  entityId: string;
  oldKeyId: string;
  newKeyId: string;
  newPublicKey: string;
  issuedAt: string;
}

export interface KeyRotationRequest {
  rotation: RotationPayload;
  oldKeyAuthorizationSignature: string;
  newKeyProofSignature: string;
}

export interface KeyRotationResponse {
  operationId: string;
  entityId: string;
  oldKeyId: string;
  newKeyId: string;
  status: 'completed';
  completedAt: string;
}

/** Revoke is deliberately an exact empty JSON object; the signed body is required. */
export type IdentityRevokeRequest = Record<string, never>;

export interface IdentityRevokeResponse {
  entityId: string;
  status: 'revoked';
  revokedAt: string;
}

export interface DerivedEntityIdentity {
  fingerprint: string;
  entityId: string;
  keyId: string;
}

export async function derivePublicKeyFingerprint(publicKey: string | Uint8Array): Promise<string> {
  const raw = typeof publicKey === 'string' ? base64UrlDecode(publicKey, 32, 'public key') : publicKey;
  if (raw.byteLength !== 32) {
    throw new TypeError('Ed25519 public key must contain exactly 32 bytes');
  }
  return base64UrlEncode(await sha256(raw));
}

export async function deriveEntityIdentity(
  entityType: EntityType,
  publicKey: string | Uint8Array,
): Promise<DerivedEntityIdentity> {
  const fingerprint = await derivePublicKeyFingerprint(publicKey);
  return {
    fingerprint,
    entityId: `${entityType === 'host' ? 'host' : 'watch'}_${fingerprint}`,
    keyId: `key_${fingerprint}`,
  };
}
