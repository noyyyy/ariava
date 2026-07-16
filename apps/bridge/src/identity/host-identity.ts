import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import {
  base64UrlDecode,
  base64UrlEncode,
  deriveEntityIdentity,
} from '@ariava/protocol';
import { HostIdentityError } from './errors';
import { NodeHostRequestSigner, rebindHostRequestSigner } from './request-signer';
import {
  HOST_IDENTITY_ALGORITHM,
  type HostIdentity,
  type HostIdentityMetadata,
  type HostPrivateKeyStorage,
} from './types';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PRIVATE_KEY_MATERIAL = new WeakMap<HostIdentity, Uint8Array>();

export interface GeneratedHostKeyMaterial {
  identity: HostIdentity;
  privateKeyPkcs8: Uint8Array;
}

export async function generateHostIdentity(
  storage: HostPrivateKeyStorage,
  createdAt = new Date().toISOString(),
): Promise<GeneratedHostKeyMaterial> {
  const { privateKey } = generateKeyPairSync('ed25519');
  return importHostIdentityPrivateKey(privateKey.export({ type: 'pkcs8', format: 'der' }), storage, createdAt);
}

export async function generateHostRotationIdentity(
  hostId: string,
  storage: HostPrivateKeyStorage,
  createdAt = new Date().toISOString(),
): Promise<GeneratedHostKeyMaterial> {
  const generated = await generateHostIdentity(storage, createdAt);
  return rebindGeneratedIdentity(generated, { ...generated.identity, hostId });
}

export async function importHostIdentityPrivateKey(
  pkcs8: Uint8Array,
  storage: HostPrivateKeyStorage,
  createdAt: string,
  expected?: Partial<HostIdentityMetadata>,
): Promise<GeneratedHostKeyMaterial> {
  try {
    const privateKey = createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('private key is not Ed25519');
    const rawPublicKey = extractRawPublicKey(createPublicKey(privateKey));
    const derived = await deriveEntityIdentity('host', rawPublicKey);
    const publicKey = base64UrlEncode(rawPublicKey);
    const canonicalHostId = derived.entityId;
    const expectedHostId = expected?.hostId;
    const rotationKey = expectedHostId !== undefined && expectedHostId !== canonicalHostId;
    if (rotationKey && (expected?.keyId === undefined || expected.keyId !== derived.keyId)) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Rotated Host identity key ID does not match the private key');
    }
    const metadata: HostIdentityMetadata = {
      identityVersion: 2,
      hostId: rotationKey ? expectedHostId : canonicalHostId,
      keyId: derived.keyId,
      algorithm: HOST_IDENTITY_ALGORITHM,
      publicKey,
      publicKeyFingerprint: derived.fingerprint,
      createdAt,
      privateKeyStorage: storage,
    };
    assertExpectedMetadata(metadata, expected);
    await proveKey(privateKey, rawPublicKey);
    const identity: HostIdentity = {
      ...metadata,
      signer: new NodeHostRequestSigner(metadata.hostId, metadata.keyId, privateKey),
    };
    const privateKeyPkcs8 = new Uint8Array(pkcs8);
    PRIVATE_KEY_MATERIAL.set(identity, privateKeyPkcs8);
    return { identity, privateKeyPkcs8 };
  } catch (error) {
    if (error instanceof HostIdentityError) throw error;
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity key material is invalid', error);
  }
}

/** Identity stores use this internal handoff; private bytes never enter application models. */
export function getHostIdentityPrivateKey(identity: HostIdentity): Uint8Array {
  const privateKey = PRIVATE_KEY_MATERIAL.get(identity);
  if (!privateKey) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity is not backed by local key material');
  return new Uint8Array(privateKey);
}

export function rebindHostIdentity(identity: HostIdentity, metadata: HostIdentityMetadata): HostIdentity {
  const privateKey = PRIVATE_KEY_MATERIAL.get(identity);
  if (!privateKey) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity is not backed by local key material');
  const rebound: HostIdentity = {
    ...metadata,
    signer: rebindHostRequestSigner(identity.signer, metadata.hostId, metadata.keyId),
  };
  PRIVATE_KEY_MATERIAL.set(rebound, new Uint8Array(privateKey));
  return rebound;
}

function rebindGeneratedIdentity(
  generated: GeneratedHostKeyMaterial,
  metadata: HostIdentityMetadata,
): GeneratedHostKeyMaterial {
  return {
    identity: rebindHostIdentity(generated.identity, {
      identityVersion: metadata.identityVersion,
      hostId: metadata.hostId,
      keyId: metadata.keyId,
      algorithm: metadata.algorithm,
      publicKey: metadata.publicKey,
      publicKeyFingerprint: metadata.publicKeyFingerprint,
      createdAt: metadata.createdAt,
      privateKeyStorage: metadata.privateKeyStorage,
    }),
    privateKeyPkcs8: generated.privateKeyPkcs8,
  };
}

export function decodePkcs8(value: string): Uint8Array {
  try {
    return base64UrlDecode(value, undefined, 'privateKeyPkcs8');
  } catch (error) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity private key encoding is invalid', error);
  }
}

export function extractRawPublicKey(publicKey: KeyObject): Uint8Array {
  const spki = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }));
  if (spki.length !== ED25519_SPKI_PREFIX.length + 32 || !spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity public key is not canonical Ed25519');
  }
  return new Uint8Array(spki.subarray(ED25519_SPKI_PREFIX.length));
}

function assertExpectedMetadata(actual: HostIdentityMetadata, expected?: Partial<HostIdentityMetadata>): void {
  if (!expected) return;
  for (const field of ['identityVersion', 'hostId', 'keyId', 'algorithm', 'publicKey', 'publicKeyFingerprint'] as const) {
    if (expected[field] !== undefined && expected[field] !== actual[field]) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', `Host identity ${field} does not match the private key`);
    }
  }
}

async function proveKey(privateKey: KeyObject, rawPublicKey: Uint8Array): Promise<void> {
  const challenge = Buffer.from('ariava-host-identity-key-proof-v1');
  const signature = sign(null, challenge, privateKey);
  const publicKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawPublicKey)]), format: 'der', type: 'spki' });
  if (!verify(null, challenge, publicKey, signature)) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity signing proof failed');
  }
}
