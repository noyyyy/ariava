import {
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto';
import {
  base64UrlDecode,
  base64UrlEncode,
  buildEncryptionBindingBytes,
  E2E_SUITE_V1,
  type EncryptionKeyBindingV1,
} from '@ariava/protocol';
import type { HostIdentity } from './types';
import { HostIdentityError } from './errors';

export interface HostEncryptionIdentity {
  version: 1;
  hostId: string;
  encryptionKeyId: string;
  publicKey: string;
  privateKeyPkcs8: Uint8Array;
  sequence: number;
  createdAt: string;
}

export function generateHostEncryptionIdentity(hostId: string, sequence = 1, createdAt = new Date().toISOString()): HostEncryptionIdentity {
  const pair = generateKeyPairSync('x25519');
  const jwk = pair.publicKey.export({ format: 'jwk' });
  if (jwk.kty !== 'OKP' || jwk.crv !== 'X25519' || typeof jwk.x !== 'string') {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Node did not produce a canonical X25519 public key');
  }
  const raw = base64UrlDecode(jwk.x, 32, 'X25519 public key');
  const digest = new Uint8Array(createHash('sha256').update(raw).digest());
  const privateKeyPkcs8 = new Uint8Array(pair.privateKey.export({ type: 'pkcs8', format: 'der' }));
  return {
    version: 1,
    hostId,
    encryptionKeyId: `ekey_${base64UrlEncode(digest)}`,
    publicKey: base64UrlEncode(raw),
    privateKeyPkcs8,
    sequence,
    createdAt,
  };
}

export function importHostEncryptionPrivateKey(identity: HostEncryptionIdentity): KeyObject {
  if (identity.version !== 1 || identity.sequence < 1 || !Number.isSafeInteger(identity.sequence)) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host encryption identity metadata is invalid');
  }
  const key = createPrivateKey({ key: Buffer.from(identity.privateKeyPkcs8), format: 'der', type: 'pkcs8' });
  if (key.asymmetricKeyType !== 'x25519') throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host encryption private key is not X25519');
  const publicJwk = createPublicKey(key).export({ format: 'jwk' });
  if (typeof publicJwk.x !== 'string' || publicJwk.x !== identity.publicKey) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host encryption public/private key evidence does not match');
  }
  return key;
}

export function agreeHostEncryptionSecret(identity: HostEncryptionIdentity, peerPublicKey: string): Uint8Array {
  const privateKey = importHostEncryptionPrivateKey(identity);
  const peerRaw = base64UrlDecode(peerPublicKey, 32, 'peer X25519 public key');
  const peer = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: base64UrlEncode(peerRaw) }, format: 'jwk' });
  if (peer.asymmetricKeyType !== 'x25519') throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Peer encryption public key is not X25519');
  const secret = new Uint8Array(diffieHellman({ privateKey, publicKey: peer }));
  if (secret.byteLength !== 32 || secret.every((byte) => byte === 0)) {
    secret.fill(0);
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'X25519 produced an invalid shared secret');
  }
  return secret;
}

export async function createHostEncryptionBinding(
  identity: HostIdentity,
  encryptionIdentity: HostEncryptionIdentity,
): Promise<EncryptionKeyBindingV1> {
  if (encryptionIdentity.hostId !== identity.hostId) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Encryption identity belongs to another Host');
  }
  const unsigned = {
    version: 1 as const,
    entityType: 'host' as const,
    entityId: identity.hostId,
    identityKeyId: identity.keyId,
    encryptionKeyId: encryptionIdentity.encryptionKeyId,
    suite: E2E_SUITE_V1,
    publicKey: encryptionIdentity.publicKey,
    sequence: encryptionIdentity.sequence,
    createdAt: encryptionIdentity.createdAt,
  };
  return { ...unsigned, bindingSignature: await identity.signer.sign(buildEncryptionBindingBytes(unsigned)) };
}

