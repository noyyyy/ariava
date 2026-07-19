import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';
import { base64UrlDecode, base64UrlEncode } from '@ariava/protocol';

export interface X25519KeyMaterial {
  privateKeyPkcs8: Uint8Array;
  publicKeyRaw: Uint8Array;
}

export function generateX25519KeyMaterial(): X25519KeyMaterial {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  return {
    privateKeyPkcs8: new Uint8Array(privateKey.export({ type: 'pkcs8', format: 'der' })),
    publicKeyRaw: exportX25519PublicKeyRaw(publicKey),
  };
}

export function importX25519PrivateKey(pkcs8: Uint8Array): KeyObject {
  const key = createPrivateKey({ key: Buffer.from(pkcs8), type: 'pkcs8', format: 'der' });
  if (key.asymmetricKeyType !== 'x25519') throw new TypeError('private key must be X25519 PKCS#8');
  return key;
}

export function importX25519PublicKeyRaw(raw: Uint8Array): KeyObject {
  if (raw.byteLength !== 32) throw new TypeError('X25519 public key must contain exactly 32 bytes');
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: base64UrlEncode(raw) }, format: 'jwk' });
  if (key.asymmetricKeyType !== 'x25519') throw new TypeError('public key must be X25519');
  return key;
}

export function exportX25519PublicKeyRaw(key: KeyObject): Uint8Array {
  if (key.asymmetricKeyType !== 'x25519') throw new TypeError('public key must be X25519');
  const jwk = key.export({ format: 'jwk' });
  if (jwk.kty !== 'OKP' || jwk.crv !== 'X25519' || typeof jwk.x !== 'string') {
    throw new TypeError('X25519 public JWK is invalid');
  }
  return base64UrlDecode(jwk.x, 32, 'X25519 JWK.x');
}

export function x25519SharedSecret(privateKeyPkcs8: Uint8Array, peerPublicKeyRaw: Uint8Array): Uint8Array {
  const secret = new Uint8Array(diffieHellman({
    privateKey: importX25519PrivateKey(privateKeyPkcs8),
    publicKey: importX25519PublicKeyRaw(peerPublicKeyRaw),
  }));
  if (secret.byteLength !== 32 || secret.every((byte) => byte === 0)) throw new TypeError('X25519 shared secret is invalid');
  return secret;
}

export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array): Uint8Array {
  if (salt.byteLength !== 32) throw new TypeError('HKDF salt must contain exactly 32 bytes');
  return new Uint8Array(hkdfSync('sha256', Buffer.from(ikm), Buffer.from(salt), Buffer.from(info), 32));
}

export function chachaPolySeal(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  nonce: Uint8Array = randomBytes(12),
): { nonce: Uint8Array; ciphertext: Uint8Array } {
  assertAeadInput(key, nonce);
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.byteLength });
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce: new Uint8Array(nonce), ciphertext: new Uint8Array(Buffer.concat([encrypted, cipher.getAuthTag()])) };
}

export function chachaPolyOpen(key: Uint8Array, nonce: Uint8Array, wireCiphertext: Uint8Array, aad: Uint8Array): Uint8Array {
  assertAeadInput(key, nonce);
  if (wireCiphertext.byteLength < 16) throw new TypeError('ChaChaPoly ciphertext is shorter than its tag');
  const ciphertext = wireCiphertext.subarray(0, wireCiphertext.byteLength - 16);
  const tag = wireCiphertext.subarray(wireCiphertext.byteLength - 16);
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad, { plaintextLength: ciphertext.byteLength });
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
}

function assertAeadInput(key: Uint8Array, nonce: Uint8Array): void {
  if (key.byteLength !== 32) throw new TypeError('ChaChaPoly key must contain exactly 32 bytes');
  if (nonce.byteLength !== 12) throw new TypeError('ChaChaPoly nonce must contain exactly 12 bytes');
}
