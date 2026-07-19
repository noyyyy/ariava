import vectors from '../../../../packages/protocol/test/fixtures/e2e-v1-vectors.json';
import { base64UrlDecode } from '@ariava/protocol';
import { chachaPolyOpen, hkdfSha256, x25519SharedSecret } from './node-crypto';

let cached: boolean | undefined;

export function runNodeCryptoSelfTest(): boolean {
  if (cached !== undefined) return cached;
  if (!isProductionNodeRuntime()) return process.env.NODE_ENV === 'test' || process.env.ARIAVA_ALLOW_BUN_DEV === '1';
  try {
    const decode = (value: string) => base64UrlDecode(value);
    const shared = x25519SharedSecret(decode(vectors.keys.hostPrivateKeyPkcs8), decode(vectors.keys.watchPublicKey));
    if (!equal(shared, decode(vectors.keys.sharedSecret))) throw new Error('X25519 known answer failed');
    const pairRoot = hkdfSha256(shared, decode(vectors.transcript.digest), decode(vectors.transcript.pairRootInfo));
    if (!equal(pairRoot, decode(vectors.derived.pairRoot))) throw new Error('HKDF known answer failed');
    const plaintext = chachaPolyOpen(
      decode(vectors.event.dek), decode(vectors.event.contentNonce),
      decode(vectors.event.ciphertext), decode(vectors.event.contentAAD),
    );
    if (!equal(plaintext, decode(vectors.event.plaintext))) throw new Error('ChaChaPoly known answer failed');
    const tampered = decode(vectors.event.ciphertext);
    tampered[tampered.length - 1] ^= 1;
    try {
      chachaPolyOpen(decode(vectors.event.dek), decode(vectors.event.contentNonce), tampered, decode(vectors.event.contentAAD));
      throw new Error('ChaChaPoly accepted a tampered tag');
    } catch (error) {
      if (error instanceof Error && error.message === 'ChaChaPoly accepted a tampered tag') throw error;
    }
    cached = true;
  } catch {
    cached = false;
  }
  return cached;
}

export function assertNodeCryptoSelfTest(): void {
  if (!runNodeCryptoSelfTest()) throw new Error('Ariava production crypto self-test failed');
}

function isProductionNodeRuntime(): boolean {
  return process.release?.name === 'node' && process.execPath.toLowerCase().includes('node');
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}
