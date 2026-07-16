import { sign, type KeyObject } from 'node:crypto';
import {
  base64UrlEncode,
  buildCanonicalRequest,
  createSignedRequestHeaders,
  type CanonicalRequestInput,
  type SignedRequestHeaders,
} from '@ariava/protocol';
import type { HostRequestSigner } from './types';

export class NodeHostRequestSigner implements HostRequestSigner {
  constructor(
    readonly entityId: string,
    readonly keyId: string,
    private readonly privateKey: KeyObject,
  ) {}

  async sign(bytes: Uint8Array): Promise<string> {
    return base64UrlEncode(sign(null, Buffer.from(bytes), this.privateKey));
  }

  async signRequest(input: CanonicalRequestInput): Promise<SignedRequestHeaders> {
    if (input.entityType !== 'host' || input.entityId !== this.entityId || input.keyId !== this.keyId) {
      throw new TypeError('Signer identity does not match canonical request identity');
    }
    const canonical = buildCanonicalRequest(input);
    return createSignedRequestHeaders(input, await this.sign(canonical.bytes));
  }
}

export function rebindHostRequestSigner(
  signer: HostRequestSigner,
  entityId: string,
  keyId: string,
): HostRequestSigner {
  return {
    entityId,
    keyId,
    sign: (bytes) => signer.sign(bytes),
    async signRequest(input) {
      if (input.entityType !== 'host' || input.entityId !== entityId || input.keyId !== keyId) {
        throw new TypeError('Signer identity does not match canonical request identity');
      }
      const canonical = buildCanonicalRequest(input);
      return createSignedRequestHeaders(input, await signer.sign(canonical.bytes));
    },
  };
}
