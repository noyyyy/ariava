declare module 'node:crypto' {
  export type KeyObject = unknown;
  export function createPrivateKey(options: unknown): KeyObject;
  export function createPublicKey(key: KeyObject): KeyObject;
  export function sign(algorithm: null, data: Uint8Array, key: KeyObject): Uint8Array;
  export function verify(algorithm: null, data: Uint8Array, key: KeyObject, signature: Uint8Array): boolean;
}

declare const Buffer: {
  from(data: string, encoding?: string): Uint8Array;
};
