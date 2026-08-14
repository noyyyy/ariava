import type { CanonicalRequestInput, SignedRequestHeaders } from '@ariava/protocol';

export const HOST_IDENTITY_ALGORITHM = 'Ed25519' as const;

export interface HostIdentityMetadata {
  identityVersion: 2;
  hostId: string;
  keyId: string;
  algorithm: typeof HOST_IDENTITY_ALGORITHM;
  publicKey: string;
  publicKeyFingerprint: string;
  createdAt: string;
  privateKeyStorage: HostPrivateKeyStorage;
}

export type HostPrivateKeyStorage =
  | { type: 'linux-json'; path: string }
  | { type: 'macos-keychain'; service: 'io.noyx.ariava.host-identity'; account: string };

export interface HostRequestSigner {
  readonly entityId: string;
  readonly keyId: string;
  sign(bytes: Uint8Array): Promise<string>;
  signRequest(input: CanonicalRequestInput): Promise<SignedRequestHeaders>;
}

export interface HostIdentity extends HostIdentityMetadata {
  signer: HostRequestSigner;
}

export interface HostIdentityInspection {
  status: 'not-initialized' | 'ready' | 'invalid';
  storageType: HostPrivateKeyStorage['type'];
  storageReference: HostPrivateKeyStorage;
  path?: string;
  hostId?: string;
  keyId?: string;
  algorithm?: typeof HOST_IDENTITY_ALGORITHM;
  publicKeyFingerprint?: string;
  ownerIntegrity: boolean;
  permissionIntegrity: boolean;
  metadataIntegrity: boolean;
}

export interface HostIdentityStore {
  inspect(): Promise<HostIdentityInspection>;
  load(): Promise<HostIdentity | null>;
  createFirstRun(): Promise<HostIdentity>;
  resetAfterExplicitConfirmation(operationId?: string): Promise<HostIdentity>;
  recoverExplicitReset?(operationId: string): Promise<HostIdentity | null>;
  completeExplicitReset?(operationId: string): void;
  deleteAfterHostReplacement?(account: string): void;
}
