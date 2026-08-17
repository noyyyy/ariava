import type {
  EncryptionKeyBindingV1,
  HostEnrollmentRequest,
  HostMetadataUpdateRequest,
  HostPlatform,
} from '@ariava/protocol';
import type { HostIdentity } from '../identity';

/**
 * Deterministic Host metadata construction (spec §5 `daemon-inputs.ts`). All
 * evidence (host name, platform, bridge version) is passed explicitly; there is
 * no config/filesystem/environment access in this module.
 */
export function buildHostMetadata(evidence: {
  hostName: string;
  hostPlatform: HostPlatform;
  bridgeVersion: string;
}): HostMetadataUpdateRequest {
  return {
    hostName: evidence.hostName,
    platform: evidence.hostPlatform,
    bridgeVersion: evidence.bridgeVersion,
  };
}

/**
 * Deterministic enrollment request assembly (spec §5 `daemon-inputs.ts`).
 * Identity fields, the encryption binding, and host metadata are explicit
 * evidence supplied by the caller (the binding is asynchronously computed and
 * the metadata is config-derived in the lifecycle shell). Preserves the exact
 * `HostEnrollmentRequest` shape and field order the daemon previously produced
 * inline.
 */
export function buildHostEnrollmentRequest(params: {
  identity: Pick<HostIdentity, 'hostId' | 'keyId' | 'algorithm' | 'publicKey'>;
  encryptionBinding: EncryptionKeyBindingV1;
  hostMetadata: HostMetadataUpdateRequest;
}): HostEnrollmentRequest {
  return {
    hostId: params.identity.hostId,
    keyId: params.identity.keyId,
    algorithm: params.identity.algorithm,
    publicKey: params.identity.publicKey,
    encryptionBinding: params.encryptionBinding,
    hostName: params.hostMetadata.hostName,
    platform: params.hostMetadata.platform,
    bridgeVersion: params.hostMetadata.bridgeVersion,
  };
}
