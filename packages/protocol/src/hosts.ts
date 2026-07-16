import type { IdentityAlgorithm, IdentityStatus } from './identity.js';

export const HOST_PLATFORMS = ['macos', 'linux'] as const;
export type HostPlatform = (typeof HOST_PLATFORMS)[number];

export const BRIDGE_STATUSES = ['online', 'offline', 'degraded'] as const;
export type BridgeStatus = (typeof BRIDGE_STATUSES)[number];

export interface HostProjection {
  hostId: string;
  hostName: string;
  platform: HostPlatform;
  bridgeVersion: string;
  registeredAt: string;
  lastSeenAt: string;
  bridgeStatus: BridgeStatus;
  status?: Extract<IdentityStatus, 'active' | 'revoked'>;
}

export interface HostEnrollmentRequest {
  hostId: string;
  keyId: string;
  algorithm: IdentityAlgorithm;
  publicKey: string;
  hostName: string;
  platform: HostPlatform;
  bridgeVersion: string;
}

export interface HostEnrollmentResponse {
  host: HostProjection;
}

export interface HostMetadataUpdateRequest {
  hostName: string;
  platform: HostPlatform;
  bridgeVersion: string;
}
