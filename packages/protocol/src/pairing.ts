import type { E2EPendingLinkProjectionV1 } from './encryption.js';
import type { HostProjection } from './hosts.js';

export const PAIRING_CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ' as const;
export const PAIRING_CODE_LIMITS = {
  codeSymbols: 6,
  codeDisplayCharacters: 6,
  ttlMs: 300_000,
} as const;

export const LINK_REVOKE_REASONS = ['watch', 'host', 'device_replaced', 'identity_revoked', 'admin_reset'] as const;
export type LinkRevokeReason = (typeof LINK_REVOKE_REASONS)[number];

export interface HostWatchLink {
  hostId: string;
  watchDeviceId: string;
  pairedAt: string;
  generation: number;
  revokedAt?: string;
  revokedBy?: LinkRevokeReason;
  updatedAt: string;
}
export interface BridgePairWatchRequest {
  pairingCode: string;
}

export interface BridgePairWatchDeviceProjection {
  watchDeviceId: string;
  selectedHostIds: string[];
  registeredAt: string;
  lastSeenAt: string;
  pairingStatus: 'unpaired' | 'paired';
}

export interface BridgePairWatchResponse {
  host: HostProjection;
  watchDevice: BridgePairWatchDeviceProjection;
  link: HostWatchLink;
  alreadyPaired: boolean;
  e2e?: E2EPendingLinkProjectionV1;
}
export interface LinkedWatchProjection {
  watchDeviceId: string;
  pairedAt: string;
  lastSeenAt: string;
  e2e?: E2EPendingLinkProjectionV1;
}

export function normalizePairingCode(value: string): string {
  if (!/^[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{6}$/u.test(value)) {
    throw new TypeError('pairing code must be exactly 6 Crockford symbols');
  }
  const upper = value.toUpperCase();
  for (const symbol of upper) {
    if (!PAIRING_CODE_ALPHABET.includes(symbol)) throw new TypeError('pairing code contains an unsupported symbol');
  }
  return upper;
}

export function formatPairingCode(value: string): string {
  return normalizePairingCode(value);
}
