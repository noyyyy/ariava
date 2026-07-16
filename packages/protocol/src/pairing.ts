import type { HostProjection } from './hosts.js';

export const PAIRING_CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ' as const;
export const PAIRING_CODE_LIMITS = {
  codeSymbols: 8,
  codeDisplayCharacters: 9,
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
}
export interface LinkedWatchProjection {
  watchDeviceId: string;
  pairedAt: string;
  lastSeenAt: string;
}

export function normalizePairingCode(value: string): string {
  const upper = value.toUpperCase();
  if (!/^(?:[0-9A-HJKMNP-TV-Z]{8}|[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4})$/u.test(upper)) {
    throw new TypeError('pairing code must be exactly 8 Crockford symbols or ABCD-EFGH');
  }
  const normalized = upper.length === PAIRING_CODE_LIMITS.codeDisplayCharacters ? `${upper.slice(0, 4)}${upper.slice(5)}` : upper;
  for (const symbol of normalized) {
    if (!PAIRING_CODE_ALPHABET.includes(symbol)) throw new TypeError('pairing code contains an unsupported symbol');
  }
  return normalized;
}

export function formatPairingCode(value: string): string {
  const normalized = normalizePairingCode(value);
  return `${normalized.slice(0, 4)}-${normalized.slice(4)}`;
}
