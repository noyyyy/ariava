import type { ActionablePrompt, SessionStatus } from './events.js';

export const SESSION_PRESENCES = ['active', 'ended'] as const;
export type SessionPresence = (typeof SESSION_PRESENCES)[number];

export interface CanonicalSessionState {
  sessionId: string;
  hostId: string;
  provider: string;
  projectName: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
  stateLabel: string;
  status: SessionStatus;
  actionablePrompt?: ActionablePrompt;
  updatedAt: string;
  lastEventId?: string;
  snoozedUntil?: string;
}

/** Host-local plaintext model. It must never be used as a Relay persistence/read projection. */
export type LocalCanonicalSessionPlaintext = CanonicalSessionState;

export interface DecryptedWatchSession extends CanonicalSessionState {
  revision: number;
}

/** A session in a Host-wide authoritative current-session replacement snapshot. */
export interface ActiveSessionSnapshot extends CanonicalSessionState {
  presence: 'active';
}

export interface SessionSummaryAssistant {
  sessionId: string;
  hostId: string;
  projectName: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
  stateLabel: string;
  status: SessionStatus;
  updatedAt: string;
}
