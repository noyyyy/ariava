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
