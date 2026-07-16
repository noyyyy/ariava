import type { ActionablePrompt, SessionStatus } from './events.js';

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
