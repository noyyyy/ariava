import {
  statusToStateLabel,
  type CanonicalEvent,
  type EventType,
  type SessionStatus,
} from '@ariava/protocol';
import type { PiSessionInfo } from './session';
import { normalizeAssistantTextForEvent } from './session';

export interface EventBuilderInput {
  type: EventType;
  status: SessionStatus;
  assistantText: string;
  userMessageText?: string;
  contextText?: string;
  actionablePrompt?: {
    promptId: string;
    type: 'question';
    label: string;
    options?: string[];
    expiresAt?: string;
  };
  correlationId?: string;
}

export function buildEvent(session: PiSessionInfo, input: EventBuilderInput): Partial<CanonicalEvent> {
  return {
    sessionId: session.sessionId,
    provider: session.provider,
    type: input.type,
    status: input.status,
    typeLabel: deriveEventTypeLabel(input.type),
    assistantText: normalizeAssistantTextForEvent(input.type, session, input.assistantText),
    userMessageText: input.userMessageText,
    contextText: input.contextText,
    actionablePrompt: input.actionablePrompt,
    correlationId: input.correlationId,
  };
}

export function buildWorkingEvent(session: PiSessionInfo, assistantText?: string): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'working',
    status: 'working',
    assistantText: normalizeAssistantTextForEvent('working', session, assistantText),
    contextText: buildContextText(session),
  });
}

export function buildDoneEvent(session: PiSessionInfo, assistantText?: string, userMessageText?: string): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'done',
    status: 'done',
    assistantText: normalizeAssistantTextForEvent('done', session, assistantText),
    userMessageText,
    contextText: buildContextText(session),
  });
}

export function buildBlockedEvent(session: PiSessionInfo, assistantText?: string, userMessageText?: string): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'blocked',
    status: 'blocked',
    assistantText: normalizeAssistantTextForEvent('blocked', session, assistantText),
    userMessageText,
    contextText: buildContextText(session),
  });
}

export function buildQuestionEvent(session: PiSessionInfo, question: string, userMessageText?: string): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'question_requested',
    status: 'blocked',
    assistantText: normalizeAssistantTextForEvent('question_requested', session, question),
    userMessageText,
    contextText: buildContextText(session),
    actionablePrompt: {
      promptId: `question-${Date.now()}`,
      type: 'question',
      label: 'Reply',
    },
  });
}

export function toCanonicalSessionState(session: PiSessionInfo) {
  return {
    sessionId: session.sessionId,
    hostId: '',
    provider: session.provider,
    projectName: session.projectName,
    nameText: session.nameText,
    openingText: session.openingText,
    latestActivityText: session.latestActivityText,
    stateLabel: statusToStateLabel(session.status),
    status: session.status,
    updatedAt: new Date().toISOString(),
  };
}

function buildContextText(session: Pick<PiSessionInfo, 'nameText' | 'projectName'>): string {
  const name = session.nameText.trim();
  const project = session.projectName.trim();
  if (name && project && name !== project) {
    return `${name} · ${project}`;
  }
  return project || name;
}

function deriveEventTypeLabel(type: EventType): string {
  switch (type) {
    case 'question_requested': return 'Agent question';
    case 'blocked': return 'Session blocked';
    case 'done': return 'Task complete';
    case 'working': return 'In progress';
    case 'driver_error': return 'Driver error';
    case 'host_unavailable': return 'Host unavailable';
  }
}
