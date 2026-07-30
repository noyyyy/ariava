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
  agentText?: string;
  humanText?: string;
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
    agentText: normalizeAssistantTextForEvent(input.type, session, input.agentText),
    humanText: input.humanText,
    projectName: session.projectName,
    contextText: input.contextText,
    workingDirectory: session.cwd,
    hbaseSessionKey: session.hbaseSessionKey ?? session.sessionId,
    harnessProvider: session.harnessProvider ?? session.provider,
    actionablePrompt: input.actionablePrompt,
    correlationId: input.correlationId,
  };
}

export function buildWorkingEvent(session: PiSessionInfo, agentText?: string): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'working',
    status: 'working',
    agentText,
    contextText: buildContextText(session),
  });
}

export function buildDoneEvent(session: PiSessionInfo, agentText?: string, humanText?: string): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'done',
    status: 'done',
    agentText,
    humanText,
    contextText: buildContextText(session),
  });
}

export function buildBlockedEvent(session: PiSessionInfo, agentText?: string, humanText?: string): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'blocked',
    status: 'blocked',
    agentText,
    humanText,
    contextText: buildContextText(session),
  });
}

export function buildQuestionEvent(session: PiSessionInfo, question: string, humanText?: string): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'question_requested',
    status: 'blocked',
    agentText: question,
    humanText,
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
    workingDirectory: session.cwd,
    hbaseSessionKey: session.hbaseSessionKey ?? session.sessionId,
    harnessProvider: session.harnessProvider ?? session.provider,
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
    case 'question_requested': return 'Human';
    case 'blocked':
    case 'done':
    case 'working': return 'Agent';
    case 'driver_error': return 'Driver error';
    case 'host_unavailable': return 'Host unavailable';
  }
}
