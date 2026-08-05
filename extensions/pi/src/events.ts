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


export function buildDoneEvent(session: PiSessionInfo, agentText?: string, humanText?: string): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'done',
    status: 'done',
    agentText,
    humanText,
    contextText: buildContextText(session),
  });
}

export function buildNeedHumanEvent(
  session: PiSessionInfo,
  agentText?: string,
  humanText?: string,
  actionablePrompt?: EventBuilderInput['actionablePrompt'],
): Partial<CanonicalEvent> {
  return buildEvent(session, {
    type: 'need_human',
    status: 'blocked',
    agentText,
    humanText,
    contextText: buildContextText(session),
    actionablePrompt,
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
    case 'done': return 'Task complete';
    case 'need_human': return 'Needs attention';
  }
}
