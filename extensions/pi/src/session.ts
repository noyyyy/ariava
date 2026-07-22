import { basename } from 'node:path';
import type { ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentMessage } from '@earendil-works/pi-agent-core';
import type { AssistantMessage, TextContent, UserMessage } from '@earendil-works/pi-ai';
import { statusToStateLabel, type EventType, type SessionStatus } from '@ariava/protocol';

export interface PiSessionInfo {
  sessionId: string;
  provider: 'pi';
  projectName: string;
  cwd: string;
  rawSessionName?: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
  stateLabel: string;
  status: SessionStatus;
  pid?: number;
}

export interface ActiveMessageOptions {
  eventMessages?: AgentMessage[];
}

type SessionManagerLike = NonNullable<ExtensionContext['sessionManager']> & {
  buildSessionContext?: () => { messages?: AgentMessage[] } | undefined;
  getLeafId?: () => string | undefined;
  getBranch?: (leafId: string) => unknown[] | undefined;
};

export function deriveSessionId(ctx: ExtensionContext): string {
  const sessionId = ctx.sessionManager?.getSessionId?.();
  if (sessionId) {
    return sessionId;
  }
  return `pi-${process.pid}-${Date.now()}`;
}

export function deriveProjectName(ctx: ExtensionContext): string {
  const cwd = ctx.cwd ?? process.cwd();
  return basename(cwd);
}

export function deriveSessionName(ctx: ExtensionContext): string | undefined {
  return ctx.sessionManager?.getSessionName?.();
}

export function deriveNameText(rawSessionName: string | undefined, projectName: string): string {
  const trimmed = rawSessionName?.trim();
  return trimmed || projectName;
}

export function deriveActiveLeafId(ctx: ExtensionContext): string | undefined {
  const leafId = (ctx.sessionManager as SessionManagerLike | undefined)?.getLeafId?.();
  return typeof leafId === 'string' && leafId.trim() ? leafId : undefined;
}

export function getActiveMessages(ctx: ExtensionContext, options: ActiveMessageOptions = {}): AgentMessage[] {
  if (Array.isArray(options.eventMessages) && options.eventMessages.length > 0) {
    return options.eventMessages;
  }

  const sessionManager = ctx.sessionManager as SessionManagerLike | undefined;
  const contextMessages = sessionManager?.buildSessionContext?.()?.messages;
  if (Array.isArray(contextMessages) && contextMessages.length > 0) {
    return contextMessages;
  }

  const leafId = sessionManager?.getLeafId?.();
  if (leafId && typeof sessionManager?.getBranch === 'function') {
    const branchEntries = sessionManager.getBranch(leafId);
    const branchMessages = entriesToMessages(branchEntries);
    if (branchMessages.length > 0) {
      return branchMessages;
    }
  }

  return entriesToMessages(ctx.sessionManager?.getEntries?.() ?? []);
}

export function deriveMessageTexts(ctx: ExtensionContext, options: ActiveMessageOptions = {}): {
  firstUserText?: string;
  latestUserText?: string;
  latestAssistantText?: string;
} {
  const messages = getActiveMessages(ctx, options);
  let firstUserText: string | undefined;
  let latestUserText: string | undefined;
  let latestAssistantText: string | undefined;

  for (const message of messages) {
    if (isUserMessage(message)) {
      const text = extractText(message);
      if (text && !firstUserText) {
        firstUserText = text;
      }
      if (text) {
        latestUserText = text;
      }
      continue;
    }

    if (isAssistantMessage(message)) {
      const text = extractText(message);
      if (text) {
        latestAssistantText = text;
      }
    }
  }

  return { firstUserText, latestUserText, latestAssistantText };
}

export function clampAssistantText(text: string | undefined): string | undefined {
  const normalized = text?.trim();
  return normalized || undefined;
}

export function findLastTextBearingAssistantText(messages: AgentMessage[]): string | undefined {
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i];
    if (!isAssistantMessage(message)) continue;
    const text = clampAssistantText(extractText(message)) ?? extractAssistantErrorText(message);
    if (text) return text;
  }
  return undefined;
}

export function findLastTextBearingUserText(messages: AgentMessage[]): string | undefined {
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i];
    if (!isUserMessage(message)) continue;
    const text = clampAssistantText(extractText(message));
    if (text) return text;
  }
  return undefined;
}

export function deriveLatestActivityText(ctx: ExtensionContext, options: ActiveMessageOptions = {}): string | undefined {
  const messages = getActiveMessages(ctx, options);
  return findLastTextBearingAssistantText(messages) ?? findLastTextBearingUserText(messages);
}

export function fallbackAssistantForEventType(type: EventType, session: Pick<PiSessionInfo, 'nameText'>): string {
  switch (type) {
    case 'done': return 'Task complete';
    case 'blocked': return 'Review needed on desktop';
    case 'question_requested': return 'Agent has a question';
    case 'working': return `${session.nameText} is running`;
    case 'driver_error': return 'Driver error';
    case 'host_unavailable': return 'Host unavailable';
    default: return 'Agent update';
  }
}

export function normalizeAssistantTextForEvent(
  type: EventType,
  session: Pick<PiSessionInfo, 'nameText' | 'latestActivityText'>,
  assistantText?: string,
): string {
  return clampAssistantText(assistantText) ?? clampAssistantText(session.latestActivityText) ?? fallbackAssistantForEventType(type, session);
}

export function deriveSession(ctx: ExtensionContext): PiSessionInfo {
  const cwd = ctx.cwd ?? process.cwd();
  const projectName = deriveProjectName(ctx);
  const rawSessionName = deriveSessionName(ctx);
  const { firstUserText } = deriveMessageTexts(ctx);

  return {
    sessionId: deriveSessionId(ctx),
    provider: 'pi',
    projectName,
    cwd,
    rawSessionName,
    nameText: deriveNameText(rawSessionName, projectName),
    openingText: clampAssistantText(firstUserText),
    latestActivityText: deriveLatestActivityText(ctx),
    stateLabel: statusToStateLabel('idle'),
    status: 'idle',
    pid: process.pid,
  };
}

export function withSessionStatus(session: PiSessionInfo, status: SessionStatus, latestActivityText?: string): PiSessionInfo {
  return {
    ...session,
    status,
    stateLabel: statusToStateLabel(status),
    latestActivityText: clampAssistantText(latestActivityText) ?? session.latestActivityText,
  };
}

function entriesToMessages(entries: unknown[] | undefined): AgentMessage[] {
  if (!Array.isArray(entries)) return [];
  return entries
    .filter((entry): entry is { type: string; message: AgentMessage } =>
      typeof entry === 'object' && entry !== null && (entry as { type?: string }).type === 'message' && 'message' in entry,
    )
    .map((entry) => entry.message);
}

function isAssistantMessage(message: AgentMessage): message is AssistantMessage {
  return (
    typeof message === 'object' &&
    message !== null &&
    'role' in message &&
    (message as AssistantMessage).role === 'assistant' &&
    Array.isArray((message as AssistantMessage).content)
  );
}

function isUserMessage(message: AgentMessage): message is UserMessage {
  return (
    typeof message === 'object' &&
    message !== null &&
    'role' in message &&
    (message as UserMessage).role === 'user' &&
    Array.isArray((message as UserMessage).content)
  );
}

function extractAssistantErrorText(message: AssistantMessage): string | undefined {
  const errorMessage = (message as AssistantMessage & { errorMessage?: unknown }).errorMessage;
  return typeof errorMessage === 'string' ? clampAssistantText(errorMessage) : undefined;
}

function extractText(message: AssistantMessage | UserMessage): string {
  const content = message.content;
  if (!Array.isArray(content)) return '';

  return content
    .filter((part): part is TextContent =>
      typeof part === 'object' && part !== null && 'type' in part && part.type === 'text' && 'text' in part,
    )
    .map((part) => part.text)
    .join('')
    .trim();
}
