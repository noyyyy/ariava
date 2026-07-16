import type { ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentMessage } from '@earendil-works/pi-agent-core';
import type { AssistantMessage, TextContent } from '@earendil-works/pi-ai';

const DEFAULT_MAX_RECENT_ENTRIES = 20;

export function generateSummary(ctx: ExtensionContext, maxLength = 180): string {
  const entries = ctx.sessionManager?.getEntries?.() ?? [];
  const assistantTexts: string[] = [];

  for (let i = entries.length - 1; i >= 0 && assistantTexts.length < DEFAULT_MAX_RECENT_ENTRIES; i--) {
    const entry = entries[i];
    if (entry?.type !== 'message') continue;
    const message = (entry as { message: AgentMessage }).message;
    if (!isAssistantMessage(message)) continue;

    const text = extractText(message);
    if (text) {
      assistantTexts.unshift(text);
    }
  }

  const combined = assistantTexts.join(' ').trim();
  return clampText(combined, maxLength);
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

function extractText(message: AssistantMessage): string {
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

export function clampText(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  const truncated = text.slice(0, maxLength - 1);
  return `${truncated}…`;
}
