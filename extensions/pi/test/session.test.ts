import { describe, expect, test } from 'bun:test';
import type { ExtensionContext, SessionMessageEntry } from '@earendil-works/pi-coding-agent';
import type { AgentMessage } from '@earendil-works/pi-agent-core';
import type { AssistantMessage, UserMessage } from '@earendil-works/pi-ai';
import { deriveLatestActivityText, deriveMessageTexts, deriveSession, getActiveMessages, normalizeAssistantTextForEvent, withSessionStatus } from '../src/session';

function textAssistantMessage(text: string): AssistantMessage {
  return {
    role: 'assistant',
    content: [{ type: 'text', text }],
    api: 'anthropic-messages',
    provider: 'anthropic',
    model: 'claude-sonnet-4-20250514',
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
    stopReason: 'stop',
    timestamp: Date.now(),
  } as AssistantMessage;
}

function toolOnlyAssistantMessage(): AssistantMessage {
  return {
    role: 'assistant',
    content: [{ type: 'tool_use', id: 'tool-1', name: 'read', input: {} }],
    api: 'anthropic-messages',
    provider: 'anthropic',
    model: 'claude-sonnet-4-20250514',
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
    stopReason: 'tool_use',
    timestamp: Date.now(),
  } as unknown as AssistantMessage;
}

function userMessage(text: string): UserMessage {
  return { role: 'user', content: [{ type: 'text', text }] } as UserMessage;
}

function entries(messages: AgentMessage[]): SessionMessageEntry[] {
  return messages.map((message) => ({ type: 'message', message, id: '', parentId: null, timestamp: new Date().toISOString() }));
}

function makeContext(options: {
  entries?: AgentMessage[];
  contextMessages?: AgentMessage[];
  branchMessages?: AgentMessage[];
  leafId?: string;
} = {}): ExtensionContext {
  return {
    cwd: '/tmp/test',
    sessionManager: {
      getEntries: () => entries(options.entries ?? []),
      buildSessionContext: options.contextMessages ? () => ({ messages: options.contextMessages }) : undefined,
      getLeafId: () => options.leafId,
      getBranch: options.branchMessages ? () => entries(options.branchMessages ?? []) : undefined,
    },
  } as unknown as ExtensionContext;
}

describe('active preview extraction', () => {
  test('derives a normal session as idle/Ready without unknown', () => {
    const session = deriveSession(makeContext({ contextMessages: [userMessage('  Start here  ')] }));

    expect(session.status).toBe('idle');
    expect(session.stateLabel).toBe('Ready');
    expect(session.openingText).toBe('Start here');
    expect(JSON.stringify(session)).not.toContain('unknown');
  });

  test('prefers agent_end event messages over getEntries', () => {
    const ctx = makeContext({ entries: [textAssistantMessage('old branch text')] });
    expect(deriveLatestActivityText(ctx, { eventMessages: [textAssistantMessage('event loop text')] })).toBe('event loop text');
  });

  test('uses buildSessionContext messages before full entries', () => {
    const ctx = makeContext({
      entries: [textAssistantMessage('old branch text')],
      contextMessages: [textAssistantMessage('new branch text')],
    });
    expect(deriveLatestActivityText(ctx)).toBe('new branch text');
  });

  test('uses current leaf branch before full entries when context messages are unavailable', () => {
    const ctx = makeContext({
      leafId: 'leaf-1',
      entries: [textAssistantMessage('old branch text')],
      branchMessages: [textAssistantMessage('branch text')],
    });
    expect(getActiveMessages(ctx)).toHaveLength(1);
    expect(deriveLatestActivityText(ctx)).toBe('branch text');
  });

  test('skips empty and tool-only assistant messages', () => {
    const ctx = makeContext({
      contextMessages: [textAssistantMessage('real assistant text'), toolOnlyAssistantMessage(), textAssistantMessage('   ')],
    });
    expect(deriveLatestActivityText(ctx)).toBe('real assistant text');
  });

  test('falls back to user text when no assistant text exists', () => {
    const ctx = makeContext({ contextMessages: [userMessage('please do the thing'), toolOnlyAssistantMessage()] });
    expect(deriveLatestActivityText(ctx)).toBe('please do the thing');
  });

  test('extracts latest user message separately from latest assistant reply', () => {
    const ctx = makeContext({
      contextMessages: [
        userMessage('please update the watch alert layout'),
        textAssistantMessage('I will update the alert details.'),
        userMessage('also rename the variables'),
        textAssistantMessage('Renamed assistant and user message fields.'),
      ],
    });

    expect(deriveMessageTexts(ctx)).toEqual({
      firstUserText: 'please update the watch alert layout',
      latestUserText: 'also rename the variables',
      latestAssistantText: 'Renamed assistant and user message fields.',
    });
  });

  test('preserves long assistant text for watch detail rendering', () => {
    const longText = `Start ${'full assistant detail '.repeat(30)}End`;
    const ctx = makeContext({ contextMessages: [textAssistantMessage(longText)] });

    expect(deriveLatestActivityText(ctx)).toBe(longText);
    expect(deriveLatestActivityText(ctx)?.endsWith('End')).toBe(true);
  });

  test('preserves long assistant text when normalizing event and session status text', () => {
    const longText = `Start ${'unclipped event text '.repeat(30)}End`;
    const session = {
      nameText: 'pi · ariava',
      latestActivityText: longText,
      sessionId: 'session-1',
      provider: 'pi',
      projectName: 'ariava',
      cwd: '/tmp/ariava',
      rawSessionName: 'ariava',
      openingText: undefined,
      stateLabel: 'Unknown',
      status: 'unknown',
      pid: 1,
    } as const;

    expect(normalizeAssistantTextForEvent('done', session, longText)).toBe(longText);
    expect(withSessionStatus(session, 'done', longText).latestActivityText).toBe(longText);
  });

  test('preserves assistant text line breaks and spacing when normalizing event text', () => {
    const assistantText = "First line\n\n  - indented item\n    code-ish spacing";
    const session = {
      nameText: 'pi · ariava',
      latestActivityText: undefined,
    } as const;

    expect(normalizeAssistantTextForEvent('done', session, assistantText)).toBe(assistantText);
  });

  test('returns undefined when no text exists', () => {
    const ctx = makeContext({ contextMessages: [toolOnlyAssistantMessage()] });
    expect(deriveLatestActivityText(ctx)).toBeUndefined();
  });
});
