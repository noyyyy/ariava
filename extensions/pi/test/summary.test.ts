import { describe, expect, test } from 'bun:test';
import type { ExtensionContext, SessionMessageEntry } from '@earendil-works/pi-coding-agent';
import type { ReadonlySessionManager } from '@earendil-works/pi-coding-agent/dist/core/session-manager';
import type { AgentMessage } from '@earendil-works/pi-agent-core';
import type { AssistantMessage } from '@earendil-works/pi-ai';
import { clampText, generateSummary } from '../src/summary';

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

function userMessage(text: string): AgentMessage {
  return { role: 'user', content: [{ type: 'text', text }] } as AgentMessage;
}

function makeContext(messages: AgentMessage[]): ExtensionContext {
  const entries: SessionMessageEntry[] = messages.map((message) => ({ type: 'message', message, id: '', parentId: null, timestamp: new Date().toISOString() }));
  return {
    sessionManager: { getEntries: () => entries } as unknown as ReadonlySessionManager,
    cwd: '/tmp/test',
  } as ExtensionContext;
}

describe('generateSummary', () => {
  test('returns empty string when no entries', () => {
    const ctx = makeContext([]);
    expect(generateSummary(ctx)).toBe('');
  });

  test('collects assistant messages', () => {
    const ctx = makeContext([textAssistantMessage('First.'), textAssistantMessage('Second update.')]);
    const summary = generateSummary(ctx);
    expect(summary).toContain('First.');
    expect(summary).toContain('Second update.');
  });

  test('ignores user messages', () => {
    const ctx = makeContext([userMessage('hello'), textAssistantMessage('Done.')]);
    expect(generateSummary(ctx)).toBe('Done.');
  });

  test('limits to 180 chars by default', () => {
    const longText = 'a'.repeat(300);
    const ctx = makeContext([textAssistantMessage(longText)]);
    const summary = generateSummary(ctx);
    expect(summary.length).toBe(180);
    expect(summary.endsWith('…')).toBe(true);
  });

  test('respects custom max length', () => {
    const ctx = makeContext([textAssistantMessage('hello world')]);
    expect(generateSummary(ctx, 5)).toBe('hell…');
  });
});

describe('clampText', () => {
  test('does not change short text', () => {
    expect(clampText('short', 10)).toBe('short');
  });

  test('truncates long text with ellipsis', () => {
    expect(clampText('hello world', 6)).toBe('hello…');
  });
});
