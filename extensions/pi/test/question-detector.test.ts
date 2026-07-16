import { describe, expect, test, beforeEach } from 'bun:test';
import type { ExtensionContext, SessionMessageEntry } from '@earendil-works/pi-coding-agent';
import type { ReadonlySessionManager } from '@earendil-works/pi-coding-agent/dist/core/session-manager';
import type { AgentMessage } from '@earendil-works/pi-agent-core';
import type { AssistantMessage } from '@earendil-works/pi-ai';
import {
  classifyAgentEnd,
  extractBlockedReason,
  looksLikeQuestion,
  looksRetryableError,
  markFingerprintEmitted,
  resetEmittedFingerprints,
} from '../src/question-detector';

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

function makeContext(messages: AgentMessage[]): ExtensionContext {
  const entries: SessionMessageEntry[] = messages.map((message) => ({ type: 'message', message, id: '', parentId: null, timestamp: new Date().toISOString() }));
  const sessionManager = {
    getEntries: () => entries,
  } as unknown as ReadonlySessionManager;

  return {
    sessionManager,
    cwd: '/tmp/test',
    mode: 'tui',
    hasUI: true,
    ui: {} as ExtensionContext['ui'],
    modelRegistry: {} as ExtensionContext['modelRegistry'],
    model: undefined,
    isIdle: () => true,
    isProjectTrusted: () => true,
    signal: undefined,
    abort: () => {},
    hasPendingMessages: () => false,
    shutdown: () => {},
    getContextUsage: () => undefined,
    compact: () => {},
    getSystemPrompt: () => '',
  } as ExtensionContext;
}

describe('classifyAgentEnd', () => {
  beforeEach(() => {
    resetEmittedFingerprints();
  });

  test('detects question by trailing question mark', () => {
    const ctx = makeContext([textAssistantMessage('What should I name this file?')]);
    const result = classifyAgentEnd(ctx, 'session-1');
    expect(result.type).toBe('question_requested');
    expect(result.assistantText).toBe('What should I name this file?');
  });

  test('detects question by strong pattern without trailing question mark', () => {
    const ctx = makeContext([textAssistantMessage('what should i do next')]);
    const result = classifyAgentEnd(ctx, 'session-1');
    expect(result.type).toBe('question_requested');
  });

  test('classifies explicit blocked evidence as blocked', () => {
    const ctx = makeContext([textAssistantMessage('I need your credentials before continuing.')]);
    const result = classifyAgentEnd(ctx, 'session-1');
    expect(result.type).toBe('blocked');
    expect(result.assistantText).toContain('credentials');
  });

  test('classifies non-question assistant message as done by default', () => {
    const ctx = makeContext([textAssistantMessage('I have updated the configuration file.')]);
    const result = classifyAgentEnd(ctx, 'session-1');
    expect(result.type).toBe('done');
    expect(result.assistantText).toBe('I have updated the configuration file.');
  });

  test('classifies empty assistant history as done', () => {
    const ctx = makeContext([]);
    const result = classifyAgentEnd(ctx, 'session-1');
    expect(result.type).toBe('done');
    expect(result.assistantText).toBe('Task complete');
  });

  test('suppresses an already-emitted fingerprint', () => {
    const ctx = makeContext([textAssistantMessage('What should I name this file?')]);
    const first = classifyAgentEnd(ctx, { sessionId: 'session-1', activeLeafId: 'leaf-1' });
    expect(first.type).toBe('question_requested');
    markFingerprintEmitted(first.fingerprint);

    const second = classifyAgentEnd(ctx, { sessionId: 'session-1', activeLeafId: 'leaf-1' });
    expect(second.type).toBe('suppress_duplicate');
  });

  test('allows same message in different sessions', () => {
    const message = textAssistantMessage('What should I name this file?');
    const ctx = makeContext([message]);
    const first = classifyAgentEnd(ctx, 'session-1');
    const second = classifyAgentEnd(ctx, 'session-2');
    expect(first.type).toBe('question_requested');
    expect(second.type).toBe('question_requested');
  });

  test('uses the last assistant message in history', () => {
    const first = textAssistantMessage('What should I name this file?');
    const last = textAssistantMessage('I have named it main.ts.');
    const ctx = makeContext([first, last]);
    const result = classifyAgentEnd(ctx, 'session-1');
    expect(result.type).toBe('done');
    expect(result.assistantText).toBe('I have named it main.ts.');
  });

  test('allows same question text in different active leaves', () => {
    const ctx = makeContext([textAssistantMessage('What should I name this file?')]);
    const first = classifyAgentEnd(ctx, { sessionId: 'session-1', activeLeafId: 'leaf-1' });
    expect(first.type).toBe('question_requested');
    markFingerprintEmitted(first.fingerprint);

    const second = classifyAgentEnd(ctx, { sessionId: 'session-1', activeLeafId: 'leaf-2' });
    expect(second.type).toBe('question_requested');
  });

  test('uses event messages before session entries', () => {
    const ctx = makeContext([textAssistantMessage('Old abandoned branch answer.')]);
    const result = classifyAgentEnd(ctx, {
      sessionId: 'session-1',
      activeLeafId: 'leaf-1',
      messages: [textAssistantMessage('Can you confirm the new branch choice?')],
    });

    expect(result.type).toBe('question_requested');
    expect(result.assistantText).toBe('Can you confirm the new branch choice?');
  });
});

describe('heuristics', () => {
  test('detects retryable errors', () => {
    expect(looksRetryableError('529 overloaded_error: Overloaded')).toBe(true);
    expect(looksRetryableError('network timeout while contacting upstream')).toBe(true);
    expect(looksRetryableError('finished successfully')).toBe(false);
  });

  test('detects blocked reasons', () => {
    expect(extractBlockedReason('permission denied while editing package.json')).toBe('permission denied while editing package.json');
    expect(extractBlockedReason('requires manual review before deploy')).toBe('requires manual review before deploy');
    expect(extractBlockedReason('All changes complete')).toBeUndefined();
  });

  test('detects question phrasing helper', () => {
    expect(looksLikeQuestion('Which environment would you like me to use')).toBe(true);
    expect(looksLikeQuestion('I updated the file.')).toBe(false);
  });
});
