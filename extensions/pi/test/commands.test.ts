import { describe, expect, test } from 'bun:test';
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { COMMAND_LIMITS, type CommandEnvelope } from '@ariava/protocol';
import { canonicalizeReplyText, executeCommand } from '../src/commands';

function makeCommand(
  type: CommandEnvelope['type'],
  payload: Record<string, string | number | boolean | null | undefined> = {},
): CommandEnvelope {
  return {
    commandId: 'cmd-1',
    hostId: 'host-1',
    sessionId: 'session-1',
    type,
    payload,
    issuedAt: '2026-08-12T00:00:00.000Z',
    expiresAt: '2026-08-12T00:01:00.000Z',
    nonce: 'nonce',
    watchDeviceId: 'watch-1',
  };
}

function makeMocks(options: { abortError?: Error; sendError?: Error } = {}): {
  pi: ExtensionAPI;
  ctx: ExtensionContext;
  sent: Array<{ text: string; deliverAs?: string }>;
  abortCalls: number;
} {
  const sent: Array<{ text: string; deliverAs?: string }> = [];
  let abortCalls = 0;
  const pi = {
    sendUserMessage: (text: string, sendOptions?: { deliverAs?: string }) => {
      if (options.sendError) throw options.sendError;
      sent.push({ text, deliverAs: sendOptions?.deliverAs });
    },
  } as unknown as ExtensionAPI;
  const ctx = {
    abort: async () => {
      abortCalls += 1;
      if (options.abortError) throw options.abortError;
    },
  } as unknown as ExtensionContext;
  return { pi, ctx, sent, get abortCalls() { return abortCalls; } };
}

function expectExecuted(result: Awaited<ReturnType<typeof executeCommand>>): void {
  expect(result).toEqual({
    kind: 'terminal',
    result: {
      commandId: 'cmd-1',
      hostId: 'host-1',
      sessionId: 'session-1',
      accepted: true,
      status: 'executed',
      updatedAt: expect.any(String),
    },
  });
}

function expectRejected(result: Awaited<ReturnType<typeof executeCommand>>): void {
  expect(result).toEqual({
    kind: 'terminal',
    result: {
      commandId: 'cmd-1',
      hostId: 'host-1',
      sessionId: 'session-1',
      accepted: false,
      status: 'rejected',
      updatedAt: expect.any(String),
    },
  });
}

const EXACT_TRIM = '\u0009\u000A\u000B\u000C\u000D\u0020\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF';

describe('reply canonicalization', () => {
  test('trims only the approved edge code points without normalization or internal rewriting', () => {
    const decomposed = 'e\u0301';
    const internal = `line one\r\n\u00A0line  two`;
    expect(canonicalizeReplyText(`${EXACT_TRIM}${decomposed}${internal}${EXACT_TRIM}`))
      .toBe(`${decomposed}${internal}`);
    expect(canonicalizeReplyText('\u0085keep\u0085')).toBe('\u0085keep\u0085');
    expect(canonicalizeReplyText('\u200Bkeep\u200B')).toBe('\u200Bkeep\u200B');
  });

  test('checks raw WHATWG UTF-8 size before trimming', () => {
    expect(canonicalizeReplyText('x'.repeat(COMMAND_LIMITS.replyTextBytes))).toBe('x'.repeat(COMMAND_LIMITS.replyTextBytes));
    expect(canonicalizeReplyText(` ${'x'.repeat(COMMAND_LIMITS.replyTextBytes)}`)).toBeNull();
    expect(canonicalizeReplyText('😀'.repeat(COMMAND_LIMITS.replyTextBytes / 4))).toBe('😀'.repeat(COMMAND_LIMITS.replyTextBytes / 4));
    expect(canonicalizeReplyText(`😀${'x'.repeat(COMMAND_LIMITS.replyTextBytes - 3)}`)).toBeNull();
  });

  test.each(['\uD800', '\uDC00', `ok\uD800`, EXACT_TRIM])(
    'rejects malformed scalar or trim-empty input: %p',
    (value) => expect(canonicalizeReplyText(value)).toBeNull(),
  );
});

describe('executeCommand', () => {
  test('reply sends the exact canonical text once and returns executed after normal completion', async () => {
    const mocks = makeMocks();
    const result = await executeCommand({
      pi: mocks.pi,
      ctx: mocks.ctx,
      command: makeCommand('reply', { text: '\u00A0 e\u0301\r\nnext \u3000' }),
    });
    expectExecuted(result);
    expect(mocks.sent).toEqual([{ text: 'e\u0301\r\nnext', deliverAs: 'steer' }]);
  });

  test.each([{}, { text: '' }, { text: '   ' }, { text: 7 }, { text: '\uD800' }])(
    'reply pre-call invalid input is rejected with zero native calls: %o',
    async (payload) => {
      const mocks = makeMocks();
      expectRejected(await executeCommand({ pi: mocks.pi, ctx: mocks.ctx, command: makeCommand('reply', payload) }));
      expect(mocks.sent).toEqual([]);
      expect(mocks.abortCalls).toBe(0);
    },
  );

  test('reply throw after a possible invocation is outcome_unknown and is not retried', async () => {
    let calls = 0;
    const mocks = makeMocks({ sendError: new Error('possibly invoked') });
    const pi = {
      sendUserMessage: (...args: Parameters<ExtensionAPI['sendUserMessage']>) => {
        calls += 1;
        return mocks.pi.sendUserMessage(...args);
      },
    } as ExtensionAPI;
    expect(await executeCommand({ pi, ctx: mocks.ctx, command: makeCommand('reply', { text: 'continue' }) }))
      .toEqual({ kind: 'outcome_unknown' });
    expect(calls).toBe(1);
  });

  test('interrupt returns executed only after abort and the fixed message both complete normally', async () => {
    const mocks = makeMocks();
    expectExecuted(await executeCommand({ pi: mocks.pi, ctx: mocks.ctx, command: makeCommand('interrupt') }));
    expect(mocks.abortCalls).toBe(1);
    expect(mocks.sent).toEqual([{ text: 'Stop. Wait for my next instruction.', deliverAs: 'steer' }]);
  });

  test.each([
    ['abort throw', makeMocks({ abortError: new Error('possibly invoked') }), 0],
    ['message throw', makeMocks({ sendError: new Error('possibly invoked') }), 0],
  ])('%s remains outcome_unknown without replay', async (_label, mocks, expectedMessages) => {
    expect(await executeCommand({ pi: mocks.pi, ctx: mocks.ctx, command: makeCommand('interrupt') }))
      .toEqual({ kind: 'outcome_unknown' });
    expect(mocks.abortCalls).toBe(1);
    expect(mocks.sent).toHaveLength(expectedMessages);
  });

  test('unsupported command is rejected before native calls', async () => {
    const mocks = makeMocks();
    const command = { ...makeCommand('interrupt'), type: 'unknown' } as unknown as CommandEnvelope;
    expectRejected(await executeCommand({ pi: mocks.pi, ctx: mocks.ctx, command }));
    expect(mocks.abortCalls).toBe(0);
    expect(mocks.sent).toEqual([]);
  });
});
