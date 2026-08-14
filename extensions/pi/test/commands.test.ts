import { describe, expect, test } from 'bun:test';
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { CommandEnvelope } from '@ariava/protocol';
import { executeCommand } from '../src/commands';

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
  aborted: boolean;
} {
  const sent: Array<{ text: string; deliverAs?: string }> = [];
  let aborted = false;

  const pi = {
    sendUserMessage: (text: string, sendOptions?: { deliverAs?: string }) => {
      if (options.sendError) throw options.sendError;
      sent.push({ text, deliverAs: sendOptions?.deliverAs });
    },
  } as unknown as ExtensionAPI;

  const ctx = {
    abort: async () => {
      aborted = true;
      if (options.abortError) throw options.abortError;
    },
  } as unknown as ExtensionContext;

  return { pi, ctx, sent, get aborted() { return aborted; } };
}

function expectExactResult(
  result: Awaited<ReturnType<typeof executeCommand>>,
  expected:
    | { accepted: true; status: 'executed' }
    | { accepted: false; status: 'failed' | 'rejected' },
): void {
  expect(result as unknown).toEqual({
    commandId: 'cmd-1',
    hostId: 'host-1',
    sessionId: 'session-1',
    accepted: expected.accepted,
    status: expected.status,
    updatedAt: expect.any(String),
  });
  expect(Object.keys(result).sort()).toEqual([
    'accepted', 'commandId', 'hostId', 'sessionId', 'status', 'updatedAt',
  ]);
  expect(JSON.stringify(result)).not.toMatch(/message|reason|detail|error|correlationId/u);
}

describe('executeCommand', () => {
  test('reply steers the exact user text and returns only the executed receipt fields', async () => {
    const mocks = makeMocks();
    const result = await executeCommand({
      pi: mocks.pi,
      ctx: mocks.ctx,
      command: makeCommand('reply', { text: '  Use the blue theme  ' }),
    });

    expectExactResult(result, { accepted: true, status: 'executed' });
    expect(mocks.sent).toEqual([{ text: 'Use the blue theme', deliverAs: 'steer' }]);
  });

  test.each([{}, { text: '' }, { text: '   ' }, { text: 7 }])(
    'reply deterministic pre-dispatch validation fails without free text: %o',
    async (payload) => {
      const mocks = makeMocks();
      const result = await executeCommand({ pi: mocks.pi, ctx: mocks.ctx, command: makeCommand('reply', payload) });

      expectExactResult(result, { accepted: false, status: 'failed' });
      expect(mocks.sent).toEqual([]);
    },
  );

  test('interrupt aborts, steers the fixed stop instruction, and returns only executed receipt fields', async () => {
    const mocks = makeMocks();
    const result = await executeCommand({ pi: mocks.pi, ctx: mocks.ctx, command: makeCommand('interrupt') });

    expectExactResult(result, { accepted: true, status: 'executed' });
    expect(mocks.aborted).toBe(true);
    expect(mocks.sent).toEqual([{ text: 'Stop. Wait for my next instruction.', deliverAs: 'steer' }]);
  });

  test.each([
    ['reply send', makeCommand('reply', { text: 'continue' }), makeMocks({ sendError: new Error('private reply text') })],
    ['interrupt abort', makeCommand('interrupt'), makeMocks({ abortError: new Error('private driver failure') })],
  ])('%s exceptions propagate instead of fabricating a terminal failure', async (_label, command, mocks) => {
    await expect(executeCommand({ pi: mocks.pi, ctx: mocks.ctx, command })).rejects.toBeInstanceOf(Error);
  });

  test('unknown command types are explicitly rejected without diagnostic text', async () => {
    const mocks = makeMocks();
    const command = { ...makeCommand('interrupt'), type: 'unknown' } as unknown as CommandEnvelope;
    const result = await executeCommand({ pi: mocks.pi, ctx: mocks.ctx, command });

    expectExactResult(result, { accepted: false, status: 'rejected' });
  });
});
