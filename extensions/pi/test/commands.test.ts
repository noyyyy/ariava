import { describe, expect, test } from 'bun:test';
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { CommandEnvelope } from '@ariava/protocol';
import type { AgentAdapter } from '../src/adapter-interface';
import { executeCommand } from '../src/commands';

function makeCommand(type: CommandEnvelope['type'], payload: Record<string, string | number | boolean | null | undefined> = {}): CommandEnvelope {
  return {
    commandId: 'cmd-1',
    hostId: 'host-1',
    sessionId: 'session-1',
    type,
    payload,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    nonce: 'nonce',
    watchDeviceId: 'watch-1',
  };
}

function makeMocks(): {
  pi: ExtensionAPI;
  ctx: ExtensionContext;
  adapter: AgentAdapter;
  sent: string[];
  aborted: boolean;
} {
  const sent: string[] = [];
  let aborted = false;

  const pi = {
    sendUserMessage: (text: string, _options?: { deliverAs?: string }) => {
      sent.push(text);
    },
  } as unknown as ExtensionAPI;

  const ctx = {
    abort: () => {
      aborted = true;
    },
    sessionManager: {
      getEntries: () => [],
    },
  } as unknown as ExtensionContext;

  const adapter = {} as AgentAdapter;

  return { pi, ctx, adapter, sent, get aborted() { return aborted; } };
}

describe('executeCommand', () => {
  test('reply sends user message', async () => {
    const { pi, ctx, adapter, sent } = makeMocks();
    const result = await executeCommand({
      pi,
      ctx,
      command: makeCommand('reply', { text: 'Use the blue theme' }),
      adapter,
    });
    expect(result.status).toBe('executed');
    expect(sent).toEqual(['Use the blue theme']);
  });

  test('reply without text fails', async () => {
    const { pi, ctx, adapter } = makeMocks();
    const result = await executeCommand({ pi, ctx, command: makeCommand('reply'), adapter });
    expect(result.status).toBe('failed');
    expect(result.accepted).toBe(false);
  });

  test('interrupt aborts and sends stop message', async () => {
    const mocks = makeMocks();
    const result = await executeCommand({ pi: mocks.pi, ctx: mocks.ctx, command: makeCommand('interrupt'), adapter: mocks.adapter });
    expect(result.status).toBe('executed');
    expect(mocks.aborted).toBe(true);
    expect(mocks.sent).toContain('Stop. Wait for my next instruction.');
  });
});
