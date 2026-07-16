import { describe, expect, test } from 'bun:test';
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { CanonicalEvent, CommandEnvelope, CommandResult } from '@ariava/protocol';
import type { AgentAdapter } from '../src/adapter-interface';
import ariavaPiExtension from '../src/index';

describe('ariavaPiExtension event mapping', () => {
  test('registers expected handlers', async () => {
    const registered: string[] = [];
    const api = {
      on: (event: string, _handler: (event: unknown, ctx: ExtensionContext) => Promise<unknown>) => {
        registered.push(event);
      },
      sendUserMessage: () => {},
    } as unknown as ExtensionAPI;

    const testAdapter: AgentAdapter = {
      registerSession: async () => ({ sessionId: 's', registeredAt: '' }),
      unregisterSession: async () => {},
      pushEvent: async (_event: Partial<CanonicalEvent>) => ({ eventId: 'evt-1' }),
      handleSession: async () => ({ ok: true, hostId: 'host-1', sessionId: 's', handledThroughEventId: 'evt-1' }),
      heartbeat: async () => {},
      pollCommands: async (_sessionId: string, _timeoutMs: number) => null as CommandEnvelope | null,
      submitResult: async () => {},
    };

    await ariavaPiExtension(api, testAdapter);

    expect(registered).toContain('session_start');
    expect(registered).toContain('session_shutdown');
    expect(registered).toContain('agent_start');
    expect(registered).toContain('agent_end');
  });
});
