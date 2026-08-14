import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { CommandEnvelope } from '@ariava/protocol';
import type { AgentAdapterCommandResult } from './adapter-interface';

export interface CommandExecutionContext {
  pi: ExtensionAPI;
  ctx: ExtensionContext;
  command: CommandEnvelope;
}

export async function executeCommand({ pi, ctx, command }: CommandExecutionContext): Promise<AgentAdapterCommandResult> {
  const base = {
    commandId: command.commandId,
    hostId: command.hostId,
    sessionId: command.sessionId,
    updatedAt: new Date().toISOString(),
  };

  switch (command.type) {
    case 'reply': {
      const text = typeof command.payload.text === 'string' ? command.payload.text.trim() : '';
      if (!text) return { ...base, accepted: false, status: 'failed' };
      pi.sendUserMessage(text, { deliverAs: 'steer' });
      return { ...base, accepted: true, status: 'executed' };
    }

    case 'interrupt': {
      await ctx.abort();
      pi.sendUserMessage('Stop. Wait for my next instruction.', { deliverAs: 'steer' });
      return { ...base, accepted: true, status: 'executed' };
    }

    default:
      return { ...base, accepted: false, status: 'rejected' };
  }
}
