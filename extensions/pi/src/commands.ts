import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { CommandEnvelope, CommandResult } from '@ariava/protocol';
import type { AgentAdapter } from './adapter-interface';

export interface CommandExecutionContext {
  pi: ExtensionAPI;
  ctx: ExtensionContext;
  command: CommandEnvelope;
  adapter: AgentAdapter;
}

export async function executeCommand({ pi, ctx, command }: CommandExecutionContext): Promise<CommandResult> {
  const now = new Date().toISOString();
  const base = {
    commandId: command.commandId,
    hostId: command.hostId,
    sessionId: command.sessionId,
    updatedAt: now,
  };

  switch (command.type) {
    case 'reply': {
      const text = String(command.payload.text ?? '').trim();
      if (!text) {
        return { ...base, accepted: false, status: 'failed', message: 'reply missing text payload' };
      }
      pi.sendUserMessage(text, { deliverAs: 'steer' });
      return { ...base, accepted: true, status: 'executed', message: 'sent user message' };
    }

    case 'interrupt': {
      await ctx.abort();
      pi.sendUserMessage('Stop. Wait for my next instruction.', { deliverAs: 'steer' });
      return { ...base, accepted: true, status: 'executed', message: 'interrupted' };
    }

    default:
      return { ...base, accepted: false, status: 'rejected', message: 'unsupported command type' };
  }
}
