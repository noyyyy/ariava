import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { COMMAND_LIMITS, type CommandEnvelope } from '@ariava/protocol';
import type { AgentAdapterCommandResult, CommandExecutionOutcome } from './adapter-interface';

export interface CommandExecutionContext {
  pi: ExtensionAPI;
  ctx: ExtensionContext;
  command: CommandEnvelope;
}

const replyTextEncoder = new TextEncoder();
const REPLY_EDGE_WHITESPACE = new Set([
  0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x00a0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
  0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff,
]);

export async function executeCommand(
  { pi, ctx, command }: CommandExecutionContext,
): Promise<CommandExecutionOutcome> {
  switch (command.type) {
    case 'reply': {
      const text = canonicalizeReplyText(command.payload.text);
      if (text === null) return rejected(command);
      try {
        pi.sendUserMessage(text, { deliverAs: 'steer' });
      } catch {
        return { kind: 'outcome_unknown' };
      }
      return executed(command);
    }

    case 'interrupt': {
      try {
        await ctx.abort();
        pi.sendUserMessage('Stop. Wait for my next instruction.', { deliverAs: 'steer' });
      } catch {
        return { kind: 'outcome_unknown' };
      }
      return executed(command);
    }

    default:
      return rejected(command);
  }
}

export function canonicalizeReplyText(value: unknown): string | null {
  if (typeof value !== 'string' || !isWellFormedUnicode(value)) return null;
  if (replyTextEncoder.encode(value).byteLength > COMMAND_LIMITS.replyTextBytes) return null;
  const codePoints = Array.from(value);
  let start = 0;
  let end = codePoints.length;
  while (start < end && REPLY_EDGE_WHITESPACE.has(codePoints[start]!.codePointAt(0)!)) start += 1;
  while (end > start && REPLY_EDGE_WHITESPACE.has(codePoints[end - 1]!.codePointAt(0)!)) end -= 1;
  if (start === end) return null;
  return codePoints.slice(start, end).join('');
}

function executed(command: CommandEnvelope): CommandExecutionOutcome {
  const result: AgentAdapterCommandResult = {
    commandId: command.commandId,
    hostId: command.hostId,
    sessionId: command.sessionId,
    accepted: true,
    status: 'executed',
    updatedAt: new Date().toISOString(),
  };
  return { kind: 'terminal', result };
}

function rejected(command: CommandEnvelope): CommandExecutionOutcome {
  const result: AgentAdapterCommandResult = {
    commandId: command.commandId,
    hostId: command.hostId,
    sessionId: command.sessionId,
    accepted: false,
    status: 'rejected',
    updatedAt: new Date().toISOString(),
  };
  return { kind: 'terminal', result };
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}
