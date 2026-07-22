import type { CanonicalSessionState, CommandEnvelope, CommandResult } from '@ariava/protocol';
import { isoNow } from '@ariava/shared-utils';
import type { AgentAdapterClient } from '../agent-adapter/client';
import type { AgentDriver, DriverCommandContext } from '../types';

export class PaiDriver implements AgentDriver {
  readonly name = 'pi';

  constructor(
    private readonly adapter: AgentAdapterClient,
    private readonly hostId: string,
  ) {}

  async listSessions(): Promise<CanonicalSessionState[]> {
    return this.adapter.listSessions();
  }

  isAuthoritativeSetReady(persistedSessions: CanonicalSessionState[]): boolean {
    return this.adapter.isAuthoritativeSetReady(persistedSessions);
  }

  async executeCommand(ctx: DriverCommandContext): Promise<CommandResult> {
    this.adapter.enqueueCommand(ctx.command);
    const result = await this.adapter.waitForResult(ctx.command.commandId, { timeoutMs: 30_000 });
    return result ?? timeoutResult(ctx.command);
  }
}

export function timeoutResult(command: CommandEnvelope): CommandResult {
  return {
    commandId: command.commandId,
    hostId: command.hostId,
    sessionId: command.sessionId,
    accepted: false,
    status: 'failed',
    message: 'The pi extension did not respond within the timeout window.',
    updatedAt: isoNow(),
  };
}
