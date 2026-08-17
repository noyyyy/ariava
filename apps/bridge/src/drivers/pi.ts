import type { CanonicalSessionState, CommandResult } from '@ariava/protocol';
import type { AgentAdapterClient } from '../agent-adapter/client';
import type { AgentDriver, DriverCommandContext } from '../types';

export class AgentAdapterDriver implements AgentDriver {
  readonly name = 'agent-adapter';

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

  preflightCommandDispatch(ctx: DriverCommandContext): void {
    this.adapter.assertCommandDispatchReady(ctx.command);
  }

  releaseCommandDispatch(ctx: DriverCommandContext): void {
    this.adapter.enqueueCommand(ctx.command);
  }

  async executeCommand(ctx: DriverCommandContext): Promise<CommandResult> {
    try {
      const result = await this.adapter.waitForResult(ctx.command.commandId, { timeoutMs: 30_000 });
      if (!result) throw new CommandDispatchOutcomeUnknownError();
      return result;
    } catch (error) {
      this.adapter.abandonCommand(ctx.command.commandId);
      if (error instanceof CommandDispatchOutcomeUnknownError) throw error;
      throw new CommandDispatchOutcomeUnknownError();
    }
  }
}

export class CommandDispatchOutcomeUnknownError extends Error {
  constructor() { super('Agent Adapter command outcome is unknown'); }
}
