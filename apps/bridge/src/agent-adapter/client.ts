import type { CanonicalSessionState, CommandEnvelope, CommandResult } from '@ariava/protocol';
import type { AgentAdapterRegistry } from './registry';

export class AgentAdapterClient {
  constructor(private readonly registry: AgentAdapterRegistry) {}

  async listSessions(): Promise<CanonicalSessionState[]> {
    return this.registry.listSessions();
  }

  enqueueCommand(command: CommandEnvelope): void {
    this.registry.enqueueCommand(command);
  }

  async waitForResult(commandId: string, options: { timeoutMs: number }): Promise<CommandResult | undefined> {
    return this.registry.waitForResult(commandId, options);
  }
}
