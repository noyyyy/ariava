import { isCommandExpired, validateCommandResult, type CommandEnvelope, type CommandResult } from '@ariava/protocol';
import { isoNow } from '@ariava/shared-utils';
import { BridgeStateStore } from './state-store';
import type { AgentDriver, CommandHandlingOutcome } from './types';

export class CommandRouter {
  constructor(
    private readonly stateStore: BridgeStateStore,
    private readonly drivers: Map<string, AgentDriver>,
    private readonly hostId: string,
  ) {}

  async handle(command: CommandEnvelope, options: { beforeDispatch?: () => void | Promise<void> } = {}): Promise<CommandHandlingOutcome> {
    const beforeDispatch = options.beforeDispatch ?? (() => {});
    if (isCommandExpired(command)) return { result: this.finalize(command, false, 'expired'), followUpEvents: [] };
    if (command.hostId !== this.hostId) return { result: this.finalize(command, false, 'rejected'), followUpEvents: [] };

    const session = this.stateStore.getSession(command.sessionId);
    if (!session) return { result: this.finalize(command, false, 'rejected'), followUpEvents: [] };

    const driverName = this.stateStore.getDriverNameForSession(session.sessionId);
    const driver = driverName ? this.drivers.get(driverName) : undefined;
    if (!driver) return { result: this.finalize(command, false, 'rejected'), followUpEvents: [] };

    const context = { command, session };
    await driver.preflightCommandDispatch?.(context);
    await beforeDispatch();
    await driver.releaseCommandDispatch?.(context);
    const result = await driver.executeCommand(context);
    if (!validateCommandResult(result) || result.commandId !== command.commandId || result.hostId !== this.hostId
      || result.sessionId !== command.sessionId) throw new TypeError('driver command result is invalid');
    return { result, followUpEvents: [] };
  }

  private finalize(command: CommandEnvelope, accepted: boolean, status: CommandResult['status']): CommandResult {
    return {
      commandId: command.commandId,
      hostId: this.hostId,
      sessionId: command.sessionId,
      accepted,
      status,
      updatedAt: isoNow(),
    } as CommandResult;
  }
}
