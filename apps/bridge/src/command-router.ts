import type { CommandEnvelope, CommandResult } from '@ariava/protocol';
import { isCommandExpired } from '@ariava/protocol';
import { isoNow } from '@ariava/shared-utils';
import { BridgeStateStore } from './state-store';
import type { AgentDriver, CommandHandlingOutcome } from './types';

export class CommandRouter {
  constructor(
    private readonly stateStore: BridgeStateStore,
    private readonly drivers: Map<string, AgentDriver>,
    private readonly hostId: string,
  ) {}

  async handle(command: CommandEnvelope): Promise<CommandHandlingOutcome> {
    const previous = this.stateStore.getCommandResult(command.commandId);
    if (previous) {
      return { result: previous, followUpEvents: [] };
    }

    if (isCommandExpired(command)) {
      const expired = this.finalize(command, false, 'expired', 'The command expired before the bridge could execute it.');
      return { result: expired, followUpEvents: [] };
    }

    if (command.hostId !== this.hostId) {
      const rejected = this.finalize(command, false, 'rejected', 'The command targets a different host.');
      return { result: rejected, followUpEvents: [] };
    }

    const session = this.stateStore.getSession(command.sessionId);
    if (!session) {
      const rejected = this.finalize(command, false, 'rejected', 'The session is no longer available on this host.');
      return { result: rejected, followUpEvents: [] };
    }

    const driverName = this.stateStore.getDriverNameForSession(session.sessionId);
    if (!driverName) {
      const rejected = this.finalize(command, false, 'rejected', 'No driver is registered for this session.');
      return { result: rejected, followUpEvents: [] };
    }

    const driver = this.drivers.get(driverName);
    if (!driver) {
      const rejected = this.finalize(command, false, 'rejected', `Driver ${driverName} is unavailable.`);
      return { result: rejected, followUpEvents: [] };
    }

    const result = await driver.executeCommand({ command, session });
    this.stateStore.rememberCommandResult(result);
    return { result, followUpEvents: [] };
  }

  private finalize(
    command: CommandEnvelope,
    accepted: boolean,
    status: CommandResult['status'],
    message: string,
  ): CommandResult {
    const result: CommandResult = {
      commandId: command.commandId,
      hostId: command.hostId,
      sessionId: command.sessionId,
      accepted,
      status,
      message,
      updatedAt: isoNow(),
    };
    this.stateStore.rememberCommandResult(result);
    return result;
  }
}
