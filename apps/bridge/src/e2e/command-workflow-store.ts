import type { CommandResult, EncryptedCommandEnvelopeV1 } from '@ariava/protocol';
import type {
  CommandReceiptOutboxInputV1,
  PersistedCommandExecutionV4,
  PersistedCommandPinReferenceV1,
} from '../types';
import type { CommandExecutionPinResolver } from '../state-store/command-transitions';
import type { PinRetentionReferences } from './link-keyring';

/**
 * Narrow capability port for the durable command execution workflow (spec §3.2).
 *
 * Consumer-owned contract: the command workflow (command routing, terminal
 * receipt construction/recovery, startup recovery, and the daemon command
 * pipeline) depends on exactly this claim/dispatch/unknown/blocked/terminal/
 * outbox surface instead of the full `BridgeStateStore`. `BridgeStateStore`
 * structurally satisfies this interface; state-store does not export consumer
 * ports and does not depend on this module.
 */
export interface CommandWorkflowStateStore {
  listCommandExecutions(): PersistedCommandExecutionV4[];
  getCommandExecution(commandId: string): PersistedCommandExecutionV4 | undefined;
  getRecipientSetVersion(): number | undefined;
  setRecipientSetVersion(version: number): void;
  durableContentPinRetentionReferences(retainThrough: string): PinRetentionReferences;
  commandExecutionPinRetentionReferences(): PinRetentionReferences;
  pruneEligibleCommandExecutions(now: string): PersistedCommandExecutionV4[];
  validateCommandExecutionPins(
    resolver: CommandExecutionPinResolver,
    options?: { allowUnavailableForTerminal?: boolean },
  ): void;
  claimCommandExecution(input: {
    originalEncryptedCommand: EncryptedCommandEnvelopeV1;
    commandDigest: string;
    pinReference: PersistedCommandPinReferenceV1;
    claimedAt: string;
  }): { status: 'claimed' | 'duplicate'; execution: PersistedCommandExecutionV4 } | { status: 'conflict' };
  markCommandDispatchStarted(commandId: string, dispatchStartedAt: string): PersistedCommandExecutionV4;
  recoverOrphanedCommandExecutions(): number;
  markCommandOutcomeUnknown(commandId: string): PersistedCommandExecutionV4;
  persistTerminalReceiptBlocked(commandId: string, terminalResult: CommandResult): PersistedCommandExecutionV4;
  persistTerminalCommandReceipt(
    commandId: string,
    terminalResult: CommandResult,
    outbox: CommandReceiptOutboxInputV1,
  ): PersistedCommandExecutionV4;
  markCommandReceiptOutbox(commandId: string, state: 'acknowledged' | 'undeliverable'): PersistedCommandExecutionV4;
}
