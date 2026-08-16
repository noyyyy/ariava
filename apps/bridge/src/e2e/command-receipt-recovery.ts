import type { CommandResult } from '@ariava/protocol';
import type { CommandWorkflowStateStore } from './command-workflow-store';
import type { CommandReceiptOutboxInputV1, PersistedCommandExecutionV4 } from '../types';
import { buildCommandReceipt, type CommandReceiptExecution } from './command-receipt';
import type { LocalLinkKeyring } from './link-keyring';

export interface CommandReceiptConstructionHooks {
  beforeBuild?(commandId: string): void;
  afterEncryptionBeforeWrite?(commandId: string, outbox: CommandReceiptOutboxInputV1): void;
  afterBlockedWrite?(commandId: string): void;
  afterTerminalWrite?(commandId: string, outbox: CommandReceiptOutboxInputV1): void;
}

export interface CommandReceiptConstructionDependencies {
  build?: typeof buildCommandReceipt;
  hooks?: CommandReceiptConstructionHooks;
}

export async function persistTerminalCommandResult(
  stateStore: CommandWorkflowStateStore,
  keyring: LocalLinkKeyring,
  commandId: string,
  terminalResult: CommandResult,
  dependencies: CommandReceiptConstructionDependencies = {},
): Promise<'terminal' | 'terminal_receipt_blocked'> {
  const execution = stateStore.getCommandExecution(commandId);
  if (!execution || (execution.state !== 'claimed' && execution.state !== 'dispatch_started')) {
    throw new TypeError('command execution cannot construct a terminal receipt from its current state');
  }
  const input = { ...execution, terminalResult: structuredClone(terminalResult) } as CommandReceiptExecution;
  dependencies.hooks?.beforeBuild?.(commandId);
  let outbox: CommandReceiptOutboxInputV1;
  try {
    outbox = await (dependencies.build ?? buildCommandReceipt)(input, keyring);
  } catch {
    stateStore.persistTerminalReceiptBlocked(commandId, terminalResult);
    dependencies.hooks?.afterBlockedWrite?.(commandId);
    return 'terminal_receipt_blocked';
  }
  dependencies.hooks?.afterEncryptionBeforeWrite?.(commandId, outbox);
  stateStore.persistTerminalCommandReceipt(commandId, terminalResult, outbox);
  dependencies.hooks?.afterTerminalWrite?.(commandId, outbox);
  return 'terminal';
}

export async function recoverBlockedCommandReceipts(
  stateStore: CommandWorkflowStateStore,
  keyring: LocalLinkKeyring,
  dependencies: CommandReceiptConstructionDependencies = {},
): Promise<number> {
  let recovered = 0;
  const blocked = stateStore.listCommandExecutions()
    .filter((execution): execution is CommandReceiptExecution =>
      execution.state === 'terminal_receipt_blocked' && execution.terminalResult !== undefined);
  for (const execution of blocked) {
    dependencies.hooks?.beforeBuild?.(execution.originalEncryptedCommand.commandId);
    let outbox: CommandReceiptOutboxInputV1;
    try {
      outbox = await (dependencies.build ?? buildCommandReceipt)(execution, keyring);
    } catch {
      continue;
    }
    dependencies.hooks?.afterEncryptionBeforeWrite?.(execution.originalEncryptedCommand.commandId, outbox);
    stateStore.persistTerminalCommandReceipt(execution.originalEncryptedCommand.commandId, execution.terminalResult, outbox);
    dependencies.hooks?.afterTerminalWrite?.(execution.originalEncryptedCommand.commandId, outbox);
    recovered += 1;
  }
  return recovered;
}

export interface PendingCommandReceiptRelayClient {
  submitCommandReceipt(canonicalBody: string): Promise<void>;
}

export interface CommandReceiptDrainHooks {
  afterSubmitBeforeAcknowledge?(commandId: string, canonicalBody: string): void;
}

export async function drainPendingCommandReceipts(
  stateStore: CommandWorkflowStateStore,
  keyring: LocalLinkKeyring,
  relayClient: PendingCommandReceiptRelayClient,
  hooks: CommandReceiptDrainHooks = {},
): Promise<number> {
  let drained = 0;
  const pending = stateStore.listCommandExecutions()
    .filter((execution) => execution.state === 'terminal' && execution.receiptOutbox?.state === 'pending')
    .sort((left, right) => left.claimedAt.localeCompare(right.claimedAt)
      || left.originalEncryptedCommand.commandId.localeCompare(right.originalEncryptedCommand.commandId));
  for (const execution of pending) {
    const commandId = execution.originalEncryptedCommand.commandId;
    const pinStatus = keyring.resolveCommandReceiptPinStatus(
      execution.pinReference, execution.originalEncryptedCommand.issuedAt,
    );
    if (pinStatus === 'revoked') {
      stateStore.markCommandReceiptOutbox(commandId, 'undeliverable');
      drained += 1;
      continue;
    }
    if (pinStatus !== 'deliverable') continue;
    const canonicalBody = execution.receiptOutbox!.canonicalBody;
    try {
      await relayClient.submitCommandReceipt(canonicalBody);
    } catch {
      continue;
    }
    hooks.afterSubmitBeforeAcknowledge?.(commandId, canonicalBody);
    stateStore.markCommandReceiptOutbox(commandId, 'acknowledged');
    drained += 1;
  }
  return drained;
}
