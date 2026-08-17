import {
  validateCommandResult,
  type CommandEnvelope,
  type CommandResult,
  type E2ERecipientSnapshotV1,
  type EncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import { prepareCommandForExecution } from '../e2e/command-execution';
import {
  drainPendingCommandReceipts,
  persistTerminalCommandResult,
  recoverBlockedCommandReceipts,
  type CommandReceiptConstructionDependencies,
} from '../e2e/command-receipt-recovery';
import type { CommandWorkflowStateStore } from '../e2e/command-workflow-store';
import type { LocalLinkKeyring, PinRetentionReferences } from '../e2e/link-keyring';
import type { CommandHandlingOutcome } from '../types';

/**
 * Narrow command workflow effect runner (spec §5 `command-workflow.ts`, plan
 * Task 6). Contains only the linear command effect bodies — authority refresh,
 * startup orphan/blocked/outbox recovery, reconciled receipt drain, pruning/
 * pin-retention merge, and pull/dispatch — behind one explicit stateless
 * dependency contract. The daemon retains everything else about commands
 * (spec §8): command/receipt single-flight state (`commandFlightActive`,
 * `receiptDrainFlight`), termination/stop checks (`isStopped`/
 * `markOutcomeUnknownIfActive`), the command clock, timers, runtime ownership
 * of the keyring/relay/router, and the nullable-keyring acquisition guards.
 */
export interface CommandWorkflowRelayClient {
  recipientSnapshot(): Promise<E2ERecipientSnapshotV1>;
  pullCommands(hostId: string, limit?: number): Promise<EncryptedCommandEnvelopeV1[]>;
  submitCommandReceipt(canonicalBody: string): Promise<void>;
}

export interface CommandWorkflowRouter {
  handle(command: CommandEnvelope, options?: { beforeDispatch?: () => void | Promise<void> }): Promise<CommandHandlingOutcome>;
}

export interface CommandWorkflowDependencies {
  stateStore: CommandWorkflowStateStore;
  keyring: LocalLinkKeyring;
  /** Lazily resolved so `client()` faults happen at the exact baseline call points. */
  relayClient(): CommandWorkflowRelayClient;
  router: CommandWorkflowRouter;
  hostId: string;
  /** Command clock; called per use exactly as the daemon field was. */
  now(): Date;
  receiptConstruction: CommandReceiptConstructionDependencies;
  /** Lifecycle signal: the daemon is stopping; skip post-dispatch terminal handling. */
  isStopped(): boolean;
  /** Daemon-owned stop-guarded outcome_unknown transition for an active execution. */
  markOutcomeUnknownIfActive(commandId: string): void;
  /** Authority refresh seam that runs through the daemon's instance method. */
  refreshAuthority(): Promise<E2ERecipientSnapshotV1>;
  /** Prune seam that runs through the daemon's instance method. */
  prune(now?: string): void;
}

/**
 * Refreshes command authority from the Relay snapshot with the exact baseline
 * contract: version rollback and same-version recipient-set conflicts reject
 * before any reconcile or version write; a healthy snapshot reconciles the
 * keyring and persists the recipient-set version.
 */
export async function refreshCommandAuthority(
  deps: CommandWorkflowDependencies,
): Promise<E2ERecipientSnapshotV1> {
  const snapshot = await deps.relayClient().recipientSnapshot();
  const acceptedVersion = deps.stateStore.getRecipientSetVersion();
  if (acceptedVersion !== undefined && snapshot.recipientSetVersion < acceptedVersion) {
    throw new TypeError('recipient snapshot rollback rejected');
  }
  if (acceptedVersion === snapshot.recipientSetVersion) {
    const active = deps.keyring.listActive().map((pin) =>
      `${pin.linkId}:${pin.linkGeneration}:${pin.epoch}:${pin.watchDeviceId}:${pin.watchBinding.encryptionKeyId}`).sort();
    const received = snapshot.recipients.map((recipient) =>
      `${recipient.linkId}:${recipient.linkGeneration}:${recipient.epoch}:${recipient.watchDeviceId}:${recipient.watchBinding.encryptionKeyId}`).sort();
    if (JSON.stringify(active) !== JSON.stringify(received)) {
      throw new TypeError('recipient snapshot version conflict rejected');
    }
  }
  deps.keyring.reconcileRecipients(snapshot);
  deps.stateStore.setRecipientSetVersion(snapshot.recipientSetVersion);
  return snapshot;
}

/**
 * Prunes eligible command executions first, merges the durable-content and
 * command-execution pin retention references, then prunes retiring pins/keys
 * with the exact baseline order.
 */
export function pruneCommandRuntime(deps: CommandWorkflowDependencies, now: string): void {
  deps.stateStore.pruneEligibleCommandExecutions(now);
  const references = mergePinRetentionReferences(
    deps.stateStore.durableContentPinRetentionReferences(now),
    deps.stateStore.commandExecutionPinRetentionReferences(),
  );
  deps.keyring.pruneRetiring(references, now);
}

/**
 * Best-effort startup command recovery pipeline: authoritative snapshot first,
 * then orphan recovery, blocked-receipt recovery, receipt outbox drain, and
 * pruning. Any failure propagates so the caller can freeze recovery until an
 * authoritative snapshot succeeds.
 */
export async function recoverStartupCommandPipeline(deps: CommandWorkflowDependencies): Promise<void> {
  await deps.refreshAuthority();
  deps.stateStore.recoverOrphanedCommandExecutions();
  await recoverBlockedCommandReceipts(deps.stateStore, deps.keyring, deps.receiptConstruction);
  await drainPendingCommandReceipts(deps.stateStore, deps.keyring, deps.relayClient());
  deps.prune();
}

/**
 * Reconciled receipt outbox drain: skips immediately without any Relay call
 * when no pending terminal receipt exists, freezes on authority-refresh
 * failure, and otherwise drains the outbox.
 */
export async function performReconciledReceiptDrain(deps: CommandWorkflowDependencies): Promise<number> {
  if (!deps.stateStore.listCommandExecutions().some((execution) =>
    execution.state === 'terminal' && execution.receiptOutbox?.state === 'pending')) return 0;
  try {
    await deps.refreshAuthority();
  } catch {
    return 0;
  }
  return drainPendingCommandReceipts(deps.stateStore, deps.keyring, deps.relayClient());
}

/**
 * The exact single-flight command pull/dispatch effect body: authority refresh
 * (freezing the whole pass on failure), blocked-receipt recovery, outbox
 * drain, pruning, pull, then per-command prepare → atomic claim → dispatch →
 * terminal/unknown split → post-terminal authority refresh → exact receipt
 * persist → outbox drain → prune. Uncertain post-dispatch paths only reach
 * `outcome_unknown`; an unavailable terminal receipt construction becomes
 * `terminal_receipt_blocked`, never a guessed failure receipt.
 */
export async function performCommandPullAndDispatch(deps: CommandWorkflowDependencies): Promise<CommandResult[]> {
  try {
    await deps.refreshAuthority();
  } catch {
    return [];
  }
  await recoverBlockedCommandReceipts(deps.stateStore, deps.keyring, deps.receiptConstruction);
  await drainPendingCommandReceipts(deps.stateStore, deps.keyring, deps.relayClient());
  deps.prune();
  const commands = await deps.relayClient().pullCommands(deps.hostId);
  const handled: CommandResult[] = [];
  for (const encrypted of commands) {
    const preparation = await prepareCommandForExecution(encrypted, deps.keyring, deps.now);
    if (!preparation.ok) continue;
    const { prepared } = preparation;
    const claim = deps.stateStore.claimCommandExecution({
      originalEncryptedCommand: prepared.originalEncryptedCommand, commandDigest: prepared.commandDigest,
      pinReference: prepared.pinReference, claimedAt: deps.now().toISOString(),
    });
    if (claim.status === 'conflict') throw new Error('Relay command replay nonce or body conflict');
    if (claim.status === 'duplicate') continue;
    let dispatchStarted = false;
    let terminalResult: CommandResult | undefined;
    try {
      const outcome = await deps.router.handle(prepared.loopbackCommand, { beforeDispatch: () => {
        deps.stateStore.markCommandDispatchStarted(encrypted.commandId, deps.now().toISOString());
        dispatchStarted = true;
      } });
      if (!validateCommandResult(outcome.result)) {
        if (dispatchStarted) deps.markOutcomeUnknownIfActive(encrypted.commandId);
        continue;
      }
      terminalResult = outcome.result;
    } catch {
      deps.markOutcomeUnknownIfActive(encrypted.commandId);
      continue;
    }
    if (deps.isStopped()) continue;
    try {
      await deps.refreshAuthority();
    } catch {
      deps.stateStore.persistTerminalReceiptBlocked(encrypted.commandId, terminalResult);
      handled.push(terminalResult);
      continue;
    }
    await persistTerminalCommandResult(
      deps.stateStore, deps.keyring, encrypted.commandId, terminalResult, deps.receiptConstruction,
    );
    await drainPendingCommandReceipts(deps.stateStore, deps.keyring, deps.relayClient());
    deps.prune();
    handled.push(terminalResult);
  }
  return handled;
}

/**
 * Merges pin retention references by keeping the latest retention timestamp
 * per category/key across all inputs.
 */
function mergePinRetentionReferences(...inputs: PinRetentionReferences[]): PinRetentionReferences {
  const merged: PinRetentionReferences = {};
  for (const input of inputs) {
    for (const [category, values] of Object.entries(input) as Array<
      [keyof PinRetentionReferences, Record<string, string> | undefined]
    >) {
      if (!values) continue;
      const target = merged[category] ?? {};
      for (const [key, timestamp] of Object.entries(values)) {
        if (!target[key] || target[key]! < timestamp) target[key] = timestamp;
      }
      merged[category] = target;
    }
  }
  return merged;
}
