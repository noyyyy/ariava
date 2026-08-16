import type {
  CommandResult,
  EncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import {
  SIGNED_REQUEST_LIMITS,
  isCanonicalTimestamp,
} from '@ariava/protocol';
import type {
  CommandReceiptOutboxInputV1,
  PersistedBridgeState,
  PersistedCommandExecutionV4,
  PersistedCommandPinReferenceV1,
} from '../types';
import type { PinRetentionReferences } from '../e2e/link-keyring';
import type { StateTransition } from './state-transitions';
import {
  assertCommandExecution,
  assertReceiptOutboxForExecution,
  isNonEmptyString,
  isPositiveSafeInteger,
  isRecord,
} from './state-codec';

export const COMMAND_RECEIPT_RETENTION_DAYS = 30 as const;
export const COMMAND_RECEIPT_RETENTION_MS = COMMAND_RECEIPT_RETENTION_DAYS * 24 * 60 * 60 * 1_000;

export interface CommandExecutionPinResolver {
  resolvePinReference(linkId: string, linkGeneration: number, epoch: number): PersistedCommandPinReferenceV1 | undefined;
}

/** Deterministic durable command-execution calculations (spec §3.2, §6.1). */

function requireCommandExecution(state: PersistedBridgeState, commandId: string): PersistedCommandExecutionV4 {
  const execution = state.commandExecutions[commandId];
  if (!execution) throw new TypeError('command execution is not claimed');
  return structuredClone(execution);
}

function replaceCommandExecutionTransition(
  state: PersistedBridgeState, commandId: string, execution: PersistedCommandExecutionV4,
): StateTransition<PersistedCommandExecutionV4> {
  assertCommandExecution(execution);
  if (execution.originalEncryptedCommand.commandId !== commandId) throw new TypeError('command execution ID binding is invalid');
  const nextState = structuredClone(state);
  nextState.commandExecutions[commandId] = execution;
  return { state: nextState, result: structuredClone(execution) };
}

export function claimCommandExecutionTransition(
  state: PersistedBridgeState,
  input: {
    originalEncryptedCommand: EncryptedCommandEnvelopeV1; commandDigest: string;
    pinReference: PersistedCommandPinReferenceV1; claimedAt: string;
  },
): StateTransition<{ status: 'claimed' | 'duplicate'; execution: PersistedCommandExecutionV4 } | { status: 'conflict' }> {
  const candidate: PersistedCommandExecutionV4 = {
    version: 1, originalEncryptedCommand: structuredClone(input.originalEncryptedCommand),
    commandDigest: input.commandDigest, pinReference: structuredClone(input.pinReference),
    watchDeviceId: input.originalEncryptedCommand.watchDeviceId, nonce: input.originalEncryptedCommand.nonce,
    expiresAt: input.originalEncryptedCommand.expiresAt, state: 'claimed', claimedAt: input.claimedAt,
  };
  assertCommandExecution(candidate);
  const existing = state.commandExecutions[input.originalEncryptedCommand.commandId];
  if (existing) return sameCommandClaim(existing, candidate)
    ? { state, result: { status: 'duplicate', execution: structuredClone(existing) } }
    : { state, result: { status: 'conflict' } };
  if (Object.values(state.commandExecutions).some((execution) =>
    execution.watchDeviceId === candidate.watchDeviceId && execution.nonce === candidate.nonce)) {
    return { state, result: { status: 'conflict' } };
  }
  const nextState = structuredClone(state);
  nextState.commandExecutions[input.originalEncryptedCommand.commandId] = candidate;
  return { state: nextState, result: { status: 'claimed', execution: structuredClone(candidate) } };
}

export function markCommandDispatchStartedTransition(
  state: PersistedBridgeState, commandId: string, dispatchStartedAt: string,
): StateTransition<PersistedCommandExecutionV4> {
  const current = requireCommandExecution(state, commandId);
  if (current.state !== 'claimed') throw new TypeError('command execution cannot start dispatch from its current state');
  return replaceCommandExecutionTransition(state, commandId, { ...current, state: 'dispatch_started', dispatchStartedAt });
}

export function recoverOrphanedCommandExecutionsTransition(state: PersistedBridgeState): StateTransition<number> {
  const orphanIds = Object.entries(state.commandExecutions)
    .filter(([, execution]) => execution.state === 'claimed' || execution.state === 'dispatch_started')
    .map(([commandId]) => commandId);
  if (orphanIds.length === 0) return { state, result: 0 };
  const nextState = structuredClone(state);
  for (const commandId of orphanIds) nextState.commandExecutions[commandId] = {
    ...nextState.commandExecutions[commandId]!, state: 'outcome_unknown',
  };
  return { state: nextState, result: orphanIds.length };
}

export function markCommandOutcomeUnknownTransition(
  state: PersistedBridgeState, commandId: string,
): StateTransition<PersistedCommandExecutionV4> {
  const current = requireCommandExecution(state, commandId);
  if (current.state !== 'claimed' && current.state !== 'dispatch_started') {
    throw new TypeError('command execution cannot become outcome-unknown from its current state');
  }
  return replaceCommandExecutionTransition(state, commandId, { ...current, state: 'outcome_unknown' });
}

export function persistTerminalReceiptBlockedTransition(
  state: PersistedBridgeState, commandId: string, terminalResult: CommandResult,
): StateTransition<PersistedCommandExecutionV4> {
  const current = requireCommandExecution(state, commandId);
  if (current.state !== 'claimed' && current.state !== 'dispatch_started') {
    throw new TypeError('command execution cannot persist a terminal result from its current state');
  }
  return replaceCommandExecutionTransition(state, commandId, {
    ...current, state: 'terminal_receipt_blocked', terminalResult: structuredClone(terminalResult),
  });
}

export function persistTerminalCommandReceiptTransition(
  state: PersistedBridgeState, commandId: string, terminalResult: CommandResult, outbox: CommandReceiptOutboxInputV1,
): StateTransition<PersistedCommandExecutionV4> {
  const current = requireCommandExecution(state, commandId);
  if (current.state !== 'claimed' && current.state !== 'dispatch_started' && current.state !== 'terminal_receipt_blocked') {
    throw new TypeError('command execution cannot become terminal from its current state');
  }
  if (current.state === 'terminal_receipt_blocked' && JSON.stringify(current.terminalResult) !== JSON.stringify(terminalResult)) {
    throw new TypeError('terminal result is immutable');
  }
  assertReceiptOutboxForExecution(current, terminalResult, outbox);
  return replaceCommandExecutionTransition(state, commandId, {
    ...current, state: 'terminal', terminalResult: structuredClone(terminalResult),
    receiptOutbox: { version: 1, state: 'pending', canonicalBody: outbox.canonicalBody, receiptDigest: outbox.receiptDigest },
  });
}

export function markCommandReceiptOutboxTransition(
  state: PersistedBridgeState, commandId: string, outboxState: 'acknowledged' | 'undeliverable',
): StateTransition<PersistedCommandExecutionV4> {
  const current = requireCommandExecution(state, commandId);
  if (current.state !== 'terminal' || !current.receiptOutbox || current.receiptOutbox.state !== 'pending') {
    throw new TypeError('command receipt outbox cannot transition from its current state');
  }
  return replaceCommandExecutionTransition(state, commandId, {
    ...current, receiptOutbox: { ...current.receiptOutbox, state: outboxState },
  });
}

export function pruneEligibleCommandExecutionsTransition(
  state: PersistedBridgeState, now: string,
): StateTransition<PersistedCommandExecutionV4[]> {
  if (!isCanonicalTimestamp(now)) throw new TypeError('command execution prune clock is invalid');
  const eligible = Object.entries(state.commandExecutions)
    .filter(([, execution]) => commandExecutionRetainedThrough(execution) < now);
  if (eligible.length === 0) return { state, result: [] };
  const nextState = structuredClone(state);
  for (const [commandId] of eligible) delete nextState.commandExecutions[commandId];
  return { state: nextState, result: eligible.map(([, execution]) => structuredClone(execution)) };
}

export function validateCommandExecutionPinsState(
  state: PersistedBridgeState, resolver: CommandExecutionPinResolver,
  options: { allowUnavailableForTerminal?: boolean } = {},
): void {
  for (const execution of Object.values(state.commandExecutions)) {
    const expected = execution.pinReference;
    const actual = resolver.resolvePinReference(expected.linkId, expected.linkGeneration, expected.epoch);
    if (!actual && options.allowUnavailableForTerminal
      && (execution.state === 'terminal_receipt_blocked' || execution.state === 'terminal')) continue;
    if (!actual || JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error('Bridge runtime command execution pin reference is unavailable or inconsistent');
    }
  }
}

export function readCommandExecutionPinRetentionReferences(state: PersistedBridgeState): PinRetentionReferences {
  const references: PinRetentionReferences = {};
  for (const execution of Object.values(state.commandExecutions)) {
    const key = `${execution.pinReference.linkId}:${execution.pinReference.linkGeneration}:${execution.pinReference.epoch}`;
    const category = commandExecutionRetentionCategory(execution);
    const retainThrough = commandExecutionRetainedThrough(execution);
    const values = references[category] ?? {};
    values[key] = laterCanonicalTimestamp(values[key], retainThrough);
    references[category] = values;
  }
  return references;
}

export function collectEncryptedUploadPinReferences(
  value: unknown, references: Record<string, string>, retainThrough: string,
): void {
  if (!isRecord(value)) return;
  for (const nested of Object.values(value)) {
    if (Array.isArray(nested)) {
      for (const item of nested) collectEncryptedUploadPinReferences(item, references, retainThrough);
      continue;
    }
    if (!isRecord(nested)) continue;
    if (isNonEmptyString(nested.linkId) && isPositiveSafeInteger(nested.linkGeneration) && isPositiveSafeInteger(nested.epoch)) {
      const key = `${nested.linkId}:${nested.linkGeneration}:${nested.epoch}`;
      references[key] = laterCanonicalTimestamp(references[key], retainThrough);
    }
    collectEncryptedUploadPinReferences(nested, references, retainThrough);
  }
}

export function sameCommandClaim(left: PersistedCommandExecutionV4, right: PersistedCommandExecutionV4): boolean {
  return left.commandDigest === right.commandDigest
    && JSON.stringify(left.originalEncryptedCommand) === JSON.stringify(right.originalEncryptedCommand)
    && JSON.stringify(left.pinReference) === JSON.stringify(right.pinReference);
}

function commandExecutionRetainedThrough(execution: PersistedCommandExecutionV4): string {
  if (execution.state === 'claimed' || execution.state === 'dispatch_started' || execution.state === 'outcome_unknown') {
    return addMilliseconds(execution.expiresAt, SIGNED_REQUEST_LIMITS.clockSkewMs, 'command execution expiry');
  }
  if (!execution.terminalResult) throw new TypeError('terminal command execution retention is noncanonical');
  return addMilliseconds(execution.terminalResult.updatedAt, COMMAND_RECEIPT_RETENTION_MS, 'command receipt retention');
}

function addMilliseconds(timestamp: string, durationMs: number, label: string): string {
  if (!isCanonicalTimestamp(timestamp)) throw new TypeError(`${label} timestamp is invalid`);
  const value = Date.parse(timestamp) + durationMs;
  if (!Number.isFinite(value)) throw new TypeError(`${label} timestamp is invalid`);
  return new Date(value).toISOString();
}

function laterCanonicalTimestamp(left: string | undefined, right: string): string {
  return left && left > right ? left : right;
}

function commandExecutionRetentionCategory(
  execution: PersistedCommandExecutionV4,
): keyof PinRetentionReferences {
  if (execution.state === 'claimed' || execution.state === 'dispatch_started' || execution.state === 'outcome_unknown') {
    return 'executionRetainedThrough';
  }
  if (execution.state === 'terminal_receipt_blocked') return 'terminalReceiptRetainedThrough';
  if (execution.receiptOutbox?.state === 'pending') return 'pendingOutboxRetainedThrough';
  if (execution.receiptOutbox?.state === 'undeliverable') return 'undeliverableOutboxRetainedThrough';
  return 'terminalReceiptRetainedThrough';
}
