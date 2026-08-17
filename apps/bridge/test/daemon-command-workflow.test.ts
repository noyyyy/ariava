import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  deriveCommandReceiptDigest,
  deriveEncryptedCommandDigest,
  type CommandReceiptEnvelopeV1,
  type CommandResult,
  type E2ERecipientSnapshotV1,
  type EncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import { BridgeStateStore } from '../src/state-store';
import type { CommandWorkflowStateStore } from '../src/e2e/command-workflow-store';
import type { LocalLinkKeyring, PinRetentionReferences } from '../src/e2e/link-keyring';
import type { CommandReceiptOutboxInputV1, PersistedCommandExecutionV4 } from '../src/types';
import {
  performCommandPullAndDispatch,
  performReconciledReceiptDrain,
  pruneCommandRuntime,
  recoverStartupCommandPipeline,
  refreshCommandAuthority,
  type CommandWorkflowDependencies,
  type CommandWorkflowRelayClient,
  type CommandWorkflowRouter,
} from '../src/daemon/command-workflow';
import fixture from '../../../packages/protocol/test/fixtures/command-e2e-v1-vectors.json';

/**
 * Focused runner tests for the Task 6B command workflow extraction (plan
 * `2026-08-16-bridge-daemon-lifecycle-decomposition.md`, spec §3.1/§8/§9):
 * the linear command effect bodies — authority refresh, startup orphan/
 * blocked/outbox recovery, reconciled receipt drain, pruning/pin-retention
 * merge, and pull/dispatch — behind the explicit stateless dependency
 * contract, independently of `BridgeDaemon` single-flight/timer/stop state.
 * Order, early returns, and error semantics are asserted directly.
 */

const FIXED_NOW = '2026-08-12T00:00:00.000Z';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function terminalResult(command: EncryptedCommandEnvelopeV1): CommandResult {
  return { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
    accepted: true, status: 'executed', updatedAt: '2026-08-12T00:00:01.000Z' };
}

function pinReferenceFor(command: EncryptedCommandEnvelopeV1) {
  return {
    version: 1 as const, linkId: command.linkId, linkGeneration: command.linkGeneration, epoch: command.epoch,
    transcriptDigest: 'T'.repeat(43), hostEncryptionKeyId: command.payload.keyWrap.recipientEncryptionKeyId,
    watchEncryptionKeyId: command.payload.keyWrap.senderEncryptionKeyId,
  };
}

async function receiptOutbox(
  execution: PersistedCommandExecutionV4 & { terminalResult: CommandResult },
): Promise<CommandReceiptOutboxInputV1> {
  const command = execution.originalEncryptedCommand;
  const receipt: CommandReceiptEnvelopeV1 = {
    version: 1, hostId: command.hostId, watchDeviceId: command.watchDeviceId, sessionId: command.sessionId,
    commandId: command.commandId, commandType: command.type, commandDigest: execution.commandDigest,
    completedAt: execution.terminalResult.updatedAt, linkId: execution.pinReference.linkId,
    linkGeneration: execution.pinReference.linkGeneration, epoch: execution.pinReference.epoch,
    content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'receipt-1',
      payloadKind: 'command-receipt-content-v1', nonce: 'A'.repeat(16), ciphertext: 'B'.repeat(192) },
    keyWrap: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'receipt-1',
      linkId: execution.pinReference.linkId, linkGeneration: execution.pinReference.linkGeneration,
      epoch: execution.pinReference.epoch, senderEncryptionKeyId: execution.pinReference.hostEncryptionKeyId,
      recipientEncryptionKeyId: execution.pinReference.watchEncryptionKeyId,
      nonce: 'C'.repeat(16), ciphertext: 'D'.repeat(64) },
  };
  return { receipt, canonicalBody: JSON.stringify(receipt), receiptDigest: await deriveCommandReceiptDigest(receipt) };
}

async function outboxFor(
  stateStore: CommandWorkflowStateStore,
  commandId: string,
  terminal: CommandResult,
): Promise<CommandReceiptOutboxInputV1> {
  const execution = stateStore.getCommandExecution(commandId)!;
  return receiptOutbox({ ...execution, terminalResult: terminal });
}

interface CommandWorkflowHarness {
  deps: CommandWorkflowDependencies;
  stateStore: CommandWorkflowStateStore;
  command: EncryptedCommandEnvelopeV1;
  keyring: Record<string, (...args: any[]) => unknown>;
  relay: Record<string, (...args: any[]) => unknown>;
  router: Record<string, (...args: any[]) => unknown>;
  order: string[];
  snapshot: E2ERecipientSnapshotV1;
  terminal: CommandResult;
}

function createHarness(overrides: {
  recipients?: E2ERecipientSnapshotV1['recipients'];
  recipientSetVersion?: number;
  activePins?: Array<{ linkId: string; linkGeneration: number; epoch: number; watchDeviceId: string; watchBinding: { encryptionKeyId: string } }>;
  stopped?: boolean;
} = {}): CommandWorkflowHarness {
  const root = join(tmpdir(), `command-workflow-runner-${crypto.randomUUID()}`);
  roots.push(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const statePath = join(root, 'state.json');
  const identityPath = join(root, 'identity.json');
  const command = { ...structuredClone(fixture.interrupt.envelope),
    issuedAt: '2026-08-12T00:00:00.000Z', expiresAt: '2026-08-12T00:05:00.000Z',
  } as EncryptedCommandEnvelopeV1;
  const stateStore = new BridgeStateStore(statePath);
  stateStore.initializeEncryptedSpool(command.hostId, identityPath, 'linux', {
    loadOrCreate: () => new Uint8Array(32).fill(7),
  });
  stateStore.validateCommandExecutionPins({ resolvePinReference: () => undefined });
  const pinReference = pinReferenceFor(command);
  const order: string[] = [];
  const terminal = terminalResult(command);
  const keyring = {
    prepare: async (wire: EncryptedCommandEnvelopeV1) => ({ pinReference, loopbackCommand: {
      commandId: wire.commandId, hostId: wire.hostId, sessionId: wire.sessionId, type: wire.type,
      payload: {}, issuedAt: wire.issuedAt, expiresAt: wire.expiresAt, nonce: wire.nonce,
      watchDeviceId: wire.watchDeviceId,
    } }),
    resolveCommandReceiptPinStatus: () => 'deliverable' as const,
    reconcileRecipients: () => { order.push('keyring-reconcile'); return []; },
    listActive: () => overrides.activePins ?? [],
    pruneRetiring: (_references: PinRetentionReferences, now: string) => {
      order.push(`prune:${now}`);
      return [];
    },
  };
  const relay = {
    recipientSnapshot: async () => {
      order.push('authority-refresh');
      return { version: 1, hostId: command.hostId, recipientSetVersion: overrides.recipientSetVersion ?? 1,
        recipients: overrides.recipients ?? [] };
    },
    pullCommands: async () => { order.push('pull'); return []; },
    submitCommandReceipt: async () => { order.push('receipt-drain'); },
  };
  const router = { handle: async () => { order.push('dispatch'); return { result: terminal, followUpEvents: [] }; } };
  const deps: CommandWorkflowDependencies = {
    stateStore,
    keyring: keyring as unknown as LocalLinkKeyring,
    relayClient: () => relay as unknown as CommandWorkflowRelayClient,
    router: router as unknown as CommandWorkflowRouter,
    hostId: command.hostId,
    now: () => new Date(FIXED_NOW),
    receiptConstruction: {
      build: async (execution: PersistedCommandExecutionV4 & { terminalResult: CommandResult }) =>
        receiptOutbox(execution),
    },
    isStopped: () => overrides.stopped ?? false,
    markOutcomeUnknownIfActive: (commandId) => {
      const execution = stateStore.getCommandExecution(commandId);
      if (!execution || execution.state === 'outcome_unknown' || (overrides.stopped ?? false)) return;
      if (execution.state === 'claimed' || execution.state === 'dispatch_started') {
        stateStore.markCommandOutcomeUnknown(commandId);
      }
    },
    refreshAuthority: () => refreshCommandAuthority(deps),
    prune: (now) => pruneCommandRuntime(deps, now ?? FIXED_NOW),
  };
  return { deps, stateStore, command, keyring, relay, router, order,
    snapshot: { version: 1, hostId: command.hostId, recipientSetVersion: 1, recipients: [] }, terminal };
}

async function claimAndDispatch(harness: CommandWorkflowHarness): Promise<void> {
  const { stateStore, command } = harness;
  stateStore.claimCommandExecution({
    originalEncryptedCommand: command,
    commandDigest: await deriveEncryptedCommandDigest(command),
    pinReference: pinReferenceFor(command),
    claimedAt: '2026-08-12T00:00:00.500Z',
  });
  stateStore.markCommandDispatchStarted(command.commandId, '2026-08-12T00:00:00.750Z');
}

async function seedTerminalReceipt(harness: CommandWorkflowHarness): Promise<string> {
  await claimAndDispatch(harness);
  const outbox = await outboxFor(harness.stateStore, harness.command.commandId, harness.terminal);
  harness.stateStore.persistTerminalCommandReceipt(harness.command.commandId, harness.terminal, outbox);
  return outbox.canonicalBody;
}

describe('refreshCommandAuthority runner', () => {
  test('accepts a healthy snapshot, reconciles the keyring, and persists the version in order', async () => {
    const harness = createHarness({ recipientSetVersion: 2 });
    const result = await refreshCommandAuthority(harness.deps);
    expect(result.recipientSetVersion).toBe(2);
    expect(harness.stateStore.getRecipientSetVersion()).toBe(2);
    expect(harness.order).toEqual(['authority-refresh', 'keyring-reconcile']);
  });

  test('rejects a version rollback before any reconcile or version write', async () => {
    const harness = createHarness();
    harness.stateStore.setRecipientSetVersion(2);
    harness.relay.recipientSnapshot = async () => {
      harness.order.push('authority-refresh');
      return { ...harness.snapshot, recipientSetVersion: 1 };
    };
    const error = await refreshCommandAuthority(harness.deps).then(() => null, (caught: unknown) => caught);
    expect(error).toBeInstanceOf(TypeError);
    expect((error as TypeError).message).toBe('recipient snapshot rollback rejected');
    expect(harness.stateStore.getRecipientSetVersion()).toBe(2);
    expect(harness.order).toEqual(['authority-refresh']);
  });

  test('rejects a same-version recipient-set conflict before any reconcile or version write', async () => {
    const pin = { linkId: 'link-1', linkGeneration: 1, epoch: 0, watchDeviceId: 'watch-1',
      watchBinding: { encryptionKeyId: 'key-watch' } };
    const harness = createHarness({ recipientSetVersion: 1, activePins: [pin] });
    harness.stateStore.setRecipientSetVersion(1);
    const error = await refreshCommandAuthority(harness.deps).then(() => null, (caught: unknown) => caught);
    expect(error).toBeInstanceOf(TypeError);
    expect((error as TypeError).message).toBe('recipient snapshot version conflict rejected');
    expect(harness.stateStore.getRecipientSetVersion()).toBe(1);
    expect(harness.order).toEqual(['authority-refresh']);
  });

  test('accepts a same-version snapshot whose recipients match the active pins', async () => {
    const pin = { linkId: 'link-1', linkGeneration: 1, epoch: 0, watchDeviceId: 'watch-1',
      watchBinding: { encryptionKeyId: 'key-watch' } };
    const harness = createHarness({ recipientSetVersion: 1, activePins: [pin] });
    harness.stateStore.setRecipientSetVersion(1);
    harness.relay.recipientSnapshot = async () => {
      harness.order.push('authority-refresh');
      return { ...harness.snapshot, recipientSetVersion: 1, recipients: [{
        linkId: 'link-1', linkGeneration: 1, epoch: 0, watchDeviceId: 'watch-1',
        state: 'active' as const, watchBinding: { encryptionKeyId: 'key-watch' },
      }] };
    };
    await expect(refreshCommandAuthority(harness.deps)).resolves.toMatchObject({ recipientSetVersion: 1 });
    expect(harness.order).toEqual(['authority-refresh', 'keyring-reconcile']);
  });
});

describe('pruneCommandRuntime runner', () => {
  test('prunes executions before merging references and retiring pins, passing the merged map and exact now', async () => {
    const harness = createHarness();
    const stateStore = harness.stateStore as BridgeStateStore;
    stateStore.durableContentPinRetentionReferences = (now: string) => {
      harness.order.push(`durable:${now}`);
      // Older timestamp for the shared key; also carries a durable-only key.
      return { contentRetainedThrough: {
        'link-1:1:0': '2026-08-12T00:00:01.000Z', 'link-2:1:0': '2026-08-12T00:00:05.000Z',
      } };
    };
    stateStore.commandExecutionPinRetentionReferences = () => {
      harness.order.push('execution-refs');
      // Newer timestamp for the shared key (link-1), a newer durable-only key
      // (link-2), and a forwarded execution-only category.
      return {
        contentRetainedThrough: { 'link-2:1:0': '2026-08-12T00:00:03.000Z', 'link-1:1:0': '2026-08-12T00:00:02.000Z' },
        pendingOutboxRetainedThrough: { 'link-1:1:0': '2026-08-12T00:00:02.000Z' },
      };
    };
    const originalPrune = stateStore.pruneEligibleCommandExecutions.bind(stateStore);
    stateStore.pruneEligibleCommandExecutions = (now: string) => {
      harness.order.push(`execution:${now}`);
      return originalPrune(now);
    };
    let received: PinRetentionReferences | undefined;
    let receivedNow: string | undefined;
    harness.keyring.pruneRetiring = (references: PinRetentionReferences, now: string) => {
      harness.order.push(`prune:${now}`);
      received = references;
      receivedNow = now;
      return [];
    };
    pruneCommandRuntime(harness.deps, '2026-08-12T00:00:03.000Z');
    expect(harness.order).toEqual([
      'execution:2026-08-12T00:00:03.000Z', 'durable:2026-08-12T00:00:03.000Z', 'execution-refs',
      'prune:2026-08-12T00:00:03.000Z',
    ]);
    // Overlapping same category/key: the later timestamp wins in either source
    // order (execution newer for link-1, durable newer for link-2); keys and
    // categories present in only one input are forwarded unchanged.
    expect(received).toEqual({
      contentRetainedThrough: {
        'link-1:1:0': '2026-08-12T00:00:02.000Z',
        'link-2:1:0': '2026-08-12T00:00:05.000Z',
      },
      pendingOutboxRetainedThrough: { 'link-1:1:0': '2026-08-12T00:00:02.000Z' },
    });
    // Category order follows first-observation order across the merged inputs.
    expect(Object.keys(received!)).toEqual(['contentRetainedThrough', 'pendingOutboxRetainedThrough']);
    expect(receivedNow).toBe('2026-08-12T00:00:03.000Z');
  });
});

describe('recoverStartupCommandPipeline runner', () => {
  test('runs refresh → orphan recovery → blocked recovery → outbox drain → prune in exact order', async () => {
    const harness = createHarness();
    const canonicalBody = await seedTerminalReceipt(harness);
    // Orphan reality: claimed but never dispatched; startup marks it outcome_unknown.
    await harness.stateStore.claimCommandExecution({
      originalEncryptedCommand: { ...harness.command, commandId: 'command_orphan', nonce: 'nonce_orphan' },
      commandDigest: await deriveEncryptedCommandDigest({ ...harness.command, commandId: 'command_orphan', nonce: 'nonce_orphan' }),
      pinReference: pinReferenceFor(harness.command),
      claimedAt: '2026-08-12T00:00:00.100Z',
    });
    // Blocked reality: terminal result persisted without a receipt; startup
    // rebuilds it through receiptConstruction.build (records 'blocked-recover').
    const blockedTerminal = { ...harness.terminal, commandId: 'command_blocked' };
    await harness.stateStore.claimCommandExecution({
      originalEncryptedCommand: { ...harness.command, commandId: 'command_blocked', nonce: 'nonce_blocked' },
      commandDigest: await deriveEncryptedCommandDigest({ ...harness.command, commandId: 'command_blocked', nonce: 'nonce_blocked' }),
      pinReference: pinReferenceFor(harness.command),
      claimedAt: '2026-08-12T00:00:00.200Z',
    });
    harness.stateStore.persistTerminalReceiptBlocked('command_blocked', blockedTerminal);
    const blockedBody = (await outboxFor(harness.stateStore, 'command_blocked', blockedTerminal)).canonicalBody;
    const stateStore = harness.stateStore as BridgeStateStore;
    const originalRecover = stateStore.recoverOrphanedCommandExecutions.bind(stateStore);
    stateStore.recoverOrphanedCommandExecutions = () => {
      harness.order.push('orphan-recover');
      return originalRecover();
    };
    harness.deps.receiptConstruction = {
      build: async (execution: PersistedCommandExecutionV4 & { terminalResult: CommandResult }) => {
        harness.order.push('blocked-recover');
        return receiptOutbox(execution);
      },
    };
    const submissions: string[] = [];
    harness.relay.submitCommandReceipt = async (body: string) => {
      harness.order.push('receipt-drain');
      submissions.push(body);
    };

    await recoverStartupCommandPipeline(harness.deps);

    expect(harness.order).toEqual([
      'authority-refresh', 'keyring-reconcile', 'orphan-recover', 'blocked-recover',
      'receipt-drain', 'receipt-drain', 'prune:2026-08-12T00:00:00.000Z',
    ]);
    // Orphan recovery: durable outcome_unknown.
    expect(harness.stateStore.getCommandExecution('command_orphan')).toMatchObject({ state: 'outcome_unknown' });
    // Blocked recovery + drain: durable terminal with an acknowledged receipt.
    expect(harness.stateStore.getCommandExecution('command_blocked')).toMatchObject({
      state: 'terminal', terminalResult: blockedTerminal, receiptOutbox: { state: 'acknowledged', canonicalBody: blockedBody },
    });
    // Pre-existing pending receipt drains: acknowledged with its exact body.
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)?.receiptOutbox).toMatchObject({
      state: 'acknowledged', canonicalBody,
    });
    // Drain order follows the startup pipeline's claimedAt ordering.
    expect(submissions).toEqual([blockedBody, canonicalBody]);
  });

  test('propagates an authority refresh failure before any recovery, drain, or prune effect', async () => {
    const harness = createHarness();
    await seedTerminalReceipt(harness);
    harness.relay.recipientSnapshot = async () => {
      harness.order.push('authority-refresh');
      throw new Error('offline');
    };
    await expect(recoverStartupCommandPipeline(harness.deps)).rejects.toThrow('offline');
    expect(harness.order).toEqual(['authority-refresh']);
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)?.receiptOutbox?.state).toBe('pending');
  });
});

describe('performReconciledReceiptDrain runner', () => {
  test('returns 0 without any Relay call when no terminal receipt is pending', async () => {
    const harness = createHarness();
    expect(await performReconciledReceiptDrain(harness.deps)).toBe(0);
    expect(harness.order).toEqual([]);
  });

  test('freezes on authority refresh failure without submitting any receipt', async () => {
    const harness = createHarness();
    await seedTerminalReceipt(harness);
    harness.relay.recipientSnapshot = async () => {
      harness.order.push('authority-refresh');
      throw new Error('offline');
    };
    expect(await performReconciledReceiptDrain(harness.deps)).toBe(0);
    expect(harness.order).toEqual(['authority-refresh']);
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)?.receiptOutbox?.state).toBe('pending');
  });

  test('drains the pending outbox after a healthy refresh', async () => {
    const harness = createHarness();
    const canonicalBody = await seedTerminalReceipt(harness);
    const submissions: string[] = [];
    harness.relay.submitCommandReceipt = async (body: string) => {
      harness.order.push('receipt-drain');
      submissions.push(body);
    };
    expect(await performReconciledReceiptDrain(harness.deps)).toBe(1);
    expect(harness.order).toEqual(['authority-refresh', 'keyring-reconcile', 'receipt-drain']);
    expect(submissions).toEqual([canonicalBody]);
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)?.receiptOutbox).toMatchObject({
      state: 'acknowledged', canonicalBody,
    });
  });
});

describe('performCommandPullAndDispatch runner', () => {
  test('performs the exact serial effect order and returns the terminal result', async () => {
    const harness = createHarness();
    harness.relay.pullCommands = async () => {
      harness.order.push('pull');
      return [harness.command];
    };
    harness.router.handle = async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch();
      harness.order.push('dispatch');
      return { result: harness.terminal, followUpEvents: [] };
    };
    harness.deps.receiptConstruction = {
      build: async (execution: PersistedCommandExecutionV4 & { terminalResult: CommandResult }) =>
        receiptOutbox(execution),
      hooks: { afterTerminalWrite: () => harness.order.push('persist') },
    };

    expect(await performCommandPullAndDispatch(harness.deps)).toEqual([harness.terminal]);

    expect(harness.order).toEqual([
      'authority-refresh', 'keyring-reconcile', 'prune:2026-08-12T00:00:00.000Z', 'pull', 'dispatch',
      'authority-refresh', 'keyring-reconcile', 'persist', 'receipt-drain', 'prune:2026-08-12T00:00:00.000Z',
    ]);
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)).toMatchObject({
      state: 'terminal', terminalResult: harness.terminal, receiptOutbox: { state: 'acknowledged' },
    });
  });

  test('freezes the whole pass on authority refresh failure without pull or dispatch', async () => {
    const harness = createHarness();
    harness.relay.recipientSnapshot = async () => {
      harness.order.push('authority-refresh');
      throw new Error('offline');
    };
    harness.relay.pullCommands = async () => {
      harness.order.push('pull');
      return [harness.command];
    };
    expect(await performCommandPullAndDispatch(harness.deps)).toEqual([]);
    expect(harness.order).toEqual(['authority-refresh']);
  });

  test('recovers blocked receipts and drains them before the pull', async () => {
    const harness = createHarness();
    await claimAndDispatch(harness);
    harness.stateStore.persistTerminalReceiptBlocked(harness.command.commandId, harness.terminal);
    const canonicalBody = (await outboxFor(harness.stateStore, harness.command.commandId, harness.terminal)).canonicalBody;
    const submissions: string[] = [];
    harness.relay.submitCommandReceipt = async (body: string) => {
      harness.order.push('receipt-drain');
      submissions.push(body);
    };
    harness.relay.pullCommands = async () => {
      harness.order.push('pull');
      return [];
    };
    harness.deps.receiptConstruction = {
      build: async (execution: PersistedCommandExecutionV4 & { terminalResult: CommandResult }) =>
        receiptOutbox(execution),
      hooks: { beforeBuild: () => harness.order.push('blocked-recover') },
    };

    expect(await performCommandPullAndDispatch(harness.deps)).toEqual([]);

    expect(harness.order).toEqual([
      'authority-refresh', 'keyring-reconcile', 'blocked-recover', 'receipt-drain',
      'prune:2026-08-12T00:00:00.000Z', 'pull',
    ]);
    expect(submissions).toEqual([canonicalBody]);
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)).toMatchObject({
      state: 'terminal', receiptOutbox: { state: 'acknowledged' },
    });
  });

  test('marks an active dispatch outcome_unknown on a post-dispatch throw and continues', async () => {
    const harness = createHarness();
    harness.relay.pullCommands = async () => [harness.command];
    harness.router.handle = async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch();
      throw new Error('private driver failure');
    };
    expect(await performCommandPullAndDispatch(harness.deps)).toEqual([]);
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)).toMatchObject({ state: 'outcome_unknown' });
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)).not.toHaveProperty('terminalResult');
  });

  test('turns an invalid post-dispatch result into outcome_unknown when dispatch started', async () => {
    const harness = createHarness();
    harness.relay.pullCommands = async () => [harness.command];
    harness.router.handle = async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch();
      return { result: { ...harness.terminal, message: 'forbidden' }, followUpEvents: [] };
    };
    expect(await performCommandPullAndDispatch(harness.deps)).toEqual([]);
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)).toMatchObject({ state: 'outcome_unknown' });
  });

  test('skips terminal handling entirely when stopped after dispatch', async () => {
    const harness = createHarness({ stopped: true });
    harness.relay.pullCommands = async () => [harness.command];
    harness.router.handle = async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch();
      return { result: harness.terminal, followUpEvents: [] };
    };
    expect(await performCommandPullAndDispatch(harness.deps)).toEqual([]);
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)).toMatchObject({ state: 'dispatch_started' });
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)).not.toHaveProperty('terminalResult');
    // The post-terminal authority refresh never runs.
    expect(harness.order.filter((entry) => entry === 'authority-refresh')).toHaveLength(1);
  });

  test('persists terminal_receipt_blocked and returns the result when post-terminal authority refresh fails', async () => {
    const harness = createHarness();
    harness.relay.pullCommands = async () => [harness.command];
    harness.router.handle = async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch();
      return { result: harness.terminal, followUpEvents: [] };
    };
    let snapshotReads = 0;
    harness.relay.recipientSnapshot = async () => {
      harness.order.push('authority-refresh');
      snapshotReads += 1;
      if (snapshotReads === 2) throw new Error('concurrent unlink authority unavailable');
      return { version: 1, hostId: harness.command.hostId, recipientSetVersion: 1, recipients: [] };
    };
    expect(await performCommandPullAndDispatch(harness.deps)).toEqual([harness.terminal]);
    expect(snapshotReads).toBe(2);
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)).toMatchObject({
      state: 'terminal_receipt_blocked', terminalResult: harness.terminal,
    });
    expect(harness.stateStore.getCommandExecution(harness.command.commandId)).not.toHaveProperty('receiptOutbox');
  });

  test('throws on a relay replay nonce or body conflict after dispatching the earlier command', async () => {
    const harness = createHarness();
    const rebound = { ...structuredClone(harness.command), commandId: `${harness.command.commandId}_rebound` };
    let dispatches = 0;
    harness.relay.pullCommands = async () => [harness.command, rebound];
    harness.router.handle = async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch();
      dispatches += 1;
      return { result: harness.terminal, followUpEvents: [] };
    };
    await expect(performCommandPullAndDispatch(harness.deps)).rejects.toThrow('Relay command replay nonce or body conflict');
    expect(dispatches).toBe(1);
  });
});
