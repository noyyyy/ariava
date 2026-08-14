import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveCommandReceiptDigest,
  deriveEncryptedCommandDigest,
} from '../../../packages/protocol/dist/index.js';
import vectors from '../../../packages/protocol/test/fixtures/command-e2e-v1-vectors.json' with { type: 'json' };
import { BridgeStateStore } from '../dist/state-store.js';

const bundledRecoveryPath = resolve('apps/bridge/src', `.node-receipt-recovery-${process.pid}.mjs`);
const bundle = spawnSync('bun', [
  'build', './apps/bridge/src/e2e/command-receipt-recovery.ts',
  '--outfile', bundledRecoveryPath, '--target', 'node', '--format', 'esm', '--external', 'none',
], { cwd: process.cwd(), env: process.env, encoding: 'utf8' });
assert.equal(bundle.status, 0, bundle.stderr || bundle.stdout);
const {
  drainPendingCommandReceipts,
  persistTerminalCommandResult,
  recoverBlockedCommandReceipts,
} = await import(pathToFileURL(bundledRecoveryPath).href);
rmSync(bundledRecoveryPath, { force: true });

const roots = [];
test.afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function harness(name) {
  const root = mkdtempSync(join(tmpdir(), `ariava-node-receipt-${name}-`));
  roots.push(root);
  const statePath = join(root, 'state.json');
  const identityPath = join(root, 'identity.json');
  const command = structuredClone(vectors.interrupt.envelope);
  command.commandId = `${command.commandId}_${name}`;
  command.nonce = `${command.nonce}_${name}`;
  const pinReference = {
    version: 1,
    linkId: command.linkId,
    linkGeneration: command.linkGeneration,
    epoch: command.epoch,
    transcriptDigest: 'T'.repeat(43),
    hostEncryptionKeyId: command.payload.keyWrap.recipientEncryptionKeyId,
    watchEncryptionKeyId: command.payload.keyWrap.senderEncryptionKeyId,
  };
  const store = new BridgeStateStore(statePath);
  store.initializeEncryptedSpool(command.hostId, identityPath, 'linux', {
    loadOrCreate: () => new Uint8Array(32).fill(7),
  });
  store.validateCommandExecutionPins({ resolvePinReference: () => pinReference });
  store.claimCommandExecution({
    originalEncryptedCommand: command,
    commandDigest: await deriveEncryptedCommandDigest(command),
    pinReference,
    claimedAt: '2026-08-12T00:00:00.500Z',
  });
  store.markCommandDispatchStarted(command.commandId, '2026-08-12T00:00:00.750Z');
  return {
    root, statePath, identityPath, store, command, pinReference,
    result: {
      commandId: command.commandId,
      hostId: command.hostId,
      sessionId: command.sessionId,
      accepted: true,
      status: 'executed',
      updatedAt: '2026-08-12T00:00:01.000Z',
    },
  };
}

function fixedBuilder() {
  return async (execution) => {
    const receipt = structuredClone(vectors.receipt.envelope);
    Object.assign(receipt, {
      commandId: execution.originalEncryptedCommand.commandId,
      commandDigest: execution.commandDigest,
      completedAt: execution.terminalResult.updatedAt,
    });
    const canonicalBody = JSON.stringify(receipt);
    return { receipt, canonicalBody, receiptDigest: await deriveCommandReceiptDigest(receipt) };
  };
}

test('blocked receipt recovers atomically and network retry or restart preserves exact outbox bytes', async () => {
  const value = await harness('retry');
  assert.equal(await persistTerminalCommandResult(
    value.store, {}, value.command.commandId, value.result,
    { build: async () => { throw new Error('historical pin temporarily unavailable'); } },
  ), 'terminal_receipt_blocked');
  const blockedBytes = readFileSync(value.statePath);
  const blockedExecution = JSON.parse(blockedBytes.toString()).commandExecutions[value.command.commandId];
  assert.equal(blockedExecution.state, 'terminal_receipt_blocked');
  assert.equal(blockedExecution.receiptOutbox, undefined);

  assert.equal(await recoverBlockedCommandReceipts(value.store, {}, { build: fixedBuilder() }), 1);
  const terminal = value.store.getCommandExecution(value.command.commandId);
  assert.equal(terminal.state, 'terminal');
  assert.equal(terminal.receiptOutbox.state, 'pending');
  const canonicalBody = terminal.receiptOutbox.canonicalBody;
  const terminalBytes = readFileSync(value.statePath);

  const attempts = [];
  const deliverableKeyring = { resolveCommandReceiptPinStatus: () => 'deliverable' };
  assert.equal(await drainPendingCommandReceipts(value.store, deliverableKeyring, {
    submitCommandReceipt: async (body) => { attempts.push(body); throw new Error('network'); },
  }), 0);
  assert.deepEqual(readFileSync(value.statePath), terminalBytes);
  assert.equal(value.store.getCommandExecution(value.command.commandId).receiptOutbox.state, 'pending');
  value.store.dispose();

  const restarted = new BridgeStateStore(value.statePath, undefined, { deferRuntimePreflight: true });
  restarted.initializeEncryptedSpool(value.command.hostId, value.identityPath, 'linux', {
    loadOrCreate: () => new Uint8Array(32).fill(7),
  });
  restarted.validateCommandExecutionPins({ resolvePinReference: () => value.pinReference });
  assert.equal(await drainPendingCommandReceipts(restarted, deliverableKeyring, {
    submitCommandReceipt: async (body) => { attempts.push(body); },
  }), 1);
  assert.deepEqual(attempts, [canonicalBody, canonicalBody]);
  assert.equal(restarted.getCommandExecution(value.command.commandId).receiptOutbox.state, 'acknowledged');
  assert.equal(restarted.getCommandExecution(value.command.commandId).receiptOutbox.canonicalBody, canonicalBody);
  restarted.dispose();
});

test('durable pending receipt becomes undeliverable without HTTP or byte retargeting', async () => {
  const value = await harness('revoked');
  assert.equal(await persistTerminalCommandResult(
    value.store, {}, value.command.commandId, value.result, { build: fixedBuilder() },
  ), 'terminal');
  const canonicalBody = value.store.getCommandExecution(value.command.commandId).receiptOutbox.canonicalBody;
  let submissions = 0;
  assert.equal(await drainPendingCommandReceipts(
    value.store,
    { resolveCommandReceiptPinStatus: () => 'revoked' },
    { submitCommandReceipt: async () => { submissions += 1; } },
  ), 1);
  assert.equal(submissions, 0);
  assert.equal(value.store.getCommandExecution(value.command.commandId).receiptOutbox.state, 'undeliverable');
  assert.equal(value.store.getCommandExecution(value.command.commandId).receiptOutbox.canonicalBody, canonicalBody);
  value.store.dispose();
});
