import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  deriveCommandReceiptDigest,
  deriveEncryptedCommandDigest,
  type CommandReceiptEnvelopeV1,
  type CommandResult,
  type EncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import {
  drainPendingCommandReceipts,
  persistTerminalCommandResult,
  recoverBlockedCommandReceipts,
} from '../src/e2e/command-receipt-recovery';
import type { LocalLinkKeyring } from '../src/e2e/link-keyring';
import { BridgeStateStore } from '../src/state-store';
import type {
  CommandReceiptOutboxInputV1,
  PersistedCommandExecutionV4,
  PersistedCommandPinReferenceV1,
} from '../src/types';
import fixture from '../../../packages/protocol/test/fixtures/command-e2e-v1-vectors.json';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function harness() {
  const root = join(tmpdir(), `command-receipt-recovery-${crypto.randomUUID()}`);
  roots.push(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const statePath = join(root, 'state.json');
  const identityPath = join(root, 'identity.json');
  const command = structuredClone(fixture.interrupt.envelope) as EncryptedCommandEnvelopeV1;
  const pinReference: PersistedCommandPinReferenceV1 = {
    version: 1,
    linkId: command.linkId,
    linkGeneration: command.linkGeneration,
    epoch: command.epoch,
    transcriptDigest: 'T'.repeat(43),
    hostEncryptionKeyId: command.payload.keyWrap.recipientEncryptionKeyId,
    watchEncryptionKeyId: command.payload.keyWrap.senderEncryptionKeyId,
  };
  const keyring = {} as LocalLinkKeyring;
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
  const result: CommandResult = {
    commandId: command.commandId,
    hostId: command.hostId,
    sessionId: command.sessionId,
    accepted: true,
    status: 'executed',
    updatedAt: '2026-08-12T00:00:01.000Z',
  };
  return { root, statePath, identityPath, store, keyring, command, pinReference, result };
}

function builder(counter: { count: number }): (
  execution: PersistedCommandExecutionV4 & { terminalResult: CommandResult },
  keyring: LocalLinkKeyring,
) => Promise<CommandReceiptOutboxInputV1> {
  return async (execution) => {
    counter.count += 1;
    const command = execution.originalEncryptedCommand;
    const contentId = `receipt-${counter.count}`;
    const receipt: CommandReceiptEnvelopeV1 = {
      version: 1,
      hostId: command.hostId,
      watchDeviceId: command.watchDeviceId,
      sessionId: command.sessionId,
      commandId: command.commandId,
      commandType: command.type,
      commandDigest: execution.commandDigest,
      completedAt: execution.terminalResult.updatedAt,
      linkId: execution.pinReference.linkId,
      linkGeneration: execution.pinReference.linkGeneration,
      epoch: execution.pinReference.epoch,
      content: {
        version: 1,
        suite: 'x25519-hkdf-sha256-chachapoly-v1',
        contentId,
        payloadKind: 'command-receipt-content-v1',
        nonce: 'A'.repeat(16),
        ciphertext: 'B'.repeat(192),
      },
      keyWrap: {
        version: 1,
        suite: 'x25519-hkdf-sha256-chachapoly-v1',
        contentId,
        linkId: execution.pinReference.linkId,
        linkGeneration: execution.pinReference.linkGeneration,
        epoch: execution.pinReference.epoch,
        senderEncryptionKeyId: execution.pinReference.hostEncryptionKeyId,
        recipientEncryptionKeyId: execution.pinReference.watchEncryptionKeyId,
        nonce: 'C'.repeat(16),
        ciphertext: 'D'.repeat(64),
      },
    };
    return { receipt, canonicalBody: JSON.stringify(receipt), receiptDigest: await deriveCommandReceiptDigest(receipt) };
  };
}

function stateBytes(path: string): Buffer {
  return readFileSync(path);
}

describe('command receipt terminal construction and recovery', () => {
  test('persists exact terminal outbox atomically and never constructs it again', async () => {
    const value = await harness();
    const builds = { count: 0 };
    const hooks: string[] = [];
    const status = await persistTerminalCommandResult(
      value.store, value.keyring, value.command.commandId, value.result,
      {
        build: builder(builds),
        hooks: {
          beforeBuild: () => hooks.push('before-build'),
          afterEncryptionBeforeWrite: () => hooks.push('after-encryption'),
          afterTerminalWrite: () => hooks.push('after-terminal'),
        },
      },
    );
    const terminal = value.store.getCommandExecution(value.command.commandId)!;
    expect(status).toBe('terminal');
    expect(hooks).toEqual(['before-build', 'after-encryption', 'after-terminal']);
    expect(terminal).toMatchObject({ state: 'terminal', terminalResult: value.result, receiptOutbox: { state: 'pending' } });
    expect(JSON.stringify(JSON.parse(terminal.receiptOutbox!.canonicalBody))).toBe(terminal.receiptOutbox!.canonicalBody);
    const frozen = stateBytes(value.statePath);
    expect(await recoverBlockedCommandReceipts(value.store, value.keyring, {
      build: async () => { builds.count += 1; throw new Error('terminal must not rebuild'); },
    })).toBe(0);
    expect(builds.count).toBe(1);
    expect(stateBytes(value.statePath)).toEqual(frozen);
    value.store.dispose();
  });

  test('failure persists exact blocked result and restart retry may create fresh ciphertext', async () => {
    const value = await harness();
    let failedBuilds = 0;
    await expect(persistTerminalCommandResult(
      value.store, value.keyring, value.command.commandId, value.result,
      {
        build: async () => { failedBuilds += 1; throw new Error('key unavailable'); },
        hooks: { afterBlockedWrite: () => { throw new Error('crash-after-blocked-write'); } },
      },
    )).rejects.toThrow('crash-after-blocked-write');
    expect(value.store.getCommandExecution(value.command.commandId)).toMatchObject({
      state: 'terminal_receipt_blocked', terminalResult: value.result,
    });
    const blocked = stateBytes(value.statePath);
    value.store.dispose();

    const restarted = new BridgeStateStore(value.statePath, undefined, { deferRuntimePreflight: true });
    restarted.initializeEncryptedSpool(value.command.hostId, value.identityPath, 'linux', {
      loadOrCreate: () => new Uint8Array(32).fill(7),
    });
    restarted.validateCommandExecutionPins({ resolvePinReference: () => value.pinReference });
    const attempts = { count: 0 };
    const attemptedBodies: string[] = [];
    await expect(recoverBlockedCommandReceipts(restarted, value.keyring, {
      build: builder(attempts),
      hooks: { afterEncryptionBeforeWrite: (_commandId, outbox) => {
        attemptedBodies.push(outbox.canonicalBody);
        throw new Error('crash-after-encryption');
      } },
    })).rejects.toThrow('crash-after-encryption');
    expect(stateBytes(value.statePath)).toEqual(blocked);
    expect(restarted.getCommandExecution(value.command.commandId)?.state).toBe('terminal_receipt_blocked');
    expect(await recoverBlockedCommandReceipts(restarted, value.keyring, {
      build: builder(attempts),
      hooks: { afterEncryptionBeforeWrite: (_commandId, outbox) => attemptedBodies.push(outbox.canonicalBody) },
    })).toBe(1);
    expect(attemptedBodies).toHaveLength(2);
    expect(attemptedBodies[1]).not.toBe(attemptedBodies[0]);
    expect(restarted.getCommandExecution(value.command.commandId)).toMatchObject({
      state: 'terminal', terminalResult: value.result, receiptOutbox: { state: 'pending', canonicalBody: attemptedBodies[1] },
    });
    expect(failedBuilds).toBe(1);
    restarted.dispose();
  });

  test('before-build crash leaves blocked bytes unchanged and never dispatches', async () => {
    const value = await harness();
    let dispatches = 0;
    await persistTerminalCommandResult(value.store, value.keyring, value.command.commandId, value.result, {
      build: async () => { throw new Error('construction failed'); },
    });
    const blocked = stateBytes(value.statePath);
    await expect(recoverBlockedCommandReceipts(value.store, value.keyring, {
      hooks: { beforeBuild: () => { throw new Error('crash-before-build'); } },
    })).rejects.toThrow('crash-before-build');
    expect(stateBytes(value.statePath)).toEqual(blocked);
    expect(dispatches).toBe(0);
    value.store.dispose();
  });

  test('after-terminal-write crash keeps exact durable body and suppresses reconstruction', async () => {
    const value = await harness();
    const builds = { count: 0 };
    await expect(persistTerminalCommandResult(
      value.store, value.keyring, value.command.commandId, value.result,
      {
        build: builder(builds),
        hooks: { afterTerminalWrite: () => { throw new Error('crash-after-terminal-write'); } },
      },
    )).rejects.toThrow('crash-after-terminal-write');
    const frozen = stateBytes(value.statePath);
    expect(value.store.getCommandExecution(value.command.commandId)?.state).toBe('terminal');
    expect(await recoverBlockedCommandReceipts(value.store, value.keyring, {
      build: async () => { builds.count += 1; throw new Error('must not rebuild'); },
    })).toBe(0);
    expect(builds.count).toBe(1);
    expect(stateBytes(value.statePath)).toEqual(frozen);
    value.store.dispose();
  });

  test('missing, revoked, or unlinked pin leaves blocked state byte-identical', async () => {
    for (const availability of ['missing', 'revoked', 'unlinked'] as const) {
      const value = await harness();
      await persistTerminalCommandResult(value.store, value.keyring, value.command.commandId, value.result, {
        build: async () => { throw new Error('construction failed'); },
      });
      const blocked = stateBytes(value.statePath);
      expect(await recoverBlockedCommandReceipts(value.store, value.keyring, {
        build: async () => { throw new Error(`${availability} pin`); },
      })).toBe(0);
      expect(stateBytes(value.statePath)).toEqual(blocked);
      expect(value.store.getCommandExecution(value.command.commandId)).toMatchObject({
        state: 'terminal_receipt_blocked', terminalResult: value.result,
      });
      value.store.dispose();
    }
  });
  test('drains success atomically and retries network failure after restart with exact bytes', async () => {
    const value = await harness();
    await persistTerminalCommandResult(value.store, value.keyring, value.command.commandId, value.result, {
      build: builder({ count: 0 }),
    });
    const body = value.store.getCommandExecution(value.command.commandId)!.receiptOutbox!.canonicalBody;
    const keyring = { resolveCommandReceiptPinStatus: () => 'deliverable' as const } as LocalLinkKeyring;
    const attempts: string[] = [];
    const logged: string[] = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => { logged.push(String(chunk)); return true; }) as typeof process.stderr.write;
    try {
      expect(await drainPendingCommandReceipts(value.store, keyring, {
        submitCommandReceipt: async (canonicalBody) => { attempts.push(canonicalBody); throw new Error('network'); },
      })).toBe(0);
    } finally {
      process.stderr.write = originalWrite;
    }
    expect(logged).toEqual([]);
    expect(value.store.getCommandExecution(value.command.commandId)?.receiptOutbox?.state).toBe('pending');
    value.store.dispose();

    const restarted = new BridgeStateStore(value.statePath, undefined, { deferRuntimePreflight: true });
    restarted.initializeEncryptedSpool(value.command.hostId, value.identityPath, 'linux', {
      loadOrCreate: () => new Uint8Array(32).fill(7),
    });
    restarted.validateCommandExecutionPins({ resolvePinReference: () => value.pinReference });
    expect(await drainPendingCommandReceipts(restarted, keyring, {
      submitCommandReceipt: async (canonicalBody) => { attempts.push(canonicalBody); },
    })).toBe(1);
    expect(attempts).toEqual([body, body]);
    expect(restarted.getCommandExecution(value.command.commandId)?.receiptOutbox).toMatchObject({
      state: 'acknowledged', canonicalBody: body,
    });
    expect(body).not.toContain('correlationId');
    expect(body).not.toContain('plaintext');
    restarted.dispose();
  });

  test('crash after Relay success retries a byte-identical receipt', async () => {
    const value = await harness();
    await persistTerminalCommandResult(value.store, value.keyring, value.command.commandId, value.result, {
      build: builder({ count: 0 }),
    });
    const body = value.store.getCommandExecution(value.command.commandId)!.receiptOutbox!.canonicalBody;
    const attempts: string[] = [];
    const keyring = { resolveCommandReceiptPinStatus: () => 'deliverable' as const } as LocalLinkKeyring;
    await expect(drainPendingCommandReceipts(value.store, keyring, {
      submitCommandReceipt: async (canonicalBody) => { attempts.push(canonicalBody); },
    }, { afterSubmitBeforeAcknowledge: () => { throw new Error('crash-after-http'); } })).rejects.toThrow('crash-after-http');
    expect(value.store.getCommandExecution(value.command.commandId)?.receiptOutbox?.state).toBe('pending');
    expect(await drainPendingCommandReceipts(value.store, keyring, {
      submitCommandReceipt: async (canonicalBody) => { attempts.push(canonicalBody); },
    })).toBe(1);
    expect(attempts).toEqual([body, body]);
    value.store.dispose();
  });

  test('explicit revocation is undeliverable without HTTP while missing pin stays pending', async () => {
    for (const [status, expected] of [['revoked', 'undeliverable'], ['unavailable', 'pending']] as const) {
      const value = await harness();
      await persistTerminalCommandResult(value.store, value.keyring, value.command.commandId, value.result, {
        build: builder({ count: 0 }),
      });
      const body = value.store.getCommandExecution(value.command.commandId)!.receiptOutbox!.canonicalBody;
      let submissions = 0;
      expect(await drainPendingCommandReceipts(value.store, {
        resolveCommandReceiptPinStatus: () => status,
      } as LocalLinkKeyring, { submitCommandReceipt: async () => { submissions += 1; } })).toBe(status === 'revoked' ? 1 : 0);
      expect(submissions).toBe(0);
      expect(value.store.getCommandExecution(value.command.commandId)?.receiptOutbox).toMatchObject({
        state: expected, canonicalBody: body,
      });
      value.store.dispose();
    }
  });

});
