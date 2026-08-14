import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const nestedPublicRoot = resolve(process.cwd(), 'open-source/ariava');
const publicRoot = existsSync(resolve(process.cwd(), 'apps/bridge')) ? process.cwd() : nestedPublicRoot;
const temp = mkdtempSync(join(tmpdir(), 'ariava-command-vector-'));
const output = resolve(publicRoot, 'apps/bridge/src', `.command-vector-${process.pid}-${Date.now()}.mjs`);
try {
  const entry = join(temp, 'entry.ts');
  writeFileSync(entry, `
    import assert from 'node:assert/strict';
    import { mkdirSync, rmSync } from 'node:fs';
    import { tmpdir } from 'node:os';
    import { join } from 'node:path';
    import { base64UrlEncode } from '${resolve(publicRoot, 'packages/protocol/src/index.ts').replaceAll('\\', '/')}';
    import { BridgeDaemon } from '${resolve(publicRoot, 'apps/bridge/src/daemon.ts').replaceAll('\\', '/')}';
    import { prepareCommandForExecution } from '${resolve(publicRoot, 'apps/bridge/src/e2e/command-execution.ts').replaceAll('\\', '/')}';
    import { BridgeStateStore } from '${resolve(publicRoot, 'apps/bridge/src/state-store.ts').replaceAll('\\', '/')}';
    import {
      createDeterministicCommandKeyringHarness, createDeterministicEncryptedCommand, tamperCiphertext,
      withDeterministicCommandTime,
    } from '${resolve(publicRoot, 'apps/bridge/test/fixtures/command-execution-keyring.ts').replaceAll('\\', '/')}';

    const roots = [];
    const root = (name) => {
      const path = join(tmpdir(), 'ariava-node-command-' + name + '-' + crypto.randomUUID());
      roots.push(path);
      mkdirSync(path, { recursive: true, mode: 0o700 });
      return path;
    };
    const commandFor = (harness, type) => structuredClone(harness[type]);
    const daemonFor = (name, keyring, command) => {
      const dir = root(name);
      const config = {
        hostId: command.hostId, hostName: 'Node vector Host', hostPlatform: 'linux',
        relayBaseUrl: 'http://relay.invalid', statePath: join(dir, 'state.json'), identityPath: join(dir, 'identity.json'),
        configPath: join(dir, 'config.json'), runtimePlatform: 'linux', pollIntervalMs: 60_000, bridgeVersion: '0.0.0-test',
        agentAdapter: { port: 0, secret: 'test-secret', configPath: join(dir, 'adapter.json') },
      };
      const daemon = new BridgeDaemon(config, []);
      const stateStore = daemon.stateStore;
      stateStore.initializeEncryptedSpool(config.hostId, config.identityPath, 'linux', {
        loadOrCreate: () => new Uint8Array(32).fill(7),
      });
      stateStore.validateCommandExecutionPins(keyring);
      let claimCalls = 0;
      const claimCommandExecution = stateStore.claimCommandExecution.bind(stateStore);
      stateStore.claimCommandExecution = (...args) => {
        claimCalls += 1;
        return claimCommandExecution(...args);
      };
      let routerCalls = 0;
      let dispatchCallbacks = 0;
      daemon.keyring = {
        prepare: keyring.prepare.bind(keyring),
        resolveCommandReceiptPinStatus: keyring.resolveCommandReceiptPinStatus.bind(keyring),
        reconcileRecipients: () => [],
        listActive: () => [],
        pruneRetiring: keyring.pruneRetiring.bind(keyring),
        resolvePinMaterial: keyring.resolvePinMaterial.bind(keyring),
      };
      daemon.relayClient = {
        recipientSnapshot: async () => ({ hostId: command.hostId, recipientSetVersion: 1, recipients: [] }),
        pullCommands: async () => [command],
      };
      daemon.router = { handle: async (_command, options) => {
        routerCalls += 1;
        options.beforeDispatch();
        dispatchCallbacks += 1;
        throw new Error('rejected command reached dispatch');
      } };
      return { daemon, stateStore, effects: () => ({ claimCalls, routerCalls, dispatchCallbacks }) };
    };
    const alteredKeyId = (character) => 'ekey_' + character.repeat(43);
    const invalidCases = [
      ['issuance-after-retiring', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'), 'retiring');
        return { harness, command: await createDeterministicEncryptedCommand(type, {
          issuedAt: harness.pin.retiringAt, expiresAt: '2026-08-12T00:05:00.000Z',
        }), code: 'e2e_epoch_unauthorized' };
      }],
      ['host-key-substitution', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        harness.mutateRuntimePin((pin) => { pin.hostBinding = {
          ...pin.hostBinding, encryptionKeyId: harness.globalCurrentHost.encryptionKeyId,
          publicKey: harness.globalCurrentHost.publicKey, sequence: harness.globalCurrentHost.sequence,
          createdAt: harness.globalCurrentHost.createdAt,
        }; });
        return { harness, command: commandFor(harness, type), code: 'e2e_epoch_unauthorized' };
      }],
      ['wrong-host-private-identity', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        harness.replaceHistoricalIdentity({ ...harness.historicalHost,
          privateKeyPkcs8: new Uint8Array(harness.globalCurrentHost.privateKeyPkcs8) });
        return { harness, command: commandFor(harness, type), code: 'e2e_payload_invalid' };
      }],
      ['watch-binding-substitution', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        harness.mutateRuntimePin((pin) => {
          pin.watchBinding = { ...pin.hostBinding, entityType: 'watch', entityId: pin.watchDeviceId };
        });
        return { harness, command: commandFor(harness, type), code: 'e2e_epoch_unauthorized' };
      }],
      ['watch-public-key-substitution', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        harness.mutateRuntimePin((pin) => { pin.watchBinding.publicKey = harness.historicalHost.publicKey; });
        return { harness, command: commandFor(harness, type), code: 'e2e_payload_invalid' };
      }],
      ['transcript-substitution', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        harness.mutateRuntimePin((pin) => { pin.transcriptDigest = base64UrlEncode(new Uint8Array(32).fill(19)); });
        return { harness, command: commandFor(harness, type), code: 'e2e_payload_invalid' };
      }],
      ['global-current-key-substitution', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        const command = commandFor(harness, type);
        command.payload.keyWrap.recipientEncryptionKeyId = harness.globalCurrentHost.encryptionKeyId;
        return { harness, command, code: 'e2e_epoch_unauthorized' };
      }],
      ['aead-content-mutation', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        return { harness, command: tamperCiphertext(commandFor(harness, type), 'content'), code: 'e2e_payload_invalid' };
      }],
      ['aead-wrap-mutation', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        return { harness, command: tamperCiphertext(commandFor(harness, type), 'wrap'), code: 'e2e_payload_invalid' };
      }],
      ['expired', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        return { harness, command: await createDeterministicEncryptedCommand(type, {
          issuedAt: '2026-08-11T23:59:00.000Z', expiresAt: '2026-08-12T00:00:59.999Z',
        }), code: 'e2e_epoch_unauthorized' };
      }],
      ['ttl-invalid', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        const command = commandFor(harness, type);
        command.expiresAt = '2026-08-12T00:05:00.001Z';
        return { harness, command, code: 'e2e_payload_invalid' };
      }],
      ['missing-pin', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        const command = commandFor(harness, type);
        command.linkId = 'link_missing';
        command.payload.keyWrap.linkId = command.linkId;
        return { harness, command, code: 'e2e_epoch_unauthorized' };
      }],
      ['revoked-pin', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'), 'revoked');
        return { harness, command: commandFor(harness, type), code: 'e2e_epoch_unauthorized' };
      }],
      ['sender-key-id-mismatch', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        const command = commandFor(harness, type);
        command.payload.keyWrap.senderEncryptionKeyId = alteredKeyId('A');
        return { harness, command, code: 'e2e_epoch_unauthorized' };
      }],
      ['recipient-key-id-mismatch', async (type, name) => {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        const command = commandFor(harness, type);
        command.payload.keyWrap.recipientEncryptionKeyId = alteredKeyId('B');
        return { harness, command, code: 'e2e_epoch_unauthorized' };
      }],
    ];

    try {
      const accepted = {};
      for (const type of ['reply', 'interrupt']) {
        const active = await createDeterministicCommandKeyringHarness(join(root(type + '-active'), 'keyring.json'));
        assert.notEqual(active.historicalHost.encryptionKeyId, active.globalCurrentHost.encryptionKeyId);
        const activeResult = await withDeterministicCommandTime(() =>
          prepareCommandForExecution(commandFor(active, type), active.keyring));
        assert.equal(activeResult.ok, true);
        assert.equal(activeResult.prepared.loopbackCommand.type, type);
        assert.equal(activeResult.prepared.pinReference.hostEncryptionKeyId, active.historicalHost.encryptionKeyId);
        assert.notEqual(activeResult.prepared.pinReference.hostEncryptionKeyId, active.globalCurrentHost.encryptionKeyId);
        if (type === 'reply') assert.equal(activeResult.prepared.loopbackCommand.payload.text, 'continue safely');

        const retiring = await createDeterministicCommandKeyringHarness(join(root(type + '-retiring'), 'keyring.json'), 'retiring');
        const allowedRetiring = await createDeterministicEncryptedCommand(type, {
          issuedAt: '2026-08-12T00:02:59.999Z', expiresAt: '2026-08-12T00:05:00.000Z',
        });
        const retiringResult = await withDeterministicCommandTime(() =>
          prepareCommandForExecution(allowedRetiring, retiring.keyring));
        assert.equal(retiringResult.ok, true);
        assert.equal(retiringResult.prepared.loopbackCommand.type, type);
        accepted[type] = { active: true, retiringBeforeBoundary: true, historicalHostKey: true };
      }

      const rejectedWithoutEffects = [];
      for (const type of ['reply', 'interrupt']) {
        for (const [caseName, build] of invalidCases) {
          const name = type + '-' + caseName;
          const { harness, command, code } = await build(type, name);
          const preparation = await withDeterministicCommandTime(() =>
            prepareCommandForExecution(command, harness.keyring));
          assert.deepEqual(preparation, { ok: false, code }, name + ' preparation result');
          const pipeline = daemonFor(name, harness.keyring, command);
          await withDeterministicCommandTime(async () => {
            assert.deepEqual(await pipeline.daemon.pullAndHandleCommands(), [], name + ' daemon result');
          });
          assert.deepEqual(pipeline.effects(), { claimCalls: 0, routerCalls: 0, dispatchCallbacks: 0 }, name + ' effects');
          assert.equal(pipeline.stateStore.listCommandExecutions().length, 0, name + ' durable claims');
          rejectedWithoutEffects.push(name);
          pipeline.daemon.stop();
        }
      }

      const active = await createDeterministicCommandKeyringHarness(join(root('pipeline'), 'keyring.json'));
      const pipelineCommands = [active.reply, active.interrupt];
      const pipeline = daemonFor('pipeline', active.keyring, pipelineCommands[0]);
      pipeline.daemon.relayClient = {
        recipientSnapshot: async () => ({ hostId: pipelineCommands[0].hostId, recipientSetVersion: 1, recipients: [] }),
        pullCommands: async () => pipelineCommands,
        submitCommandReceipt: async () => { throw new Error('retain pending receipt'); },
      };
      let dispatches = 0;
      pipeline.daemon.router = { handle: async (command, options) => {
        await options.beforeDispatch();
        dispatches += 1;
        return { result: { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
          accepted: true, status: 'executed', updatedAt: '2026-08-12T00:00:01.000Z' }, followUpEvents: [] };
      } };
      await withDeterministicCommandTime(async () => {
        const results = await pipeline.daemon.pullAndHandleCommands();
        assert.equal(results.length, 2);
      });
      assert.equal(dispatches, 2);
      assert.equal(pipeline.stateStore.listCommandExecutions().length, 2);
      for (const execution of pipeline.stateStore.listCommandExecutions()) {
        assert.equal(execution.state, 'terminal');
        assert.equal(execution.receiptOutbox?.state, 'pending');
      }
      pipeline.daemon.stop();
      process.stdout.write(JSON.stringify({
        accepted,
        invalidCasesPerCommand: invalidCases.length,
        rejectedWithoutEffects,
        totalInvalidPreparations: rejectedWithoutEffects.length,
        terminalBoundary: 'terminal-pending-receipt',
      }));
    } finally {
      for (const path of roots) rmSync(path, { recursive: true, force: true });
    }
  `);
  const built = spawnSync('bun', ['build', entry, '--outfile', output, '--target', 'node', '--format', 'esm', '--external', 'none'], {
    cwd: publicRoot, encoding: 'utf8', env: process.env,
  });
  if (built.status !== 0) {
    throw new Error(`Bun bundle failed (${built.status ?? built.signal ?? built.error?.message ?? 'unknown'}): ${built.stderr || built.stdout || 'no output'}`);
  }
  await import(pathToFileURL(output).href);
} finally {
  rmSync(temp, { recursive: true, force: true });
  rmSync(output, { force: true });
}
