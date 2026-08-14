import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const nestedPublicRoot = resolve(process.cwd(), 'open-source/ariava');
const publicRoot = existsSync(resolve(process.cwd(), 'apps/bridge')) ? process.cwd() : nestedPublicRoot;
const temp = mkdtempSync(join(tmpdir(), 'ariava-command-receipt-'));
const output = resolve(publicRoot, 'apps/bridge/src', `.command-receipt-${process.pid}-${Date.now()}.mjs`);
try {
  const entry = join(temp, 'entry.ts');
  writeFileSync(entry, `
    import assert from 'node:assert/strict';
    import { mkdirSync, rmSync } from 'node:fs';
    import { tmpdir } from 'node:os';
    import { join } from 'node:path';
    import {
      E2E_LIMITS, base64UrlDecode, buildCommandReceiptContentAAD, buildWrapAAD,
      deriveEncryptedCommandDigest, validateProtectedCommandReceiptBytes,
    } from '${resolve(publicRoot, 'packages/protocol/src/index.ts').replaceAll('\\', '/')}';
    import { buildCommandReceipt } from '${resolve(publicRoot, 'apps/bridge/src/e2e/command-receipt.ts').replaceAll('\\', '/')}';
    import { chachaPolyOpen } from '${resolve(publicRoot, 'apps/bridge/src/e2e/node-crypto.ts').replaceAll('\\', '/')}';
    import {
      createDeterministicCommandKeyringHarness,
    } from '${resolve(publicRoot, 'apps/bridge/test/fixtures/command-execution-keyring.ts').replaceAll('\\', '/')}';
    import vectors from '${resolve(publicRoot, 'packages/protocol/test/fixtures/command-e2e-v1-vectors.json').replaceAll('\\', '/')}';

    const roots = [];
    const root = (name) => {
      const path = join(tmpdir(), 'ariava-node-receipt-' + name + '-' + crypto.randomUUID());
      roots.push(path);
      mkdirSync(path, { recursive: true, mode: 0o700 });
      return path;
    };
    const fixtureCommand = () => structuredClone(vectors.interrupt.envelope);
    const randomness = () => ({
      contentId: vectors.receipt.envelope.content.contentId,
      dek: base64UrlDecode(vectors.receipt.dek, 32),
      contentNonce: base64UrlDecode(vectors.receipt.envelope.content.nonce, 12),
      wrapNonce: base64UrlDecode(vectors.receipt.envelope.keyWrap.nonce, 12),
    });
    const pinReference = (pin) => ({
      version: 1, linkId: pin.linkId, linkGeneration: pin.linkGeneration, epoch: pin.epoch,
      transcriptDigest: pin.transcriptDigest, hostEncryptionKeyId: pin.hostBinding.encryptionKeyId,
      watchEncryptionKeyId: pin.watchBinding.encryptionKeyId,
    });
    const execution = async (harness, overrides = {}) => {
      const command = overrides.command ?? fixtureCommand();
      return {
        version: 1,
        originalEncryptedCommand: command,
        commandDigest: overrides.commandDigest ?? await deriveEncryptedCommandDigest(command),
        pinReference: overrides.pinReference ?? pinReference(harness.pin),
        watchDeviceId: overrides.watchDeviceId ?? command.watchDeviceId,
        nonce: overrides.nonce ?? command.nonce,
        expiresAt: overrides.expiresAt ?? command.expiresAt,
        state: overrides.state ?? 'terminal_receipt_blocked',
        claimedAt: overrides.claimedAt ?? '2026-08-12T00:00:00.500Z',
        ...(overrides.dispatchStartedAt === undefined ? {} : { dispatchStartedAt: overrides.dispatchStartedAt }),
        terminalResult: overrides.terminalResult ?? {
          commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
          accepted: true, status: 'executed', updatedAt: '2026-08-12T00:00:01.000Z',
        },
      };
    };
    const openReceipt = (receipt) => {
      const wrapKey = base64UrlDecode(vectors.keys.bridgeToWatchWrapKey, 32);
      let dek;
      let plaintext;
      try {
        dek = chachaPolyOpen(wrapKey, base64UrlDecode(receipt.keyWrap.nonce, 12),
          base64UrlDecode(receipt.keyWrap.ciphertext, 48), buildWrapAAD({
            direction: 'bridge-to-watch', linkId: receipt.linkId, linkGeneration: receipt.linkGeneration,
            epoch: receipt.epoch, hostId: receipt.hostId, watchDeviceId: receipt.watchDeviceId,
            senderEncryptionKeyId: receipt.keyWrap.senderEncryptionKeyId,
            recipientEncryptionKeyId: receipt.keyWrap.recipientEncryptionKeyId,
            contentId: receipt.content.contentId, payloadKind: 'command-receipt-content-v1',
          }));
        plaintext = chachaPolyOpen(dek, base64UrlDecode(receipt.content.nonce, 12),
          base64UrlDecode(receipt.content.ciphertext), buildCommandReceiptContentAAD({
            hostId: receipt.hostId, watchDeviceId: receipt.watchDeviceId, sessionId: receipt.sessionId,
            commandId: receipt.commandId, commandType: receipt.commandType, commandDigest: receipt.commandDigest,
            completedAt: receipt.completedAt, contentId: receipt.content.contentId,
          }));
        return validateProtectedCommandReceiptBytes(plaintext);
      } finally {
        wrapKey.fill(0);
        dek?.fill(0);
        plaintext?.fill(0);
      }
    };
    const alteredId = (prefix, character) => prefix + '_' + character.repeat(43);
    const mutateCommand = (name, mutate) => ({ name: 'command-' + name, apply: async (base) => {
      const command = structuredClone(base.originalEncryptedCommand);
      mutate(command);
      return { ...base, originalEncryptedCommand: command };
    } });
    const commandMutations = [
      mutateCommand('commandId', (value) => { value.commandId += '_changed'; }),
      mutateCommand('hostId', (value) => { value.hostId = alteredId('host', 'A'); }),
      mutateCommand('watchDeviceId', (value) => { value.watchDeviceId = alteredId('watch', 'B'); }),
      mutateCommand('sessionId', (value) => { value.sessionId += '_changed'; }),
      mutateCommand('issuedAt', (value) => { value.issuedAt = '2026-08-12T00:00:00.001Z'; }),
      mutateCommand('expiresAt', (value) => { value.expiresAt = '2026-08-12T00:04:59.999Z'; }),
      mutateCommand('nonce', (value) => { value.nonce += '_changed'; }),
      mutateCommand('linkId', (value) => { value.linkId += '_changed'; value.payload.keyWrap.linkId = value.linkId; }),
      mutateCommand('linkGeneration', (value) => { value.linkGeneration += 1; value.payload.keyWrap.linkGeneration = value.linkGeneration; }),
      mutateCommand('epoch', (value) => { value.epoch += 1; value.payload.keyWrap.epoch = value.epoch; }),
      mutateCommand('contentId', (value) => { value.payload.content.contentId += '_changed'; value.payload.keyWrap.contentId = value.payload.content.contentId; }),
      mutateCommand('contentNonce', (value) => { value.payload.content.nonce = 'AQEBAQEBAQEBAQEB'; }),
      mutateCommand('contentCiphertext', (value) => { value.payload.content.ciphertext = 'A' + value.payload.content.ciphertext.slice(1); }),
      mutateCommand('wrapSenderKey', (value) => { value.payload.keyWrap.senderEncryptionKeyId = alteredId('ekey', 'C'); }),
      mutateCommand('wrapRecipientKey', (value) => { value.payload.keyWrap.recipientEncryptionKeyId = alteredId('ekey', 'D'); }),
      mutateCommand('wrapNonce', (value) => { value.payload.keyWrap.nonce = 'AgICAgICAgICAgIC'; }),
      mutateCommand('wrapCiphertext', (value) => { value.payload.keyWrap.ciphertext = 'A' + value.payload.keyWrap.ciphertext.slice(1); }),
    ];
    const executionMutations = [
      { name: 'stored-commandDigest', apply: async (base) => ({ ...base, commandDigest: 'A'.repeat(43) }) },
      { name: 'stored-watchDeviceId', apply: async (base) => ({ ...base, watchDeviceId: alteredId('watch', 'E') }) },
      { name: 'stored-nonce', apply: async (base) => ({ ...base, nonce: base.nonce + '_changed' }) },
      { name: 'stored-expiresAt', apply: async (base) => ({ ...base, expiresAt: '2026-08-12T00:04:59.999Z' }) },
      { name: 'pin-linkId', apply: async (base) => ({ ...base, pinReference: { ...base.pinReference, linkId: base.pinReference.linkId + '_changed' } }) },
      { name: 'pin-linkGeneration', apply: async (base) => ({ ...base, pinReference: { ...base.pinReference, linkGeneration: base.pinReference.linkGeneration + 1 } }) },
      { name: 'pin-epoch', apply: async (base) => ({ ...base, pinReference: { ...base.pinReference, epoch: base.pinReference.epoch + 1 } }) },
      { name: 'pin-transcript', apply: async (base) => ({ ...base, pinReference: { ...base.pinReference, transcriptDigest: 'A'.repeat(43) } }) },
      { name: 'pin-hostKey', apply: async (base) => ({ ...base, pinReference: { ...base.pinReference, hostEncryptionKeyId: alteredId('ekey', 'F') } }) },
      { name: 'pin-watchKey', apply: async (base) => ({ ...base, pinReference: { ...base.pinReference, watchEncryptionKeyId: alteredId('ekey', 'G') } }) },
      { name: 'result-commandId', apply: async (base) => ({ ...base, terminalResult: { ...base.terminalResult, commandId: base.terminalResult.commandId + '_changed' } }) },
      { name: 'result-hostId', apply: async (base) => ({ ...base, terminalResult: { ...base.terminalResult, hostId: alteredId('host', 'H') } }) },
      { name: 'result-sessionId', apply: async (base) => ({ ...base, terminalResult: { ...base.terminalResult, sessionId: base.terminalResult.sessionId + '_changed' } }) },
      { name: 'result-status-combination', apply: async (base) => ({ ...base, terminalResult: { ...base.terminalResult, accepted: false } }) },
      { name: 'terminal-state', apply: async (base) => ({ ...base, state: 'terminal' }) },
      { name: 'unknown-state', apply: async (base) => ({ ...base, state: 'outcome_unknown' }) },
    ];

    try {
      const active = await createDeterministicCommandKeyringHarness(join(root('vector'), 'keyring.json'));
      assert.notEqual(active.historicalHost.encryptionKeyId, active.globalCurrentHost.encryptionKeyId);
      const vectorRandomness = randomness();
      const vectorResult = await buildCommandReceipt(await execution(active), active.keyring, vectorRandomness);
      assert.deepEqual(vectorResult.receipt, vectors.receipt.envelope);
      assert.equal(vectorResult.canonicalBody, JSON.stringify(vectors.receipt.envelope));
      assert.equal(vectorResult.receiptDigest, vectors.receipt.receiptDigest);
      assert.ok(vectorRandomness.dek.every((byte) => byte === 0));
      assert.equal(vectorResult.receipt.completedAt, '2026-08-12T00:00:01.000Z');
      assert.equal(vectorResult.canonicalBody.includes('correlation'), false);
      assert.equal(vectorResult.receipt.keyWrap.senderEncryptionKeyId, active.historicalHost.encryptionKeyId);
      assert.notEqual(vectorResult.receipt.keyWrap.senderEncryptionKeyId, active.globalCurrentHost.encryptionKeyId);
      const reply = await createDeterministicCommandKeyringHarness(join(root('reply-vector'), 'keyring.json'));
      const replyExecution = await execution(reply, { command: reply.reply });
      const replyResult = await buildCommandReceipt(replyExecution, reply.keyring, randomness());
      assert.equal(replyResult.receipt.commandType, 'reply');
      assert.equal(replyResult.receipt.commandId, reply.reply.commandId);
      assert.equal(replyResult.receipt.commandDigest, replyExecution.commandDigest);
      assert.deepEqual(openReceipt(replyResult.receipt), { version: 1, accepted: true, status: 'executed' });


      const statuses = [
        { accepted: true, status: 'executed' },
        { accepted: false, status: 'expired' },
        { accepted: false, status: 'rejected' },
        { accepted: false, status: 'failed' },
      ];
      const ciphertextLengths = { interrupt: [], reply: [] };
      for (const commandType of ['interrupt', 'reply']) {
        for (const status of statuses) {
          const harness = await createDeterministicCommandKeyringHarness(join(root('status-' + commandType + '-' + status.status), 'keyring.json'));
          const base = await execution(harness, { command: harness[commandType] });
          const result = await buildCommandReceipt({ ...base, terminalResult: { ...base.terminalResult, ...status } }, harness.keyring, randomness());
          ciphertextLengths[commandType].push(base64UrlDecode(result.receipt.content.ciphertext).byteLength);
          assert.equal(result.receipt.commandType, commandType);
          assert.deepEqual(openReceipt(result.receipt), { version: 1, ...status });
        }
      }
      assert.deepEqual(ciphertextLengths.interrupt, [144, 144, 144, 144]);
      assert.deepEqual(ciphertextLengths.reply, ciphertextLengths.interrupt);

      const retiring = await createDeterministicCommandKeyringHarness(join(root('retiring'), 'keyring.json'), 'retiring');
      const retiringResult = await buildCommandReceipt(await execution(retiring), retiring.keyring, randomness());
      assert.deepEqual(openReceipt(retiringResult.receipt), { version: 1, accepted: true, status: 'executed' });

      const rejected = [];
      for (const mutation of [...commandMutations, ...executionMutations]) {
        const harness = await createDeterministicCommandKeyringHarness(join(root(mutation.name), 'keyring.json'));
        const base = await execution(harness);
        const candidate = await mutation.apply(base);
        const injected = randomness();
        await assert.rejects(buildCommandReceipt(candidate, harness.keyring, injected), TypeError, mutation.name);
        assert.ok(injected.dek.every((byte) => byte === 0), mutation.name + ' DEK zeroization');
        rejected.push(mutation.name);
      }

      const replyMutationHarness = await createDeterministicCommandKeyringHarness(join(root('reply-mutations'), 'keyring.json'));
      const replyMutationBase = await execution(replyMutationHarness, { command: replyMutationHarness.reply });
      const replyMutations = [
        mutateCommand('reply-type', (value) => { value.type = 'interrupt'; delete value.targetAlertEventId; }),
        mutateCommand('reply-targetAlertEventId', (value) => { value.targetAlertEventId += '_changed'; }),
      ];
      for (const mutation of replyMutations) {
        const candidate = await mutation.apply(replyMutationBase);
        const injected = randomness();
        await assert.rejects(buildCommandReceipt(candidate, replyMutationHarness.keyring, injected), TypeError, mutation.name);
        assert.ok(injected.dek.every((byte) => byte === 0), mutation.name + ' DEK zeroization');
        rejected.push(mutation.name);
      }

      const materialCases = [
        ['missing-pin', (harness) => { harness.mutateRuntimePin((pin) => { pin.linkId = 'link_missing'; }); }],
        ['revoked-pin', (harness) => { harness.keyring.revokeCompromisedEncryptionKey(harness.historicalHost.encryptionKeyId); }],
        ['unlinked-watch', (harness) => { harness.keyring.revokeWatch(harness.pin.watchDeviceId); }],
        ['missing-historical-key', (harness) => { harness.replaceHistoricalIdentity(null); }],
        ['wrong-historical-private-key', (harness) => { harness.replaceHistoricalIdentity({ ...harness.historicalHost, privateKeyPkcs8: new Uint8Array(harness.globalCurrentHost.privateKeyPkcs8) }); }],
        ['host-binding-substitution', (harness) => { harness.mutateRuntimePin((pin) => { pin.hostBinding = { ...pin.hostBinding, encryptionKeyId: harness.globalCurrentHost.encryptionKeyId, publicKey: harness.globalCurrentHost.publicKey, sequence: harness.globalCurrentHost.sequence, createdAt: harness.globalCurrentHost.createdAt }; }); }],
        ['watch-public-substitution', (harness) => { harness.mutateRuntimePin((pin) => { pin.watchBinding.publicKey = harness.historicalHost.publicKey; }); }],
        ['transcript-substitution', (harness) => { harness.mutateRuntimePin((pin) => { pin.transcriptDigest = 'A'.repeat(43); }); }],
      ];
      for (const [name, mutate] of materialCases) {
        const harness = await createDeterministicCommandKeyringHarness(join(root(name), 'keyring.json'));
        const base = await execution(harness);
        mutate(harness);
        const injected = randomness();
        await assert.rejects(buildCommandReceipt(base, harness.keyring, injected), undefined, name);
        assert.ok(injected.dek.every((byte) => byte === 0), name + ' DEK zeroization');
        rejected.push(name);
      }

      const boundary = await createDeterministicCommandKeyringHarness(join(root('retiring-boundary'), 'keyring.json'), 'retiring');
      const boundaryCommand = fixtureCommand();
      boundaryCommand.issuedAt = boundary.pin.retiringAt;
      boundaryCommand.expiresAt = '2026-08-12T00:05:00.000Z';
      const boundaryExecution = await execution(boundary, { command: boundaryCommand });
      await assert.rejects(buildCommandReceipt(boundaryExecution, boundary.keyring, randomness()), TypeError);
      rejected.push('retiring-boundary');

      const explicitlyUnlinked = await createDeterministicCommandKeyringHarness(join(root('post-unlink-terminal-commit'), 'keyring.json'));
      const preUnlinkExecution = await execution(explicitlyUnlinked, { command: explicitlyUnlinked.reply });
      const originalTuple = {
        linkId: preUnlinkExecution.originalEncryptedCommand.linkId,
        linkGeneration: preUnlinkExecution.originalEncryptedCommand.linkGeneration,
        epoch: preUnlinkExecution.originalEncryptedCommand.epoch,
      };
      explicitlyUnlinked.keyring.revokeWatch(explicitlyUnlinked.pin.watchDeviceId);
      const postUnlinkRandomness = randomness();
      await assert.rejects(buildCommandReceipt(preUnlinkExecution, explicitlyUnlinked.keyring, postUnlinkRandomness), TypeError);
      assert.ok(postUnlinkRandomness.dek.every((byte) => byte === 0));
      assert.deepEqual({
        linkId: preUnlinkExecution.originalEncryptedCommand.linkId,
        linkGeneration: preUnlinkExecution.originalEncryptedCommand.linkGeneration,
        epoch: preUnlinkExecution.originalEncryptedCommand.epoch,
      }, originalTuple);
      assert.equal(explicitlyUnlinked.keyring.getUsable(originalTuple.linkId, originalTuple.linkGeneration, originalTuple.epoch), undefined);
      rejected.push('post-unlink-terminal-commit');

      process.stdout.write(JSON.stringify({
        deterministicVector: true,
        canonicalBody: true,
        historicalHostKey: true,
        activePin: true,
        allowedRetiringPin: true,
        ciphertextLengths,
        statuses: statuses.map((value) => value.status),
        validCommandTypes: ['interrupt', 'reply'],
        replyTargetBound: true,
        postUnlinkTerminalCommitRefused: true,
        noRetarget: true,
        rejected,
        zeroizedInjectedDeks: rejected.length + 1,
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
