import { afterAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode } from '@ariava/protocol';

const sharedSecrets: Uint8Array[] = [];
const derivedKeys: Uint8Array[] = [];
const sealedInputs: Array<{ key: Uint8Array; plaintext: Uint8Array }> = [];

mock.module('../src/e2e/node-crypto', () => ({
  ChaChaPolyAuthenticationError: class ChaChaPolyAuthenticationError extends Error {},
  chachaPolySeal: (key: Uint8Array, plaintext: Uint8Array, _aad: Uint8Array, nonce: Uint8Array) => {
    sealedInputs.push({ key, plaintext });
    return { nonce: new Uint8Array(nonce), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]) };
  },
  chachaPolyOpen: () => { throw new Error('not used'); },
  generateX25519KeyMaterial: () => {
    const { privateKey, publicKey } = generateKeyPairSync('x25519');
    const publicJwk = publicKey.export({ format: 'jwk' });
    if (typeof publicJwk.x !== 'string') throw new TypeError('test X25519 public key is invalid');
    return {
      privateKeyPkcs8: new Uint8Array(privateKey.export({ type: 'pkcs8', format: 'der' })),
      publicKeyRaw: base64UrlDecode(publicJwk.x, 32, 'test X25519 public key'),
    };
  },
  x25519SharedSecret: (privateKeyPkcs8: Uint8Array, peerPublicKeyRaw: Uint8Array) => {
    const secret = new Uint8Array(diffieHellman({
      privateKey: createPrivateKey({ key: Buffer.from(privateKeyPkcs8), type: 'pkcs8', format: 'der' }),
      publicKey: createPublicKey({
        key: { kty: 'OKP', crv: 'X25519', x: base64UrlEncode(peerPublicKeyRaw) }, format: 'jwk',
      }),
    }));
    sharedSecrets.push(secret);
    return secret;
  },
  hkdfSha256: (input: Uint8Array, salt: Uint8Array, info: Uint8Array) => {
    const key = new Uint8Array(hkdfSync(
      'sha256', Buffer.from(input), Buffer.from(salt), Buffer.from(info), 32,
    ));
    derivedKeys.push(key);
    return key;
  },
}));

const { buildCommandReceipt } = await import('../src/e2e/command-receipt');
const { createDeterministicCommandKeyringHarness } = await import('./fixtures/command-execution-keyring');

const roots: string[] = [];
beforeEach(() => {
  sharedSecrets.length = 0;
  derivedKeys.length = 0;
  sealedInputs.length = 0;
});
afterAll(async () => {
  const { rmSync } = await import('node:fs');
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});

describe('command receipt cryptography', () => {
  test('zeroizes observable shared, root, wrap, DEK, and plaintext buffers', async () => {
    const { mkdirSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const root = join(tmpdir(), `ariava-receipt-zeroization-${crypto.randomUUID()}`);
    roots.push(root);
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const harness = await createDeterministicCommandKeyringHarness(join(root, 'keyring.json'));
    sharedSecrets.length = 0;
    derivedKeys.length = 0;
    sealedInputs.length = 0;
    const command = harness.interrupt;
    const dek = new Uint8Array(32).fill(9);
    await buildCommandReceipt({
      version: 1,
      originalEncryptedCommand: command,
      commandDigest: await (await import('@ariava/protocol')).deriveEncryptedCommandDigest(command),
      pinReference: {
        version: 1,
        linkId: harness.pin.linkId,
        linkGeneration: harness.pin.linkGeneration,
        epoch: harness.pin.epoch,
        transcriptDigest: harness.pin.transcriptDigest,
        hostEncryptionKeyId: harness.pin.hostBinding.encryptionKeyId,
        watchEncryptionKeyId: harness.pin.watchBinding.encryptionKeyId,
      },
      watchDeviceId: command.watchDeviceId,
      nonce: command.nonce,
      expiresAt: command.expiresAt,
      state: 'terminal_receipt_blocked',
      claimedAt: '2026-08-12T00:00:00.500Z',
      terminalResult: {
        commandId: command.commandId,
        hostId: command.hostId,
        sessionId: command.sessionId,
        accepted: true,
        status: 'executed',
        updatedAt: '2026-08-12T00:00:01.000Z',
      },
    }, harness.keyring, {
      contentId: 'content_receipt_zeroization',
      dek,
      contentNonce: new Uint8Array(12).fill(10),
      wrapNonce: new Uint8Array(12).fill(11),
    });

    expect(sharedSecrets).toHaveLength(1);
    expect(derivedKeys).toHaveLength(2);
    expect(sealedInputs).toHaveLength(2);
    expect(sharedSecrets[0]!.every((byte) => byte === 0)).toBe(true);
    expect(derivedKeys.every((key) => key.every((byte) => byte === 0))).toBe(true);
    expect(dek.every((byte) => byte === 0)).toBe(true);
    expect(sealedInputs[0]!.plaintext.every((byte) => byte === 0)).toBe(true);
    expect(sealedInputs[1]!.plaintext).toBe(dek);
    expect(base64UrlDecode(harness.pin.transcriptDigest)).toHaveLength(32);
  });

  test('passes deterministic production-Node vectors and fail-closed mutations', () => {
    const result = Bun.spawnSync({
      cmd: ['node', new URL('./fixtures/command-receipt-vector-runner.mjs', import.meta.url).pathname],
      cwd: process.cwd(),
      env: process.env,
    });
    expect(new TextDecoder().decode(result.stderr)).toBe('');
    expect(result.exitCode).toBe(0);
    const output = JSON.parse(new TextDecoder().decode(result.stdout));
    expect(output).toMatchObject({
      deterministicVector: true,
      canonicalBody: true,
      historicalHostKey: true,
      activePin: true,
      allowedRetiringPin: true,
      ciphertextLengths: {
        interrupt: [144, 144, 144, 144],
        reply: [144, 144, 144, 144],
      },
      statuses: ['executed', 'expired', 'rejected', 'failed'],
      validCommandTypes: ['interrupt', 'reply'],
      replyTargetBound: true,
      postUnlinkTerminalCommitRefused: true,
      noRetarget: true,
    });
    expect(output.rejected).toHaveLength(45);
    expect(output.rejected).toEqual(expect.arrayContaining([
      'command-commandId', 'command-hostId', 'command-watchDeviceId', 'command-sessionId',
      'command-issuedAt', 'command-expiresAt', 'command-nonce', 'command-linkId',
      'command-linkGeneration', 'command-epoch', 'command-contentId', 'command-contentNonce',
      'command-contentCiphertext', 'command-wrapSenderKey', 'command-wrapRecipientKey',
      'command-wrapNonce', 'command-wrapCiphertext', 'stored-commandDigest', 'pin-transcript',
      'result-status-combination', 'terminal-state', 'unknown-state', 'missing-pin', 'revoked-pin',
      'unlinked-watch', 'missing-historical-key', 'wrong-historical-private-key',
      'host-binding-substitution', 'watch-public-substitution', 'transcript-substitution',
      'retiring-boundary', 'command-reply-type', 'command-reply-targetAlertEventId',
      'post-unlink-terminal-commit',
    ]));
    expect(output.zeroizedInjectedDeks).toBe(46);
  }, 15_000);
});
