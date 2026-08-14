import { describe, expect, test } from 'bun:test';
import { E2E_SUITE_V1, base64UrlEncode, type EncryptedCommandEnvelopeV1 } from '@ariava/protocol';
import { CommandEpochAuthorizationError, prepareCommandForExecution } from '../src/e2e/command-execution';

const encryptedReply = (): EncryptedCommandEnvelopeV1 => ({
  commandId: 'command-1', hostId: 'host-1', sessionId: 'session-1', type: 'reply', targetAlertEventId: 'event-1',
  issuedAt: '2026-07-20T00:00:00.000Z', expiresAt: '2026-07-20T00:05:00.000Z', nonce: 'nonce-1', watchDeviceId: 'watch-1',
  linkId: 'link-1', linkGeneration: 1, epoch: 1,
  payload: {
    content: { version: 1, suite: E2E_SUITE_V1, contentId: 'content-1', payloadKind: 'reply-content-v1',
      nonce: base64UrlEncode(new Uint8Array(12)), ciphertext: base64UrlEncode(new Uint8Array(32)) },
    keyWrap: { version: 1, suite: E2E_SUITE_V1, contentId: 'content-1', linkId: 'link-1', linkGeneration: 1, epoch: 1,
      senderEncryptionKeyId: `ekey_${'W'.repeat(43)}`, recipientEncryptionKeyId: `ekey_${'H'.repeat(43)}`, nonce: base64UrlEncode(new Uint8Array(12)),
      ciphertext: base64UrlEncode(new Uint8Array(48)) },
  },
});

const localReply = (command: Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>) => ({
  commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, type: 'reply' as const,
  payload: { text: 'continue' }, targetAlertEventId: command.targetAlertEventId, issuedAt: command.issuedAt,
  expiresAt: command.expiresAt, nonce: command.nonce, watchDeviceId: command.watchDeviceId,
});

describe('encrypted command execution boundary', () => {
  test('strictly validates before keyring preparation or digest work', async () => {
    let prepareCalls = 0;
    const keyring = { prepare: async () => {
      prepareCalls += 1;
      throw new Error('must not run');
    } };
    const malformed = { ...encryptedReply(), unsupported: true } as unknown as EncryptedCommandEnvelopeV1;
    expect(await prepareCommandForExecution(malformed, keyring)).toEqual({ ok: false, code: 'e2e_payload_invalid' });
    expect(prepareCalls).toBe(0);
  });

  test('fails closed without a keyring for a strict encrypted command', async () => {
    const reply = encryptedReply();
    expect(await prepareCommandForExecution(reply)).toEqual({ ok: false, code: 'e2e_key_unavailable' });
    expect(JSON.stringify(await prepareCommandForExecution(reply))).not.toContain(reply.payload.content.ciphertext);
  });

  test('maps local pin authorization failure without exposing encrypted content', async () => {
    const reply = encryptedReply();
    let prepareCalls = 0;
    const stalePin = { prepare: async () => { prepareCalls += 1; throw new CommandEpochAuthorizationError(); } };
    expect(await prepareCommandForExecution(reply, stalePin)).toEqual({ ok: false, code: 'e2e_epoch_unauthorized' });
    expect(prepareCalls).toBe(1);
  });

  test.each(['reply', 'interrupt'] as const)('accepts future skew boundary and rejects boundary plus one for %s', async (type) => {
    const now = new Date('2026-07-20T00:00:00.000Z');
    const base = encryptedReply();
    const command: EncryptedCommandEnvelopeV1 = type === 'reply' ? base : {
      commandId: base.commandId, hostId: base.hostId, sessionId: base.sessionId, type,
      issuedAt: base.issuedAt, expiresAt: base.expiresAt, nonce: base.nonce, watchDeviceId: base.watchDeviceId,
      linkId: base.linkId, linkGeneration: base.linkGeneration, epoch: base.epoch,
      payload: { ...base.payload, content: { ...base.payload.content, payloadKind: 'interrupt-content-v1',
        ciphertext: base64UrlEncode(new Uint8Array(50)) } },
    };
    let pinCalls = 0;
    const keyring = { prepare: async (wire: EncryptedCommandEnvelopeV1) => {
      pinCalls += 1;
      return {
        pinReference: { version: 1 as const, linkId: wire.linkId, linkGeneration: wire.linkGeneration, epoch: wire.epoch,
          transcriptDigest: 'T'.repeat(43), hostEncryptionKeyId: `ekey_${'H'.repeat(43)}`, watchEncryptionKeyId: `ekey_${'W'.repeat(43)}` },
        loopbackCommand: type === 'reply' ? localReply(wire as Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>) : {
          commandId: wire.commandId, hostId: wire.hostId, sessionId: wire.sessionId, type, payload: {},
          issuedAt: wire.issuedAt, expiresAt: wire.expiresAt, nonce: wire.nonce, watchDeviceId: wire.watchDeviceId,
        },
      };
    } };
    const boundary = { ...structuredClone(command), issuedAt: '2026-07-20T00:05:00.000Z', expiresAt: '2026-07-20T00:10:00.000Z' };
    expect((await prepareCommandForExecution(boundary, keyring, () => now)).ok).toBe(true);
    const plusOne = { ...boundary, issuedAt: '2026-07-20T00:05:00.001Z', expiresAt: '2026-07-20T00:10:00.001Z' };
    expect(await prepareCommandForExecution(plusOne, keyring, () => now)).toEqual({ ok: false, code: 'e2e_epoch_unauthorized' });
    expect(pinCalls).toBe(1);
  });

  test('returns immutable wire binding, digest, exact pin reference, and loopback command', async () => {
    const reply = encryptedReply();
    const result = await prepareCommandForExecution(reply, {
      prepare: async (command) => ({
        pinReference: { version: 1, linkId: command.linkId, linkGeneration: command.linkGeneration, epoch: command.epoch,
          transcriptDigest: 'T'.repeat(43), hostEncryptionKeyId: `ekey_${'H'.repeat(43)}`, watchEncryptionKeyId: `ekey_${'W'.repeat(43)}` },
        loopbackCommand: localReply(command as Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>),
      }),
    });
    expect(result).toMatchObject({ ok: true, prepared: {
      originalEncryptedCommand: { commandId: reply.commandId }, loopbackCommand: { type: 'reply', payload: { text: 'continue' } },
      pinReference: { linkId: 'link-1', epoch: 1 }, commandDigest: expect.any(String),
    } });
  });

  test('runs the real LocalLinkKeyring and daemon execution pipeline under Node', () => {
    const result = Bun.spawnSync({
      cmd: ['node', new URL('./fixtures/command-execution-vector-runner.mjs', import.meta.url).pathname],
      cwd: process.cwd(), env: process.env,
    });
    expect(new TextDecoder().decode(result.stderr)).toBe('');
    expect(result.exitCode).toBe(0);
    const output = JSON.parse(new TextDecoder().decode(result.stdout));
    expect(output.accepted).toEqual({
      reply: { active: true, retiringBeforeBoundary: true, historicalHostKey: true },
      interrupt: { active: true, retiringBeforeBoundary: true, historicalHostKey: true },
    });
    expect(output.invalidCasesPerCommand).toBe(15);
    expect(output.totalInvalidPreparations).toBe(30);
    expect(output.rejectedWithoutEffects).toHaveLength(30);
    expect(output.rejectedWithoutEffects).toEqual(expect.arrayContaining([
      'reply-issuance-after-retiring', 'reply-host-key-substitution', 'reply-wrong-host-private-identity',
      'reply-watch-binding-substitution', 'reply-watch-public-key-substitution', 'reply-transcript-substitution',
      'reply-global-current-key-substitution', 'reply-aead-content-mutation', 'reply-aead-wrap-mutation',
      'reply-expired', 'reply-ttl-invalid', 'reply-missing-pin', 'reply-revoked-pin',
      'reply-sender-key-id-mismatch', 'reply-recipient-key-id-mismatch',
      'interrupt-issuance-after-retiring', 'interrupt-host-key-substitution', 'interrupt-wrong-host-private-identity',
      'interrupt-watch-binding-substitution', 'interrupt-watch-public-key-substitution', 'interrupt-transcript-substitution',
      'interrupt-global-current-key-substitution', 'interrupt-aead-content-mutation', 'interrupt-aead-wrap-mutation',
      'interrupt-expired', 'interrupt-ttl-invalid', 'interrupt-missing-pin', 'interrupt-revoked-pin',
      'interrupt-sender-key-id-mismatch', 'interrupt-recipient-key-id-mismatch',
    ]));
    expect(output.terminalBoundary).toBe('terminal-pending-receipt');
  }, 15_000);
});
