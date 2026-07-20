import { describe, expect, test } from 'bun:test';
import { E2E_SUITE_V1, base64UrlEncode, type EncryptedCommandEnvelopeV1 } from '@ariava/protocol';
import { prepareCommandForExecution } from '../src/e2e/command-execution';

const encryptedReply = (): EncryptedCommandEnvelopeV1 => ({
  commandId: 'command-1', hostId: 'host-1', sessionId: 'session-1', type: 'reply', targetAlertEventId: 'event-1',
  issuedAt: '2026-07-20T00:00:00.000Z', expiresAt: '2026-07-20T00:05:00.000Z', nonce: 'nonce-1', watchDeviceId: 'watch-1',
  linkId: 'link-1', linkGeneration: 1, epoch: 1,
  payload: {
    content: { version: 1, suite: E2E_SUITE_V1, contentId: 'content-1', payloadKind: 'reply-content-v1',
      nonce: base64UrlEncode(new Uint8Array(12)), ciphertext: base64UrlEncode(new Uint8Array(32)) },
    keyWrap: { version: 1, suite: E2E_SUITE_V1, contentId: 'content-1', linkId: 'link-1', linkGeneration: 1, epoch: 1,
      senderEncryptionKeyId: 'watch-key', recipientEncryptionKeyId: 'host-key', nonce: base64UrlEncode(new Uint8Array(12)),
      ciphertext: base64UrlEncode(new Uint8Array(48)) },
  },
});

describe('encrypted command execution boundary', () => {
  const localReply = (command: Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>) => ({
    commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, type: 'reply' as const,
    payload: { text: 'continue' }, targetAlertEventId: command.targetAlertEventId, issuedAt: command.issuedAt,
    expiresAt: command.expiresAt, nonce: command.nonce, watchDeviceId: command.watchDeviceId,
  });

  test('fails closed without a keyring for both encrypted reply and interrupt', async () => {
    const reply = encryptedReply();
    const interrupt = { ...reply, type: 'interrupt' as const, payload: {} };
    delete (interrupt as Partial<typeof interrupt>).targetAlertEventId;
    expect(await prepareCommandForExecution(reply)).toEqual({ ok: false, code: 'e2e_key_unavailable' });
    expect(await prepareCommandForExecution(interrupt)).toEqual({ ok: false, code: 'e2e_key_unavailable' });
    expect(JSON.stringify(await prepareCommandForExecution(reply))).not.toContain(reply.payload.content.ciphertext);
  });

  test('checks the local active pin before reply decryption or interrupt execution', async () => {
    const reply = encryptedReply();
    const interrupt = { ...reply, type: 'interrupt' as const, payload: {} };
    delete (interrupt as Partial<typeof interrupt>).targetAlertEventId;
    let decodeCalls = 0;
    const stalePin = { authorize: async () => false, decodeReply: async (command: Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>) => {
      decodeCalls += 1; return localReply(command);
    } };
    expect(await prepareCommandForExecution(reply, stalePin)).toEqual({ ok: false, code: 'e2e_epoch_unauthorized' });
    expect(await prepareCommandForExecution(interrupt, stalePin)).toEqual({ ok: false, code: 'e2e_epoch_unauthorized' });
    expect(decodeCalls).toBe(0);
  });

  test('accepts only a locally authorized current epoch and a non-empty decrypted reply', async () => {
    const result = await prepareCommandForExecution(encryptedReply(), {
      authorize: async (command) => command.linkId === 'link-1' && command.linkGeneration === 1 && command.epoch === 1,
      decodeReply: async (command) => localReply(command),
    });
    expect(result).toMatchObject({ ok: true, command: { type: 'reply', payload: { text: 'continue' } } });
  });
});
