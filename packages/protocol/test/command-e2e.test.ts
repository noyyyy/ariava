import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import vectors from './fixtures/command-e2e-v1-vectors.json';
import {
  COMMAND_LIMITS,
  E2E_LIMITS,
  E2E_SUITE_V1,
  base64UrlDecode,
  base64UrlEncode,
  buildCommandReceiptContentAAD,
  buildCommandReceiptEnvelopeBindingBytes,
  buildEncryptedCommandEnvelopeBindingBytes,
  buildInterruptContentAAD,
  buildProtectedCommandReceiptBytes,
  buildProtectedInterruptContentBytes,
  buildProtectedReplyContentBytes,
  buildReplyContentAAD,
  buildWrapAAD,
  deriveCommandReceiptDigest,
  deriveEncryptedCommandDigest,
  validateCommandReceiptEnvelopeV1,
  validateEncryptedCommandEnvelopeV1,
  validateEncryptedContentV1,
  validateProtectedCommandReceiptBytes,
  validateProtectedCommandReceiptV1,
  validateProtectedInterruptContentV1,
  type CommandReceiptEnvelopeV1,
  type EncryptedCommandEnvelopeV1,
} from '../src';

function openChaChaPoly(key: string, nonce: string, ciphertext: string, aad: Uint8Array): Uint8Array {
  const script = `
    const { createDecipheriv } = require('node:crypto');
    const [key, nonce, wire, aad] = process.argv.slice(1).map((value) => Buffer.from(value, 'base64url'));
    const body = wire.subarray(0, wire.length - 16);
    const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: body.length });
    decipher.setAuthTag(wire.subarray(wire.length - 16));
    process.stdout.write(Buffer.concat([decipher.update(body), decipher.final()]).toString('base64url'));
  `;
  const result = spawnSync('node', ['-e', script, key, nonce, ciphertext, base64UrlEncode(aad)], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr || 'ChaChaPoly authentication failed');
  return base64UrlDecode(result.stdout);
}

function sealChaChaPoly(key: string, nonce: string, plaintext: Uint8Array, aad: Uint8Array): string {
  const script = `
    const { createCipheriv } = require('node:crypto');
    const [key, nonce, plaintext, aad] = process.argv.slice(1).map((value) => Buffer.from(value, 'base64url'));
    const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    process.stdout.write(Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]).toString('base64url'));
  `;
  const result = spawnSync('node', [
    '-e', script, key, nonce, base64UrlEncode(plaintext), base64UrlEncode(aad),
  ], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr || 'ChaChaPoly encryption failed');
  return result.stdout;
}

function customPrototype<T extends object>(value: T): T {
  return Object.assign(Object.create({ toJSON: () => ({ replaced: true }) }), value) as T;
}

function mutateBase64(value: string): string {
  const bytes = base64UrlDecode(value);
  bytes[0]! ^= 1;
  return base64UrlEncode(bytes);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

const command = vectors.interrupt.envelope as EncryptedCommandEnvelopeV1;
const receipt = vectors.receipt.envelope as CommandReceiptEnvelopeV1;

describe('command E2E v1 protocol vectors', () => {
  test('preserves 4000 UTF-8 reply text through worst-case canonical escaping and wire validation', () => {
    expect(COMMAND_LIMITS.replyTextBytes).toBe(4_000);
    expect(COMMAND_LIMITS.replyCanonicalPlaintextBytes).toBe(24_023);
    expect(COMMAND_LIMITS.replyCiphertextBytes).toBe(24_039);
    const replyTemplate = clone(command) as unknown as EncryptedCommandEnvelopeV1;
    Object.assign(replyTemplate, { type: 'reply', targetAlertEventId: 'event_reply_limit' });
    replyTemplate.payload.content.payloadKind = 'reply-content-v1';
    const aad = buildReplyContentAAD({
      hostId: replyTemplate.hostId, watchDeviceId: replyTemplate.watchDeviceId, sessionId: replyTemplate.sessionId,
      commandId: replyTemplate.commandId, targetAlertEventId: 'event_reply_limit', issuedAt: replyTemplate.issuedAt,
      expiresAt: replyTemplate.expiresAt, nonce: replyTemplate.nonce, contentId: replyTemplate.payload.content.contentId,
    });
    for (const text of ['a'.repeat(4_000), '\u0000'.repeat(4_000)]) {
      const plaintext = buildProtectedReplyContentBytes({ version: 1, text });
      const ciphertext = sealChaChaPoly(vectors.interrupt.dek, replyTemplate.payload.content.nonce, plaintext, aad);
      const wire = { ...replyTemplate, payload: { ...replyTemplate.payload, content: { ...replyTemplate.payload.content, ciphertext } } };
      expect(new TextEncoder().encode(text).byteLength).toBe(4_000);
      expect(plaintext.byteLength <= COMMAND_LIMITS.replyCanonicalPlaintextBytes).toBe(true);
      expect(base64UrlDecode(ciphertext).byteLength).toBe(plaintext.byteLength + 16);
      expect(validateEncryptedContentV1(wire.payload.content)).toBe(true);
      expect(validateEncryptedCommandEnvelopeV1(wire)).toBe(true);
      plaintext.fill(0);
    }
    expect(() => buildProtectedReplyContentBytes({ version: 1, text: 'a'.repeat(4_001) })).toThrow();
  });

  test('rejects custom prototypes while accepting null-prototype exact records', () => {
    const nullCommand = Object.assign(Object.create(null), clone(command));
    nullCommand.payload = Object.assign(Object.create(null), clone(command.payload));
    nullCommand.payload.content = Object.assign(Object.create(null), clone(command.payload.content));
    nullCommand.payload.keyWrap = Object.assign(Object.create(null), clone(command.payload.keyWrap));
    expect(validateEncryptedCommandEnvelopeV1(nullCommand)).toBe(true);
    expect(validateEncryptedCommandEnvelopeV1(customPrototype(clone(command)))).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, payload: customPrototype(clone(command.payload)) })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, payload: { ...command.payload, content: customPrototype(clone(command.payload.content)) } })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, payload: { ...command.payload, keyWrap: customPrototype(clone(command.payload.keyWrap)) } })).toBe(false);

    const nullReceipt = Object.assign(Object.create(null), clone(receipt));
    nullReceipt.content = Object.assign(Object.create(null), clone(receipt.content));
    nullReceipt.keyWrap = Object.assign(Object.create(null), clone(receipt.keyWrap));
    expect(validateCommandReceiptEnvelopeV1(nullReceipt)).toBe(true);
    expect(validateCommandReceiptEnvelopeV1(customPrototype(clone(receipt)))).toBe(false);
    expect(validateCommandReceiptEnvelopeV1({ ...receipt, content: customPrototype(clone(receipt.content)) })).toBe(false);
    expect(validateCommandReceiptEnvelopeV1({ ...receipt, keyWrap: customPrototype(clone(receipt.keyWrap)) })).toBe(false);
    expect(validateProtectedCommandReceiptV1(Object.assign(Object.create(null), { version: 1, accepted: true, status: 'executed' }))).toBe(true);
    expect(validateProtectedInterruptContentV1(Object.assign(Object.create(null), { version: 1, action: 'interrupt' }))).toBe(true);
    expect(new TextDecoder().decode(buildProtectedReplyContentBytes(Object.assign(Object.create(null), { version: 1, text: 'reply' })))).toBe('{"version":1,"text":"reply"}');
    expect(validateProtectedCommandReceiptV1(customPrototype({ version: 1, accepted: true, status: 'executed' }))).toBe(false);
    expect(validateProtectedInterruptContentV1(customPrototype({ version: 1, action: 'interrupt' }))).toBe(false);
    expect(() => buildProtectedReplyContentBytes(customPrototype({ version: 1, text: 'reply' }))).toThrow();
    expect(() => buildProtectedInterruptContentBytes(customPrototype({ version: 1, action: 'interrupt' }))).toThrow();
    expect(() => buildProtectedCommandReceiptBytes(customPrototype({ version: 1, accepted: true, status: 'executed' }))).toThrow();
  });

  test('rejects non-canonical command and receipt encryption key IDs', () => {
    for (const field of ['senderEncryptionKeyId', 'recipientEncryptionKeyId'] as const) {
      for (const invalid of ['ekey_short', `key_${'A'.repeat(43)}`, `ekey_${'A'.repeat(42)}`, `ekey_${'A'.repeat(44)}`, `ekey_${'!'.repeat(43)}`]) {
        expect(validateEncryptedCommandEnvelopeV1({
          ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, [field]: invalid } },
        })).toBe(false);
        expect(validateCommandReceiptEnvelopeV1({
          ...receipt, keyWrap: { ...receipt.keyWrap, [field]: invalid },
        })).toBe(false);
      }
    }
  });

  test('seals every terminal receipt status to the same exact ciphertext length', () => {
    const aad = buildCommandReceiptContentAAD({
      hostId: receipt.hostId, watchDeviceId: receipt.watchDeviceId, sessionId: receipt.sessionId,
      commandId: receipt.commandId, commandType: receipt.commandType, commandDigest: receipt.commandDigest,
      completedAt: receipt.completedAt, contentId: receipt.content.contentId,
    });
    for (const { value } of vectors.receiptPlaintexts) {
      const plaintext = buildProtectedCommandReceiptBytes(value);
      const ciphertext = sealChaChaPoly(vectors.receipt.dek, receipt.content.nonce, plaintext, aad);
      expect(base64UrlDecode(ciphertext).byteLength).toBe(144);
      expect(validateEncryptedContentV1({ ...receipt.content, ciphertext })).toBe(true);
      plaintext.fill(0);
    }
  });

  test('validates and decrypts the deterministic encrypted interrupt fixture', async () => {
    expect(validateEncryptedCommandEnvelopeV1(command)).toBe(true);
    expect(base64UrlEncode(buildProtectedInterruptContentBytes({ action: 'interrupt', version: 1 }))).toBe(vectors.interrupt.plaintext);
    expect(validateProtectedInterruptContentV1({ version: 1, action: 'interrupt' })).toBe(true);
    expect(validateProtectedInterruptContentV1({ version: 1, action: 'interrupt', reason: 'forbidden' })).toBe(false);
    expect(validateProtectedInterruptContentV1({ version: 1, action: 'stop' })).toBe(false);
    expect(base64UrlEncode(buildInterruptContentAAD({
      hostId: command.hostId, watchDeviceId: command.watchDeviceId, sessionId: command.sessionId,
      commandId: command.commandId, issuedAt: command.issuedAt, expiresAt: command.expiresAt,
      nonce: command.nonce, contentId: command.payload.content.contentId,
    }))).toBe(vectors.interrupt.contentAAD);
    expect(base64UrlEncode(buildWrapAAD({
      direction: 'watch-to-bridge', linkId: command.linkId, linkGeneration: command.linkGeneration,
      epoch: command.epoch, hostId: command.hostId, watchDeviceId: command.watchDeviceId,
      senderEncryptionKeyId: command.payload.keyWrap.senderEncryptionKeyId,
      recipientEncryptionKeyId: command.payload.keyWrap.recipientEncryptionKeyId,
      contentId: command.payload.content.contentId, payloadKind: 'interrupt-content-v1',
    }))).toBe(vectors.interrupt.wrapAAD);
    const dek = openChaChaPoly(
      vectors.keys.watchToBridgeWrapKey, command.payload.keyWrap.nonce,
      command.payload.keyWrap.ciphertext, base64UrlDecode(vectors.interrupt.wrapAAD),
    );
    expect(base64UrlEncode(dek)).toBe(vectors.interrupt.dek);
    const interruptPlaintext = openChaChaPoly(
      vectors.interrupt.dek, command.payload.content.nonce,
      command.payload.content.ciphertext, base64UrlDecode(vectors.interrupt.contentAAD),
    );
    expect(base64UrlEncode(interruptPlaintext)).toBe(vectors.interrupt.plaintext);
    expect(base64UrlEncode(buildEncryptedCommandEnvelopeBindingBytes(command))).toBe(vectors.interrupt.envelopeBinding);
    expect(await deriveEncryptedCommandDigest(command)).toBe(vectors.interrupt.commandDigest);
    dek.fill(0);
    interruptPlaintext.fill(0);
  });

  test('rejects plaintext, partial, malformed, extra, and tuple-mismatched interrupt payloads', () => {
    expect(validateEncryptedCommandEnvelopeV1({ ...command, payload: {} })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, payload: { content: command.payload.content } })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, targetAlertEventId: 'event_1' })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, extra: true })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, issuedAt: '2026-08-12T00:00:00Z' })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, expiresAt: '2026-08-12T00:05:00.001Z' })).toBe(false);
    expect(() => buildInterruptContentAAD({
      hostId: command.hostId, watchDeviceId: command.watchDeviceId, sessionId: command.sessionId,
      commandId: command.commandId, issuedAt: command.issuedAt, expiresAt: '2026-08-12T00:05:00.001Z',
      nonce: command.nonce, contentId: command.payload.content.contentId,
    })).toThrow();
    expect(validateEncryptedCommandEnvelopeV1({ ...command, linkGeneration: 0 })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, payload: { ...command.payload, content: { ...command.payload.content, payloadKind: 'reply-content-v1' } } })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, linkId: 'link_other' } } })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, contentId: 'content_other' } } })).toBe(false);
    expect(validateEncryptedCommandEnvelopeV1({ ...command, payload: { ...command.payload, content: { ...command.payload.content, ciphertext: base64UrlEncode(new Uint8Array(49)) } } })).toBe(false);
    for (const candidate of [
      { ...command, type: 'reply' },
      { ...command, payload: { ...command.payload, content: { ...command.payload.content, version: 2 } } },
      { ...command, payload: { ...command.payload, content: { ...command.payload.content, suite: 'other' } } },
      { ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, version: 2 } } },
      { ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, suite: 'other' } } },
      { ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, linkGeneration: 8 } } },
      { ...command, payload: { ...command.payload, keyWrap: { ...command.payload.keyWrap, epoch: 4 } } },
    ]) {
      expect(validateEncryptedCommandEnvelopeV1(candidate)).toBe(false);
      expect(() => buildEncryptedCommandEnvelopeBindingBytes(candidate as EncryptedCommandEnvelopeV1)).toThrow();
    }
    let getterCalls = 0;
    const accessor = Object.defineProperty({ ...command }, 'payload', { enumerable: true, get: () => { getterCalls += 1; return command.payload; } });
    expect(validateEncryptedCommandEnvelopeV1(accessor)).toBe(false);
    expect(getterCalls).toBe(0);
  });

  test('binds every encrypted command scalar, content field, and wrap field', async () => {
    const baseline = vectors.interrupt.commandDigest;
    const scalarMutations: Array<[string, unknown]> = [
      ['hostId', 'host_other'], ['watchDeviceId', 'watch_other'], ['sessionId', 'session_other'],
      ['commandId', 'command_other'], ['issuedAt', '2026-08-12T00:00:00.001Z'],
      ['expiresAt', '2026-08-12T00:04:59.999Z'], ['nonce', 'nonce_other'], ['linkId', 'link_other'],
      ['linkGeneration', 8], ['epoch', 4],
    ];
    for (const [field, value] of scalarMutations) {
      const candidate = { ...command, [field]: value } as EncryptedCommandEnvelopeV1;
      if (field === 'linkId' || field === 'linkGeneration' || field === 'epoch') {
        candidate.payload = { ...candidate.payload, keyWrap: { ...candidate.payload.keyWrap, [field]: value } };
      }
      expect(await deriveEncryptedCommandDigest(candidate), field).not.toBe(baseline);
    }
    for (const [field, value] of [
      ['contentId', 'content_other'], ['nonce', mutateBase64(command.payload.content.nonce)],
      ['ciphertext', mutateBase64(command.payload.content.ciphertext)],
    ] as const) {
      const candidate = clone(command);
      candidate.payload.content[field] = value;
      if (field === 'contentId') candidate.payload.keyWrap.contentId = value;
      expect(await deriveEncryptedCommandDigest(candidate), `content.${field}`).not.toBe(baseline);
    }
    for (const [field, value] of [
      [`senderEncryptionKeyId`, `ekey_${'B'.repeat(43)}`], [`recipientEncryptionKeyId`, `ekey_${'C'.repeat(43)}`],
      ['nonce', mutateBase64(command.payload.keyWrap.nonce)], ['ciphertext', mutateBase64(command.payload.keyWrap.ciphertext)],
    ] as const) {
      const candidate = clone(command);
      candidate.payload.keyWrap[field] = value as never;
      expect(await deriveEncryptedCommandDigest(candidate), `keyWrap.${field}`).not.toBe(baseline);
    }
    const reordered = {
      epoch: command.epoch, payload: command.payload, linkGeneration: command.linkGeneration, linkId: command.linkId,
      watchDeviceId: command.watchDeviceId, nonce: command.nonce, expiresAt: command.expiresAt, issuedAt: command.issuedAt,
      type: command.type, commandId: command.commandId, sessionId: command.sessionId, hostId: command.hostId,
    } as EncryptedCommandEnvelopeV1;
    expect(await deriveEncryptedCommandDigest(reordered)).toBe(baseline);

    const reply = clone(command) as unknown as EncryptedCommandEnvelopeV1;
    Object.assign(reply, { type: 'reply', targetAlertEventId: 'event_a' });
    reply.payload.content.payloadKind = 'reply-content-v1';
    const replyBaseline = await deriveEncryptedCommandDigest(reply);
    expect(await deriveEncryptedCommandDigest({ ...reply, targetAlertEventId: 'event_b' })).not.toBe(replyBaseline);
  });

  test('pads every terminal receipt plaintext to one exact canonical length', () => {
    expect(E2E_LIMITS.commandReceiptPlaintextBytes).toBe(128);
    const encoded = vectors.receiptPlaintexts.map(({ value, plaintext }) => {
      expect(validateProtectedCommandReceiptV1(value)).toBe(true);
      const bytes = buildProtectedCommandReceiptBytes(value);
      expect(bytes.byteLength).toBe(128);
      expect(base64UrlEncode(bytes)).toBe(plaintext);
      expect(validateProtectedCommandReceiptBytes(bytes)).toEqual(value);
      return bytes;
    });
    expect(new Set(encoded.map((bytes) => bytes.byteLength))).toEqual(new Set([128]));
    for (const invalid of [
      { version: 1, accepted: false, status: 'executed' }, { version: 1, accepted: true, status: 'failed' },
      { version: 1, accepted: false, status: 'queued' }, { version: 1, accepted: false, status: 'failed', reason: 'x' },
    ]) expect(validateProtectedCommandReceiptV1(invalid)).toBe(false);
    const nonSpacePadding = encoded[0]!.slice(); nonSpacePadding[127] = 0;
    expect(validateProtectedCommandReceiptBytes(nonSpacePadding)).toBeUndefined();
    expect(validateProtectedCommandReceiptBytes(encoded[0]!.subarray(0, 127))).toBeUndefined();
  });

  test('validates and decrypts the deterministic fixed-length receipt fixture', async () => {
    expect(validateCommandReceiptEnvelopeV1(receipt)).toBe(true);
    expect(base64UrlEncode(buildCommandReceiptContentAAD({
      hostId: receipt.hostId, watchDeviceId: receipt.watchDeviceId, sessionId: receipt.sessionId,
      commandId: receipt.commandId, commandType: receipt.commandType, commandDigest: receipt.commandDigest,
      completedAt: receipt.completedAt, contentId: receipt.content.contentId,
    }))).toBe(vectors.receipt.contentAAD);
    expect(base64UrlEncode(buildWrapAAD({
      direction: 'bridge-to-watch', linkId: receipt.linkId, linkGeneration: receipt.linkGeneration,
      epoch: receipt.epoch, hostId: receipt.hostId, watchDeviceId: receipt.watchDeviceId,
      senderEncryptionKeyId: receipt.keyWrap.senderEncryptionKeyId,
      recipientEncryptionKeyId: receipt.keyWrap.recipientEncryptionKeyId,
      contentId: receipt.content.contentId, payloadKind: 'command-receipt-content-v1',
    }))).toBe(vectors.receipt.wrapAAD);
    const dek = openChaChaPoly(
      vectors.keys.bridgeToWatchWrapKey, receipt.keyWrap.nonce,
      receipt.keyWrap.ciphertext, base64UrlDecode(vectors.receipt.wrapAAD),
    );
    expect(base64UrlEncode(dek)).toBe(vectors.receipt.dek);
    const plaintext = openChaChaPoly(
      vectors.receipt.dek, receipt.content.nonce,
      receipt.content.ciphertext, base64UrlDecode(vectors.receipt.contentAAD),
    );
    expect(validateProtectedCommandReceiptBytes(plaintext)).toEqual({ version: 1, accepted: true, status: 'executed' });
    expect(base64UrlEncode(buildCommandReceiptEnvelopeBindingBytes(receipt))).toBe(vectors.receipt.envelopeBinding);
    expect(await deriveCommandReceiptDigest(receipt)).toBe(vectors.receipt.receiptDigest);
    dek.fill(0);
    plaintext.fill(0);
  });

  test('binds every receipt scalar, content field, and wrap field and rejects tuple mismatch', async () => {
    const baseline = vectors.receipt.receiptDigest;
    const scalarMutations: Array<[string, unknown]> = [
      ['version', 2], ['hostId', 'host_other'], ['watchDeviceId', 'watch_other'], ['sessionId', 'session_other'],
      ['commandId', 'command_other'], ['commandType', 'reply'], ['commandDigest', mutateBase64(receipt.commandDigest)],
      ['completedAt', '2026-08-12T00:00:01.001Z'], ['linkId', 'link_other'], ['linkGeneration', 8], ['epoch', 4],
    ];
    for (const [field, value] of scalarMutations) {
      const candidate = { ...receipt, [field]: value } as CommandReceiptEnvelopeV1;
      if (field === 'linkId' || field === 'linkGeneration' || field === 'epoch') {
        candidate.keyWrap = { ...candidate.keyWrap, [field]: value };
      }
      if (field === 'version') {
        expect(validateCommandReceiptEnvelopeV1(candidate)).toBe(false);
      } else {
        expect(await deriveCommandReceiptDigest(candidate), field).not.toBe(baseline);
      }
    }
    for (const [container, field, value] of [
      ['content', 'contentId', 'content_other'], ['content', 'nonce', mutateBase64(receipt.content.nonce)],
      ['content', 'ciphertext', mutateBase64(receipt.content.ciphertext)],
      ['keyWrap', 'senderEncryptionKeyId', `ekey_${'B'.repeat(43)}`], ['keyWrap', 'recipientEncryptionKeyId', `ekey_${'C'.repeat(43)}`],
      ['keyWrap', 'nonce', mutateBase64(receipt.keyWrap.nonce)], ['keyWrap', 'ciphertext', mutateBase64(receipt.keyWrap.ciphertext)],
    ] as const) {
      const candidate = clone(receipt);
      candidate[container][field] = value as never;
      if (container === 'content' && field === 'contentId') candidate.keyWrap.contentId = value;
      expect(await deriveCommandReceiptDigest(candidate), `${container}.${field}`).not.toBe(baseline);
    }
    expect(validateCommandReceiptEnvelopeV1({ ...receipt, extra: true })).toBe(false);
    for (const candidate of [
      { ...receipt, content: { ...receipt.content, version: 2 } },
      { ...receipt, content: { ...receipt.content, suite: 'other' } },
      { ...receipt, content: { ...receipt.content, payloadKind: 'event-content-v2' } },
      { ...receipt, keyWrap: { ...receipt.keyWrap, version: 2 } },
      { ...receipt, keyWrap: { ...receipt.keyWrap, suite: 'other' } },
      { ...receipt, keyWrap: { ...receipt.keyWrap, contentId: 'content_other' } },
      { ...receipt, keyWrap: { ...receipt.keyWrap, linkId: 'link_other' } },
      { ...receipt, keyWrap: { ...receipt.keyWrap, linkGeneration: 8 } },
      { ...receipt, keyWrap: { ...receipt.keyWrap, epoch: 4 } },
    ]) {
      expect(validateCommandReceiptEnvelopeV1(candidate)).toBe(false);
      expect(() => buildCommandReceiptEnvelopeBindingBytes(candidate as CommandReceiptEnvelopeV1)).toThrow();
    }
    expect(validateCommandReceiptEnvelopeV1({ ...receipt, content: { ...receipt.content, ciphertext: base64UrlEncode(new Uint8Array(143)) } })).toBe(false);
    const reordered = {
      keyWrap: receipt.keyWrap, content: receipt.content, epoch: receipt.epoch, linkGeneration: receipt.linkGeneration,
      linkId: receipt.linkId, completedAt: receipt.completedAt, commandDigest: receipt.commandDigest,
      commandType: receipt.commandType, commandId: receipt.commandId, sessionId: receipt.sessionId,
      watchDeviceId: receipt.watchDeviceId, hostId: receipt.hostId, version: receipt.version,
    } as CommandReceiptEnvelopeV1;
    expect(await deriveCommandReceiptDigest(reordered)).toBe(baseline);
  });
});
