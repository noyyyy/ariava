import type {
  EncryptedContentV1,
  EncryptedPayloadForRecipientV1,
  RecipientKeyWrapV1,
} from './encryption.js';
import { base64UrlDecode } from './request-signing.js';
import { isCanonicalTimestamp } from './validation.js';

export const COMMAND_TYPES = ['reply', 'interrupt'] as const;
export type CommandType = (typeof COMMAND_TYPES)[number];
export const COMMAND_RESULT_STATUSES = ['executed', 'expired', 'rejected', 'failed'] as const;
export type CommandResultStatus = (typeof COMMAND_RESULT_STATUSES)[number];
export const COMMAND_LIMITS = {
  maxTtlMs: 300_000,
  replyTextBytes: 4_000,
  replyCanonicalPlaintextBytes: 24_023,
  replyCiphertextBytes: 24_039,
} as const;

const COMMAND_IDENTIFIER_BYTES = 256;
const encoder = new TextEncoder();

export interface EncryptedCommandEnvelopeBaseV1 {
  commandId: string;
  hostId: string;
  sessionId: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  watchDeviceId: string;
  linkId: string;
  linkGeneration: number;
  epoch: number;
}

export interface EncryptedReplyPayloadV1 {
  content: EncryptedContentV1 & { payloadKind: 'reply-content-v1' };
  keyWrap: RecipientKeyWrapV1;
}

export interface EncryptedInterruptPayloadV1 {
  content: EncryptedContentV1 & { payloadKind: 'interrupt-content-v1' };
  keyWrap: RecipientKeyWrapV1;
}

export interface EncryptedReplyCommandEnvelopeV1 extends EncryptedCommandEnvelopeBaseV1 {
  type: 'reply';
  payload: EncryptedReplyPayloadV1;
  targetAlertEventId: string;
}

export interface InterruptCommandEnvelopeV1 extends EncryptedCommandEnvelopeBaseV1 {
  type: 'interrupt';
  payload: EncryptedInterruptPayloadV1;
  targetAlertEventId?: never;
}

/** Relay/Watch wire command. Command content can only exist inside the encrypted payload. */
export type EncryptedCommandEnvelopeV1 = EncryptedReplyCommandEnvelopeV1 | InterruptCommandEnvelopeV1;

/**
 * Decrypted loopback-only Agent Adapter command. This legacy name remains the
 * local extension boundary; Relay code must use EncryptedCommandEnvelopeV1.
 */
export interface CommandEnvelope {
  commandId: string;
  hostId: string;
  sessionId: string;
  type: CommandType;
  payload: Record<string, string | number | boolean | null | undefined>;
  targetAlertEventId?: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  watchDeviceId: string;
}
export type LocalAgentCommandEnvelope = CommandEnvelope;

interface CommandResultBase {
  commandId: string;
  hostId: string;
  sessionId: string;
  updatedAt: string;
}

export type CommandResult = CommandResultBase & (
  | { accepted: true; status: 'executed' }
  | { accepted: false; status: 'expired' | 'rejected' | 'failed' }
);

export interface CommandSubmissionAckV1 {
  commandId: string;
  receivedAt: string;
}

export function isCommandExpired(command: Pick<CommandEnvelope | EncryptedCommandEnvelopeV1, 'expiresAt'>, now = new Date()): boolean {
  return new Date(command.expiresAt).getTime() <= now.getTime();
}

export function validateCommandType(type: string): type is CommandType {
  return (COMMAND_TYPES as readonly string[]).includes(type);
}

export function validateCommandResult(value: unknown): value is CommandResult {
  if (!isExactRecord(value, ['commandId', 'hostId', 'sessionId', 'accepted', 'status', 'updatedAt'], ['commandId', 'hostId', 'sessionId', 'accepted', 'status', 'updatedAt'])) return false;
  return isIdentifier(value.commandId)
    && isIdentifier(value.hostId)
    && isIdentifier(value.sessionId)
    && isCanonicalTimestamp(value.updatedAt)
    && ((value.accepted === true && value.status === 'executed')
      || (value.accepted === false && (value.status === 'expired' || value.status === 'rejected' || value.status === 'failed')));
}

export function validateCommandSubmissionAckV1(value: unknown): value is CommandSubmissionAckV1 {
  return isExactRecord(value, ['commandId', 'receivedAt'], ['commandId', 'receivedAt'])
    && isIdentifier(value.commandId)
    && isCanonicalTimestamp(value.receivedAt);
}

export function validateEncryptedCommandEnvelopeV1(value: unknown): value is EncryptedCommandEnvelopeV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const typeDescriptor = Object.getOwnPropertyDescriptor(value, 'type');
  if (!typeDescriptor || !typeDescriptor.enumerable || !('value' in typeDescriptor)) return false;
  const type = typeDescriptor.value;
  const keys = type === 'reply'
    ? ['commandId', 'hostId', 'sessionId', 'type', 'payload', 'targetAlertEventId', 'issuedAt', 'expiresAt', 'nonce', 'watchDeviceId', 'linkId', 'linkGeneration', 'epoch']
    : ['commandId', 'hostId', 'sessionId', 'type', 'payload', 'issuedAt', 'expiresAt', 'nonce', 'watchDeviceId', 'linkId', 'linkGeneration', 'epoch'];
  if ((type !== 'reply' && type !== 'interrupt') || !isExactRecord(value, keys, keys)) return false;
  if (!isIdentifier(value.commandId) || !isIdentifier(value.hostId) || !isIdentifier(value.sessionId)
    || !isIdentifier(value.watchDeviceId) || !isIdentifier(value.linkId)
    || !isCanonicalTimestamp(value.issuedAt) || !isCanonicalTimestamp(value.expiresAt)
    || new Date(value.expiresAt as string).getTime() <= new Date(value.issuedAt as string).getTime()
    || new Date(value.expiresAt as string).getTime() > new Date(value.issuedAt as string).getTime() + COMMAND_LIMITS.maxTtlMs
    || !isIdentifier(value.nonce) || !isPositiveInteger(value.linkGeneration) || !isPositiveInteger(value.epoch)
    || !validateEncryptedPayload(value.payload, type === 'reply' ? 'reply-content-v1' : 'interrupt-content-v1')) return false;
  const payload = value.payload as EncryptedPayloadForRecipientV1;
  if (payload.keyWrap.linkId !== value.linkId || payload.keyWrap.linkGeneration !== value.linkGeneration
    || payload.keyWrap.epoch !== value.epoch) return false;
  return type === 'interrupt' || isIdentifier(value.targetAlertEventId);
}

function validateEncryptedPayload(value: unknown, payloadKind: 'reply-content-v1' | 'interrupt-content-v1'): value is EncryptedPayloadForRecipientV1 {
  if (!isExactRecord(value, ['content', 'keyWrap'], ['content', 'keyWrap'])) return false;
  const { content, keyWrap } = value;
  if (!isExactRecord(content, ['version', 'suite', 'contentId', 'payloadKind', 'nonce', 'ciphertext'], ['version', 'suite', 'contentId', 'payloadKind', 'nonce', 'ciphertext'])
    || !isExactRecord(keyWrap, ['version', 'suite', 'contentId', 'linkId', 'linkGeneration', 'epoch', 'senderEncryptionKeyId', 'recipientEncryptionKeyId', 'nonce', 'ciphertext'], ['version', 'suite', 'contentId', 'linkId', 'linkGeneration', 'epoch', 'senderEncryptionKeyId', 'recipientEncryptionKeyId', 'nonce', 'ciphertext'])) return false;
  return content.payloadKind === payloadKind
    && content.version === 1
    && content.suite === 'x25519-hkdf-sha256-chachapoly-v1'
    && isIdentifier(content.contentId)
    && isBase64UrlBytes(content.nonce, 12)
    && isBase64UrlCiphertext(
      content.ciphertext,
      payloadKind === 'interrupt-content-v1' ? 50 : 16,
      payloadKind === 'interrupt-content-v1' ? 50 : COMMAND_LIMITS.replyCiphertextBytes,
    )
    && keyWrap.version === 1
    && keyWrap.suite === content.suite
    && keyWrap.contentId === content.contentId
    && isIdentifier(keyWrap.linkId)
    && isPositiveInteger(keyWrap.linkGeneration)
    && isPositiveInteger(keyWrap.epoch)
    && typeof keyWrap.senderEncryptionKeyId === 'string'
    && ID_PATTERNS.encryptionKey.test(keyWrap.senderEncryptionKeyId)
    && typeof keyWrap.recipientEncryptionKeyId === 'string'
    && ID_PATTERNS.encryptionKey.test(keyWrap.recipientEncryptionKeyId)
    && isBase64UrlBytes(keyWrap.nonce, 12)
    && isBase64UrlBytes(keyWrap.ciphertext, 48);
}

function isBase64UrlBytes(value: unknown, length: number): boolean {
  if (typeof value !== 'string') return false;
  try { base64UrlDecode(value, length); return true; } catch { return false; }
}

function isBase64UrlCiphertext(value: unknown, minimumLength: number, maximumLength: number): boolean {
  if (typeof value !== 'string') return false;
  try {
    const bytes = base64UrlDecode(value);
    return bytes.byteLength >= minimumLength && bytes.byteLength <= maximumLength;
  } catch { return false; }
}

function isIdentifier(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && encoder.encode(value).byteLength <= COMMAND_IDENTIFIER_BYTES && isWellFormedUnicode(value);
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

const ID_PATTERNS = {
  encryptionKey: /^ekey_[A-Za-z0-9_-]{43}$/u,
} as const;

function isExactRecord(
  value: unknown,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = new Set(allowedKeys);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.has(key)) return false;
    const descriptor = descriptors[key]!;
    if (!descriptor.enumerable || !('value' in descriptor)) return false;
  }
  for (const key of requiredKeys) if (!Object.hasOwn(value, key)) return false;
  for (const key of allowedKeys) if (!Object.hasOwn(value, key) && key in value) return false;
  return true;
}
