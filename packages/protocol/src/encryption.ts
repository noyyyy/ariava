import { base64UrlDecode } from './request-signing.js';
import type { EventType, SessionStatus } from './events.js';

export const E2E_SUITE_V1 = 'x25519-hkdf-sha256-chachapoly-v1' as const;
export const E2E_EPOCH_STATES = [
  'pending_confirmation',
  'confirmations_complete',
  'host_activated',
  'watch_activated',
  'active',
  'retiring',
  'revoked',
  'expired',
] as const;
export type E2EEpochState = (typeof E2E_EPOCH_STATES)[number];
export const E2E_EPOCH_OPERATIONS = [
  'create_event_wrap',
  'create_session_wrap',
  'read_historical_content',
  'create_command',
  'deliver_existing_command',
] as const;
export type E2EEpochOperation = (typeof E2E_EPOCH_OPERATIONS)[number];
export type E2EDirection = 'bridge-to-watch' | 'watch-to-bridge';
export type ProtectedPayloadKind = 'event-content-v1' | 'session-content-v1' | 'reply-content-v1';

export const E2E_LIMITS = {
  publicKeyBytes: 32,
  digestBytes: 32,
  nonceBytes: 12,
  authenticationTagBytes: 16,
  wrappedDekBytes: 48,
  eventPlaintextBytes: 32 * 1024,
  sessionPlaintextBytes: 16 * 1024,
  replyPlaintextBytes: 4_000,
  promptOptions: 10,
  promptOptionBytes: 500,
} as const;

export interface EncryptionKeyBindingV1 {
  version: 1;
  entityType: 'host' | 'watch';
  entityId: string;
  identityKeyId: string;
  encryptionKeyId: string;
  suite: typeof E2E_SUITE_V1;
  publicKey: string;
  sequence: number;
  createdAt: string;
  bindingSignature: string;
}

export interface E2EPendingLinkProjectionV1 {
  linkId: string;
  hostId: string;
  watchDeviceId: string;
  linkGeneration: number;
  epoch: number;
  hostBinding: EncryptionKeyBindingV1;
  watchBinding: EncryptionKeyBindingV1;
  transcriptDigest: string;
  confirmationExpiresAt: string;
  state: Extract<E2EEpochState, 'pending_confirmation' | 'confirmations_complete' | 'host_activated' | 'watch_activated'>;
}

export interface E2EConfirmationSubmissionV1 {
  linkId: string;
  linkGeneration: number;
  epoch: number;
  transcriptDigest: string;
  confirmationProof: string;
}

export interface E2EActivationAckV1 {
  linkId: string;
  linkGeneration: number;
  epoch: number;
  transcriptDigest: string;
  peerRole: 'host' | 'watch';
  peerProofDigest: string;
  activatedAt: string;
}

export const E2E_REASON_CODES = [
  'e2e_upgrade_required',
  'e2e_recipient_not_ready',
  'e2e_recipient_set_changed',
  'e2e_key_unavailable',
  'e2e_epoch_mismatch',
  'e2e_unwrap_failed',
  'e2e_content_auth_failed',
  'e2e_payload_invalid',
  'session_revision_stale',
  'session_revision_gap',
] as const;
export type E2EReasonCode = (typeof E2E_REASON_CODES)[number];

export interface EncryptedContentV1 {
  version: 1;
  suite: typeof E2E_SUITE_V1;
  contentId: string;
  payloadKind: ProtectedPayloadKind;
  nonce: string;
  ciphertext: string;
}

export interface RecipientKeyWrapV1 {
  version: 1;
  suite: typeof E2E_SUITE_V1;
  contentId: string;
  linkId: string;
  linkGeneration: number;
  epoch: number;
  senderEncryptionKeyId: string;
  recipientEncryptionKeyId: string;
  nonce: string;
  ciphertext: string;
}

export interface EncryptedPayloadForRecipientV1 {
  content: EncryptedContentV1;
  keyWrap: RecipientKeyWrapV1;
}

export interface E2ERecipientV1 {
  linkId: string;
  linkGeneration: number;
  watchDeviceId: string;
  epoch: number;
  state: Extract<E2EEpochState, 'active'>;
  watchBinding: EncryptionKeyBindingV1;
}

export interface E2ERecipientSnapshotV1 {
  hostId: string;
  recipientSetVersion: number;
  recipients: E2ERecipientV1[];
}

export interface ProtectedActionablePromptV1 {
  promptId: string;
  type: 'question';
  label: string;
  options?: string[];
  expiresAt?: string;
}

export interface ProtectedEventContentV1 {
  version: 1;
  assistantText: string;
  userMessageText?: string;
  contextText?: string;
  actionablePrompt?: ProtectedActionablePromptV1;
}

export interface ProtectedSessionContentV1 {
  version: 1;
  projectName: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
}

export interface ProtectedReplyContentV1 { version: 1; text: string }

export interface RelayEventMetadataV1 {
  eventId: string;
  hostId: string;
  sessionId: string;
  provider: string;
  type: EventType;
  status: SessionStatus;
  correlationId?: string;
  createdAt: string;
}

export interface RelaySessionMetadataV1 {
  hostId: string;
  sessionId: string;
  provider: string;
  status: SessionStatus;
  updatedAt: string;
  lastEventId?: string;
  snoozedUntil?: string;
}

export interface EncryptedEventProjectionV1 extends RelayEventMetadataV1 {
  content: EncryptedContentV1;
  keyWrap: RecipientKeyWrapV1;
}

export interface EncryptedSessionProjectionV1 extends RelaySessionMetadataV1 {
  revision: number;
  content: EncryptedContentV1;
  keyWrap: RecipientKeyWrapV1;
}

export interface EncryptedEventUploadV1 extends RelayEventMetadataV1 {
  recipientSetVersion: number;
  content: EncryptedContentV1;
  keyWraps: RecipientKeyWrapV1[];
}

export interface EncryptedSessionSnapshotUploadV1 extends RelaySessionMetadataV1 {
  revision: number;
  recipientSetVersion: number;
  content: EncryptedContentV1;
  keyWraps: RecipientKeyWrapV1[];
}

export interface EncryptedSessionCurrentProjectionV1 {
  hostId: string;
  sessionId: string;
  currentRevision: number;
  snapshot: EncryptedSessionProjectionV1;
}

export interface EventContentAADInput extends RelayEventMetadataV1 { contentId: string }
export interface SessionContentAADInput extends RelaySessionMetadataV1 { revision: number; contentId: string }
export interface ReplyContentAADInput {
  hostId: string;
  watchDeviceId: string;
  sessionId: string;
  commandId: string;
  targetAlertEventId: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  contentId: string;
}
export interface WrapAADInput {
  direction: E2EDirection;
  linkId: string;
  linkGeneration: number;
  epoch: number;
  hostId: string;
  watchDeviceId: string;
  senderEncryptionKeyId: string;
  recipientEncryptionKeyId: string;
  contentId: string;
  payloadKind: ProtectedPayloadKind;
}

const encoder = new TextEncoder();

export function encodeLengthPrefixedFields(fields: readonly string[]): Uint8Array {
  const chunks = fields.map((field) => {
    const bytes = encoder.encode(field);
    return encoder.encode(`${bytes.byteLength}:${field}\n`);
  });
  const size = chunks.reduce((sum, value) => sum + value.byteLength, 0);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}

export function buildEncryptionBindingBytes(binding: Omit<EncryptionKeyBindingV1, 'bindingSignature'>): Uint8Array {
  return encodeLengthPrefixedFields([
    'ariava-e2e-binding-v1', binding.entityType, binding.entityId, binding.identityKeyId,
    binding.encryptionKeyId, binding.suite, String(binding.sequence), binding.createdAt, binding.publicKey,
  ]);
}

export function buildLinkTranscriptBytes(input: {
  linkId: string; hostId: string; watchDeviceId: string; linkGeneration: number; epoch: number;
  hostBindingDigest: string; watchBindingDigest: string; suite?: typeof E2E_SUITE_V1;
}): Uint8Array {
  return encodeLengthPrefixedFields([
    'ariava-e2e-link-transcript-v1', input.linkId, input.hostId, input.watchDeviceId,
    String(input.linkGeneration), String(input.epoch), input.hostBindingDigest, input.watchBindingDigest,
    input.suite ?? E2E_SUITE_V1,
  ]);
}

export function pairRootInfo(linkId: string, linkGeneration: number, epoch: number): Uint8Array {
  return encoder.encode(`ariava:e2e:v1:pair-root:${linkId}:${linkGeneration}:${epoch}`);
}

export function buildConfirmationProofBytes(role: 'host' | 'watch', transcriptDigest: string): Uint8Array {
  return encodeLengthPrefixedFields(['ariava-e2e-confirmation-proof-v1', role, transcriptDigest]);
}

export function buildSafetyCodeInput(transcriptDigest: string, linkGeneration: number, epoch: number): Uint8Array {
  return encodeLengthPrefixedFields([
    'ariava-e2e-safety-code-v1', transcriptDigest, String(linkGeneration), String(epoch),
  ]);
}

export function buildEventContentAAD(input: EventContentAADInput): Uint8Array {
  return encodeLengthPrefixedFields([
    'ariava-content-aad-v1', 'bridge-to-watch', input.hostId, input.sessionId, input.provider,
    input.eventId, input.type, input.status, input.createdAt, input.contentId, 'event-content-v1',
  ]);
}

export function buildSessionContentAAD(input: SessionContentAADInput): Uint8Array {
  return encodeLengthPrefixedFields([
    'ariava-content-aad-v1', 'bridge-to-watch', input.hostId, input.sessionId, input.provider,
    input.status, input.updatedAt, String(input.revision), input.contentId, 'session-content-v1',
  ]);
}

export function buildReplyContentAAD(input: ReplyContentAADInput): Uint8Array {
  return encodeLengthPrefixedFields([
    'ariava-content-aad-v1', 'watch-to-bridge', input.hostId, input.watchDeviceId, input.sessionId,
    input.commandId, input.targetAlertEventId, input.issuedAt, input.expiresAt, input.nonce,
    input.contentId, 'reply-content-v1',
  ]);
}

export function buildWrapAAD(input: WrapAADInput): Uint8Array {
  return encodeLengthPrefixedFields([
    'ariava-wrap-aad-v1', input.direction, input.linkId, String(input.linkGeneration), String(input.epoch),
    input.hostId, input.watchDeviceId, input.senderEncryptionKeyId, input.recipientEncryptionKeyId,
    input.contentId, input.payloadKind,
  ]);
}

export function isEpochOperationAllowed(state: E2EEpochState, operation: E2EEpochOperation): boolean {
  if (state === 'active') return true;
  if (state !== 'retiring') return false;
  return operation === 'read_historical_content' || operation === 'deliver_existing_command';
}

export function validateEncryptionKeyBindingV1(value: unknown): value is EncryptionKeyBindingV1 {
  if (!isExactRecord(value, ['version', 'entityType', 'entityId', 'identityKeyId', 'encryptionKeyId', 'suite', 'publicKey', 'sequence', 'createdAt', 'bindingSignature'])) return false;
  try {
    return value.version === 1 && (value.entityType === 'host' || value.entityType === 'watch')
      && typeof value.entityId === 'string' && typeof value.identityKeyId === 'string'
      && typeof value.encryptionKeyId === 'string' && /^ekey_[A-Za-z0-9_-]{43}$/u.test(value.encryptionKeyId)
      && value.suite === E2E_SUITE_V1 && decodeBase64Url(value.publicKey, 32)
      && Number.isSafeInteger(value.sequence) && (value.sequence as number) > 0
      && typeof value.createdAt === 'string' && typeof value.bindingSignature === 'string'
      && decodeBase64Url(value.bindingSignature, 64);
  } catch { return false; }
}

export function validateEncryptedContentV1(value: unknown): value is EncryptedContentV1 {
  if (!isExactRecord(value, ['version', 'suite', 'contentId', 'payloadKind', 'nonce', 'ciphertext'])) return false;
  const max = value.payloadKind === 'event-content-v1' ? E2E_LIMITS.eventPlaintextBytes
    : value.payloadKind === 'session-content-v1' ? E2E_LIMITS.sessionPlaintextBytes
      : value.payloadKind === 'reply-content-v1' ? E2E_LIMITS.replyPlaintextBytes : -1;
  try {
    const ciphertext = typeof value.ciphertext === 'string' ? base64UrlDecode(value.ciphertext) : new Uint8Array();
    return value.version === 1 && value.suite === E2E_SUITE_V1 && typeof value.contentId === 'string'
      && max >= 0 && decodeBase64Url(value.nonce, 12) && ciphertext.byteLength >= 16
      && ciphertext.byteLength <= max + 16;
  } catch { return false; }
}

export function validateRecipientKeyWrapV1(value: unknown): value is RecipientKeyWrapV1 {
  if (!isExactRecord(value, ['version', 'suite', 'contentId', 'linkId', 'linkGeneration', 'epoch', 'senderEncryptionKeyId', 'recipientEncryptionKeyId', 'nonce', 'ciphertext'])) return false;
  return value.version === 1 && value.suite === E2E_SUITE_V1 && typeof value.contentId === 'string'
    && typeof value.linkId === 'string' && isPositiveInteger(value.linkGeneration) && isPositiveInteger(value.epoch)
    && typeof value.senderEncryptionKeyId === 'string' && typeof value.recipientEncryptionKeyId === 'string'
    && decodeBase64Url(value.nonce, 12) && decodeBase64Url(value.ciphertext, 48);
}

function decodeBase64Url(value: unknown, bytes: number): boolean {
  if (typeof value !== 'string') return false;
  try { base64UrlDecode(value, bytes); return true; } catch { return false; }
}
function isPositiveInteger(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) > 0; }
function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}
