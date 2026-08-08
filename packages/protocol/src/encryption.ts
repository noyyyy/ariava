import { base64UrlDecode, contentSha256 } from './request-signing.js';
import { SESSION_STATUSES, type EventType, type NeedHumanContext, type SessionStatus } from './events.js';
import { validateCanonicalEventInvariant } from './validation.js';

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
export type ProtectedPayloadKind =
  | 'event-content-v2'
  | 'session-content-v2'
  | 'reply-content-v1'
  | 'notification-preview-v2';

export const E2E_LIMITS = {
  publicKeyBytes: 32,
  digestBytes: 32,
  nonceBytes: 12,
  authenticationTagBytes: 16,
  wrappedDekBytes: 48,
  eventPlaintextBytes: 32 * 1024,
  sessionPlaintextBytes: 16 * 1024,
  replyPlaintextBytes: 4_000,
  notificationPreviewPlaintextBytes: 4_000,
  notificationPreviewProjectNameBytes: 256,
  notificationPreviewBodyTextBytes: 4_000,
  notificationPreviewIdentifierBytes: 256,
  notificationPreviewContentIdBytes: 256,
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
  hostIdentityPublicKey: string;
  watchBinding: EncryptionKeyBindingV1;
  watchIdentityPublicKey: string;
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

export interface ProtectedEventContentV2 {
  version: 2;
  agentText: string;
  humanText?: string;
  projectName?: string;
  contextText?: string;
  workingDirectory?: string;
  hbaseSessionKey?: string;
  harnessProvider?: string;
  actionablePrompt?: ProtectedActionablePromptV1;
  needHuman?: NeedHumanContext;
}

export interface ProtectedSessionContentV2 {
  version: 2;
  projectName: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
  workingDirectory?: string;
  hbaseSessionKey?: string;
  harnessProvider?: string;
}

export interface ProtectedReplyContentV1 { version: 1; text: string }

export interface EncryptedNotificationPreviewPlaintextV2 {
  version: 2;
  projectName: string;
  eventType: EventType;
  bodyText: string;
  truncated: boolean;
}

interface RelayEventMetadataBaseV2 {
  eventId: string;
  hostId: string;
  sessionId: string;
  provider: string;
  correlationId?: string;
  createdAt: string;
}

export type RelayEventMetadataV2 = RelayEventMetadataBaseV2 & (
  | { type: 'done'; status: 'idle' }
  | { type: 'need_human'; status: 'need_human' }
);

export interface RelaySessionMetadataV2 {
  hostId: string;
  sessionId: string;
  provider: string;
  status: SessionStatus;
  updatedAt: string;
  lastEventId?: string;
  snoozedUntil?: string;
}

export type EncryptedEventProjectionV2 = RelayEventMetadataV2 & {
  content: EncryptedContentV1 & { payloadKind: 'event-content-v2' };
  keyWrap: RecipientKeyWrapV1;
};

export interface EncryptedSessionProjectionV2 extends RelaySessionMetadataV2 {
  revision: number;
  content: EncryptedContentV1 & { payloadKind: 'session-content-v2' };
  keyWrap: RecipientKeyWrapV1;
}

export type EncryptedEventUploadV2 = RelayEventMetadataV2 & {
  recipientSetVersion: number;
  content: EncryptedContentV1 & { payloadKind: 'event-content-v2' };
  keyWraps: RecipientKeyWrapV1[];
  notificationPreviews?: NotificationPreviewEnvelopeV2[];
};

export interface EncryptedSessionSnapshotUploadV2 extends RelaySessionMetadataV2 {
  revision: number;
  recipientSetVersion: number;
  content: EncryptedContentV1 & { payloadKind: 'session-content-v2' };
  keyWraps: RecipientKeyWrapV1[];
}

export interface EncryptedSessionCurrentProjectionV2 {
  hostId: string;
  sessionId: string;
  currentRevision: number;
  snapshot: EncryptedSessionProjectionV2;
}

export type EventContentAADInput = RelayEventMetadataV2 & { contentId: string };
export interface SessionContentAADInput extends RelaySessionMetadataV2 { revision: number; contentId: string }
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
export interface NotificationPreviewAADInput {
  hostId: string;
  watchDeviceId: string;
  eventId: string;
  sessionId: string;
  eventType: EventType;
  linkId: string;
  linkGeneration: number;
  epoch: number;
  senderEncryptionKeyId: string;
  recipientEncryptionKeyId: string;
  contentId: string;
  payloadKind: 'notification-preview-v2';
}

export interface NotificationPreviewEnvelopeV2 {
  eventId: string;
  sessionId: string;
  eventType: EventType;
  watchDeviceId: string;
  content: EncryptedContentV1 & { payloadKind: 'notification-preview-v2' };
  keyWrap: RecipientKeyWrapV1;
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

function isBoundedWellFormedString(value: unknown, maxBytes: number): value is string {
  return typeof value === 'string'
    && value.length > 0
    && encoder.encode(value).byteLength <= maxBytes
    && isWellFormedUnicode(value);
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

const CANONICAL_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ID_PATTERNS = {
  host: /^host_[A-Za-z0-9_-]{43}$/u,
  watch: /^watch_[A-Za-z0-9_-]{43}$/u,
  identityKey: /^key_[A-Za-z0-9_-]{43}$/u,
  encryptionKey: /^ekey_[A-Za-z0-9_-]{43}$/u,
} as const;

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
  assertValidEncryptionBinding(binding);
  return encodeLengthPrefixedFields([
    'ariava-e2e-binding-v1', binding.entityType, binding.entityId, binding.identityKeyId,
    binding.encryptionKeyId, binding.suite, String(binding.sequence), binding.createdAt, binding.publicKey,
  ]);
}

export function buildProtectedEventContentBytes(content: ProtectedEventContentV2): Uint8Array {
  const actionablePrompt = assertProtectedEventContent(content);
  const canonical = {
    version: 2,
    agentText: content.agentText,
    ...(content.humanText === undefined ? {} : { humanText: content.humanText }),
    ...(content.projectName === undefined ? {} : { projectName: content.projectName }),
    ...(content.contextText === undefined ? {} : { contextText: content.contextText }),
    ...(content.workingDirectory === undefined ? {} : { workingDirectory: content.workingDirectory }),
    ...(content.hbaseSessionKey === undefined ? {} : { hbaseSessionKey: content.hbaseSessionKey }),
    ...(content.harnessProvider === undefined ? {} : { harnessProvider: content.harnessProvider }),
    ...(actionablePrompt === undefined ? {} : { actionablePrompt }),
    ...(content.needHuman === undefined ? {} : { needHuman: canonicalNeedHumanContext(content.needHuman) }),
  };
  const bytes = encoder.encode(JSON.stringify(canonical));
  if (bytes.byteLength > E2E_LIMITS.eventPlaintextBytes) throw new TypeError('protected event content is invalid');
  return bytes;
}

export function buildProtectedSessionContentBytes(content: ProtectedSessionContentV2): Uint8Array {
  assertProtectedSessionContent(content);
  const bytes = encoder.encode(JSON.stringify({
    version: 2,
    projectName: content.projectName,
    nameText: content.nameText,
    ...(content.openingText === undefined ? {} : { openingText: content.openingText }),
    ...(content.latestActivityText === undefined ? {} : { latestActivityText: content.latestActivityText }),
    ...(content.workingDirectory === undefined ? {} : { workingDirectory: content.workingDirectory }),
    ...(content.hbaseSessionKey === undefined ? {} : { hbaseSessionKey: content.hbaseSessionKey }),
    ...(content.harnessProvider === undefined ? {} : { harnessProvider: content.harnessProvider }),
  }));
  if (bytes.byteLength > E2E_LIMITS.sessionPlaintextBytes) throw new TypeError('protected session content is invalid');
  return bytes;
}

export function buildProtectedReplyContentBytes(content: ProtectedReplyContentV1): Uint8Array {
  assertExactKeys(content, ['version', 'text'], 'protected reply content', ['version', 'text']);
  if (content.version !== 1 || typeof content.text !== 'string' || encoder.encode(content.text).byteLength > E2E_LIMITS.replyPlaintextBytes) {
    throw new TypeError('protected reply content is invalid');
  }
  return encoder.encode(JSON.stringify({ version: 1, text: content.text }));
}

function canonicalNotificationPreviewPlaintextBytes(content: unknown): Uint8Array | undefined {
  if (!isExactRecord(content, ['version', 'projectName', 'eventType', 'bodyText', 'truncated'])) return undefined;
  const descriptors = Object.getOwnPropertyDescriptors(content);
  const version = descriptors.version!.value;
  const projectName = descriptors.projectName!.value;
  const eventType = descriptors.eventType!.value;
  const bodyText = descriptors.bodyText!.value;
  const truncated = descriptors.truncated!.value;
  if (version !== 2
    || !isBoundedWellFormedString(projectName, E2E_LIMITS.notificationPreviewProjectNameBytes)
    || (eventType !== 'done' && eventType !== 'need_human')
    || !isBoundedWellFormedString(bodyText, E2E_LIMITS.notificationPreviewBodyTextBytes)
    || typeof truncated !== 'boolean') return undefined;
  const canonical = Object.assign(Object.create(null) as Record<string, unknown>, {
    version: 2, projectName, eventType, bodyText, truncated,
  });
  const bytes = encoder.encode(JSON.stringify(canonical));
  return bytes.byteLength <= E2E_LIMITS.notificationPreviewPlaintextBytes ? bytes : undefined;
}

export function buildNotificationPreviewPlaintextBytes(content: EncryptedNotificationPreviewPlaintextV2): Uint8Array {
  const bytes = canonicalNotificationPreviewPlaintextBytes(content);
  if (!bytes) throw new TypeError('notification preview plaintext is invalid');
  return bytes;
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

function isCanonicalOptionalAADString(value: unknown): boolean {
  return value === undefined || isBoundedWellFormedString(value, E2E_LIMITS.notificationPreviewIdentifierBytes);
}

function isCanonicalOptionalTimestamp(value: unknown): boolean {
  return value === undefined || (typeof value === 'string' && isCanonicalTimestamp(value));
}

export function buildEventContentAAD(input: EventContentAADInput): Uint8Array {
  if (!((input.type === 'done' && input.status === 'idle')
    || (input.type === 'need_human' && input.status === 'need_human'))
    || !isBoundedWellFormedString(input.hostId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.sessionId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.provider, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.eventId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isCanonicalOptionalAADString(input.correlationId)
    || !isCanonicalTimestamp(input.createdAt)
    || !isBoundedWellFormedString(input.contentId, E2E_LIMITS.notificationPreviewContentIdBytes)) {
    throw new TypeError('event content AAD input is invalid');
  }
  return encodeLengthPrefixedFields([
    'ariava-event-content-aad-v2', 'bridge-to-watch', input.hostId, input.sessionId, input.provider,
    input.eventId, input.type, input.status, input.correlationId ?? '', input.createdAt, input.contentId, 'event-content-v2',
  ]);
}

export function buildSessionContentAAD(input: SessionContentAADInput): Uint8Array {
  if (!(SESSION_STATUSES as readonly unknown[]).includes(input.status)
    || !isBoundedWellFormedString(input.hostId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.sessionId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.provider, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isCanonicalTimestamp(input.updatedAt) || !isPositiveInteger(input.revision)
    || !isCanonicalOptionalAADString(input.lastEventId) || !isCanonicalOptionalTimestamp(input.snoozedUntil)
    || !isBoundedWellFormedString(input.contentId, E2E_LIMITS.notificationPreviewContentIdBytes)) {
    throw new TypeError('session content AAD input is invalid');
  }
  return encodeLengthPrefixedFields([
    'ariava-session-content-aad-v2', 'bridge-to-watch', input.hostId, input.sessionId, input.provider,
    input.status, input.updatedAt, input.lastEventId ?? '', input.snoozedUntil ?? '',
    String(input.revision), input.contentId, 'session-content-v2',
  ]);
}

export function buildReplyContentAAD(input: ReplyContentAADInput): Uint8Array {
  if (!isBoundedWellFormedString(input.contentId, E2E_LIMITS.notificationPreviewContentIdBytes)) {
    throw new TypeError('reply content AAD input is invalid');
  }
  return encodeLengthPrefixedFields([
    'ariava-content-aad-v1', 'watch-to-bridge', input.hostId, input.watchDeviceId, input.sessionId,
    input.commandId, input.targetAlertEventId, input.issuedAt, input.expiresAt, input.nonce,
    input.contentId, 'reply-content-v1',
  ]);
}

export function buildNotificationPreviewAAD(input: NotificationPreviewAADInput): Uint8Array {
  if (input.payloadKind !== 'notification-preview-v2'
    || (input.eventType !== 'done' && input.eventType !== 'need_human')
    || !isBoundedWellFormedString(input.hostId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.watchDeviceId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.eventId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.sessionId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.linkId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isPositiveInteger(input.linkGeneration) || !isPositiveInteger(input.epoch)
    || !isBoundedWellFormedString(input.senderEncryptionKeyId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.recipientEncryptionKeyId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.contentId, E2E_LIMITS.notificationPreviewContentIdBytes)) {
    throw new TypeError('notification preview AAD input is invalid');
  }
  return encodeLengthPrefixedFields([
    'ariava-notification-preview-aad-v2', 'bridge-to-watch', input.hostId, input.watchDeviceId,
    input.eventId, input.sessionId, input.eventType, input.linkId, String(input.linkGeneration), String(input.epoch),
    input.senderEncryptionKeyId, input.recipientEncryptionKeyId, input.contentId, input.payloadKind,
  ]);
}

export function buildWrapAAD(input: WrapAADInput): Uint8Array {
  if ((input.direction !== 'bridge-to-watch' && input.direction !== 'watch-to-bridge')
    || !(['event-content-v2', 'session-content-v2', 'reply-content-v1', 'notification-preview-v2'] as readonly unknown[]).includes(input.payloadKind)
    || !isBoundedWellFormedString(input.linkId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isPositiveInteger(input.linkGeneration) || !isPositiveInteger(input.epoch)
    || !isBoundedWellFormedString(input.hostId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.watchDeviceId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.senderEncryptionKeyId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.recipientEncryptionKeyId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(input.contentId, E2E_LIMITS.notificationPreviewContentIdBytes)) {
    throw new TypeError('wrap AAD input is invalid');
  }
  const domain = input.payloadKind === 'reply-content-v1' ? 'ariava-wrap-aad-v1' : 'ariava-wrap-aad-v2';
  return encodeLengthPrefixedFields([
    domain, input.direction, input.linkId, String(input.linkGeneration), String(input.epoch),
    input.hostId, input.watchDeviceId, input.senderEncryptionKeyId, input.recipientEncryptionKeyId,
    input.contentId, input.payloadKind,
  ]);
}

export function isEpochOperationAllowed(state: E2EEpochState, operation: E2EEpochOperation): boolean {
  if (state === 'active') return true;
  if (state !== 'retiring') return false;
  return operation === 'read_historical_content' || operation === 'deliver_existing_command';
}

export async function deriveEncryptionKeyId(publicKey: string | Uint8Array): Promise<string> {
  const raw = typeof publicKey === 'string'
    ? base64UrlDecode(publicKey, E2E_LIMITS.publicKeyBytes, 'X25519 public key')
    : publicKey;
  if (raw.byteLength !== E2E_LIMITS.publicKeyBytes) throw new TypeError('X25519 public key must be 32 bytes');
  return `ekey_${await contentSha256(raw)}`;
}

export async function encryptionKeyIdMatchesPublicKey(encryptionKeyId: string, publicKey: string): Promise<boolean> {
  try { return encryptionKeyId === await deriveEncryptionKeyId(publicKey); } catch { return false; }
}

export function validateEncryptionKeyBindingV1(value: unknown): value is EncryptionKeyBindingV1 {
  if (!isExactRecord(value, ['version', 'entityType', 'entityId', 'identityKeyId', 'encryptionKeyId', 'suite', 'publicKey', 'sequence', 'createdAt', 'bindingSignature'])) return false;
  try {
    return value.version === 1 && (value.entityType === 'host' || value.entityType === 'watch')
      && typeof value.entityId === 'string' && ID_PATTERNS[value.entityType].test(value.entityId)
      && typeof value.identityKeyId === 'string' && ID_PATTERNS.identityKey.test(value.identityKeyId)
      && typeof value.encryptionKeyId === 'string' && ID_PATTERNS.encryptionKey.test(value.encryptionKeyId)
      && value.suite === E2E_SUITE_V1 && decodeBase64Url(value.publicKey, 32)
      && Number.isSafeInteger(value.sequence) && (value.sequence as number) > 0
      && typeof value.createdAt === 'string' && isCanonicalTimestamp(value.createdAt)
      && typeof value.bindingSignature === 'string' && decodeBase64Url(value.bindingSignature, 64);
  } catch { return false; }
}

export function validateEncryptedContentV1(value: unknown): value is EncryptedContentV1 {
  if (!isExactRecord(value, ['version', 'suite', 'contentId', 'payloadKind', 'nonce', 'ciphertext'])) return false;
  let maxPlaintextBytes: number;
  switch (value.payloadKind) {
    case 'event-content-v2':
      maxPlaintextBytes = E2E_LIMITS.eventPlaintextBytes;
      break;
    case 'session-content-v2':
      maxPlaintextBytes = E2E_LIMITS.sessionPlaintextBytes;
      break;
    case 'reply-content-v1':
      maxPlaintextBytes = E2E_LIMITS.replyPlaintextBytes;
      break;
    case 'notification-preview-v2':
      maxPlaintextBytes = E2E_LIMITS.notificationPreviewPlaintextBytes;
      break;
    default:
      return false;
  }
  try {
    const ciphertext = typeof value.ciphertext === 'string' ? base64UrlDecode(value.ciphertext) : new Uint8Array();
    return value.version === 1 && value.suite === E2E_SUITE_V1
      && isBoundedWellFormedString(value.contentId, E2E_LIMITS.notificationPreviewContentIdBytes)
      && decodeBase64Url(value.nonce, 12) && ciphertext.byteLength >= 16
      && ciphertext.byteLength <= maxPlaintextBytes + 16;
  } catch { return false; }
}

export function validateNotificationPreviewPlaintextV2(value: unknown): value is EncryptedNotificationPreviewPlaintextV2 {
  return canonicalNotificationPreviewPlaintextBytes(value) !== undefined;
}

export function validateNotificationPreviewEnvelopeV2(value: unknown): value is NotificationPreviewEnvelopeV2 {
  if (!isExactRecord(value, ['eventId', 'sessionId', 'eventType', 'watchDeviceId', 'content', 'keyWrap'])) return false;
  if (!isBoundedWellFormedString(value.eventId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(value.sessionId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || (value.eventType !== 'done' && value.eventType !== 'need_human')
    || typeof value.watchDeviceId !== 'string' || !ID_PATTERNS.watch.test(value.watchDeviceId)
    || !validateEncryptedContentV1(value.content) || value.content.payloadKind !== 'notification-preview-v2'
    || !isBoundedWellFormedString(value.content.contentId, E2E_LIMITS.notificationPreviewContentIdBytes)
    || !validateRecipientKeyWrapV1(value.keyWrap)
    || !isBoundedWellFormedString(value.keyWrap.linkId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(value.keyWrap.senderEncryptionKeyId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    || !isBoundedWellFormedString(value.keyWrap.recipientEncryptionKeyId, E2E_LIMITS.notificationPreviewIdentifierBytes)) return false;
  return value.content.contentId === value.keyWrap.contentId;
}

export function validateRecipientKeyWrapV1(value: unknown): value is RecipientKeyWrapV1 {
  if (!isExactRecord(value, ['version', 'suite', 'contentId', 'linkId', 'linkGeneration', 'epoch', 'senderEncryptionKeyId', 'recipientEncryptionKeyId', 'nonce', 'ciphertext'])) return false;
  return value.version === 1 && value.suite === E2E_SUITE_V1
    && isBoundedWellFormedString(value.contentId, E2E_LIMITS.notificationPreviewContentIdBytes)
    && isBoundedWellFormedString(value.linkId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    && isPositiveInteger(value.linkGeneration) && isPositiveInteger(value.epoch)
    && isBoundedWellFormedString(value.senderEncryptionKeyId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    && isBoundedWellFormedString(value.recipientEncryptionKeyId, E2E_LIMITS.notificationPreviewIdentifierBytes)
    && decodeBase64Url(value.nonce, 12) && decodeBase64Url(value.ciphertext, 48);
}

function assertValidEncryptionBinding(binding: Omit<EncryptionKeyBindingV1, 'bindingSignature'>): void {
  const candidate = { ...binding, bindingSignature: base64UrlZeros(64) };
  if (!validateEncryptionKeyBindingV1(candidate)) throw new TypeError('encryption key binding is not canonical');
}

function assertProtectedEventContent(content: ProtectedEventContentV2): ProtectedActionablePromptV1 | undefined {
  assertExactKeys(
    content,
    ['version', 'agentText', 'humanText', 'projectName', 'contextText', 'workingDirectory', 'hbaseSessionKey', 'harnessProvider', 'actionablePrompt', 'needHuman'],
    'protected event content',
    ['version', 'agentText'],
  );
  if (content.version !== 2 || typeof content.agentText !== 'string'
    || (content.humanText !== undefined && typeof content.humanText !== 'string')
    || (content.projectName !== undefined && typeof content.projectName !== 'string')
    || (content.contextText !== undefined && typeof content.contextText !== 'string')
    || (content.workingDirectory !== undefined && typeof content.workingDirectory !== 'string')
    || (content.hbaseSessionKey !== undefined && typeof content.hbaseSessionKey !== 'string')
    || (content.harnessProvider !== undefined && typeof content.harnessProvider !== 'string')) {
    throw new TypeError('protected event content is invalid');
  }
  if (content.needHuman !== undefined
    && !validateCanonicalEventInvariant({ type: 'need_human', status: 'need_human', needHuman: content.needHuman }).success) {
    throw new TypeError('protected needHuman context is invalid');
  }
  const prompt = content.actionablePrompt;
  if (prompt === undefined) return undefined;
  assertExactKeys(
    prompt, ['promptId', 'type', 'label', 'options', 'expiresAt'], 'protected actionable prompt', ['promptId', 'type', 'label'],
  );
  if (typeof prompt.promptId !== 'string' || prompt.type !== 'question' || typeof prompt.label !== 'string'
    || (prompt.expiresAt !== undefined && !isCanonicalTimestamp(prompt.expiresAt))) {
    throw new TypeError('protected actionable prompt is invalid');
  }
  const options = prompt.options === undefined ? undefined : canonicalPromptOptions(prompt.options);
  return {
    promptId: prompt.promptId,
    type: 'question',
    label: prompt.label,
    ...(options === undefined ? {} : { options }),
    ...(prompt.expiresAt === undefined ? {} : { expiresAt: prompt.expiresAt }),
  };
}

function canonicalPromptOptions(value: unknown): string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || 'toJSON' in value) {
    throw new TypeError('protected actionable prompt options are invalid');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (!lengthDescriptor || !('value' in lengthDescriptor) || typeof lengthDescriptor.value !== 'number'
    || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0
    || lengthDescriptor.value > E2E_LIMITS.promptOptions || lengthDescriptor.enumerable !== false
    || lengthDescriptor.configurable !== false || lengthDescriptor.writable !== true
    || Reflect.ownKeys(value).length !== lengthDescriptor.value + 1) {
    throw new TypeError('protected actionable prompt options are invalid');
  }
  const length = lengthDescriptor.value;
  const options: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || descriptor.configurable !== true || descriptor.writable !== true
      || !('value' in descriptor) || typeof descriptor.value !== 'string'
      || encoder.encode(descriptor.value).byteLength > E2E_LIMITS.promptOptionBytes) {
      throw new TypeError('protected actionable prompt options are invalid');
    }
    options.push(descriptor.value);
  }
  return options;
}

function canonicalNeedHumanContext(context: NeedHumanContext): NeedHumanContext {
  return context.reason === 'error'
    ? { reason: 'error', error: {
      kind: context.error.kind,
      message: context.error.message,
      ...(context.error.providerCode === undefined ? {} : { providerCode: context.error.providerCode }),
      retryExhausted: context.error.retryExhausted,
    } }
    : { reason: context.reason };
}

function assertProtectedSessionContent(content: ProtectedSessionContentV2): void {
  assertExactKeys(
    content,
    ['version', 'projectName', 'nameText', 'openingText', 'latestActivityText', 'workingDirectory', 'hbaseSessionKey', 'harnessProvider'],
    'protected session content',
    ['version', 'projectName', 'nameText'],
  );
  if (content.version !== 2 || typeof content.projectName !== 'string' || typeof content.nameText !== 'string'
    || (content.openingText !== undefined && typeof content.openingText !== 'string')
    || (content.latestActivityText !== undefined && typeof content.latestActivityText !== 'string')
    || (content.workingDirectory !== undefined && typeof content.workingDirectory !== 'string')
    || (content.hbaseSessionKey !== undefined && typeof content.hbaseSessionKey !== 'string')
    || (content.harnessProvider !== undefined && typeof content.harnessProvider !== 'string')) {
    throw new TypeError('protected session content is invalid');
  }
}

function assertExactKeys(
  value: object,
  allowed: readonly string[],
  label: string,
  required: readonly string[] = [],
): void {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  const supported = new Set(allowed);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new TypeError(`${label} contains unsupported fields`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!supported.has(key)) throw new TypeError(`${label} contains unsupported fields`);
    if (!descriptor.enumerable || !('value' in descriptor)) {
      throw new TypeError(`${label}.${key} must be an enumerable own data property`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
  }
  for (const key of allowed) {
    if (!Object.hasOwn(value, key) && key in value) throw new TypeError(`${label}.${key} must be an own data property`);
  }
}

function isCanonicalTimestamp(value: string): boolean {
  if (!CANONICAL_TIMESTAMP_RE.test(value)) return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

function base64UrlZeros(bytes: number): string {
  const binary = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

function decodeBase64Url(value: unknown, bytes: number): boolean {
  if (typeof value !== 'string') return false;
  try { base64UrlDecode(value, bytes); return true; } catch { return false; }
}
function isPositiveInteger(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) > 0; }
function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length) return false;
  const supported = new Set(keys);
  return actual.every((key) => {
    if (typeof key !== 'string' || !supported.has(key)) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    return descriptor.enumerable && 'value' in descriptor;
  });
}
