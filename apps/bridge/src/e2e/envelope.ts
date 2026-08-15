import { randomBytes } from 'node:crypto';
import {
  E2E_SUITE_V1,
  base64UrlDecode,
  base64UrlEncode,
  buildEventContentAAD,
  buildNotificationPreviewAAD,
  buildNotificationPreviewPlaintextBytes,
  buildProtectedEventContentBytes,
  buildProtectedInterruptContentBytes,
  buildProtectedReplyContentBytes,
  buildProtectedSessionContentBytes,
  buildInterruptContentAAD,
  buildReplyContentAAD,
  buildSessionContentAAD,
  buildWrapAAD,
  pairRootInfo,
  validateProtectedInterruptContentV1,
  type CommandEnvelope,
  type E2ERecipientV1,
  type E2EEventAndSessionUploadV3,
  type EncryptedCommandEnvelopeV1,
  type EncryptedContentV1,
  type EncryptedEventUploadV3,
  type EncryptedNotificationPreviewPlaintextV2,
  type EncryptedSessionSnapshotUploadV3,
  type NotificationPreviewEnvelopeV2,
  type ProtectedEventContentV3,
  type ProtectedSessionContentV3,
  type RecipientKeyWrapV1,
  type RelayEventMetadataV3,
  type RelaySessionMetadataV2,
} from '@ariava/protocol';
import { chachaPolyOpen, chachaPolySeal, hkdfSha256, x25519SharedSecret } from './node-crypto';
import type { HostEncryptionIdentity } from '../identity';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export interface ActiveRecipientMaterial extends E2ERecipientV1 {
  transcriptDigest: string;
  hostBinding: import('@ariava/protocol').EncryptionKeyBindingV1;
  hostIdentity: HostEncryptionIdentity;
}

export function encryptEventUpload(input: {
  event: RelayEventMetadataV3;
  protectedEvent: ProtectedEventContentV3;
  session: RelaySessionMetadataV2;
  protectedSession: ProtectedSessionContentV3;
  revision: number;
  recipientSetVersion: number;
  recipients: ActiveRecipientMaterial[];
}): E2EEventAndSessionUploadV3 {
  const eventContentId = crypto.randomUUID();
  const sessionContentId = crypto.randomUUID();
  const eventContent = sealContent('event-content-v3', eventContentId,
    buildProtectedEventContentBytes(input.protectedEvent), buildEventContentAAD({ ...input.event, contentId: eventContentId }));
  const sessionContent = sealContent('session-content-v3', sessionContentId,
    buildProtectedSessionContentBytes(input.protectedSession), buildSessionContentAAD({ ...input.session, revision: input.revision, contentId: sessionContentId }));
  try {
    return {
      event: { ...input.event, recipientSetVersion: input.recipientSetVersion,
        content: eventContent.content as EncryptedEventUploadV3['content'],
        keyWraps: wrapDekForRecipients(eventContent.dek, eventContentId, 'event-content-v3', input.recipients) },
      session: { ...input.session, revision: input.revision, recipientSetVersion: input.recipientSetVersion,
        content: sessionContent.content as EncryptedSessionSnapshotUploadV3['content'],
        keyWraps: wrapDekForRecipients(sessionContent.dek, sessionContentId, 'session-content-v3', input.recipients) },
    };
  } finally { eventContent.dek.fill(0); sessionContent.dek.fill(0); }
}

export function encryptNotificationPreviews({ event, plaintext, recipients }: {
  event: RelayEventMetadataV3;
  plaintext: EncryptedNotificationPreviewPlaintextV2;
  recipients: ActiveRecipientMaterial[];
}): NotificationPreviewEnvelopeV2[] {
  if (plaintext.eventType !== event.type) throw new TypeError('notification preview eventType does not match Event metadata');
  return recipients.map((recipient) => {
    const contentId = crypto.randomUUID();
    const sealed = sealContent('notification-preview-v2', contentId, buildNotificationPreviewPlaintextBytes(plaintext),
      buildNotificationPreviewAAD({ hostId: event.hostId, watchDeviceId: recipient.watchDeviceId,
        eventId: event.eventId, sessionId: event.sessionId, eventType: event.type,
        linkId: recipient.linkId, linkGeneration: recipient.linkGeneration, epoch: recipient.epoch,
        senderEncryptionKeyId: recipient.hostBinding.encryptionKeyId,
        recipientEncryptionKeyId: recipient.watchBinding.encryptionKeyId, contentId,
        payloadKind: 'notification-preview-v2' }));
    try {
      const [keyWrap] = wrapDekForRecipients(sealed.dek, contentId, 'notification-preview-v2', [recipient]);
      return { eventId: event.eventId, sessionId: event.sessionId, eventType: event.type,
        watchDeviceId: recipient.watchDeviceId,
        content: sealed.content as NotificationPreviewEnvelopeV2['content'], keyWrap: keyWrap! };
    } finally { sealed.dek.fill(0); }
  });
}

export function encryptSessionSnapshot(input: {
  session: RelaySessionMetadataV2;
  protectedSession: ProtectedSessionContentV3;
  revision: number;
  recipientSetVersion: number;
  recipients: ActiveRecipientMaterial[];
}): EncryptedSessionSnapshotUploadV3 {
  const contentId = crypto.randomUUID();
  const sealed = sealContent('session-content-v3', contentId, buildProtectedSessionContentBytes(input.protectedSession),
    buildSessionContentAAD({ ...input.session, revision: input.revision, contentId }));
  try {
    return { ...input.session, revision: input.revision, recipientSetVersion: input.recipientSetVersion,
      content: sealed.content as EncryptedSessionSnapshotUploadV3['content'],
      keyWraps: wrapDekForRecipients(sealed.dek, contentId, 'session-content-v3', input.recipients) };
  } finally { sealed.dek.fill(0); }
}

export function decryptCommandForPin(command: EncryptedCommandEnvelopeV1, input: {
  hostIdentity: HostEncryptionIdentity; watchPublicKey: string; transcriptDigest: string;
}): CommandEnvelope {
  assertCommandEnvelopeTuple(command);
  const { content, keyWrap } = command.payload;
  const wrapKey = deriveDirectionKey(input.hostIdentity, input.watchPublicKey, input.transcriptDigest,
    command.linkId, command.linkGeneration, command.epoch, 'watch-to-bridge');
  let dek: Uint8Array | undefined; let plaintext: Uint8Array | undefined;
  try {
    dek = chachaPolyOpen(wrapKey, base64UrlDecode(keyWrap.nonce, 12, 'command wrap nonce'),
      base64UrlDecode(keyWrap.ciphertext, 48, 'wrapped command DEK'), buildWrapAAD({
        direction: 'watch-to-bridge', linkId: command.linkId, linkGeneration: command.linkGeneration, epoch: command.epoch,
        hostId: command.hostId, watchDeviceId: command.watchDeviceId,
        senderEncryptionKeyId: keyWrap.senderEncryptionKeyId, recipientEncryptionKeyId: keyWrap.recipientEncryptionKeyId,
        contentId: content.contentId, payloadKind: content.payloadKind }));
    const contentAAD = command.type === 'reply'
      ? buildReplyContentAAD({ hostId: command.hostId, watchDeviceId: command.watchDeviceId, sessionId: command.sessionId,
        commandId: command.commandId, targetAlertEventId: command.targetAlertEventId, issuedAt: command.issuedAt,
        expiresAt: command.expiresAt, nonce: command.nonce, contentId: content.contentId })
      : buildInterruptContentAAD({ hostId: command.hostId, watchDeviceId: command.watchDeviceId, sessionId: command.sessionId,
        commandId: command.commandId, issuedAt: command.issuedAt, expiresAt: command.expiresAt, nonce: command.nonce,
        contentId: content.contentId });
    plaintext = chachaPolyOpen(dek, base64UrlDecode(content.nonce, 12, 'command content nonce'),
      base64UrlDecode(content.ciphertext, undefined, 'command ciphertext'), contentAAD);
    const parsed = JSON.parse(decoder.decode(plaintext)) as unknown;
    const canonical = command.type === 'reply'
      ? buildProtectedReplyContentBytes(parsed as { version: 1; text: string })
      : buildProtectedInterruptContentBytes(parsed as { version: 1; action: 'interrupt' });
    try {
      if (!equalBytes(canonical, plaintext)) throw new TypeError('decrypted command plaintext is not canonical');
    } finally { canonical.fill(0); }
    if (command.type === 'interrupt' && !validateProtectedInterruptContentV1(parsed)) {
      throw new TypeError('decrypted interrupt is invalid');
    }
    return { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, type: command.type,
      payload: command.type === 'reply' ? { text: (parsed as { text: string }).text } : {},
      ...(command.type === 'reply' ? { targetAlertEventId: command.targetAlertEventId } : {}),
      issuedAt: command.issuedAt, expiresAt: command.expiresAt, nonce: command.nonce, watchDeviceId: command.watchDeviceId };
  } finally { wrapKey.fill(0); dek?.fill(0); plaintext?.fill(0); }
}

export function decryptReplyForPin(command: Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>, input: {
  hostIdentity: HostEncryptionIdentity; watchPublicKey: string; transcriptDigest: string;
}): string {
  const decoded = decryptCommandForPin(command, input);
  if (decoded.type !== 'reply' || typeof decoded.payload.text !== 'string') throw new TypeError('decrypted reply is invalid');
  return decoded.payload.text;
}

function assertCommandEnvelopeTuple(command: EncryptedCommandEnvelopeV1): void {
  const { content, keyWrap } = command.payload;
  const payloadKind = command.type === 'reply' ? 'reply-content-v1' : 'interrupt-content-v1';
  if (content.version !== 1 || content.suite !== E2E_SUITE_V1 || content.payloadKind !== payloadKind
    || keyWrap.version !== 1 || keyWrap.suite !== E2E_SUITE_V1 || keyWrap.contentId !== content.contentId
    || keyWrap.linkId !== command.linkId || keyWrap.linkGeneration !== command.linkGeneration || keyWrap.epoch !== command.epoch
    || keyWrap.senderEncryptionKeyId.length === 0 || keyWrap.recipientEncryptionKeyId.length === 0) {
    throw new TypeError('encrypted command envelope tuple is invalid');
  }
}

function sealContent(payloadKind: EncryptedContentV1['payloadKind'], contentId: string, plaintext: Uint8Array, aad: Uint8Array) {
  const dek = new Uint8Array(randomBytes(32));
  try {
    const sealed = chachaPolySeal(dek, plaintext, aad);
    return { dek, content: { version: 1, suite: E2E_SUITE_V1, contentId, payloadKind,
      nonce: base64UrlEncode(sealed.nonce), ciphertext: base64UrlEncode(sealed.ciphertext) } satisfies EncryptedContentV1 };
  } catch (error) { dek.fill(0); throw error; } finally { plaintext.fill(0); }
}

function wrapDekForRecipients(dek: Uint8Array, contentId: string, payloadKind: EncryptedContentV1['payloadKind'],
  recipients: ActiveRecipientMaterial[]): RecipientKeyWrapV1[] {
  return recipients.map((recipient) => {
    const hostIdentity = recipient.hostIdentity;
    if (recipient.state !== 'active' || recipient.watchBinding.entityId !== recipient.watchDeviceId
      || recipient.hostBinding.entityType !== 'host' || recipient.hostBinding.entityId !== hostIdentity.hostId
      || recipient.hostBinding.encryptionKeyId !== hostIdentity.encryptionKeyId
      || recipient.hostBinding.publicKey !== hostIdentity.publicKey
      || recipient.hostBinding.sequence !== hostIdentity.sequence
      || recipient.hostBinding.createdAt !== hostIdentity.createdAt
      || recipient.watchBinding.encryptionKeyId === hostIdentity.encryptionKeyId) {
      throw new TypeError('recipient pin sender identity is invalid');
    }
    const key = deriveDirectionKey(hostIdentity, recipient.watchBinding.publicKey, recipient.transcriptDigest,
      recipient.linkId, recipient.linkGeneration, recipient.epoch, 'bridge-to-watch');
    try {
      const aad = buildWrapAAD({ direction: 'bridge-to-watch', linkId: recipient.linkId,
        linkGeneration: recipient.linkGeneration, epoch: recipient.epoch, hostId: hostIdentity.hostId,
        watchDeviceId: recipient.watchDeviceId, senderEncryptionKeyId: hostIdentity.encryptionKeyId,
        recipientEncryptionKeyId: recipient.watchBinding.encryptionKeyId, contentId, payloadKind });
      const sealed = chachaPolySeal(key, dek, aad);
      return { version: 1, suite: E2E_SUITE_V1, contentId, linkId: recipient.linkId,
        linkGeneration: recipient.linkGeneration, epoch: recipient.epoch,
        senderEncryptionKeyId: hostIdentity.encryptionKeyId, recipientEncryptionKeyId: recipient.watchBinding.encryptionKeyId,
        nonce: base64UrlEncode(sealed.nonce), ciphertext: base64UrlEncode(sealed.ciphertext) };
    } finally { key.fill(0); }
  });
}

function deriveDirectionKey(identity: HostEncryptionIdentity, peerPublicKey: string, transcriptDigest: string,
  linkId: string, generation: number, epoch: number, direction: 'bridge-to-watch' | 'watch-to-bridge'): Uint8Array {
  const shared = x25519SharedSecret(identity.privateKeyPkcs8, base64UrlDecode(peerPublicKey, 32, 'peer X25519 public key'));
  const salt = base64UrlDecode(transcriptDigest, 32, 'transcript digest'); let root: Uint8Array | undefined;
  try {
    root = hkdfSha256(shared, salt, pairRootInfo(linkId, generation, epoch));
    return hkdfSha256(root, salt, encoder.encode(`ariava:e2e:v1:wrap:${direction}`));
  } finally { shared.fill(0); root?.fill(0); salt.fill(0); }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}
