import { randomBytes } from 'node:crypto';
import {
  E2E_SUITE_V1,
  base64UrlDecode,
  base64UrlEncode,
  buildEventContentAAD,
  buildProtectedEventContentBytes,
  buildProtectedReplyContentBytes,
  buildProtectedSessionContentBytes,
  buildReplyContentAAD,
  buildSessionContentAAD,
  buildWrapAAD,
  pairRootInfo,
  type E2ERecipientV1,
  type EncryptedCommandEnvelopeV1,
  type EncryptedContentV1,
  type EncryptedEventUploadV1,
  type EncryptedSessionSnapshotUploadV1,
  type ProtectedEventContentV1,
  type ProtectedSessionContentV1,
  type RecipientKeyWrapV1,
  type RelayEventMetadataV1,
  type RelaySessionMetadataV1,
} from '@ariava/protocol';
import { chachaPolyOpen, chachaPolySeal, hkdfSha256, x25519SharedSecret } from './node-crypto';
import type { HostEncryptionIdentity } from '../identity';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export interface ActiveRecipientMaterial extends E2ERecipientV1 {
  transcriptDigest: string;
}

export function encryptEventUpload(input: {
  event: RelayEventMetadataV1;
  protectedEvent: ProtectedEventContentV1;
  session: RelaySessionMetadataV1;
  protectedSession: ProtectedSessionContentV1;
  revision: number;
  recipientSetVersion: number;
  recipients: ActiveRecipientMaterial[];
  hostIdentity: HostEncryptionIdentity;
}): { event: EncryptedEventUploadV1; session: EncryptedSessionSnapshotUploadV1 } {
  const eventContentId = crypto.randomUUID();
  const sessionContentId = crypto.randomUUID();
  const eventContent = sealContent('event-content-v1', eventContentId,
    buildProtectedEventContentBytes(input.protectedEvent), buildEventContentAAD({ ...input.event, contentId: eventContentId }));
  const sessionContent = sealContent('session-content-v1', sessionContentId,
    buildProtectedSessionContentBytes(input.protectedSession), buildSessionContentAAD({ ...input.session, revision: input.revision, contentId: sessionContentId }));
  try {
    return {
      event: { ...input.event, recipientSetVersion: input.recipientSetVersion, content: eventContent.content,
        keyWraps: wrapDekForRecipients(eventContent.dek, eventContentId, 'event-content-v1', input.recipients, input.hostIdentity) },
      session: { ...input.session, revision: input.revision, recipientSetVersion: input.recipientSetVersion, content: sessionContent.content,
        keyWraps: wrapDekForRecipients(sessionContent.dek, sessionContentId, 'session-content-v1', input.recipients, input.hostIdentity) },
    };
  } finally {
    eventContent.dek.fill(0);
    sessionContent.dek.fill(0);
  }
}

export function encryptSessionSnapshot(input: { session: RelaySessionMetadataV1; protectedSession: ProtectedSessionContentV1;
  revision: number; recipientSetVersion: number; recipients: ActiveRecipientMaterial[]; hostIdentity: HostEncryptionIdentity
}): EncryptedSessionSnapshotUploadV1 {
  const contentId = crypto.randomUUID();
  const sealed = sealContent('session-content-v1', contentId, buildProtectedSessionContentBytes(input.protectedSession),
    buildSessionContentAAD({ ...input.session, revision: input.revision, contentId }));
  try {
    return { ...input.session, revision: input.revision, recipientSetVersion: input.recipientSetVersion, content: sealed.content,
      keyWraps: wrapDekForRecipients(sealed.dek, contentId, 'session-content-v1', input.recipients, input.hostIdentity) };
  } finally { sealed.dek.fill(0); }
}

export function decryptReplyForPin(command: Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>, input: {
  hostIdentity: HostEncryptionIdentity;
  watchPublicKey: string;
  transcriptDigest: string;
}): string {
  assertReplyEnvelopeTuple(command);
  const { content, keyWrap } = command.payload;
  const wrapKey = deriveDirectionKey(input.hostIdentity, input.watchPublicKey, input.transcriptDigest,
    command.linkId, command.linkGeneration, command.epoch, 'watch-to-bridge');
  let dek: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    dek = chachaPolyOpen(wrapKey, base64UrlDecode(keyWrap.nonce, 12, 'reply wrap nonce'),
      base64UrlDecode(keyWrap.ciphertext, 48, 'wrapped reply DEK'), buildWrapAAD({
        direction: 'watch-to-bridge', linkId: command.linkId, linkGeneration: command.linkGeneration, epoch: command.epoch,
        hostId: command.hostId, watchDeviceId: command.watchDeviceId,
        senderEncryptionKeyId: keyWrap.senderEncryptionKeyId, recipientEncryptionKeyId: keyWrap.recipientEncryptionKeyId,
        contentId: content.contentId, payloadKind: 'reply-content-v1',
      }));
    plaintext = chachaPolyOpen(dek, base64UrlDecode(content.nonce, 12, 'reply content nonce'),
      base64UrlDecode(content.ciphertext, undefined, 'reply ciphertext'), buildReplyContentAAD({
        hostId: command.hostId, watchDeviceId: command.watchDeviceId, sessionId: command.sessionId,
        commandId: command.commandId, targetAlertEventId: command.targetAlertEventId, issuedAt: command.issuedAt,
        expiresAt: command.expiresAt, nonce: command.nonce, contentId: content.contentId,
      }));
    const parsed = JSON.parse(decoder.decode(plaintext)) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.keys(parsed).length !== 2 || (parsed as { version?: unknown }).version !== 1
      || typeof (parsed as { text?: unknown }).text !== 'string') throw new TypeError('decrypted reply is invalid');
    buildProtectedReplyContentBytes(parsed as { version: 1; text: string });
    return (parsed as { text: string }).text;
  } finally {
    wrapKey.fill(0);
    dek?.fill(0);
    plaintext?.fill(0);
  }
}

function assertReplyEnvelopeTuple(command: Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>): void {
  const { content, keyWrap } = command.payload;
  if (content.version !== 1 || content.suite !== E2E_SUITE_V1 || content.payloadKind !== 'reply-content-v1'
    || keyWrap.version !== 1 || keyWrap.suite !== E2E_SUITE_V1 || keyWrap.contentId !== content.contentId
    || keyWrap.linkId !== command.linkId || keyWrap.linkGeneration !== command.linkGeneration || keyWrap.epoch !== command.epoch
    || keyWrap.senderEncryptionKeyId.length === 0 || keyWrap.recipientEncryptionKeyId.length === 0) {
    throw new TypeError('encrypted reply envelope tuple is invalid');
  }
}

function sealContent(payloadKind: EncryptedContentV1['payloadKind'], contentId: string, plaintext: Uint8Array, aad: Uint8Array) {
  const dek = new Uint8Array(randomBytes(32));
  try {
    const sealed = chachaPolySeal(dek, plaintext, aad);
    return { dek, content: { version: 1, suite: E2E_SUITE_V1, contentId, payloadKind,
      nonce: base64UrlEncode(sealed.nonce), ciphertext: base64UrlEncode(sealed.ciphertext) } satisfies EncryptedContentV1 };
  } catch (error) {
    dek.fill(0);
    throw error;
  } finally {
    plaintext.fill(0);
  }
}

function wrapDekForRecipients(dek: Uint8Array, contentId: string, payloadKind: EncryptedContentV1['payloadKind'],
  recipients: ActiveRecipientMaterial[], hostIdentity: HostEncryptionIdentity): RecipientKeyWrapV1[] {
  return recipients.map((recipient) => {
    if (recipient.state !== 'active' || recipient.watchBinding.entityId !== recipient.watchDeviceId
      || recipient.watchBinding.encryptionKeyId === hostIdentity.encryptionKeyId) throw new TypeError('recipient pin is invalid');
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
        senderEncryptionKeyId: hostIdentity.encryptionKeyId,
        recipientEncryptionKeyId: recipient.watchBinding.encryptionKeyId,
        nonce: base64UrlEncode(sealed.nonce), ciphertext: base64UrlEncode(sealed.ciphertext) };
    } finally { key.fill(0); }
  });
}

function deriveDirectionKey(identity: HostEncryptionIdentity, peerPublicKey: string, transcriptDigest: string,
  linkId: string, generation: number, epoch: number, direction: 'bridge-to-watch' | 'watch-to-bridge'): Uint8Array {
  const shared = x25519SharedSecret(identity.privateKeyPkcs8, base64UrlDecode(peerPublicKey, 32, 'peer X25519 public key'));
  const salt = base64UrlDecode(transcriptDigest, 32, 'transcript digest');
  let root: Uint8Array | undefined;
  try {
    root = hkdfSha256(shared, salt, pairRootInfo(linkId, generation, epoch));
    return hkdfSha256(root, salt, encoder.encode(`ariava:e2e:v1:wrap:${direction}`));
  } finally {
    shared.fill(0);
    root?.fill(0);
    salt.fill(0);
  }
}
