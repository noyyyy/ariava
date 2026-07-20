import { createHmac, createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import {
  PAIRING_CODE_ALPHABET, base64UrlDecode, base64UrlEncode, buildConfirmationProofBytes,
  buildEncryptionBindingBytes, buildLinkTranscriptBytes, buildSafetyCodeInput, contentSha256,
  deriveEntityIdentity, encryptionKeyIdMatchesPublicKey, validateEncryptionKeyBindingV1,
  type E2EActivationAckV1, type E2EConfirmationSubmissionV1, type E2EPendingLinkProjectionV1,
  type E2ERecipientSnapshotV1, type EncryptionKeyBindingV1, type EncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import { pathHasFilesystemEvidence, readSecureJson, writeSecureJson } from '../host-manager/secure-files';
import type { HostEncryptionIdentity } from '../identity';
import { hkdfSha256, x25519SharedSecret } from './node-crypto';
import { decryptReplyForPin } from './envelope';
import type { EncryptedCommandKeyring } from './command-execution';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const encoder = new TextEncoder();
export type LocalPinStatus = 'active' | 'retiring' | 'revoked';

export interface ActiveLinkPinV1 {
  version: 1; status: LocalPinStatus; linkId: string; hostId: string; watchDeviceId: string;
  linkGeneration: number; epoch: number; transcriptDigest: string; watchBinding: EncryptionKeyBindingV1;
  watchBindingDigest: string; peerProofDigest: string; activatedAt: string; retiringAt?: string;
}
export interface PendingActivationV1 { version: 1; linkId: string; linkGeneration: number; epoch: number;
  peerProofDigest: string; activatedAt: string; pin: ActiveLinkPinV1 }
interface PersistedKeyringV1 { version: 1; pins: ActiveLinkPinV1[]; pendingActivations?: PendingActivationV1[] }
export interface HostActivationTransport {
  confirmLink(linkId: string, request: E2EConfirmationSubmissionV1): Promise<{ state: string; peerConfirmationProof?: E2EConfirmationSubmissionV1 }>;
  activateLink(linkId: string, request: E2EActivationAckV1): Promise<{ state: string }>;
}

export class LocalLinkKeyring implements EncryptedCommandKeyring {
  private pins: ActiveLinkPinV1[]; private pendingActivations: PendingActivationV1[];
  constructor(private readonly path: string, private readonly hostIdentity: HostEncryptionIdentity) {
    const state = this.load(); this.pins = state.pins; this.pendingActivations = state.pendingActivations;
  }
  listActive(): ActiveLinkPinV1[] { return this.pins.filter((pin) => pin.status === 'active').map((pin) => structuredClone(pin)); }
  listRetiring(): ActiveLinkPinV1[] { return this.pins.filter((pin) => pin.status === 'retiring').map((pin) => structuredClone(pin)); }
  getUsable(linkId: string, generation: number, epoch: number): ActiveLinkPinV1 | undefined {
    return this.pins.find((pin) => pin.status !== 'revoked' && pin.linkId === linkId && pin.linkGeneration === generation && pin.epoch === epoch);
  }
  persistActive(pin: ActiveLinkPinV1): void {
    if (pin.hostId !== this.hostIdentity.hostId || pin.watchBinding.entityId !== pin.watchDeviceId
      || pin.watchBinding.encryptionKeyId === this.hostIdentity.encryptionKeyId) throw new TypeError('active link pin is invalid');
    const sameWatch = this.pins.filter((item) => item.watchDeviceId === pin.watchDeviceId && item.status !== 'revoked');
    if (sameWatch.some((item) => item.linkGeneration > pin.linkGeneration || (item.linkGeneration === pin.linkGeneration && item.epoch > pin.epoch)
      || item.watchBinding.sequence > pin.watchBinding.sequence)) throw new TypeError('active link pin rollback rejected');
    const now = new Date().toISOString();
    this.pins = this.pins.map((item) => item.watchDeviceId === pin.watchDeviceId && item.status === 'active'
      ? { ...item, status: 'retiring' as const, retiringAt: now } : item);
    const index = this.pins.findIndex((item) => item.linkId === pin.linkId && item.linkGeneration === pin.linkGeneration && item.epoch === pin.epoch);
    if (index >= 0) this.pins[index] = structuredClone({ ...pin, status: 'active' }); else this.pins.push(structuredClone({ ...pin, status: 'active' }));
    this.pendingActivations = this.pendingActivations.filter((item) => !(item.linkId === pin.linkId && item.linkGeneration === pin.linkGeneration && item.epoch === pin.epoch));
    this.persist();
  }
  stageActivation(pending: PendingActivationV1): void {
    const existing = this.pendingActivations.find((item) => item.linkId === pending.linkId && item.linkGeneration === pending.linkGeneration && item.epoch === pending.epoch);
    if (existing && JSON.stringify(existing) !== JSON.stringify(pending)) throw new TypeError('pending activation conflict');
    if (!existing) { this.pendingActivations.push(structuredClone(pending)); this.persist(); }
  }
  pendingActivation(linkId: string, generation: number, epoch: number): PendingActivationV1 | undefined {
    const value = this.pendingActivations.find((item) => item.linkId === linkId && item.linkGeneration === generation && item.epoch === epoch);
    return value && structuredClone(value);
  }
  reconcileRecipients(snapshot: E2ERecipientSnapshotV1) {
    if (snapshot.hostId !== this.hostIdentity.hostId || !Number.isSafeInteger(snapshot.recipientSetVersion) || snapshot.recipientSetVersion < 1) throw new TypeError('recipient snapshot is invalid');
    // Absence from the active recipient snapshot means either retiring or revoked. Keep retiring
    // material for TTL-valid commands; explicit unlink/generation mismatch is rejected by command tuple checks.
    const activeKeys = new Set(snapshot.recipients.map((recipient) => `${recipient.linkId}:${recipient.linkGeneration}:${recipient.epoch}`));
    const now = new Date().toISOString(); const before = JSON.stringify(this.pins);
    this.pins = this.pins.map((pin) => pin.status === 'active' && !activeKeys.has(`${pin.linkId}:${pin.linkGeneration}:${pin.epoch}`)
      ? { ...pin, status: 'retiring' as const, retiringAt: now } : pin);
    if (before !== JSON.stringify(this.pins)) this.persist();
    return snapshot.recipients.map((recipient) => this.materialForRecipient(recipient));
  }
  revokeWatch(watchDeviceId: string, generation?: number): void {
    this.pins = this.pins.map((pin) => pin.watchDeviceId === watchDeviceId && (generation === undefined || pin.linkGeneration !== generation)
      ? { ...pin, status: 'revoked' as const } : pin); this.persist();
  }
  async authorize(command: EncryptedCommandEnvelopeV1): Promise<boolean> {
    const pin = this.getUsable(command.linkId, command.linkGeneration, command.epoch);
    if (!pin || pin.hostId !== command.hostId || pin.watchDeviceId !== command.watchDeviceId || new Date(command.expiresAt).getTime() <= Date.now()) return false;
    // Relay only delivers a retiring command if it was queued before cutover. Local enforcement
    // uses immutable issuedAt versus the durable retiringAt boundary.
    if (pin.status === 'retiring' && (!pin.retiringAt || command.issuedAt >= pin.retiringAt)) return false;
    return command.type !== 'reply' || (command.payload.keyWrap.senderEncryptionKeyId === pin.watchBinding.encryptionKeyId
      && command.payload.keyWrap.recipientEncryptionKeyId === this.hostIdentity.encryptionKeyId);
  }
  async decodeReply(command: Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>) {
    const pin = this.getUsable(command.linkId, command.linkGeneration, command.epoch);
    if (!pin || !await this.authorize(command)) throw new TypeError('reply epoch is not locally authorized');
    const text = decryptReplyForPin(command, { hostIdentity: this.hostIdentity, watchPublicKey: pin.watchBinding.publicKey, transcriptDigest: pin.transcriptDigest });
    return { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, type: 'reply' as const,
      payload: { text }, targetAlertEventId: command.targetAlertEventId, issuedAt: command.issuedAt, expiresAt: command.expiresAt,
      nonce: command.nonce, watchDeviceId: command.watchDeviceId };
  }
  private materialForRecipient(recipient: E2ERecipientSnapshotV1['recipients'][number]) {
    const pin = this.getUsable(recipient.linkId, recipient.linkGeneration, recipient.epoch);
    if (!pin || pin.status !== 'active' || recipient.state !== 'active' || recipient.watchDeviceId !== pin.watchDeviceId || !sameBinding(recipient.watchBinding, pin.watchBinding)) {
      throw new TypeError('recipient lacks a matching locally verified active pin');
    }
    return { ...recipient, transcriptDigest: pin.transcriptDigest };
  }
  private load(): { pins: ActiveLinkPinV1[]; pendingActivations: PendingActivationV1[] } {
    if (!pathHasFilesystemEvidence(this.path)) return { pins: [], pendingActivations: [] };
    const record = readSecureJson<PersistedKeyringV1>(this.path); const pending = record.pendingActivations ?? [];
    if (record?.version !== 1 || !Array.isArray(record.pins) || !Array.isArray(pending)
      || record.pins.some((pin) => !validPin(pin, this.hostIdentity.hostId))) throw new TypeError('local E2E keyring is invalid');
    return { pins: record.pins, pendingActivations: pending };
  }
  private persist(): void { writeSecureJson(this.path, { version: 1, pins: this.pins, pendingActivations: this.pendingActivations } satisfies PersistedKeyringV1); }
}

export async function prepareHostActivation(input: { projection: E2EPendingLinkProjectionV1; hostIdentity: HostEncryptionIdentity;
  hostBinding: EncryptionKeyBindingV1; keyring: LocalLinkKeyring;
  now?: () => string }): Promise<{ safetyCode: string; confirm: E2EConfirmationSubmissionV1; complete(transport: HostActivationTransport): Promise<ActiveLinkPinV1> }> {
  const { projection, hostIdentity, hostBinding } = input;
  if (projection.hostId !== hostIdentity.hostId || projection.hostBinding.encryptionKeyId !== hostIdentity.encryptionKeyId || !sameBinding(projection.hostBinding, hostBinding)) throw new TypeError('Host binding projection mismatch');
  if (!await validatePeerBinding(projection.watchBinding, projection.watchDeviceId, projection.watchIdentityPublicKey)) throw new TypeError('Watch encryption binding verification failed');
  const hostDigest = await bindingDigest(projection.hostBinding); const watchDigest = await bindingDigest(projection.watchBinding);
  const expectedTranscript = await contentSha256(buildLinkTranscriptBytes({ linkId: projection.linkId, hostId: projection.hostId,
    watchDeviceId: projection.watchDeviceId, linkGeneration: projection.linkGeneration, epoch: projection.epoch,
    hostBindingDigest: hostDigest, watchBindingDigest: watchDigest }));
  if (expectedTranscript !== projection.transcriptDigest) throw new TypeError('link transcript digest mismatch');
  const confirmationKey = deriveConfirmationKey(hostIdentity, projection.watchBinding.publicKey, projection.transcriptDigest);
  const ownProof = hmac(confirmationKey, buildConfirmationProofBytes('host', projection.transcriptDigest));
  const expectedPeerProof = hmac(confirmationKey, buildConfirmationProofBytes('watch', projection.transcriptDigest));
  const safetyDigest = createHmac('sha256', confirmationKey).update(buildSafetyCodeInput(projection.transcriptDigest, projection.linkGeneration, projection.epoch)).digest();
  confirmationKey.fill(0);
  const confirm = { linkId: projection.linkId, linkGeneration: projection.linkGeneration, epoch: projection.epoch,
    transcriptDigest: projection.transcriptDigest, confirmationProof: ownProof } satisfies E2EConfirmationSubmissionV1;
  return { safetyCode: crockford30(safetyDigest), confirm, complete: async (transport) => {
    const existing = input.keyring.pendingActivation(projection.linkId, projection.linkGeneration, projection.epoch);
    let pending = existing;
    if (!pending) {
      const confirmation = await transport.confirmLink(projection.linkId, confirm); const peer = confirmation.peerConfirmationProof;
      if (!peer || peer.linkId !== projection.linkId || peer.linkGeneration !== projection.linkGeneration || peer.epoch !== projection.epoch
        || peer.transcriptDigest !== projection.transcriptDigest || !safeEncodedEqual(peer.confirmationProof, expectedPeerProof)) throw new TypeError('peer confirmation proof verification failed');
      const peerProofDigest = await contentSha256(encoder.encode(peer.confirmationProof)); const activatedAt = (input.now ?? (() => new Date().toISOString()))();
      const pin = { version: 1 as const, status: 'active' as const, linkId: projection.linkId, hostId: projection.hostId,
        watchDeviceId: projection.watchDeviceId, linkGeneration: projection.linkGeneration, epoch: projection.epoch,
        transcriptDigest: projection.transcriptDigest, watchBinding: projection.watchBinding, watchBindingDigest: watchDigest,
        peerProofDigest, activatedAt };
      pending = { version: 1, linkId: projection.linkId, linkGeneration: projection.linkGeneration, epoch: projection.epoch, peerProofDigest, activatedAt, pin };
      input.keyring.stageActivation(pending);
    }
    await transport.activateLink(projection.linkId, { linkId: projection.linkId, linkGeneration: projection.linkGeneration,
      epoch: projection.epoch, transcriptDigest: projection.transcriptDigest, peerRole: 'watch',
      peerProofDigest: pending.peerProofDigest, activatedAt: pending.activatedAt });
    input.keyring.persistActive(pending.pin); return pending.pin;
  } };
}

export function verifyBindingWithIdentityPublicKey(binding: EncryptionKeyBindingV1, identityPublicKey: string): boolean {
  try { const { bindingSignature, ...unsigned } = binding; const raw = base64UrlDecode(identityPublicKey, 32, 'Ed25519 public key');
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]), format: 'der', type: 'spki' });
    return verify(null, buildEncryptionBindingBytes(unsigned), key, base64UrlDecode(bindingSignature, 64, 'binding signature')); } catch { return false; }
}
async function validatePeerBinding(binding: EncryptionKeyBindingV1, watchDeviceId: string, identityPublicKey: string): Promise<boolean> {
  if (!validateEncryptionKeyBindingV1(binding) || binding.entityType !== 'watch' || binding.entityId !== watchDeviceId
    || !await encryptionKeyIdMatchesPublicKey(binding.encryptionKeyId, binding.publicKey)) return false;
  const derived = await deriveEntityIdentity('watch', identityPublicKey);
  return derived.entityId === watchDeviceId && derived.keyId === binding.identityKeyId
    && verifyBindingWithIdentityPublicKey(binding, identityPublicKey);
}
async function bindingDigest(binding: EncryptionKeyBindingV1): Promise<string> { const { bindingSignature: _, ...unsigned } = binding; return contentSha256(buildEncryptionBindingBytes(unsigned)); }
function deriveConfirmationKey(identity: HostEncryptionIdentity, peerPublicKey: string, transcriptDigest: string): Uint8Array {
  const shared = x25519SharedSecret(identity.privateKeyPkcs8, base64UrlDecode(peerPublicKey, 32, 'Watch public key')); const salt = base64UrlDecode(transcriptDigest, 32, 'transcript digest');
  try { return hkdfSha256(shared, salt, encoder.encode('ariava:e2e:v1:confirmation')); } finally { shared.fill(0); salt.fill(0); }
}
function hmac(key: Uint8Array, bytes: Uint8Array): string { return base64UrlEncode(createHmac('sha256', key).update(bytes).digest()); }
function safeEncodedEqual(left: string, right: string): boolean { try { const a = base64UrlDecode(left); const b = base64UrlDecode(right); return a.length === b.length && timingSafeEqual(a, b); } catch { return false; } }
function crockford30(bytes: Uint8Array): string { let value = ((bytes[0]! << 22) | (bytes[1]! << 14) | (bytes[2]! << 6) | (bytes[3]! >>> 2)) >>> 0; let result = ''; for (let i = 0; i < 6; i += 1) result += PAIRING_CODE_ALPHABET[(value >>> (25 - i * 5)) & 31]; return result; }
function sameBinding(left: EncryptionKeyBindingV1, right: EncryptionKeyBindingV1): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function validPin(value: ActiveLinkPinV1, hostId: string): boolean {
  return value?.version === 1 && ['active', 'retiring', 'revoked'].includes(value.status) && value.hostId === hostId
    && typeof value.linkId === 'string' && typeof value.watchDeviceId === 'string' && Number.isSafeInteger(value.linkGeneration) && value.linkGeneration > 0
    && Number.isSafeInteger(value.epoch) && value.epoch > 0 && typeof value.transcriptDigest === 'string'
    && validateEncryptionKeyBindingV1(value.watchBinding) && value.watchBinding.entityId === value.watchDeviceId
    && typeof value.watchBindingDigest === 'string' && typeof value.peerProofDigest === 'string' && typeof value.activatedAt === 'string'
    && (value.retiringAt === undefined || typeof value.retiringAt === 'string');
}
