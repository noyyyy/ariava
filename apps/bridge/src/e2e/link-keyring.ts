import { createHash, createHmac, createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import {
  PAIRING_CODE_ALPHABET, base64UrlDecode, base64UrlEncode, buildConfirmationProofBytes,
  buildEncryptionBindingBytes, buildLinkTranscriptBytes, buildSafetyCodeInput, contentSha256,
  deriveEntityIdentity, encryptionKeyIdMatchesPublicKey, isCanonicalTimestamp, validateEncryptionKeyBindingV1,
  type E2EActivationAckV1, type E2EConfirmationSubmissionV1, type E2EPendingLinkProjectionV1,
  type E2ERecipientSnapshotV1, type EncryptionKeyBindingV1, type EncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import { pathHasFilesystemEvidence, readSecureJson, writeSecureJson } from '../host-manager/secure-files';
import { acquireProcessAwareLock } from '../host-manager/process-aware-lock';
import { deriveHostEncryptionKeyId, importHostEncryptionPrivateKey, type HostEncryptionIdentity, type HostIdentity } from '../identity';
import type { HostEncryptionIdentityStore } from '../identity/runtime-store';
import { hkdfSha256, x25519SharedSecret } from './node-crypto';
import { decryptCommandForPin } from './envelope';
import { CommandEpochAuthorizationError, type EncryptedCommandKeyring } from './command-execution';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const encoder = new TextEncoder();
export type LocalPinStatus = 'active' | 'retiring' | 'revoked';

export interface ActiveLinkPinV2 {
  version: 2; status: LocalPinStatus; linkId: string; hostId: string; watchDeviceId: string;
  linkGeneration: number; epoch: number; transcriptDigest: string;
  hostBinding: EncryptionKeyBindingV1; hostBindingDigest: string;
  watchBinding: EncryptionKeyBindingV1; watchBindingDigest: string;
  peerProofDigest: string; activatedAt: string; retiringAt?: string;
}
export interface PendingActivationV2 {
  version: 2; linkId: string; linkGeneration: number; epoch: number;
  peerProofDigest: string; activatedAt: string; pin: ActiveLinkPinV2;
}
interface PersistedKeyringV2 { version: 2; pins: ActiveLinkPinV2[]; pendingActivations: PendingActivationV2[] }
interface LegacyLinkPinV1 {
  version: 1; status: LocalPinStatus; linkId: string; hostId: string; watchDeviceId: string;
  linkGeneration: number; epoch: number; transcriptDigest: string; watchBinding: EncryptionKeyBindingV1;
  watchBindingDigest: string; peerProofDigest: string; activatedAt: string; retiringAt?: string;
}
interface LegacyPendingActivationV1 { version: 1; linkId: string; linkGeneration: number; epoch: number; peerProofDigest: string; activatedAt: string; pin: LegacyLinkPinV1 }
interface PersistedKeyringV1 { version: 1; pins: LegacyLinkPinV1[]; pendingActivations?: LegacyPendingActivationV1[] }

export interface HostActivationTransport {
  confirmLink(linkId: string, request: E2EConfirmationSubmissionV1): Promise<{ state: string; peerConfirmationProof?: E2EConfirmationSubmissionV1 }>;
  activateLink(linkId: string, request: E2EActivationAckV1): Promise<{ state: string }>;
}
export interface PinRetentionReferences {
  contentRetainedThrough?: Record<string, string>;
  commandRetainedThrough?: Record<string, string>;
  executionRetainedThrough?: Record<string, string>;
  terminalReceiptRetainedThrough?: Record<string, string>;
  pendingOutboxRetainedThrough?: Record<string, string>;
  undeliverableOutboxRetainedThrough?: Record<string, string>;
}
interface HostIdentityResolver {
  load(): HostEncryptionIdentity | null;
  identity(encryptionKeyId: string): HostEncryptionIdentity | null;
  prune?(referencedKeyIds: ReadonlySet<string>): string[];
}

export interface LinkKeyringMigrationContext {
  currentHostIdentity: Pick<HostIdentity, 'hostId' | 'keyId' | 'algorithm' | 'publicKey' | 'publicKeyFingerprint'>;
  signedCurrentHostBinding: EncryptionKeyBindingV1;
}

export class LocalLinkKeyring implements EncryptedCommandKeyring {
  private pins: ActiveLinkPinV2[];
  private pendingActivations: PendingActivationV2[];
  private readonly identities: HostIdentityResolver;
  private readonly currentHostId: string;

  constructor(
    private readonly path: string,
    identities: HostEncryptionIdentity | Pick<HostEncryptionIdentityStore, 'load' | 'identity' | 'prune'> | HostIdentityResolver,
    migrationContext?: LinkKeyringMigrationContext,
  ) {
    this.identities = identityResolver(identities);
    const current = this.identities.load();
    if (!current) throw new TypeError('Host encryption identity is unavailable');
    this.currentHostId = current.hostId;
    const state = this.load(migrationContext);
    this.pins = state.pins;
    this.pendingActivations = state.pendingActivations;
  }

  listActive(): ActiveLinkPinV2[] { return this.pins.filter((pin) => pin.status === 'active').map((pin) => structuredClone(pin)); }
  listRetiring(): ActiveLinkPinV2[] { return this.pins.filter((pin) => pin.status === 'retiring').map((pin) => structuredClone(pin)); }
  referencedHostEncryptionKeyIds(): Set<string> {
    return new Set([
      ...this.pins.map((pin) => pin.hostBinding.encryptionKeyId),
      ...this.pendingActivations.map((pending) => pending.pin.hostBinding.encryptionKeyId),
    ]);
  }
  resolvePinReference(linkId: string, linkGeneration: number, epoch: number) {
    const pin = this.getUsable(linkId, linkGeneration, epoch);
    if (!pin) return undefined;
    return {
      version: 1 as const, linkId: pin.linkId, linkGeneration: pin.linkGeneration, epoch: pin.epoch,
      transcriptDigest: pin.transcriptDigest, hostEncryptionKeyId: pin.hostBinding.encryptionKeyId,
      watchEncryptionKeyId: pin.watchBinding.encryptionKeyId,
    };
  }
  resolvePinMaterial(linkId: string, generation: number, epoch: number): { pin: ActiveLinkPinV2; hostIdentity: HostEncryptionIdentity; watchBinding: EncryptionKeyBindingV1 } {
    const pin = this.getUsable(linkId, generation, epoch);
    if (!pin) throw new TypeError('link pin is unavailable');
    const hostIdentity = this.identities.identity(pin.hostBinding.encryptionKeyId);
    if (!hostIdentity || !bindingMatchesIdentity(pin.hostBinding, hostIdentity)) throw new TypeError('Host identity for link pin is unavailable');
    return { pin: structuredClone(pin), hostIdentity, watchBinding: structuredClone(pin.watchBinding) };
  }
  resolveCommandReceiptPinStatus(
    reference: {
      linkId: string; linkGeneration: number; epoch: number; transcriptDigest: string;
      hostEncryptionKeyId: string; watchEncryptionKeyId: string;
    },
    issuedAt: string,
  ): 'deliverable' | 'revoked' | 'unavailable' {
    const pin = this.pins.find((item) => item.linkId === reference.linkId
      && item.linkGeneration === reference.linkGeneration && item.epoch === reference.epoch);
    if (!pin || pin.transcriptDigest !== reference.transcriptDigest
      || pin.hostBinding.encryptionKeyId !== reference.hostEncryptionKeyId
      || pin.watchBinding.encryptionKeyId !== reference.watchEncryptionKeyId) return 'unavailable';
    if (pin.status === 'revoked') return 'revoked';
    if (pin.status === 'retiring' && (!pin.retiringAt || issuedAt >= pin.retiringAt)) return 'unavailable';
    return 'deliverable';
  }
  pruneRetiring(input: PinRetentionReferences, now = new Date().toISOString()): ActiveLinkPinV2[] {
    assertCanonicalRetentionReferences(input, now);
    const removed: ActiveLinkPinV2[] = [];
    this.pins = this.pins.filter((pin) => {
      if (pin.status === 'active') return true;
      const key = pinKey(pin);
      const retainUntil = maxTimestamp(
        input.contentRetainedThrough?.[key], input.commandRetainedThrough?.[key], input.executionRetainedThrough?.[key],
        input.terminalReceiptRetainedThrough?.[key], input.pendingOutboxRetainedThrough?.[key], input.undeliverableOutboxRetainedThrough?.[key],
      );
      if (retainUntil && retainUntil >= now) return true;
      removed.push(pin); return false;
    });
    if (removed.length) {
      this.persist();
      this.identities.prune?.(this.referencedHostEncryptionKeyIds());
    }
    return removed.map((pin) => structuredClone(pin));
  }
  revokeCompromisedEncryptionKey(encryptionKeyId: string): number {
    const before = this.pins.filter((pin) => pin.status !== 'revoked' && pin.hostBinding.encryptionKeyId === encryptionKeyId).length;
    this.pins = this.pins.map((pin) => pin.status !== 'revoked' && pin.hostBinding.encryptionKeyId === encryptionKeyId
      ? { ...pin, status: 'revoked' as const } : pin);
    if (before) this.persist();
    return before;
  }
  getUsable(linkId: string, generation: number, epoch: number): ActiveLinkPinV2 | undefined {
    const pin = this.pins.find((item) => item.status !== 'revoked' && item.linkId === linkId && item.linkGeneration === generation && item.epoch === epoch);
    return pin && structuredClone(pin);
  }
  persistActive(pin: ActiveLinkPinV2): void {
    assertValidPin(pin, this.currentHostId, this.identities);
    if (pin.status !== 'active') throw new TypeError('new link pin must be active');
    this.updatePersisted(() => {
      const sameWatch = this.pins.filter((item) => item.watchDeviceId === pin.watchDeviceId);
      if (sameWatch.some((item) => item.linkGeneration > pin.linkGeneration
        || (item.linkGeneration === pin.linkGeneration && (item.epoch > pin.epoch
          || (item.epoch === pin.epoch && item.linkId !== pin.linkId)))
        || item.watchBinding.sequence > pin.watchBinding.sequence || item.hostBinding.sequence > pin.hostBinding.sequence)) {
        throw new TypeError('active link pin rollback rejected');
      }
      const index = this.pins.findIndex((item) => item.linkId === pin.linkId && item.linkGeneration === pin.linkGeneration && item.epoch === pin.epoch);
      if (index >= 0) {
        if (JSON.stringify(this.pins[index]) !== JSON.stringify(pin)) throw new TypeError('active link pin immutable tuple conflict');
        this.pendingActivations = this.pendingActivations.filter((item) => !(item.linkId === pin.linkId && item.linkGeneration === pin.linkGeneration && item.epoch === pin.epoch));
        return;
      }
      const now = new Date().toISOString();
      this.pins = this.pins.map((item) => item.watchDeviceId === pin.watchDeviceId && item.status === 'active'
        && comparePinTuple(pin, item) > 0
        ? { ...item, status: 'retiring' as const, retiringAt: laterTimestamp(now, item.activatedAt) } : item);
      this.pins.push(structuredClone(pin));
      this.pendingActivations = this.pendingActivations.filter((item) => !(item.linkId === pin.linkId && item.linkGeneration === pin.linkGeneration && item.epoch === pin.epoch));
    });
  }
  stageActivation(pending: PendingActivationV2): void {
    assertValidPending(pending, this.currentHostId, this.identities);
    this.updatePersisted(() => {
      const existing = this.pendingActivations.find((item) => item.linkId === pending.linkId && item.linkGeneration === pending.linkGeneration && item.epoch === pending.epoch);
      if (existing && JSON.stringify(existing) !== JSON.stringify(pending)) throw new TypeError('pending activation conflict');
      if (!existing) this.pendingActivations = [...this.pendingActivations, structuredClone(pending)];
    });
  }
  pendingActivation(linkId: string, generation: number, epoch: number): PendingActivationV2 | undefined {
    const value = this.pendingActivations.find((item) => item.linkId === linkId && item.linkGeneration === generation && item.epoch === epoch);
    return value && structuredClone(value);
  }
  reconcileRecipients(snapshot: E2ERecipientSnapshotV1) {
    if (snapshot.hostId !== this.currentHostId || !Number.isSafeInteger(snapshot.recipientSetVersion) || snapshot.recipientSetVersion < 1) throw new TypeError('recipient snapshot is invalid');
    const recipients = snapshot.recipients.map((recipient) => this.materialForRecipient(recipient));
    const activeKeys = new Set(snapshot.recipients.map((recipient) => pinKey(recipient)));
    const authoritativeByWatch = new Map(snapshot.recipients.map((recipient) => [recipient.watchDeviceId, recipient]));
    const before = JSON.stringify(this.pins);
    this.pins = this.pins.map((pin) => {
      if (pin.status === 'revoked' || activeKeys.has(pinKey(pin))) return pin;
      const successor = authoritativeByWatch.get(pin.watchDeviceId);
      if (pin.status === 'retiring' && successor && comparePinTuple(successor, pin) > 0) return pin;
      const { retiringAt: _retiringAt, ...revoked } = pin;
      return { ...revoked, status: 'revoked' as const };
    });
    if (before !== JSON.stringify(this.pins)) this.persist();
    return recipients;
  }
  revokeWatch(watchDeviceId: string): void {
    const before = JSON.stringify(this.pins);
    this.pins = this.pins.map((pin) => {
      if (pin.watchDeviceId !== watchDeviceId) return pin;
      const { retiringAt: _retiringAt, ...revoked } = pin;
      return { ...revoked, status: 'revoked' as const };
    });
    if (before !== JSON.stringify(this.pins)) this.persist();
  }
  revokeWatchGeneration(watchDeviceId: string, linkGeneration: number): void {
    if (!watchDeviceId || !Number.isSafeInteger(linkGeneration) || linkGeneration < 1) {
      throw new TypeError('Watch relation generation is invalid');
    }
    this.updatePersisted(() => {
      this.pins = this.pins.map((pin) => {
        if (pin.watchDeviceId !== watchDeviceId || pin.linkGeneration !== linkGeneration) return pin;
        const { retiringAt: _retiringAt, ...revoked } = pin;
        return { ...revoked, status: 'revoked' as const };
      });
      this.pendingActivations = this.pendingActivations.filter((pending) =>
        pending.pin.watchDeviceId !== watchDeviceId || pending.linkGeneration !== linkGeneration);
    });
  }
  async prepare(command: EncryptedCommandEnvelopeV1, now = new Date(Date.now())) {
    const material = this.tryResolvePinMaterial(command.linkId, command.linkGeneration, command.epoch);
    if (!material || material.pin.hostId !== command.hostId || material.pin.watchDeviceId !== command.watchDeviceId
      || !Number.isFinite(now.getTime()) || new Date(command.expiresAt).getTime() <= now.getTime()
      || (material.pin.status === 'retiring' && (!material.pin.retiringAt || command.issuedAt >= material.pin.retiringAt))
      || command.payload.keyWrap.senderEncryptionKeyId !== material.pin.watchBinding.encryptionKeyId
      || command.payload.keyWrap.recipientEncryptionKeyId !== material.pin.hostBinding.encryptionKeyId) {
      throw new CommandEpochAuthorizationError('command epoch is not locally authorized');
    }
    const loopbackCommand = decryptCommandForPin(command, {
      hostIdentity: material.hostIdentity, watchPublicKey: material.pin.watchBinding.publicKey,
      transcriptDigest: material.pin.transcriptDigest,
    });
    return { pinReference: {
      version: 1 as const, linkId: material.pin.linkId, linkGeneration: material.pin.linkGeneration, epoch: material.pin.epoch,
      transcriptDigest: material.pin.transcriptDigest, hostEncryptionKeyId: material.pin.hostBinding.encryptionKeyId,
      watchEncryptionKeyId: material.pin.watchBinding.encryptionKeyId,
    }, loopbackCommand };
  }
  private tryResolvePinMaterial(linkId: string, generation: number, epoch: number) {
    try { return this.resolvePinMaterial(linkId, generation, epoch); } catch { return undefined; }
  }
  private materialForRecipient(recipient: E2ERecipientSnapshotV1['recipients'][number]) {
    const material = this.tryResolvePinMaterial(recipient.linkId, recipient.linkGeneration, recipient.epoch);
    const pin = material?.pin;
    if (!pin || pin.status !== 'active' || recipient.state !== 'active' || recipient.watchDeviceId !== pin.watchDeviceId || !sameBinding(recipient.watchBinding, pin.watchBinding)) {
      throw new TypeError('recipient lacks a matching locally verified active pin');
    }
    return { ...recipient, transcriptDigest: pin.transcriptDigest,
      hostBinding: structuredClone(pin.hostBinding), hostIdentity: material.hostIdentity };
  }
  private load(migrationContext?: LinkKeyringMigrationContext): PersistedKeyringV2 {
    if (!pathHasFilesystemEvidence(this.path)) return { version: 2, pins: [], pendingActivations: [] };
    const raw = readSecureJson<unknown>(this.path);
    const state = decodeKeyring(raw, this.currentHostId, this.identities, migrationContext);
    if (isLegacyKeyring(raw)) this.persistState(state);
    return state;
  }
  private persist(): void { this.persistState({ version: 2, pins: this.pins, pendingActivations: this.pendingActivations }); }
  private persistState(state: PersistedKeyringV2): void { writeSecureJson(this.path, state); }
  private updatePersisted(mutate: () => void): void {
    const lock = acquireProcessAwareLock(
      `${this.path}.mutation.lock`,
      () => new TypeError('local E2E keyring mutation is already in progress'),
    );
    try {
      const latest = this.load();
      this.pins = latest.pins;
      this.pendingActivations = latest.pendingActivations;
      const before = JSON.stringify(latest);
      mutate();
      const next = { version: 2 as const, pins: this.pins, pendingActivations: this.pendingActivations };
      validateState(next, this.currentHostId, this.identities);
      if (before !== JSON.stringify(next)) this.persistState(next);
    } finally {
      lock.release();
    }
  }
}

export async function prepareHostActivation(input: { projection: E2EPendingLinkProjectionV1; hostIdentity: HostEncryptionIdentity;
  hostBinding: EncryptionKeyBindingV1; keyring: LocalLinkKeyring;
  now?: () => string }): Promise<{ safetyCode: string; confirm: E2EConfirmationSubmissionV1; complete(transport: HostActivationTransport): Promise<ActiveLinkPinV2> }> {
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
      if (!peer) throw new TypeError('peer confirmation proof is not available yet');
      if (peer.linkId !== projection.linkId || peer.linkGeneration !== projection.linkGeneration || peer.epoch !== projection.epoch
        || peer.transcriptDigest !== projection.transcriptDigest || !safeEncodedEqual(peer.confirmationProof, expectedPeerProof)) throw new TypeError('peer confirmation proof verification failed');
      const peerProofDigest = await contentSha256(encoder.encode(peer.confirmationProof)); const activatedAt = (input.now ?? (() => new Date().toISOString()))();
      const pin = { version: 2 as const, status: 'active' as const, linkId: projection.linkId, hostId: projection.hostId,
        watchDeviceId: projection.watchDeviceId, linkGeneration: projection.linkGeneration, epoch: projection.epoch,
        transcriptDigest: projection.transcriptDigest, hostBinding: projection.hostBinding, hostBindingDigest: hostDigest,
        watchBinding: projection.watchBinding, watchBindingDigest: watchDigest, peerProofDigest, activatedAt };
      pending = { version: 2, linkId: projection.linkId, linkGeneration: projection.linkGeneration, epoch: projection.epoch, peerProofDigest, activatedAt, pin };
      input.keyring.stageActivation(pending);
    }
    await transport.activateLink(projection.linkId, { linkId: projection.linkId, linkGeneration: projection.linkGeneration,
      epoch: projection.epoch, transcriptDigest: projection.transcriptDigest, peerRole: 'watch',
      peerProofDigest: pending.peerProofDigest, activatedAt: pending.activatedAt });
    input.keyring.persistActive(pending.pin); return pending.pin;
  } };
}

export function verifyBindingWithIdentityPublicKey(binding: EncryptionKeyBindingV1, identityPublicKey: string): boolean {
  try {
    const { bindingSignature, ...unsigned } = binding; const raw = base64UrlDecode(identityPublicKey, 32, 'Ed25519 public key');
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]), format: 'der', type: 'spki' });
    return verify(null, buildEncryptionBindingBytes(unsigned), key, base64UrlDecode(bindingSignature, 64, 'binding signature'));
  } catch { return false; }
}

function decodeKeyring(value: unknown, hostId: string, identities: HostIdentityResolver, migrationContext?: LinkKeyringMigrationContext): PersistedKeyringV2 {
  if (isLegacyKeyring(value)) {
    if (!migrationContext) throw new TypeError('local E2E keyring v1 migration requires the verified current Host identity and signed binding');
    const { currentHostIdentity, signedCurrentHostBinding: migrationHostBinding } = migrationContext;
    const current = identities.load();
    if (current) importHostEncryptionPrivateKey(current);
    if (!current || !isCanonicalMigrationIdentity(currentHostIdentity, hostId)
      || migrationHostBinding.identityKeyId !== currentHostIdentity.keyId
      || !verifyBindingWithIdentityPublicKey(migrationHostBinding, currentHostIdentity.publicKey)
      || !bindingMatchesIdentity(migrationHostBinding, current) || migrationHostBinding.entityId !== hostId) {
      throw new TypeError('local E2E keyring v1 migration binding is invalid');
    }
    const pending = value.pendingActivations ?? [];
    if (value.pins.some((pin) => !validLegacyPin(pin, hostId)) || pending.some((item) => !validLegacyPending(item, hostId))) throw new TypeError('local E2E keyring v1 is invalid');
    const hostBindingDigest = bindingDigestSync(migrationHostBinding);
    const migratePin = (pin: LegacyLinkPinV1): ActiveLinkPinV2 => ({ ...pin, version: 2, hostBinding: migrationHostBinding, hostBindingDigest });
    const state = { version: 2 as const, pins: value.pins.map(migratePin), pendingActivations: pending.map((item) => ({ ...item, version: 2 as const, pin: migratePin(item.pin) })) };
    validateState(state, hostId, identities);
    return state;
  }
  if (!isPlainRecord(value) || !exactKeys(value, ['version', 'pins', 'pendingActivations']) || value.version !== 2
    || !Array.isArray(value.pins) || !Array.isArray(value.pendingActivations)) throw new TypeError('local E2E keyring is invalid');
  const state = value as unknown as PersistedKeyringV2;
  validateState(state, hostId, identities);
  return state;
}
function validateState(state: PersistedKeyringV2, hostId: string, identities: HostIdentityResolver): void {
  const tuples = new Set<string>();
  for (const pin of state.pins) {
    assertValidPin(pin, hostId, identities);
    const key = pinKey(pin); if (tuples.has(key)) throw new TypeError('duplicate local E2E pin tuple'); tuples.add(key);
  }
  const pendingTuples = new Set<string>();
  const pendingWatches = new Set<string>();
  for (const pending of state.pendingActivations) {
    assertValidPending(pending, hostId, identities);
    const key = pinKey(pending.pin);
    if (tuples.has(key) || pendingTuples.has(key) || pendingWatches.has(pending.pin.watchDeviceId)) {
      throw new TypeError('duplicate pending local E2E activation');
    }
    pendingTuples.add(key);
    pendingWatches.add(pending.pin.watchDeviceId);
  }
  const byWatch = new Map<string, ActiveLinkPinV2[]>();
  for (const pin of state.pins) {
    byWatch.set(pin.watchDeviceId, [...(byWatch.get(pin.watchDeviceId) ?? []), pin]);
  }
  for (const [watchDeviceId, pins] of byWatch) {
    const active = pins.filter((pin) => pin.status === 'active');
    if (active.length > 1) throw new TypeError('multiple active local E2E pins for Watch');
    const maximalTuple = pins.reduce(latestPin);
    if (active.some((pin) => comparePinTuple(pin, maximalTuple) !== 0)) {
      throw new TypeError('local E2E pin rollback detected');
    }
    const pending = state.pendingActivations.find((item) => item.pin.watchDeviceId === watchDeviceId);
    if (pending && comparePinTuple(pending.pin, maximalTuple) <= 0) {
      throw new TypeError('pending local E2E activation rollback detected');
    }
  }
}
function assertValidPin(value: unknown, hostId: string, identities: HostIdentityResolver): asserts value is ActiveLinkPinV2 {
  if (!isPlainRecord(value) || !exactKeys(value, value.retiringAt === undefined ? PIN_KEYS : [...PIN_KEYS, 'retiringAt'])
    || value.version !== 2 || !['active', 'retiring', 'revoked'].includes(value.status as string) || value.hostId !== hostId
    || typeof value.linkId !== 'string' || typeof value.watchDeviceId !== 'string'
    || !Number.isSafeInteger(value.linkGeneration) || (value.linkGeneration as number) < 1 || !Number.isSafeInteger(value.epoch) || (value.epoch as number) < 1
    || !isDigest(value.transcriptDigest) || !isDigest(value.hostBindingDigest) || !isDigest(value.watchBindingDigest) || !isDigest(value.peerProofDigest)
    || !isCanonicalTimestamp(value.activatedAt as string) || (value.retiringAt !== undefined && !isCanonicalTimestamp(value.retiringAt as string))
    || !validateEncryptionKeyBindingV1(value.hostBinding) || !validateEncryptionKeyBindingV1(value.watchBinding)) throw new TypeError('local E2E pin is invalid');
  const pin = value as unknown as ActiveLinkPinV2;
  if ((pin.status === 'active' && pin.retiringAt !== undefined)
    || (pin.status === 'retiring' && (pin.retiringAt === undefined || pin.retiringAt < pin.activatedAt))
    || (pin.status === 'revoked' && pin.retiringAt !== undefined && pin.retiringAt < pin.activatedAt)) {
    throw new TypeError('local E2E pin retirement boundary is invalid');
  }
  if (pin.hostBinding.entityType !== 'host' || pin.hostBinding.entityId !== hostId || pin.watchBinding.entityType !== 'watch'
    || pin.watchBinding.entityId !== pin.watchDeviceId || deriveHostEncryptionKeyId(pin.watchBinding.publicKey) !== pin.watchBinding.encryptionKeyId
    || pin.hostBinding.encryptionKeyId === pin.watchBinding.encryptionKeyId
    || pin.hostBindingDigest !== bindingDigestSync(pin.hostBinding) || pin.watchBindingDigest !== bindingDigestSync(pin.watchBinding)
    || pin.transcriptDigest !== transcriptDigestSync(pin)) throw new TypeError('local E2E pin binding is invalid');
  const identity = identities.identity(pin.hostBinding.encryptionKeyId);
  if (!identity || !bindingMatchesIdentity(pin.hostBinding, identity)) throw new TypeError('local E2E pin Host key is unavailable');
}
function assertValidPending(value: unknown, hostId: string, identities: HostIdentityResolver): asserts value is PendingActivationV2 {
  if (!isPlainRecord(value) || !exactKeys(value, ['version', 'linkId', 'linkGeneration', 'epoch', 'peerProofDigest', 'activatedAt', 'pin'])
    || value.version !== 2 || typeof value.linkId !== 'string' || !Number.isSafeInteger(value.linkGeneration) || !Number.isSafeInteger(value.epoch)
    || !isDigest(value.peerProofDigest) || !isCanonicalTimestamp(value.activatedAt as string)) throw new TypeError('pending activation is invalid');
  assertValidPin(value.pin, hostId, identities);
  const pending = value as unknown as PendingActivationV2;
  if (pending.pin.status !== 'active' || pending.pin.retiringAt !== undefined
    || pending.linkId !== pending.pin.linkId || pending.linkGeneration !== pending.pin.linkGeneration || pending.epoch !== pending.pin.epoch
    || pending.peerProofDigest !== pending.pin.peerProofDigest || pending.activatedAt !== pending.pin.activatedAt) throw new TypeError('pending activation tuple mismatch');
}
const PIN_KEYS = ['version', 'status', 'linkId', 'hostId', 'watchDeviceId', 'linkGeneration', 'epoch', 'transcriptDigest', 'hostBinding', 'hostBindingDigest', 'watchBinding', 'watchBindingDigest', 'peerProofDigest', 'activatedAt'] as const;
function isLegacyKeyring(value: unknown): value is PersistedKeyringV1 {
  if (!isPlainRecord(value) || value.version !== 1 || !Array.isArray(value.pins)) return false;
  return exactKeys(value, value.pendingActivations === undefined ? ['version', 'pins'] : ['version', 'pins', 'pendingActivations'])
    && (value.pendingActivations === undefined || Array.isArray(value.pendingActivations));
}
function validLegacyPin(value: unknown, hostId: string): value is LegacyLinkPinV1 {
  if (!isPlainRecord(value) || !exactKeys(value, value.retiringAt === undefined ? LEGACY_PIN_KEYS : [...LEGACY_PIN_KEYS, 'retiringAt'])) return false;
  return value.version === 1 && ['active', 'retiring', 'revoked'].includes(value.status as string) && value.hostId === hostId
    && typeof value.linkId === 'string' && typeof value.watchDeviceId === 'string'
    && Number.isSafeInteger(value.linkGeneration) && (value.linkGeneration as number) > 0
    && Number.isSafeInteger(value.epoch) && (value.epoch as number) > 0 && isDigest(value.transcriptDigest)
    && validateEncryptionKeyBindingV1(value.watchBinding) && (value.watchBinding as EncryptionKeyBindingV1).entityId === value.watchDeviceId
    && value.watchBindingDigest === bindingDigestSync(value.watchBinding as EncryptionKeyBindingV1) && isDigest(value.peerProofDigest)
    && isCanonicalTimestamp(value.activatedAt as string)
    && ((value.status === 'active' && value.retiringAt === undefined)
      || (value.status === 'retiring' && isCanonicalTimestamp(value.retiringAt as string) && value.retiringAt >= value.activatedAt)
      || (value.status === 'revoked' && (value.retiringAt === undefined
        || (isCanonicalTimestamp(value.retiringAt as string) && value.retiringAt >= value.activatedAt))));
}
function validLegacyPending(value: unknown, hostId: string): value is LegacyPendingActivationV1 {
  if (!isPlainRecord(value) || !exactKeys(value, ['version', 'linkId', 'linkGeneration', 'epoch', 'peerProofDigest', 'activatedAt', 'pin'])
    || value.version !== 1 || !validLegacyPin(value.pin, hostId)) return false;
  const pin = value.pin;
  return pin.status === 'active' && pin.retiringAt === undefined
    && value.linkId === pin.linkId && value.linkGeneration === pin.linkGeneration && value.epoch === pin.epoch
    && value.peerProofDigest === pin.peerProofDigest && value.activatedAt === pin.activatedAt;
}
const LEGACY_PIN_KEYS = ['version', 'status', 'linkId', 'hostId', 'watchDeviceId', 'linkGeneration', 'epoch', 'transcriptDigest', 'watchBinding', 'watchBindingDigest', 'peerProofDigest', 'activatedAt'] as const;
function identityResolver(value: HostEncryptionIdentity | Pick<HostEncryptionIdentityStore, 'load' | 'identity' | 'prune'> | HostIdentityResolver): HostIdentityResolver {
  if ('privateKeyPkcs8' in value) return { load: () => value, identity: (keyId) => keyId === value.encryptionKeyId ? value : null };
  return value;
}
function isCanonicalMigrationIdentity(identity: LinkKeyringMigrationContext['currentHostIdentity'], hostId: string): boolean {
  try {
    if (identity.algorithm !== 'Ed25519') return false;
    const publicKey = base64UrlDecode(identity.publicKey, 32, 'Host Ed25519 public key');
    const fingerprint = base64UrlEncode(new Uint8Array(createHash('sha256').update(publicKey).digest()));
    return identity.publicKeyFingerprint === fingerprint && identity.hostId === `host_${fingerprint}`
      && identity.keyId === `key_${fingerprint}` && identity.hostId === hostId;
  } catch { return false; }
}
function comparePinTuple(left: Pick<ActiveLinkPinV2, 'linkGeneration' | 'epoch'>, right: Pick<ActiveLinkPinV2, 'linkGeneration' | 'epoch'>): number {
  return left.linkGeneration === right.linkGeneration ? left.epoch - right.epoch : left.linkGeneration - right.linkGeneration;
}
function latestPin(left: ActiveLinkPinV2, right: ActiveLinkPinV2): ActiveLinkPinV2 {
  return comparePinTuple(left, right) >= 0 ? left : right;
}
function assertCanonicalRetentionReferences(input: PinRetentionReferences, now: string): void {
  if (!isCanonicalTimestamp(now)) throw new TypeError('pin retention clock is invalid');
  for (const references of Object.values(input)) {
    if (references === undefined) continue;
    if (!isPlainRecord(references)) throw new TypeError('pin retention references are invalid');
    for (const [key, timestamp] of Object.entries(references)) {
      if (!/^.+:[1-9][0-9]*:[1-9][0-9]*$/u.test(key) || !isCanonicalTimestamp(timestamp)) {
        throw new TypeError('pin retention reference is invalid');
      }
    }
  }
}
function laterTimestamp(left: string, right: string): string { return left >= right ? left : right; }
function bindingMatchesIdentity(binding: EncryptionKeyBindingV1, identity: HostEncryptionIdentity): boolean {
  return binding.entityType === 'host' && binding.entityId === identity.hostId && binding.encryptionKeyId === identity.encryptionKeyId
    && binding.publicKey === identity.publicKey && binding.sequence === identity.sequence && binding.createdAt === identity.createdAt
    && deriveHostEncryptionKeyId(binding.publicKey) === binding.encryptionKeyId;
}
async function validatePeerBinding(binding: EncryptionKeyBindingV1, watchDeviceId: string, identityPublicKey: string): Promise<boolean> {
  if (!validateEncryptionKeyBindingV1(binding) || binding.entityType !== 'watch' || binding.entityId !== watchDeviceId
    || !await encryptionKeyIdMatchesPublicKey(binding.encryptionKeyId, binding.publicKey)) return false;
  const derived = await deriveEntityIdentity('watch', identityPublicKey);
  return derived.entityId === watchDeviceId && derived.keyId === binding.identityKeyId && verifyBindingWithIdentityPublicKey(binding, identityPublicKey);
}
async function bindingDigest(binding: EncryptionKeyBindingV1): Promise<string> { return contentSha256(buildBindingBytes(binding)); }
function bindingDigestSync(binding: EncryptionKeyBindingV1): string { return hash(buildBindingBytes(binding)); }
function buildBindingBytes(binding: EncryptionKeyBindingV1): Uint8Array { const { bindingSignature: _, ...unsigned } = binding; return buildEncryptionBindingBytes(unsigned); }
function transcriptDigestSync(pin: Pick<ActiveLinkPinV2, 'linkId' | 'hostId' | 'watchDeviceId' | 'linkGeneration' | 'epoch' | 'hostBindingDigest' | 'watchBindingDigest'>): string {
  return hash(buildLinkTranscriptBytes(pin));
}
function deriveConfirmationKey(identity: HostEncryptionIdentity, peerPublicKey: string, transcriptDigest: string): Uint8Array {
  const shared = x25519SharedSecret(identity.privateKeyPkcs8, base64UrlDecode(peerPublicKey, 32, 'Watch public key')); const salt = base64UrlDecode(transcriptDigest, 32, 'transcript digest');
  try { return hkdfSha256(shared, salt, encoder.encode('ariava:e2e:v1:confirmation')); } finally { shared.fill(0); salt.fill(0); }
}
function hmac(key: Uint8Array, bytes: Uint8Array): string { return base64UrlEncode(createHmac('sha256', key).update(bytes).digest()); }
function hash(bytes: Uint8Array): string { return base64UrlEncode(new Uint8Array(createHash('sha256').update(bytes).digest())); }
function safeEncodedEqual(left: string, right: string): boolean { try { const a = base64UrlDecode(left); const b = base64UrlDecode(right); return a.length === b.length && timingSafeEqual(a, b); } catch { return false; } }
function crockford30(bytes: Uint8Array): string { let value = ((bytes[0]! << 22) | (bytes[1]! << 14) | (bytes[2]! << 6) | (bytes[3]! >>> 2)) >>> 0; let result = ''; for (let i = 0; i < 6; i += 1) result += PAIRING_CODE_ALPHABET[(value >>> (25 - i * 5)) & 31]; return result; }
function pinKey(pin: Pick<ActiveLinkPinV2, 'linkId' | 'linkGeneration' | 'epoch'>): string { return `${pin.linkId}:${pin.linkGeneration}:${pin.epoch}`; }
function maxTimestamp(...values: Array<string | undefined>): string | undefined { const defined = values.filter((value): value is string => value !== undefined); return defined.length ? defined.reduce((latest, value) => value > latest ? value : latest) : undefined; }
function sameBinding(left: EncryptionKeyBindingV1, right: EncryptionKeyBindingV1): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function isDigest(value: unknown): value is string { if (typeof value !== 'string') return false; try { return base64UrlDecode(value, 32, 'digest').length === 32; } catch { return false; } }
function isPlainRecord(value: unknown): value is Record<string, any> { if (!value || typeof value !== 'object' || Array.isArray(value)) return false; const prototype = Object.getPrototypeOf(value); return prototype === Object.prototype || prototype === null; }
function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean { const keys = Object.keys(value); return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key)); }
