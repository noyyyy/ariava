import { randomBytes, randomUUID } from 'node:crypto';
import {
  E2E_LIMITS,
  E2E_SUITE_V1,
  base64UrlDecode,
  base64UrlEncode,
  buildCommandReceiptContentAAD,
  buildEncryptionBindingBytes,
  buildLinkTranscriptBytes,
  buildProtectedCommandReceiptBytes,
  buildWrapAAD,
  contentSha256,
  deriveCommandReceiptDigest,
  deriveEncryptedCommandDigest,
  isCanonicalTimestamp,
  pairRootInfo,
  validateCommandReceiptEnvelopeV1,
  validateCommandResult,
  validateEncryptedCommandEnvelopeV1,
  validateEncryptionKeyBindingV1,
  type CommandReceiptEnvelopeV1,
  type CommandResult,
  type EncryptionKeyBindingV1,
} from '@ariava/protocol';
import { deriveHostEncryptionKeyId, importHostEncryptionPrivateKey } from '../identity';
import type {
  CommandReceiptOutboxInputV1,
  PersistedCommandExecutionV4,
  PersistedCommandPinReferenceV1,
} from '../types';
import { chachaPolySeal, hkdfSha256, x25519SharedSecret } from './node-crypto';
import { LocalLinkKeyring, type ActiveLinkPinV2 } from './link-keyring';

const encoder = new TextEncoder();

export interface CommandReceiptRandomness {
  contentId: string;
  dek: Uint8Array;
  contentNonce: Uint8Array;
  wrapNonce: Uint8Array;
}

export type CommandReceiptExecution = Readonly<PersistedCommandExecutionV4> & {
  readonly terminalResult: CommandResult;
};

export async function buildCommandReceipt(
  execution: CommandReceiptExecution,
  keyring: LocalLinkKeyring,
  randomness: CommandReceiptRandomness = productionRandomness(),
): Promise<CommandReceiptOutboxInputV1> {
  let plaintext: Uint8Array | undefined;
  let wrapKey: Uint8Array | undefined;
  try {
    assertRandomness(randomness);
    const { command, terminalResult, pinReference } = await validateExecution(execution);
    const material = await resolveExactPinMaterial(command, pinReference, keyring);
    plaintext = buildProtectedCommandReceiptBytes({
      version: 1,
      accepted: terminalResult.accepted,
      status: terminalResult.status,
    });
    const contentAAD = buildCommandReceiptContentAAD({
      hostId: command.hostId,
      watchDeviceId: command.watchDeviceId,
      sessionId: command.sessionId,
      commandId: command.commandId,
      commandType: command.type,
      commandDigest: execution.commandDigest,
      completedAt: terminalResult.updatedAt,
      contentId: randomness.contentId,
    });
    const sealedContent = chachaPolySeal(randomness.dek, plaintext, contentAAD, randomness.contentNonce);
    wrapKey = deriveReceiptWrapKey(material.pin, material.hostIdentity.privateKeyPkcs8);
    const sealedWrap = chachaPolySeal(wrapKey, randomness.dek, buildWrapAAD({
      direction: 'bridge-to-watch',
      linkId: material.pin.linkId,
      linkGeneration: material.pin.linkGeneration,
      epoch: material.pin.epoch,
      hostId: material.pin.hostId,
      watchDeviceId: material.pin.watchDeviceId,
      senderEncryptionKeyId: material.pin.hostBinding.encryptionKeyId,
      recipientEncryptionKeyId: material.pin.watchBinding.encryptionKeyId,
      contentId: randomness.contentId,
      payloadKind: 'command-receipt-content-v1',
    }), randomness.wrapNonce);
    const receipt: CommandReceiptEnvelopeV1 = {
      version: 1,
      hostId: command.hostId,
      watchDeviceId: command.watchDeviceId,
      sessionId: command.sessionId,
      commandId: command.commandId,
      commandType: command.type,
      commandDigest: execution.commandDigest,
      completedAt: terminalResult.updatedAt,
      linkId: material.pin.linkId,
      linkGeneration: material.pin.linkGeneration,
      epoch: material.pin.epoch,
      content: {
        version: 1,
        suite: E2E_SUITE_V1,
        contentId: randomness.contentId,
        payloadKind: 'command-receipt-content-v1',
        nonce: base64UrlEncode(sealedContent.nonce),
        ciphertext: base64UrlEncode(sealedContent.ciphertext),
      },
      keyWrap: {
        version: 1,
        suite: E2E_SUITE_V1,
        contentId: randomness.contentId,
        linkId: material.pin.linkId,
        linkGeneration: material.pin.linkGeneration,
        epoch: material.pin.epoch,
        senderEncryptionKeyId: material.pin.hostBinding.encryptionKeyId,
        recipientEncryptionKeyId: material.pin.watchBinding.encryptionKeyId,
        nonce: base64UrlEncode(sealedWrap.nonce),
        ciphertext: base64UrlEncode(sealedWrap.ciphertext),
      },
    };
    if (!validateCommandReceiptEnvelopeV1(receipt)) throw new TypeError('command receipt envelope is invalid');
    return {
      receipt,
      canonicalBody: JSON.stringify(receipt),
      receiptDigest: await deriveCommandReceiptDigest(receipt),
    };
  } finally {
    wrapKey?.fill(0);
    randomness.dek.fill(0);
    plaintext?.fill(0);
  }
}

async function validateExecution(execution: CommandReceiptExecution): Promise<{
  command: PersistedCommandExecutionV4['originalEncryptedCommand'];
  terminalResult: CommandResult;
  pinReference: PersistedCommandPinReferenceV1;
}> {
  assertExactOwnDataKeys(execution, [
    'version', 'originalEncryptedCommand', 'commandDigest', 'pinReference', 'watchDeviceId', 'nonce', 'expiresAt',
    'state', 'claimedAt', 'dispatchStartedAt', 'terminalResult',
  ], ['version', 'originalEncryptedCommand', 'commandDigest', 'pinReference', 'watchDeviceId', 'nonce', 'expiresAt',
    'state', 'claimedAt', 'terminalResult']);
  const command = execution.originalEncryptedCommand;
  const terminalResult = execution.terminalResult;
  const pinReference = execution.pinReference;
  if (execution.version !== 1
    || (execution.state !== 'claimed' && execution.state !== 'dispatch_started'
      && execution.state !== 'terminal_receipt_blocked')
    || !isCanonicalTimestamp(execution.claimedAt)
    || (execution.dispatchStartedAt !== undefined && !isCanonicalTimestamp(execution.dispatchStartedAt))
    || !validateEncryptedCommandEnvelopeV1(command)
    || !validateCommandResult(terminalResult)) {
    throw new TypeError('command receipt execution is invalid');
  }
  assertPinReference(pinReference);
  const digest = await deriveEncryptedCommandDigest(command);
  if (digest !== execution.commandDigest
    || execution.watchDeviceId !== command.watchDeviceId
    || execution.nonce !== command.nonce
    || execution.expiresAt !== command.expiresAt
    || terminalResult.commandId !== command.commandId
    || terminalResult.hostId !== command.hostId
    || terminalResult.sessionId !== command.sessionId
    || pinReference.linkId !== command.linkId
    || pinReference.linkGeneration !== command.linkGeneration
    || pinReference.epoch !== command.epoch
    || pinReference.watchEncryptionKeyId !== command.payload.keyWrap.senderEncryptionKeyId
    || pinReference.hostEncryptionKeyId !== command.payload.keyWrap.recipientEncryptionKeyId) {
    throw new TypeError('command receipt execution binding is invalid');
  }
  return { command, terminalResult, pinReference };
}

async function resolveExactPinMaterial(
  command: PersistedCommandExecutionV4['originalEncryptedCommand'],
  reference: PersistedCommandPinReferenceV1,
  keyring: LocalLinkKeyring,
) {
  const material = keyring.resolvePinMaterial(reference.linkId, reference.linkGeneration, reference.epoch);
  const { pin, hostIdentity, watchBinding } = material;
  if ((pin.status !== 'active' && pin.status !== 'retiring')
    || (pin.status === 'retiring' && (!pin.retiringAt || command.issuedAt >= pin.retiringAt))
    || pin.hostId !== command.hostId
    || pin.watchDeviceId !== command.watchDeviceId
    || pin.transcriptDigest !== reference.transcriptDigest
    || pin.hostBinding.encryptionKeyId !== reference.hostEncryptionKeyId
    || pin.watchBinding.encryptionKeyId !== reference.watchEncryptionKeyId
    || hostIdentity.encryptionKeyId !== reference.hostEncryptionKeyId
    || watchBinding.encryptionKeyId !== reference.watchEncryptionKeyId) {
    throw new TypeError('command receipt pin binding is unavailable');
  }
  importHostEncryptionPrivateKey(hostIdentity);
  if (deriveHostEncryptionKeyId(watchBinding.publicKey) !== watchBinding.encryptionKeyId) {
    throw new TypeError('command receipt Watch key binding is invalid');
  }
  const hostBindingDigest = await bindingDigest(pin.hostBinding);
  const watchBindingDigest = await bindingDigest(pin.watchBinding);
  const transcriptDigest = await contentSha256(buildLinkTranscriptBytes({
    linkId: pin.linkId,
    hostId: pin.hostId,
    watchDeviceId: pin.watchDeviceId,
    linkGeneration: pin.linkGeneration,
    epoch: pin.epoch,
    hostBindingDigest,
    watchBindingDigest,
  }));
  if (pin.hostBindingDigest !== hostBindingDigest
    || pin.watchBindingDigest !== watchBindingDigest
    || pin.transcriptDigest !== transcriptDigest) {
    throw new TypeError('command receipt pin transcript is invalid');
  }
  return material;
}

function deriveReceiptWrapKey(pin: ActiveLinkPinV2, hostPrivateKey: Uint8Array): Uint8Array {
  const shared = x25519SharedSecret(hostPrivateKey, base64UrlDecode(pin.watchBinding.publicKey, 32, 'Watch public key'));
  const salt = base64UrlDecode(pin.transcriptDigest, E2E_LIMITS.digestBytes, 'link transcript digest');
  let root: Uint8Array | undefined;
  try {
    root = hkdfSha256(shared, salt, pairRootInfo(pin.linkId, pin.linkGeneration, pin.epoch));
    return hkdfSha256(root, salt, encoder.encode('ariava:e2e:v1:wrap:bridge-to-watch'));
  } finally {
    shared.fill(0);
    root?.fill(0);
    salt.fill(0);
  }
}

async function bindingDigest(binding: EncryptionKeyBindingV1): Promise<string> {
  if (!validateEncryptionKeyBindingV1(binding)) throw new TypeError('command receipt encryption binding is invalid');
  const { bindingSignature: _bindingSignature, ...unsigned } = binding;
  return contentSha256(buildEncryptionBindingBytes(unsigned));
}

function assertPinReference(reference: PersistedCommandPinReferenceV1): void {
  assertExactOwnDataKeys(reference, [
    'version', 'linkId', 'linkGeneration', 'epoch', 'transcriptDigest', 'hostEncryptionKeyId', 'watchEncryptionKeyId',
  ], ['version', 'linkId', 'linkGeneration', 'epoch', 'transcriptDigest', 'hostEncryptionKeyId', 'watchEncryptionKeyId']);
  if (reference.version !== 1
    || !Number.isSafeInteger(reference.linkGeneration) || reference.linkGeneration < 1
    || !Number.isSafeInteger(reference.epoch) || reference.epoch < 1) {
    throw new TypeError('command receipt pin reference is invalid');
  }
  base64UrlDecode(reference.transcriptDigest, E2E_LIMITS.digestBytes, 'link transcript digest');
  if (!/^ekey_[A-Za-z0-9_-]{43}$/u.test(reference.hostEncryptionKeyId)
    || !/^ekey_[A-Za-z0-9_-]{43}$/u.test(reference.watchEncryptionKeyId)) {
    throw new TypeError('command receipt pin reference is invalid');
  }
}

function assertRandomness(randomness: CommandReceiptRandomness): void {
  assertExactOwnDataKeys(randomness, ['contentId', 'dek', 'contentNonce', 'wrapNonce'],
    ['contentId', 'dek', 'contentNonce', 'wrapNonce']);
  if (typeof randomness.contentId !== 'string' || encoder.encode(randomness.contentId).byteLength < 1
    || encoder.encode(randomness.contentId).byteLength > 256
    || !(randomness.dek instanceof Uint8Array) || randomness.dek.byteLength !== 32
    || !(randomness.contentNonce instanceof Uint8Array) || randomness.contentNonce.byteLength !== E2E_LIMITS.nonceBytes
    || !(randomness.wrapNonce instanceof Uint8Array) || randomness.wrapNonce.byteLength !== E2E_LIMITS.nonceBytes) {
    throw new TypeError('command receipt randomness is invalid');
  }
}

function productionRandomness(): CommandReceiptRandomness {
  return {
    contentId: randomUUID(),
    dek: new Uint8Array(randomBytes(32)),
    contentNonce: new Uint8Array(randomBytes(E2E_LIMITS.nonceBytes)),
    wrapNonce: new Uint8Array(randomBytes(E2E_LIMITS.nonceBytes)),
  };
}

function assertExactOwnDataKeys(
  value: object,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
): void {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('command receipt input is invalid');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('command receipt input is invalid');
  const allowed = new Set(allowedKeys);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.has(key)) throw new TypeError('command receipt input is invalid');
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!descriptor.enumerable || !('value' in descriptor)) throw new TypeError('command receipt input is invalid');
  }
  for (const key of requiredKeys) if (!Object.hasOwn(value, key)) throw new TypeError('command receipt input is invalid');
  for (const key of allowedKeys) {
    if (!Object.hasOwn(value, key) && key in value) throw new TypeError('command receipt input is invalid');
  }
}
