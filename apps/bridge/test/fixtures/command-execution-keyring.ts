import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  E2E_SUITE_V1,
  base64UrlDecode,
  base64UrlEncode,
  buildEncryptionBindingBytes,
  buildInterruptContentAAD,
  buildLinkTranscriptBytes,
  buildProtectedInterruptContentBytes,
  buildProtectedReplyContentBytes,
  buildReplyContentAAD,
  buildWrapAAD,
  contentSha256,
  type EncryptedCommandEnvelopeV1,
  type EncryptionKeyBindingV1,
} from '@ariava/protocol';
import type { HostEncryptionIdentity } from '../../src/identity';
import { chachaPolySeal } from '../../src/e2e/node-crypto';
import { LocalLinkKeyring, type ActiveLinkPinV2, type LocalPinStatus } from '../../src/e2e/link-keyring';
import fixture from '../../../../packages/protocol/test/fixtures/command-e2e-v1-vectors.json';

const FIXED_NOW = Date.parse('2026-08-12T00:01:00.000Z');

export interface DeterministicCommandKeyringHarness {
  keyring: LocalLinkKeyring;
  interrupt: EncryptedCommandEnvelopeV1;
  reply: EncryptedCommandEnvelopeV1;
  pin: ActiveLinkPinV2;
  historicalHost: HostEncryptionIdentity;
  globalCurrentHost: HostEncryptionIdentity;
  replaceHistoricalIdentity(identity: HostEncryptionIdentity | null): void;
  mutateRuntimePin(mutate: (pin: ActiveLinkPinV2) => void): void;
}

export async function createDeterministicCommandKeyringHarness(
  path: string,
  status: LocalPinStatus = 'active',
): Promise<DeterministicCommandKeyringHarness> {
  const material = await deterministicCommandKeyringMaterial(status);
  const { historicalHost, globalCurrentHost, pin } = material;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify({ version: 2, pins: [pin], pendingActivations: [] })}\n`, { mode: 0o600 });
  const identities = new Map<string, HostEncryptionIdentity>([
    [historicalHost.encryptionKeyId, historicalHost],
    [globalCurrentHost.encryptionKeyId, globalCurrentHost],
  ]);
  const keyring = new LocalLinkKeyring(path, {
    load: () => globalCurrentHost,
    identity: (keyId) => identities.get(keyId) ?? null,
  });
  return {
    keyring,
    interrupt: await createDeterministicEncryptedCommand('interrupt'),
    reply: await createDeterministicEncryptedCommand('reply'),
    pin,
    historicalHost,
    globalCurrentHost,
    replaceHistoricalIdentity: (identity) => {
      if (identity) identities.set(historicalHost.encryptionKeyId, identity);
      else identities.delete(historicalHost.encryptionKeyId);
    },
    mutateRuntimePin: (mutate) => {
      const runtimePin = (keyring as unknown as { pins: ActiveLinkPinV2[] }).pins[0];
      if (!runtimePin) throw new Error('deterministic command pin is unavailable');
      mutate(runtimePin);
    },
  };
}

export async function deterministicCommandKeyringMaterial(status: LocalPinStatus = 'active'): Promise<{
  pin: ActiveLinkPinV2;
  historicalHost: HostEncryptionIdentity;
  globalCurrentHost: HostEncryptionIdentity;
  hostBinding: EncryptionKeyBindingV1;
  watchBinding: EncryptionKeyBindingV1;
}> {
  const hostBinding = binding(fixture.bindings.host);
  const watchBinding = binding(fixture.bindings.watch);
  const hostBindingDigest = await bindingDigest(hostBinding);
  const watchBindingDigest = await bindingDigest(watchBinding);
  const transcriptDigest = await contentSha256(buildLinkTranscriptBytes({
    ...fixture.link, hostBindingDigest, watchBindingDigest,
  }));
  const historicalHost = hostIdentity(
    fixture.keys.hostPrivateKeyPkcs8, fixture.keys.hostPublicKey, fixture.bindings.host.encryptionKeyId,
    fixture.bindings.host.sequence, fixture.bindings.host.createdAt,
  );
  const globalCurrentHost = hostIdentity(
    fixture.keys.watchPrivateKeyPkcs8, fixture.keys.watchPublicKey, fixture.bindings.watch.encryptionKeyId,
    2, '2026-08-12T00:00:30.000Z',
  );
  const pin: ActiveLinkPinV2 = {
    version: 2, status, ...fixture.link, transcriptDigest, hostBinding, hostBindingDigest, watchBinding, watchBindingDigest,
    peerProofDigest: base64UrlEncode(new Uint8Array(32).fill(7)), activatedAt: '2026-08-12T00:00:00.000Z',
    ...(status === 'retiring' ? { retiringAt: '2026-08-12T00:03:00.000Z' } : {}),
  };
  return { pin, historicalHost, globalCurrentHost, hostBinding, watchBinding };
}

export async function withDeterministicCommandTime<T>(operation: () => Promise<T>): Promise<T> {
  const originalNow = Date.now;
  Date.now = () => FIXED_NOW;
  try {
    return await operation();
  } finally {
    Date.now = originalNow;
  }
}

export async function createDeterministicEncryptedCommand(
  type: 'reply' | 'interrupt',
  timing: { issuedAt?: string; expiresAt?: string } = {},
): Promise<EncryptedCommandEnvelopeV1> {
  const base = {
    commandId: `command_${type}_vector_01`,
    hostId: fixture.link.hostId,
    sessionId: 'session_command_vector_01',
    type,
    ...(type === 'reply' ? { targetAlertEventId: 'event_reply_vector_01' } : {}),
    issuedAt: timing.issuedAt ?? '2026-08-12T00:00:00.000Z',
    expiresAt: timing.expiresAt ?? '2026-08-12T00:05:00.000Z',
    nonce: `nonce_${type}_vector_01`,
    watchDeviceId: fixture.link.watchDeviceId,
    linkId: fixture.link.linkId,
    linkGeneration: fixture.link.linkGeneration,
    epoch: fixture.link.epoch,
  };
  const contentId = `content_${type}_vector_01`;
  const payloadKind = type === 'reply' ? 'reply-content-v1' as const : 'interrupt-content-v1' as const;
  const dek = base64UrlDecode(fixture.interrupt.dek, 32);
  const plaintext = type === 'reply'
    ? buildProtectedReplyContentBytes({ version: 1, text: 'continue safely' })
    : buildProtectedInterruptContentBytes({ version: 1, action: 'interrupt' });
  const contentAAD = type === 'reply'
    ? buildReplyContentAAD({ ...base, type: 'reply', targetAlertEventId: 'event_reply_vector_01', contentId })
    : buildInterruptContentAAD({ ...base, type: 'interrupt', contentId });
  const content = chachaPolySeal(
    dek, plaintext, contentAAD,
    type === 'reply'
      ? new Uint8Array([41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52])
      : new Uint8Array([33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44]),
  );
  const wrapKey = base64UrlDecode(fixture.keys.watchToBridgeWrapKey, 32);
  const wrap = chachaPolySeal(
    wrapKey,
    dek,
    buildWrapAAD({
      direction: 'watch-to-bridge',
      ...fixture.link,
      senderEncryptionKeyId: fixture.bindings.watch.encryptionKeyId,
      recipientEncryptionKeyId: fixture.bindings.host.encryptionKeyId,
      contentId,
      payloadKind,
    }),
    type === 'reply'
      ? new Uint8Array([61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72])
      : new Uint8Array([45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56]),
  );
  plaintext.fill(0);
  dek.fill(0);
  wrapKey.fill(0);
  return {
    ...base,
    payload: {
      content: {
        version: 1,
        suite: E2E_SUITE_V1,
        contentId,
        payloadKind,
        nonce: base64UrlEncode(content.nonce),
        ciphertext: base64UrlEncode(content.ciphertext),
      },
      keyWrap: {
        version: 1,
        suite: E2E_SUITE_V1,
        contentId,
        linkId: fixture.link.linkId,
        linkGeneration: fixture.link.linkGeneration,
        epoch: fixture.link.epoch,
        senderEncryptionKeyId: fixture.bindings.watch.encryptionKeyId,
        recipientEncryptionKeyId: fixture.bindings.host.encryptionKeyId,
        nonce: base64UrlEncode(wrap.nonce),
        ciphertext: base64UrlEncode(wrap.ciphertext),
      },
    },
  } as EncryptedCommandEnvelopeV1;
}

function hostIdentity(
  privateKeyPkcs8: string,
  publicKey: string,
  encryptionKeyId: string,
  sequence: number,
  createdAt: string,
): HostEncryptionIdentity {
  return {
    version: 1,
    hostId: fixture.link.hostId,
    encryptionKeyId,
    publicKey,
    privateKeyPkcs8: base64UrlDecode(privateKeyPkcs8),
    sequence,
    createdAt,
  };
}

function binding(value: typeof fixture.bindings.host | typeof fixture.bindings.watch): EncryptionKeyBindingV1 {
  const { canonicalBytes: _canonicalBytes, ...result } = value;
  return result as EncryptionKeyBindingV1;
}

async function bindingDigest(value: EncryptionKeyBindingV1): Promise<string> {
  const { bindingSignature: _bindingSignature, ...unsigned } = value;
  return contentSha256(buildEncryptionBindingBytes(unsigned));
}


export function tamperCiphertext(
  command: EncryptedCommandEnvelopeV1,
  target: 'content' | 'wrap',
): EncryptedCommandEnvelopeV1 {
  const tampered = structuredClone(command);
  const encrypted = target === 'content' ? tampered.payload.content : tampered.payload.keyWrap;
  const ciphertext = base64UrlDecode(encrypted.ciphertext);
  ciphertext[0] = ciphertext[0]! ^ 1;
  encrypted.ciphertext = base64UrlEncode(ciphertext);
  return tampered;
}
