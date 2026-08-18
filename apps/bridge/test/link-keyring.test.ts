import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  base64UrlEncode,
  buildEncryptionBindingBytes,
  buildLinkTranscriptBytes,
  deriveEntityIdentity,
  E2E_SUITE_V1,
  type EncryptionKeyBindingV1,
} from '@ariava/protocol';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createHostEncryptionBinding, generateHostEncryptionIdentity } from '../src/identity';
import { generateHostIdentity } from '../src/identity/host-identity';
import { LocalLinkKeyring, verifyBindingWithIdentityPublicKey } from '../src/e2e/link-keyring';

const roots: string[] = [];
afterEach(() => roots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true })));

function root(name: string): string {
  const value = join(tmpdir(), `ariava-${name}-${crypto.randomUUID()}`);
  roots.push(value);
  mkdirSync(value, { mode: 0o700 });
  return value;
}

describe('verified local E2E pins', () => {
  test('persists schema v2 with immutable full Host/Watch bindings and actual Host key references', () => {
    const path = join(root('keyring-v2'), 'pins.json');
    const hostId = `host_${'H'.repeat(43)}`;
    const firstHost = generateHostEncryptionIdentity(hostId, 1, '2026-07-20T00:00:00.000Z');
    const secondHost = generateHostEncryptionIdentity(hostId, 2, '2026-07-20T00:01:00.000Z');
    const identities = new Map([[firstHost.encryptionKeyId, firstHost], [secondHost.encryptionKeyId, secondHost]]);
    const keyring = new LocalLinkKeyring(path, {
      load: () => secondHost,
      identity: (keyId) => identities.get(keyId) ?? null,
    });
    const first = pin(firstHost, 'old', 1, 1);
    keyring.persistActive(first);
    keyring.persistActive(pin(secondHost, 'current', 1, 2));

    const persisted = JSON.parse(readFileSync(path, 'utf8'));
    expect(persisted.version).toBe(2);
    expect(persisted.pins[0].version).toBe(2);
    expect(persisted.pins[0].hostBinding.encryptionKeyId).toBe(firstHost.encryptionKeyId);
    expect(keyring.referencedHostEncryptionKeyIds()).toEqual(new Set([firstHost.encryptionKeyId, secondHost.encryptionKeyId]));
    expect(keyring.resolvePinMaterial('old', 1, 1).hostIdentity.encryptionKeyId).toBe(firstHost.encryptionKeyId);
    expect(() => keyring.persistActive({ ...keyring.listActive()[0]!, hostBinding: first.hostBinding })).toThrow();
  });

  test('migrates exact v1 only with a matching verified current Host identity and signed binding', async () => {
    const dir = root('keyring-v1');
    const path = join(dir, 'pins.json');
    const signing = await generateHostIdentity({ type: 'linux-json', path: join(dir, 'identity.json') }, '2026-07-20T00:00:00.000Z');
    const host = generateHostEncryptionIdentity(signing.identity.hostId);
    const hostBinding = await createHostEncryptionBinding(signing.identity, host);
    const watchDeviceId = `watch_${'W'.repeat(43)}`;
    const watchBinding = fakeWatchBinding(watchDeviceId, 1);
    const hostBindingDigest = bindingDigest(hostBinding);
    const watchBindingDigest = bindingDigest(watchBinding);
    const legacyPin = {
      version: 1, status: 'active', linkId: 'legacy', hostId: host.hostId, watchDeviceId,
      linkGeneration: 1, epoch: 1,
      transcriptDigest: transcriptDigest('legacy', host.hostId, watchDeviceId, 1, 1, hostBindingDigest, watchBindingDigest),
      watchBinding, watchBindingDigest, peerProofDigest: digest(3), activatedAt: '2026-07-20T00:00:00.000Z',
    };
    writeFileSync(path, `${JSON.stringify({ version: 1, pins: [legacyPin], pendingActivations: [] })}\n`, { mode: 0o600 });
    const migrationContext = { currentHostIdentity: signing.identity, signedCurrentHostBinding: hostBinding };
    expect(() => new LocalLinkKeyring(path, host)).toThrow(/migration/i);

    const migrated = new LocalLinkKeyring(path, host, migrationContext);
    expect(migrated.listActive()[0]?.hostBinding).toEqual(hostBinding);
    expect(JSON.parse(readFileSync(path, 'utf8')).version).toBe(2);

    const legacy = { version: 1, pins: [legacyPin], pendingActivations: [] };
    const resetLegacy = () => writeFileSync(path, `${JSON.stringify(legacy)}\n`, { mode: 0o600 });
    const expectMigrationFailure = (context: typeof migrationContext) => {
      resetLegacy();
      expect(() => new LocalLinkKeyring(path, host, context)).toThrow(/migration binding/i);
    };
    expectMigrationFailure({ ...migrationContext, signedCurrentHostBinding: { ...hostBinding, bindingSignature: digest(9) } });
    const wrongSigner = await generateHostIdentity({ type: 'linux-json', path: join(dir, 'wrong.json') });
    const { bindingSignature: _signature, ...unsigned } = hostBinding;
    expectMigrationFailure({ ...migrationContext, signedCurrentHostBinding: {
      ...unsigned, bindingSignature: await wrongSigner.identity.signer.sign(buildEncryptionBindingBytes(unsigned)),
    } });
    expectMigrationFailure({ ...migrationContext, signedCurrentHostBinding: { ...hostBinding, identityKeyId: wrongSigner.identity.keyId } });

    writeFileSync(path, `${JSON.stringify({ version: 1, pins: [{ ...legacyPin, hostId: `host_${'X'.repeat(43)}` }], pendingActivations: [] })}\n`, { mode: 0o600 });
    expect(() => new LocalLinkKeyring(path, host, migrationContext)).toThrow();
  });

  test.each([
    'contentRetainedThrough', 'commandRetainedThrough', 'executionRetainedThrough',
    'terminalReceiptRetainedThrough', 'pendingOutboxRetainedThrough', 'undeliverableOutboxRetainedThrough',
  ] as const)('retains a retiring pin for an independent %s reference', (category) => {
    const path = join(root(`retention-${category}`), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(path, host);
    keyring.persistActive(pin(host, 'retained', 1, 1));
    keyring.persistActive(pin(host, 'current', 1, 2));
    const refs = { [category]: { 'retained:1:1': '2026-07-20T00:15:00.000Z' } };
    expect(keyring.pruneRetiring(refs, '2026-07-20T00:14:59.999Z')).toEqual([]);
    expect(keyring.pruneRetiring(refs, '2026-07-20T00:15:00.001Z')).toHaveLength(1);
  });

  test('rejects malformed retention timestamps without mutating persisted pins', () => {
    const path = join(root('retention-invalid'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(path, host);
    keyring.persistActive(pin(host, 'retained', 1, 1));
    keyring.persistActive(pin(host, 'current', 1, 2));
    const before = readFileSync(path);
    expect(() => keyring.pruneRetiring({ commandRetainedThrough: { 'retained:1:1': '2026-07-20' } })).toThrow(/retention/);
    expect(readFileSync(path)).toEqual(before);
  });

  test('retains revoked and pending key references until their exact records are safely deleted', () => {
    const path = join(root('revoked-pending-retention'), 'pins.json');
    const hostId = `host_${'H'.repeat(43)}`;
    const first = generateHostEncryptionIdentity(hostId, 1);
    const second = generateHostEncryptionIdentity(hostId, 2);
    const identities = new Map([[first.encryptionKeyId, first], [second.encryptionKeyId, second]]);
    const keyring = new LocalLinkKeyring(path, { load: () => second, identity: (id) => identities.get(id) ?? null });
    keyring.persistActive(pin(first, 'revoked', 1, 1));
    keyring.revokeCompromisedEncryptionKey(first.encryptionKeyId);
    const pendingPin = pin(first, 'pending', 2, 1);
    keyring.stageActivation({ version: 2, linkId: pendingPin.linkId, linkGeneration: pendingPin.linkGeneration,
      epoch: pendingPin.epoch, peerProofDigest: pendingPin.peerProofDigest, activatedAt: pendingPin.activatedAt, pin: pendingPin });
    expect(keyring.referencedHostEncryptionKeyIds()).toEqual(new Set([first.encryptionKeyId]));
    expect(keyring.pruneRetiring({ undeliverableOutboxRetainedThrough: {
      'revoked:1:1': '2026-07-20T00:15:00.000Z',
    } }, '2026-07-20T00:14:00.000Z')).toEqual([]);
    expect(keyring.referencedHostEncryptionKeyIds()).toEqual(new Set([first.encryptionKeyId]));
    expect(keyring.pruneRetiring({ undeliverableOutboxRetainedThrough: {
      'revoked:1:1': '2026-07-20T00:15:00.000Z',
    } }, '2026-07-20T00:15:00.001Z').map((item) => item.linkId)).toEqual(['revoked']);
    expect(keyring.referencedHostEncryptionKeyIds()).toEqual(new Set([first.encryptionKeyId]));
  });

  test('prunes mixed historical keys only after each exact pin record loses all references', () => {
    const path = join(root('mixed-key-retention'), 'pins.json');
    const hostId = `host_${'H'.repeat(43)}`;
    const first = generateHostEncryptionIdentity(hostId, 1);
    const second = generateHostEncryptionIdentity(hostId, 2);
    const third = generateHostEncryptionIdentity(hostId, 3);
    const identities = new Map([first, second, third].map((identity) => [identity.encryptionKeyId, identity]));
    const pruneCalls: Set<string>[] = [];
    const keyring = new LocalLinkKeyring(path, { load: () => third, identity: (id) => identities.get(id) ?? null,
      prune: (ids) => { pruneCalls.push(new Set(ids)); return []; } });
    keyring.persistActive(pin(first, 'first', 1, 1));
    keyring.persistActive(pin(second, 'second', 1, 2));
    keyring.persistActive(pin(third, 'third', 1, 3));
    expect(keyring.pruneRetiring({ commandRetainedThrough: { 'first:1:1': '2026-07-20T00:10:00.000Z' } },
      '2026-07-20T00:09:00.000Z').map((item) => item.linkId)).toEqual(['second']);
    expect(pruneCalls.at(-1)).toEqual(new Set([first.encryptionKeyId, third.encryptionKeyId]));
  });

  test('retains retiring pins through every content, command, execution, and receipt reference', () => {
    const path = join(root('retention'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(path, host);
    keyring.persistActive(pin(host, 'retained', 1, 1));
    keyring.persistActive(pin(host, 'current', 1, 2));
    const key = 'retained:1:1';
    const refs = {
      contentRetainedThrough: { [key]: '2026-07-20T00:10:00.000Z' },
      commandRetainedThrough: { [key]: '2026-07-20T00:11:00.000Z' },
      executionRetainedThrough: { [key]: '2026-07-20T00:12:00.000Z' },
      terminalReceiptRetainedThrough: { [key]: '2026-07-20T00:13:00.000Z' },
      pendingOutboxRetainedThrough: { [key]: '2026-07-20T00:14:00.000Z' },
      undeliverableOutboxRetainedThrough: { [key]: '2026-07-20T00:15:00.000Z' },
    };
    expect(keyring.pruneRetiring(refs, '2026-07-20T00:14:59.999Z')).toEqual([]);
    expect(keyring.pruneRetiring(refs, '2026-07-20T00:15:00.001Z')).toHaveLength(1);
    const third = pin(host, 'third', 1, 3);
    keyring.persistActive(third);
    expect(keyring.pruneRetiring({}, '2026-07-20T00:16:00.000Z')).toHaveLength(1);
  });

  test('scopes compromise revocation to pins bound to that exact Host key', () => {
    const path = join(root('revoke'), 'pins.json');
    const hostId = `host_${'H'.repeat(43)}`;
    const first = generateHostEncryptionIdentity(hostId, 1);
    const second = generateHostEncryptionIdentity(hostId, 2);
    const identities = new Map([[first.encryptionKeyId, first], [second.encryptionKeyId, second]]);
    const keyring = new LocalLinkKeyring(path, { load: () => second, identity: (id) => identities.get(id) ?? null });
    keyring.persistActive(pin(first, 'first', 1, 1));
    keyring.persistActive(pin(second, 'second', 2, 1));
    expect(keyring.revokeCompromisedEncryptionKey(first.encryptionKeyId)).toBe(1);
    expect(keyring.getUsable('first', 1, 1)).toBeUndefined();
    expect(keyring.getUsable('second', 2, 1)).toBeDefined();
  });

  test('recipient reconciliation observes an activation persisted by another keyring instance', () => {
    const path = join(root('snapshot-stale-instance'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const daemonKeyring = new LocalLinkKeyring(path, host);
    const pairingKeyring = new LocalLinkKeyring(path, host);
    const activated = pin(host, 'paired-after-daemon-start', 1, 1);
    pairingKeyring.persistActive(activated);

    const recipients = daemonKeyring.reconcileRecipients({
      hostId: host.hostId, recipientSetVersion: 1, recipients: [recipient(activated)],
    });

    expect(recipients).toHaveLength(1);
    expect(recipients[0]).toMatchObject({
      linkId: activated.linkId, watchDeviceId: activated.watchDeviceId,
      transcriptDigest: activated.transcriptDigest,
    });
    expect(daemonKeyring.listActive()).toEqual([activated]);
  });

  test('recipient reconciliation never overwrites an activation persisted after an older snapshot was fetched', () => {
    const path = join(root('snapshot-write-race'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const daemonKeyring = new LocalLinkKeyring(path, host);
    const oldPin = pin(host, 'old-before-pairing', 1, 1);
    daemonKeyring.persistActive(oldPin);
    const staleSnapshot = { hostId: host.hostId, recipientSetVersion: 1, recipients: [] };
    const activated = pin(host, 'paired-after-snapshot', 2, 1);
    new LocalLinkKeyring(path, host).persistActive(activated);

    expect(() => daemonKeyring.reconcileRecipients(staleSnapshot)).toThrow(/predates/);
    const reloaded = new LocalLinkKeyring(path, host);
    expect(reloaded.listActive()).toEqual([activated]);
    expect(reloaded.listRetiring().map((item) => item.linkId)).toEqual([oldPin.linkId]);
  });

  test('recipient refresh rejects a snapshot that omits a later durable activation', () => {
    const path = join(root('snapshot-refresh-race'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const daemonKeyring = new LocalLinkKeyring(path, host);
    const firstWatch = pin(host, 'first-after-daemon-start', 1, 1);
    const secondWatch = pin(host, 'second-after-snapshot', 1, 1, `watch_${'S'.repeat(43)}`);
    const writer = new LocalLinkKeyring(path, host);
    writer.persistActive(firstWatch);
    const staleSnapshot = {
      hostId: host.hostId, recipientSetVersion: 1, recipients: [recipient(firstWatch)],
    };
    writer.persistActive(secondWatch);

    expect(() => daemonKeyring.reconcileRecipients(staleSnapshot)).toThrow(/predates/);
    const reloaded = new LocalLinkKeyring(path, host);
    expect(reloaded.listActive().map((item) => item.linkId).sort()).toEqual(
      [firstWatch.linkId, secondWatch.linkId].sort(),
    );
  });

  test('authoritative snapshots preserve retiring history only for a confirmed same-Watch successor', () => {
    const path = join(root('snapshot-reconciliation'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(path, host);
    const disappeared = pin(host, 'disappeared', 1, 1);
    keyring.persistActive(disappeared);

    expect(keyring.reconcileRecipients({
      hostId: host.hostId, recipientSetVersion: 1, recipients: [],
    })).toEqual([]);
    expect(keyring.getUsable(disappeared.linkId, disappeared.linkGeneration, disappeared.epoch)).toBeUndefined();
    expect(JSON.parse(readFileSync(path, 'utf8')).pins[0]).toMatchObject({
      linkId: disappeared.linkId, status: 'revoked',
    });

    const successor = pin(host, 'successor', 2, 1);
    keyring.persistActive(successor);
    expect(keyring.reconcileRecipients({
      hostId: host.hostId, recipientSetVersion: 2, recipients: [recipient(successor)],
    })).toHaveLength(1);

    const rotated = pin(host, 'rotated', 3, 1);
    keyring.persistActive(rotated);
    const retiring = keyring.listRetiring().find((item) => item.linkId === successor.linkId)!;
    const reference = {
      linkId: retiring.linkId, linkGeneration: retiring.linkGeneration, epoch: retiring.epoch,
      transcriptDigest: retiring.transcriptDigest, hostEncryptionKeyId: retiring.hostBinding.encryptionKeyId,
      watchEncryptionKeyId: retiring.watchBinding.encryptionKeyId,
    };
    keyring.reconcileRecipients({
      hostId: host.hostId, recipientSetVersion: 3, recipients: [recipient(rotated)],
    });
    expect(keyring.resolveCommandReceiptPinStatus(reference, timestampBefore(retiring.retiringAt!))).toBe('deliverable');
    expect(keyring.resolveCommandReceiptPinStatus(reference, retiring.retiringAt!)).toBe('unavailable');

    const otherWatch = pin(host, 'other-watch', 1, 1, `watch_${'O'.repeat(43)}`);
    keyring.persistActive(otherWatch);
    keyring.reconcileRecipients({
      hostId: host.hostId, recipientSetVersion: 4, recipients: [recipient(otherWatch)],
    });
    expect(keyring.getUsable(successor.linkId, successor.linkGeneration, successor.epoch)).toBeUndefined();
    expect(keyring.getUsable(rotated.linkId, rotated.linkGeneration, rotated.epoch)).toBeUndefined();
    expect(keyring.listActive().map((item) => item.linkId)).toEqual(['other-watch']);
    expect(keyring.listRetiring()).toEqual([]);
  });

  test('explicit Watch revoke makes every matching active or retiring pin unusable without retargeting', () => {
    const path = join(root('explicit-watch-revoke'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(path, host);
    const oldPin = pin(host, 'old-watch-link', 1, 1);
    const currentPin = pin(host, 'current-watch-link', 2, 1);
    keyring.persistActive(oldPin);
    keyring.persistActive(currentPin);

    keyring.revokeWatch(currentPin.watchDeviceId);

    expect(keyring.listActive()).toEqual([]);
    expect(keyring.listRetiring()).toEqual([]);
    expect(keyring.getUsable(oldPin.linkId, oldPin.linkGeneration, oldPin.epoch)).toBeUndefined();
    expect(keyring.getUsable(currentPin.linkId, currentPin.linkGeneration, currentPin.epoch)).toBeUndefined();
    const persisted = JSON.parse(readFileSync(path, 'utf8')).pins;
    expect(persisted.map((item: any) => ({
      linkId: item.linkId, status: item.status, retiringAt: item.retiringAt,
    }))).toEqual([
      { linkId: oldPin.linkId, status: 'revoked', retiringAt: undefined },
      { linkId: currentPin.linkId, status: 'revoked', retiringAt: undefined },
    ]);
  });

  test('delayed generation revoke reloads durable N+1 state and preserves its active and pending records', () => {
    const path = join(root('generation-revoke-race'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const delayedGenerationOne = new LocalLinkKeyring(path, host);
    const generationOne = pin(host, 'generation-one', 1, 1);
    delayedGenerationOne.persistActive(generationOne);

    const concurrentGenerationTwo = new LocalLinkKeyring(path, host);
    const generationTwo = pin(host, 'generation-two', 2, 1);
    concurrentGenerationTwo.persistActive(generationTwo);
    const pendingGenerationTwo = pin(host, 'generation-two-pending', 2, 2);
    concurrentGenerationTwo.stageActivation({
      version: 2, linkId: pendingGenerationTwo.linkId, linkGeneration: pendingGenerationTwo.linkGeneration,
      epoch: pendingGenerationTwo.epoch, peerProofDigest: pendingGenerationTwo.peerProofDigest,
      activatedAt: pendingGenerationTwo.activatedAt, pin: pendingGenerationTwo,
    });

    delayedGenerationOne.revokeWatchGeneration(generationOne.watchDeviceId, generationOne.linkGeneration);

    const reloaded = new LocalLinkKeyring(path, host);
    expect(reloaded.getUsable(generationOne.linkId, generationOne.linkGeneration, generationOne.epoch)).toBeUndefined();
    expect(reloaded.getUsable(generationTwo.linkId, generationTwo.linkGeneration, generationTwo.epoch)).toEqual(generationTwo);
    expect(reloaded.pendingActivation(
      pendingGenerationTwo.linkId, pendingGenerationTwo.linkGeneration, pendingGenerationTwo.epoch,
    )?.pin).toEqual(pendingGenerationTwo);
    expect(JSON.parse(readFileSync(path, 'utf8')).pins.map((item: any) => ({
      linkId: item.linkId, generation: item.linkGeneration, status: item.status,
    }))).toEqual([
      { linkId: generationOne.linkId, generation: 1, status: 'revoked' },
      { linkId: generationTwo.linkId, generation: 2, status: 'active' },
    ]);
  });

  test('prunes a historical private key only after its last pin reference is durably removed', () => {
    const path = join(root('pin-key-prune'), 'pins.json');
    const hostId = `host_${'H'.repeat(43)}`;
    const first = generateHostEncryptionIdentity(hostId, 1, '2026-07-20T00:00:00.000Z');
    const second = generateHostEncryptionIdentity(hostId, 2, '2026-07-20T00:01:00.000Z');
    const identities = new Map([[first.encryptionKeyId, first], [second.encryptionKeyId, second]]);
    const pruneCalls: Set<string>[] = [];
    const keyring = new LocalLinkKeyring(path, {
      load: () => second,
      identity: (id) => identities.get(id) ?? null,
      prune: (referenced) => {
        pruneCalls.push(new Set(referenced));
        for (const id of [...identities.keys()]) if (id !== second.encryptionKeyId && !referenced.has(id)) identities.delete(id);
        return [];
      },
    });
    keyring.persistActive(pin(first, 'old-prune', 1, 1));
    keyring.persistActive(pin(second, 'new-prune', 1, 2));
    expect(identities.has(first.encryptionKeyId)).toBe(true);
    keyring.pruneRetiring({ commandRetainedThrough: { 'old-prune:1:1': '2026-07-20T00:02:00.000Z' } }, '2026-07-20T00:02:00.001Z');
    expect(pruneCalls).toHaveLength(1);
    expect(pruneCalls[0]).toEqual(new Set([second.encryptionKeyId]));
    expect(identities.has(first.encryptionKeyId)).toBe(false);
    expect(JSON.parse(readFileSync(path, 'utf8')).pins.some((item: any) => item.hostBinding.encryptionKeyId === first.encryptionKeyId)).toBe(false);
  });

  test.each([
    ['active with retiringAt', (value: any) => { value.pins[0].retiringAt = value.pins[0].activatedAt; }],
    ['retiring without retiringAt', (value: any) => { value.pins[0].status = 'retiring'; }],
    ['retiring before activation', (value: any) => { value.pins[0].status = 'retiring'; value.pins[0].retiringAt = '2026-07-19T23:59:59.999Z'; }],
    ['revoked before activation', (value: any) => { value.pins[0].status = 'revoked'; value.pins[0].retiringAt = '2026-07-19T23:59:59.999Z'; }],
  ])('rejects corrupted exact pin invariant: %s', (_label, mutate) => {
    const path = join(root('pin-invariant'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(path, host);
    keyring.persistActive(pin(host, 'pin', 1, 1));
    const persisted = JSON.parse(readFileSync(path, 'utf8'));
    mutate(persisted);
    writeFileSync(path, `${JSON.stringify(persisted)}\n`, { mode: 0o600 });
    expect(() => new LocalLinkKeyring(path, host)).toThrow();
  });

  test('rejects pending activation state, duplicates, and rollback before persistence', () => {
    const path = join(root('pending-invariant'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(path, host);
    keyring.persistActive(pin(host, 'active', 2, 1));
    const rollbackPin = pin(host, 'rollback', 1, 1);
    const pending = { version: 2 as const, linkId: rollbackPin.linkId, linkGeneration: rollbackPin.linkGeneration,
      epoch: rollbackPin.epoch, peerProofDigest: rollbackPin.peerProofDigest, activatedAt: rollbackPin.activatedAt, pin: rollbackPin };
    expect(() => keyring.stageActivation(pending)).toThrow(/rollback/);
    const validPin = pin(host, 'next', 3, 1);
    const valid = { version: 2 as const, linkId: validPin.linkId, linkGeneration: validPin.linkGeneration,
      epoch: validPin.epoch, peerProofDigest: validPin.peerProofDigest, activatedAt: validPin.activatedAt, pin: validPin };
    keyring.stageActivation(valid);
    const duplicatePin = pin(host, 'other', 4, 1);
    expect(() => keyring.stageActivation({ ...valid, linkId: duplicatePin.linkId, linkGeneration: duplicatePin.linkGeneration,
      epoch: duplicatePin.epoch, pin: duplicatePin })).toThrow(/duplicate/);
    const persisted = JSON.parse(readFileSync(path, 'utf8'));
    persisted.pendingActivations[0].pin.status = 'retiring';
    persisted.pendingActivations[0].pin.retiringAt = persisted.pendingActivations[0].pin.activatedAt;
    writeFileSync(path, `${JSON.stringify(persisted)}\n`, { mode: 0o600 });
    expect(() => new LocalLinkKeyring(path, host)).toThrow(/pending/);
  });

  test('revoked highest tuple prevents active or pending rollback', () => {
    const path = join(root('revoked-rollback'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(path, host);
    keyring.persistActive(pin(host, 'highest', 3, 1));
    keyring.revokeCompromisedEncryptionKey(host.encryptionKeyId);
    expect(() => keyring.persistActive(pin(host, 'active-rollback', 2, 1))).toThrow(/rollback/);
    expect(() => keyring.persistActive(pin(host, 'same-tuple-other-link', 3, 1))).toThrow(/rollback/);
    const pendingPin = pin(host, 'pending-rollback', 2, 2);
    expect(() => keyring.stageActivation({ version: 2, linkId: pendingPin.linkId,
      linkGeneration: pendingPin.linkGeneration, epoch: pendingPin.epoch, peerProofDigest: pendingPin.peerProofDigest,
      activatedAt: pendingPin.activatedAt, pin: pendingPin })).toThrow(/rollback/);
  });

  test('receipt delivery status honors the exact active, retiring, revoked, and missing tuple', () => {
    const path = join(root('receipt-status'), 'pins.json');
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(path, host);
    const original = pin(host, 'original', 1, 1);
    keyring.persistActive(original);
    expect(keyring.resolveCommandReceiptPinStatus({
      linkId: original.linkId, linkGeneration: original.linkGeneration, epoch: original.epoch,
      transcriptDigest: original.transcriptDigest, hostEncryptionKeyId: original.hostBinding.encryptionKeyId,
      watchEncryptionKeyId: original.watchBinding.encryptionKeyId,
    }, original.activatedAt)).toBe('deliverable');
    keyring.persistActive(pin(host, 'successor', 1, 2));
    const retiring = keyring.listRetiring()[0]!;
    const reference = {
      linkId: retiring.linkId, linkGeneration: retiring.linkGeneration, epoch: retiring.epoch,
      transcriptDigest: retiring.transcriptDigest, hostEncryptionKeyId: retiring.hostBinding.encryptionKeyId,
      watchEncryptionKeyId: retiring.watchBinding.encryptionKeyId,
    };
    expect(keyring.resolveCommandReceiptPinStatus(reference, retiring.activatedAt)).toBe('deliverable');
    expect(keyring.resolveCommandReceiptPinStatus({ ...reference, transcriptDigest: digest(9) }, retiring.activatedAt)).toBe('unavailable');
    keyring.revokeWatchGeneration(retiring.watchDeviceId, retiring.linkGeneration);
    expect(keyring.resolveCommandReceiptPinStatus(reference, retiring.activatedAt)).toBe('revoked');
    expect(keyring.resolveCommandReceiptPinStatus({ ...reference, linkId: 'missing' }, retiring.activatedAt)).toBe('unavailable');
  });

  test('binding verifier checks Ed25519 signature rather than Relay state', async () => {
    const pair = generateKeyPairSync('ed25519');
    const raw = pair.publicKey.export({ format: 'jwk' }).x!;
    const derived = await deriveEntityIdentity('watch', raw);
    const unsigned = { ...fakeWatchBinding(derived.entityId, 1), identityKeyId: derived.keyId };
    const binding = { ...unsigned, bindingSignature: base64UrlEncode(sign(null, buildEncryptionBindingBytes(unsigned), pair.privateKey)) };
    expect(verifyBindingWithIdentityPublicKey(binding, raw)).toBe(true);
    expect(verifyBindingWithIdentityPublicKey({ ...binding, sequence: 2 }, raw)).toBe(false);
  });
});

function pin(
  host: ReturnType<typeof generateHostEncryptionIdentity>,
  linkId: string,
  generation: number,
  epoch: number,
  watchDeviceId = `watch_${'W'.repeat(43)}`,
) {
  const hostBinding = hostBindingFor(host);
  const watchBinding = fakeWatchBinding(watchDeviceId, generation);
  const hostBindingDigest = bindingDigest(hostBinding);
  const watchBindingDigest = bindingDigest(watchBinding);
  return {
    version: 2 as const, status: 'active' as const, linkId, hostId: host.hostId, watchDeviceId, linkGeneration: generation, epoch,
    transcriptDigest: transcriptDigest(linkId, host.hostId, watchDeviceId, generation, epoch, hostBindingDigest, watchBindingDigest),
    hostBinding, hostBindingDigest, watchBinding, watchBindingDigest, peerProofDigest: digest(7), activatedAt: '2026-07-20T00:00:00.000Z',
  };
}

function recipient(value: ReturnType<typeof pin>) {
  return {
    linkId: value.linkId,
    linkGeneration: value.linkGeneration,
    watchDeviceId: value.watchDeviceId,
    epoch: value.epoch,
    state: 'active' as const,
    watchBinding: value.watchBinding,
  };
}


function hostBindingFor(host: ReturnType<typeof generateHostEncryptionIdentity>): EncryptionKeyBindingV1 {
  return { ...fakeBinding('host', host.hostId, host.encryptionKeyId, host.publicKey, host.sequence), createdAt: host.createdAt };
}
function fakeWatchBinding(watchDeviceId: string, sequence: number): EncryptionKeyBindingV1 {
  const pair = generateKeyPairSync('x25519');
  const publicKey = pair.publicKey.export({ format: 'jwk' }).x!;
  return fakeBinding('watch', watchDeviceId, encryptionKeyId(publicKey), publicKey, sequence);
}

function fakeBinding(
  entityType: 'host' | 'watch', entityId: string, encryptionKeyId: string, publicKey: string, sequence: number,
): EncryptionKeyBindingV1 {
  return {
    version: 1, entityType, entityId, identityKeyId: `key_${'A'.repeat(43)}`, encryptionKeyId,
    suite: E2E_SUITE_V1, publicKey, sequence, createdAt: '2026-07-20T00:00:00.000Z',
    bindingSignature: base64UrlEncode(new Uint8Array(64)),
  };
}

function encryptionKeyId(publicKey: string): string {
  return `ekey_${base64UrlEncode(createHash('sha256').update(Buffer.from(publicKey.replaceAll('-', '+').replaceAll('_', '/'), 'base64')).digest())}`;
}
function digest(fill: number): string { return base64UrlEncode(new Uint8Array(32).fill(fill)); }
function bindingDigest(binding: EncryptionKeyBindingV1): string {
  const { bindingSignature: _, ...unsigned } = binding;
  return base64UrlEncode(createHash('sha256').update(buildEncryptionBindingBytes(unsigned)).digest());
}
function transcriptDigest(linkId: string, hostId: string, watchDeviceId: string, linkGeneration: number, epoch: number, hostBindingDigest: string, watchBindingDigest: string): string {
  return base64UrlEncode(createHash('sha256').update(buildLinkTranscriptBytes({ linkId, hostId, watchDeviceId, linkGeneration, epoch, hostBindingDigest, watchBindingDigest })).digest());
}
function timestampBefore(value: string): string { return new Date(Date.parse(value) - 1).toISOString(); }
