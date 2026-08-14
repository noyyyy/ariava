import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BridgeDaemon,
  EncryptedEventFailureLogger,
  loadBridgeConfig,
  type ReconciliationScheduler,
} from '../src/daemon';
import {
  createHostEncryptionBinding, generateHostEncryptionIdentity, LinuxEncryptionKeyStore, LinuxJsonHostIdentityStore,
  publicIdentityMetadata,
} from '../src/identity';
import { spoolKeyIdForKey } from '../src/e2e/local-spool';
import commandFixture from '../../../packages/protocol/test/fixtures/command-e2e-v1-vectors.json';
import {
  buildEncryptionBindingBytes, buildLinkTranscriptBytes, contentSha256, deriveCommandReceiptDigest, deriveEncryptedCommandDigest,
  type CommandReceiptEnvelopeV1, type CommandResult, type EncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import { BridgeStateStore } from '../src/state-store';
import { LocalLinkKeyring, type ActiveLinkPinV2 } from '../src/e2e/link-keyring';
import { deterministicCommandKeyringMaterial, withDeterministicCommandTime } from './fixtures/command-execution-keyring';
import type { HostEncryptionIdentity } from '../src/identity';
import type { CommandReceiptOutboxInputV1, PersistedCommandExecutionV4 } from '../src/types';

const roots: string[] = [];
const servers: Array<{ stop(closeActiveConnections?: boolean): void }> = [];
const decoder = new TextDecoder();
const bunPath = process.execPath;
const cliPath = './apps/bridge/src/cli.ts';
const publicRoot = existsSync(join(process.cwd(), 'apps/bridge')) ? process.cwd() : join(process.cwd(), 'open-source/ariava');

afterEach(() => {
  for (const server of servers.splice(0)) {
    server.stop(true);
  }
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function decode(bytes: Uint8Array | ArrayBuffer | SharedArrayBuffer | null | undefined): string {
  if (!bytes) {
    return '';
  }
  return decoder.decode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).trim();
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
}

interface EnrollmentRequest {
  hostId: string;
  hostName: string;
  platform: string;
  bridgeVersion: string;
}

interface HostResponseOverrides {
  hostName?: string;
  registeredAt?: string;
  lastSeenAt?: string;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function waitFor(condition: () => boolean, context: string, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${context}`);
    await Bun.sleep(1);
  }
}

async function waitForPromise<T>(promise: Promise<T>, context: string, timeoutMs = 1_000): Promise<T> {
  return Promise.race([
    promise,
    Bun.sleep(timeoutMs).then(() => { throw new Error(`Timed out waiting for ${context}`); }),
  ]);
}

function createEnrollmentResponse(body: EnrollmentRequest, overrides: HostResponseOverrides = {}): Response {
  const now = new Date().toISOString();
  return Response.json({
    host: {
      hostId: body.hostId,
      hostName: overrides.hostName ?? body.hostName,
      platform: body.platform,
      bridgeVersion: body.bridgeVersion,
      registeredAt: overrides.registeredAt ?? now,
      lastSeenAt: overrides.lastSeenAt ?? now,
      bridgeStatus: 'online',
    },
  });
}

class ControllableScheduler implements ReconciliationScheduler {
  readonly scheduled: Array<{ callback: () => void; delayMs: number; canceled: boolean }> = [];

  schedule(callback: () => void, delayMs: number): unknown {
    const handle = { callback, delayMs, canceled: false };
    this.scheduled.push(handle);
    return handle;
  }

  cancel(handle: unknown): void {
    (handle as (typeof this.scheduled)[number]).canceled = true;
  }

  run(index: number): void {
    this.scheduled[index]?.callback();
  }
}

async function createPresenceDaemon(
  relayBaseUrl: string,
  scheduler: ReconciliationScheduler,
  listSessions: () => Promise<[]>,
): Promise<{ daemon: BridgeDaemon; statePath: string }> {
  const root = join(tmpdir(), `bridge-daemon-presence-${Date.now()}-${roots.length}`);
  roots.push(root);
  mkdirSync(root, { mode: 0o700 });
  const identityPath = join(root, 'identity.json');
  const store = new LinuxJsonHostIdentityStore(identityPath);
  const identity = await store.createFirstRun();
  const statePath = join(root, 'state.json');
  const config = loadBridgeConfig();
  Object.assign(config, {
    runtimePlatform: 'linux',
    hostPlatform: 'linux',
    hostId: identity.hostId,
    identity: publicIdentityMetadata(identity),
    relayBaseUrl,
    pollIntervalMs: 60_000,
    configPath: join(root, 'config.json'),
    statePath,
    identityPath,
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  return { daemon: new BridgeDaemon(config, [{ name: 'test', listSessions }], store, undefined, scheduler), statePath };
}

async function createLongPollingDaemon(relayBaseUrl: string): Promise<BridgeDaemon> {
  const root = join(tmpdir(), `bridge-daemon-stop-${Date.now()}-${roots.length}`);
  roots.push(root);
  mkdirSync(root, { mode: 0o700 });
  const identityPath = join(root, 'identity.json');
  const store = new LinuxJsonHostIdentityStore(identityPath);
  const identity = await store.createFirstRun();
  const config = loadBridgeConfig();
  Object.assign(config, {
    runtimePlatform: 'linux',
    hostPlatform: 'linux',
    hostId: identity.hostId,
    identity: publicIdentityMetadata(identity),
    relayBaseUrl,
    pollIntervalMs: 60_000,
    configPath: join(root, 'config.json'),
    statePath: join(root, 'state.json'),
    identityPath,
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  return new BridgeDaemon(config, [{ name: 'test', listSessions: async () => [] }], store);
}

function createCommandHarness(): { daemon: BridgeDaemon; stateStore: BridgeStateStore; command: EncryptedCommandEnvelopeV1 } {
  const root = join(tmpdir(), `bridge-daemon-command-${crypto.randomUUID()}`); roots.push(root);
  mkdirSync(root, { mode: 0o700 });
  const config = loadBridgeConfig();
  Object.assign(config, { hostId: commandFixture.link.hostId, statePath: join(root, 'state.json'),
    identityPath: join(root, 'identity.json'), configPath: join(root, 'config.json'), relayBaseUrl: 'http://relay.invalid',
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') } });
  const daemon = new BridgeDaemon(config, []);
  const stateStore = (daemon as any).stateStore as BridgeStateStore;
  stateStore.initializeEncryptedSpool(config.hostId, config.identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  stateStore.validateCommandExecutionPins({ resolvePinReference: () => undefined });
  const command = { ...structuredClone(commandFixture.interrupt.envelope),
    issuedAt: '2026-08-12T00:00:00.000Z', expiresAt: '2026-08-12T00:05:00.000Z',
  } as EncryptedCommandEnvelopeV1;
  const pinReference = { version: 1 as const, linkId: command.linkId, linkGeneration: command.linkGeneration, epoch: command.epoch,
    transcriptDigest: 'T'.repeat(43), hostEncryptionKeyId: command.payload.keyWrap.recipientEncryptionKeyId,
    watchEncryptionKeyId: command.payload.keyWrap.senderEncryptionKeyId };
  const keyring = {
    prepare: async (wire: EncryptedCommandEnvelopeV1) => ({ pinReference, loopbackCommand: {
      commandId: wire.commandId, hostId: wire.hostId, sessionId: wire.sessionId, type: wire.type, payload: {},
      issuedAt: wire.issuedAt, expiresAt: wire.expiresAt, nonce: wire.nonce, watchDeviceId: wire.watchDeviceId,
    } }),
    resolveCommandReceiptPinStatus: () => 'deliverable' as const,
    reconcileRecipients: () => [],
    listActive: () => [],
    pruneRetiring: () => [],
  };
  (daemon as any).keyring = keyring;
  (daemon as any).commandReceiptConstruction = { build: receiptBuilder() };
  return { daemon, stateStore, command };
}

function terminalResult(command: EncryptedCommandEnvelopeV1): CommandResult {
  return { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
    accepted: true, status: 'executed', updatedAt: '2026-08-12T00:00:01.000Z' };
}

function receiptBuilder(counter?: { count: number }): (
  execution: PersistedCommandExecutionV4 & { terminalResult: CommandResult },
  keyring: LocalLinkKeyring,
 ) => Promise<CommandReceiptOutboxInputV1> {
  return async (execution) => {
    if (counter) counter.count += 1;
    const command = execution.originalEncryptedCommand;
    const receipt: CommandReceiptEnvelopeV1 = {
      version: 1, hostId: command.hostId, watchDeviceId: command.watchDeviceId, sessionId: command.sessionId,
      commandId: command.commandId, commandType: command.type, commandDigest: execution.commandDigest,
      completedAt: execution.terminalResult.updatedAt, linkId: execution.pinReference.linkId,
      linkGeneration: execution.pinReference.linkGeneration, epoch: execution.pinReference.epoch,
      content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: `receipt-${counter?.count ?? 1}`,
        payloadKind: 'command-receipt-content-v1', nonce: 'A'.repeat(16), ciphertext: 'B'.repeat(192) },
      keyWrap: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: `receipt-${counter?.count ?? 1}`,
        linkId: execution.pinReference.linkId, linkGeneration: execution.pinReference.linkGeneration,
        epoch: execution.pinReference.epoch, senderEncryptionKeyId: execution.pinReference.hostEncryptionKeyId,
        recipientEncryptionKeyId: execution.pinReference.watchEncryptionKeyId, nonce: 'C'.repeat(16), ciphertext: 'D'.repeat(64) },
    };
    return { receipt, canonicalBody: JSON.stringify(receipt), receiptDigest: await deriveCommandReceiptDigest(receipt) };
  };
}

function recipientSnapshotPin(pin: ActiveLinkPinV2) {
  return {
    linkId: pin.linkId, linkGeneration: pin.linkGeneration, watchDeviceId: pin.watchDeviceId,
    epoch: pin.epoch, state: 'active' as const, watchBinding: pin.watchBinding,
  };
}

async function successorPin(
  original: ActiveLinkPinV2,
  linkId: string,
  linkGeneration: number,
  watchDeviceId = original.watchDeviceId,
  hostIdentity?: HostEncryptionIdentity,
): Promise<ActiveLinkPinV2> {
  const watchBinding = { ...original.watchBinding, entityId: watchDeviceId, sequence: linkGeneration };
  const hostBinding = hostIdentity ? {
    ...original.hostBinding, encryptionKeyId: hostIdentity.encryptionKeyId, publicKey: hostIdentity.publicKey,
    sequence: hostIdentity.sequence, createdAt: hostIdentity.createdAt,
  } : original.hostBinding;
  const { bindingSignature: _watchSignature, ...unsignedWatchBinding } = watchBinding;
  const { bindingSignature: _hostSignature, ...unsignedHostBinding } = hostBinding;
  const watchBindingDigest = await contentSha256(buildEncryptionBindingBytes(unsignedWatchBinding));
  const hostBindingDigest = await contentSha256(buildEncryptionBindingBytes(unsignedHostBinding));
  return {
    ...structuredClone(original), status: 'active', linkId, watchDeviceId, linkGeneration, epoch: 1,
    hostBinding, hostBindingDigest, watchBinding, watchBindingDigest,
    transcriptDigest: await contentSha256(buildLinkTranscriptBytes({
      linkId, hostId: original.hostId, watchDeviceId, linkGeneration, epoch: 1,
      hostBindingDigest, watchBindingDigest,
    })),
  };
}

async function createReconciledReceiptHarness(input: {
  issuedAt?: 'just-before' | 'equal';
  snapshotRecipients?: 'same-watch' | 'other-watch' | 'none';
} = {}) {
  const root = join(tmpdir(), `bridge-daemon-reconciled-receipt-${crypto.randomUUID()}`); roots.push(root);
  mkdirSync(root, { mode: 0o700 });
  const config = loadBridgeConfig();
  Object.assign(config, {
    hostId: commandFixture.link.hostId, statePath: join(root, 'state.json'), identityPath: join(root, 'identity.json'),
    configPath: join(root, 'config.json'), relayBaseUrl: 'http://relay.invalid',
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  const daemon = new BridgeDaemon(config, []);
  const stateStore = (daemon as any).stateStore as BridgeStateStore;
  stateStore.initializeEncryptedSpool(config.hostId, config.identityPath, 'linux', {
    loadOrCreate: () => new Uint8Array(32).fill(7),
  });
  const material = await deterministicCommandKeyringMaterial();
  const currentHost = generateHostEncryptionIdentity(material.pin.hostId, 2, '2026-08-12T00:00:30.000Z');
  const sameWatchSuccessor = await successorPin(
    material.pin, 'link_same_watch_successor', 8, material.pin.watchDeviceId, currentHost,
  );
  const otherWatchSuccessor = await successorPin(
    material.pin, 'link_other_watch_successor', 1, `watch_${'O'.repeat(43)}`,
  );
  const retiring = {
    ...material.pin, status: 'retiring' as const, retiringAt: '2026-08-12T00:03:00.000Z',
  };
  writeFileSync(join(root, 'keyring.json'), `${JSON.stringify({
    version: 2, pins: [retiring, sameWatchSuccessor, otherWatchSuccessor], pendingActivations: [],
  })}\n`, { mode: 0o600 });
  const identities = new Map([
    [material.historicalHost.encryptionKeyId, material.historicalHost],
    [currentHost.encryptionKeyId, currentHost],
  ]);
  const pruneCalls: Set<string>[] = [];
  const keyring = new LocalLinkKeyring(join(root, 'keyring.json'), {
    load: () => currentHost,
    identity: (keyId) => identities.get(keyId) ?? null,
    prune: (referencedKeyIds) => {
      pruneCalls.push(new Set(referencedKeyIds));
      for (const keyId of identities.keys()) {
        if (keyId !== currentHost.encryptionKeyId && !referencedKeyIds.has(keyId)) identities.delete(keyId);
      }
      return [];
    },
  });
  const command = {
    ...structuredClone(commandFixture.interrupt.envelope), commandId: `command_${crypto.randomUUID()}`,
    nonce: `nonce_${crypto.randomUUID()}`, issuedAt: input.issuedAt === 'equal'
      ? retiring.retiringAt! : new Date(Date.parse(retiring.retiringAt!) - 1).toISOString(),
  } as EncryptedCommandEnvelopeV1;
  stateStore.validateCommandExecutionPins(keyring);
  const pinReference = keyring.resolvePinReference(command.linkId, command.linkGeneration, command.epoch)!;
  stateStore.claimCommandExecution({
    originalEncryptedCommand: command, commandDigest: await deriveEncryptedCommandDigest(command),
    pinReference, claimedAt: '2026-08-12T00:00:00.500Z',
  });
  stateStore.markCommandDispatchStarted(command.commandId, '2026-08-12T00:00:00.750Z');
  const result = terminalResult(command);
  const execution = stateStore.getCommandExecution(command.commandId)!;
  const outbox = await receiptBuilder()({ ...execution, terminalResult: result }, keyring);
  stateStore.persistTerminalCommandReceipt(command.commandId, result, outbox);
  const snapshotRecipients = input.snapshotRecipients === 'same-watch'
    ? [recipientSnapshotPin(sameWatchSuccessor)]
    : input.snapshotRecipients === 'other-watch'
      ? [recipientSnapshotPin(otherWatchSuccessor)] : [];
  (daemon as any).keyring = keyring;
  return {
    daemon, stateStore, keyring, identities, pruneCalls, material, command, outbox, retiring, sameWatchSuccessor,
    snapshot: { version: 1 as const, hostId: config.hostId, recipientSetVersion: 1, recipients: snapshotRecipients },
  };
}

describe('BridgeDaemon', () => {
  test('loads PaiDriver by default', () => {
    const config = loadBridgeConfig();
    config.statePath = `${process.cwd()}/.state/ariava/test-bridge-state-${Date.now()}.json`;
    const daemon = new BridgeDaemon(config);
    expect(daemon.driverNames).toEqual(['pi']);
    daemon.stop();
  });

  test('Bun source daemon defers schema 2 state to startup preflight', async () => {
    const root = join(tmpdir(), `bridge-daemon-schema2-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const identityStore = new LinuxJsonHostIdentityStore(identityPath);
    const identity = await identityStore.createFirstRun();
    const statePath = join(root, 'state.json');
    const epoch = '00000000-0000-4000-8000-000000000002';
    const state = {
      schemaVersion: 2, runtimeResetEpoch: epoch, host: null, sessions: {}, sessionDrivers: {}, reconciledDrivers: {},
      recentEvents: [], sessionRevisions: {}, pendingHandles: {}, commandResults: {}, seenCommands: {},
      currentSessionsSnapshot: { version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 },
      runtimeHealth: { status: 'healthy', drivers: [] },
    };
    const key = new Uint8Array(32).fill(7);
    const keyId = spoolKeyIdForKey(key);
    writeFileSync(statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    writeFileSync(`${statePath}.spool.json`, `${JSON.stringify({
      version: 2, runtimeStateSchemaVersion: 2, runtimeResetEpoch: epoch, hostId: identity.hostId, keyId, items: [],
    })}\n`, { mode: 0o600 });
    writeFileSync(`${identityPath}.spool-key.json`, `${JSON.stringify({
      version: 1, hostId: identity.hostId, key: Buffer.from(key).toString('base64url'),
    })}\n`, { mode: 0o600 });
    const config = loadBridgeConfig();
    Object.assign(config, {
      runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, identity: publicIdentityMetadata(identity),
      relayBaseUrl: 'http://relay.invalid', configPath: join(root, 'config.json'), statePath, identityPath,
      agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
    });
    const daemon = new BridgeDaemon(config, [], identityStore);
    expect(JSON.parse(readFileSync(statePath, 'utf8')).schemaVersion).toBe(2);
    await (daemon as any).validateStartup();
    expect(JSON.parse(readFileSync(statePath, 'utf8'))).toMatchObject({ schemaVersion: 4, recentEvents: [], sessions: {} });
    daemon.stop();
  });

  test('startup reconciles an authoritative snapshot before draining a persisted pending receipt', async () => {
    const root = join(tmpdir(), `bridge-daemon-startup-receipt-${crypto.randomUUID()}`); roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const statePath = join(root, 'state.json');
    const identityStore = new LinuxJsonHostIdentityStore(identityPath);
    const identity = await identityStore.createFirstRun();
    const encryptionStore = new LinuxEncryptionKeyStore(`${identityPath}.e2e.json`);
    const encryptionIdentity = encryptionStore.loadOrCreate(identity.hostId);
    const hostBinding = await createHostEncryptionBinding(identity, encryptionIdentity);
    const material = await deterministicCommandKeyringMaterial();
    const { bindingSignature: _hostSignature, ...unsignedHostBinding } = hostBinding;
    const { bindingSignature: _watchSignature, ...unsignedWatchBinding } = material.watchBinding;
    const hostBindingDigest = await contentSha256(buildEncryptionBindingBytes(unsignedHostBinding));
    const watchBindingDigest = await contentSha256(buildEncryptionBindingBytes(unsignedWatchBinding));
    const pin = {
      ...material.pin, hostId: identity.hostId, hostBinding, hostBindingDigest,
      transcriptDigest: await contentSha256(buildLinkTranscriptBytes({
        linkId: material.pin.linkId, hostId: identity.hostId, watchDeviceId: material.pin.watchDeviceId,
        linkGeneration: material.pin.linkGeneration, epoch: material.pin.epoch, hostBindingDigest, watchBindingDigest,
      })),
    };
    writeFileSync(`${identityPath}.e2e-keyring.json`, `${JSON.stringify({
      version: 2, pins: [pin], pendingActivations: [],
    })}\n`, { mode: 0o600 });
    const keyring = new LocalLinkKeyring(`${identityPath}.e2e-keyring.json`, encryptionStore);
    const command = {
      ...structuredClone(commandFixture.interrupt.envelope), hostId: identity.hostId,
      payload: { ...structuredClone(commandFixture.interrupt.envelope.payload), keyWrap: {
        ...structuredClone(commandFixture.interrupt.envelope.payload.keyWrap),
        recipientEncryptionKeyId: encryptionIdentity.encryptionKeyId,
      } },
    } as EncryptedCommandEnvelopeV1;
    const seed = new BridgeStateStore(statePath);
    seed.initializeEncryptedSpool(identity.hostId, identityPath, 'linux');
    seed.validateCommandExecutionPins(keyring);
    const pinReference = keyring.resolvePinReference(command.linkId, command.linkGeneration, command.epoch)!;
    seed.claimCommandExecution({
      originalEncryptedCommand: command, commandDigest: await deriveEncryptedCommandDigest(command), pinReference,
      claimedAt: '2026-08-12T00:00:00.500Z',
    });
    seed.markCommandDispatchStarted(command.commandId, '2026-08-12T00:00:00.750Z');
    const result = { ...terminalResult(command), hostId: identity.hostId };
    const execution = seed.getCommandExecution(command.commandId)!;
    const outbox = await receiptBuilder()({ ...execution, terminalResult: result }, keyring);
    seed.persistTerminalCommandReceipt(command.commandId, result, outbox);
    seed.dispose();

    const requests: Array<{ path: string; body?: string }> = [];
    const relay = Bun.serve({ port: 0, fetch: async (request) => {
      const path = new URL(request.url).pathname;
      if (path === '/v2/bridge/e2e/recipients') {
        requests.push({ path });
        return Response.json({ hostId: identity.hostId, recipientSetVersion: 1, recipients: [recipientSnapshotPin(pin)] });
      }
      if (path === '/v2/bridge/e2e/commands/receipt') {
        requests.push({ path, body: await request.text() });
        return Response.json({ ok: true });
      }
      return new Response('unexpected', { status: 500 });
    } });
    servers.push(relay);
    const config = loadBridgeConfig();
    Object.assign(config, {
      runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, identity: publicIdentityMetadata(identity),
      relayBaseUrl: `http://127.0.0.1:${relay.port}`, configPath: join(root, 'config.json'), statePath, identityPath,
      agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
    });
    const daemon = new BridgeDaemon(config, [], identityStore);
    await (daemon as any).validateStartup();
    expect(requests).toEqual([
      { path: '/v2/bridge/e2e/recipients' },
      { path: '/v2/bridge/e2e/commands/receipt', body: outbox.canonicalBody },
    ]);
    expect(((daemon as any).stateStore as BridgeStateStore).getCommandExecution(command.commandId)?.receiptOutbox).toMatchObject({
      state: 'acknowledged', canonicalBody: outbox.canonicalBody,
    });
    daemon.stop();
  });

  test('offline restart freezes pending receipt before build, drain, or command pull', async () => {
    const value = await createReconciledReceiptHarness({ snapshotRecipients: 'same-watch' });
    let builds = 0; let receiptHttp = 0; let pulls = 0;
    (value.daemon as any).commandReceiptConstruction = { build: async () => { builds += 1; throw new Error('must not build'); } };
    (value.daemon as any).relayClient = {
      recipientSnapshot: async () => { throw new Error('offline'); },
      submitCommandReceipt: async () => { receiptHttp += 1; },
      pullCommands: async () => { pulls += 1; return []; },
    };
    expect(await (value.daemon as any).pullAndHandleCommands()).toEqual([]);
    expect({ builds, receiptHttp, pulls }).toEqual({ builds: 0, receiptHttp: 0, pulls: 0 });
    expect(value.stateStore.getCommandExecution(value.command.commandId)?.receiptOutbox).toMatchObject({
      state: 'pending', canonicalBody: value.outbox.canonicalBody,
    });
    value.daemon.stop();
  });

  test('drains pending receipts before pull and immediately after terminal handling', async () => {
    const { daemon, stateStore, command } = createCommandHarness();
    const order: string[] = [];
    let receiptAttempts = 0; let pulls = 0;
    (daemon as any).relayClient = {
      recipientSnapshot: async () => ({
        version: 1, hostId: command.hostId, recipientSetVersion: 1, recipients: [],
      }),
      submitCommandReceipt: async () => {
        order.push('receipt'); receiptAttempts += 1;
        if (receiptAttempts === 1) throw new Error('retry');
      },
      pullCommands: async () => { order.push('pull'); pulls += 1; return pulls === 1 ? [command] : []; },
    };
    (daemon as any).router = { handle: async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch(); order.push('dispatch');
      return { result: terminalResult(command), followUpEvents: [] };
    } };
    expect(await (daemon as any).pullAndHandleCommands()).toEqual([terminalResult(command)]);
    expect(order).toEqual(['pull', 'dispatch', 'receipt']);
    expect(stateStore.getCommandExecution(command.commandId)?.receiptOutbox?.state).toBe('pending');
    order.length = 0;
    expect(await (daemon as any).pullAndHandleCommands()).toEqual([]);
    expect(order).toEqual(['receipt', 'pull']);
    expect(stateStore.getCommandExecution(command.commandId)?.receiptOutbox?.state).toBe('acknowledged');
    daemon.stop();
  });

  test('concurrent unlink after dispatch blocks terminal receipt construction', async () => {
    const { daemon, stateStore, command } = createCommandHarness();
    let snapshotReads = 0; let builds = 0; let pulls = 0;
    (daemon as any).commandNow = () => new Date('2026-08-12T00:00:00.000Z');
    (daemon as any).commandReceiptConstruction = { build: async (...args: Parameters<ReturnType<typeof receiptBuilder>>) => {
      builds += 1;
      return receiptBuilder()(...args);
    } };
    (daemon as any).relayClient = {
      recipientSnapshot: async () => {
        snapshotReads += 1;
        if (snapshotReads === 2) throw new Error('concurrent unlink authority unavailable');
        return { hostId: command.hostId, recipientSetVersion: 1, recipients: [] };
      },
      pullCommands: async () => { pulls += 1; return [command]; },
      submitCommandReceipt: async () => { throw new Error('must not submit'); },
    };
    (daemon as any).router = { handle: async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch();
      return { result: terminalResult(command), followUpEvents: [] };
    } };
    expect(await (daemon as any).pullAndHandleCommands()).toEqual([terminalResult(command)]);
    expect({ snapshotReads, pulls, builds }).toEqual({ snapshotReads: 2, pulls: 1, builds: 0 });
    expect(stateStore.getCommandExecution(command.commandId)).toMatchObject({
      state: 'terminal_receipt_blocked', terminalResult: terminalResult(command),
    });
    daemon.stop();
  });

  test.each([
    ['same-Watch successor at just-before boundary', 'same-watch', 'just-before', 'acknowledged', 1, 1],
    ['same-Watch successor at equal boundary', 'same-watch', 'equal', 'pending', 0, 0],
    ['other-Watch successor', 'other-watch', 'just-before', 'undeliverable', 0, 1],
    ['no successor', 'none', 'just-before', 'undeliverable', 0, 1],
  ] as const)('reconciles authority before receipt drain: %s', async (
    _label, snapshotRecipients, issuedAt, expectedState, expectedHttp, expectedDrained,
  ) => {
    const value = await createReconciledReceiptHarness({ snapshotRecipients, issuedAt });
    const submitted: string[] = [];
    (value.daemon as any).relayClient = {
      recipientSnapshot: async () => value.snapshot,
      submitCommandReceipt: async (canonicalBody: string) => { submitted.push(canonicalBody); },
    };
    expect(await (value.daemon as any).reconcileRecipientsAndDrainReceipts()).toBe(expectedDrained);
    expect(submitted).toHaveLength(expectedHttp);
    if (expectedHttp) expect(submitted).toEqual([value.outbox.canonicalBody]);
    expect(value.stateStore.getCommandExecution(value.command.commandId)?.receiptOutbox).toMatchObject({
      state: expectedState, canonicalBody: value.outbox.canonicalBody,
    });
    value.daemon.stop();
  });

  test('snapshot failure leaves the persisted receipt pending and performs zero receipt HTTP', async () => {
    const value = await createReconciledReceiptHarness({ snapshotRecipients: 'same-watch' });
    let receiptHttp = 0;
    (value.daemon as any).relayClient = {
      recipientSnapshot: async () => { throw new Error('snapshot unavailable'); },
      submitCommandReceipt: async () => { receiptHttp += 1; },
    };
    expect(await (value.daemon as any).reconcileRecipientsAndDrainReceipts()).toBe(0);
    expect(receiptHttp).toBe(0);
    expect(value.stateStore.getCommandExecution(value.command.commandId)?.receiptOutbox).toMatchObject({
      state: 'pending', canonicalBody: value.outbox.canonicalBody,
    });
    value.daemon.stop();
  });

  test.each(['rollback', 'same-version-conflict'] as const)('%s snapshot freezes command pull and pending receipt', async (failure) => {
    const value = await createReconciledReceiptHarness({ snapshotRecipients: 'same-watch' });
    value.stateStore.setRecipientSetVersion(2);
    let pulls = 0; let receiptHttp = 0;
    (value.daemon as any).relayClient = {
      recipientSnapshot: async () => failure === 'rollback'
        ? { ...value.snapshot, recipientSetVersion: 1 }
        : { ...value.snapshot, recipientSetVersion: 2, recipients: [] },
      pullCommands: async () => { pulls += 1; return []; },
      submitCommandReceipt: async () => { receiptHttp += 1; },
    };
    expect(await (value.daemon as any).pullAndHandleCommands()).toEqual([]);
    expect({ pulls, receiptHttp }).toEqual({ pulls: 0, receiptHttp: 0 });
    expect(value.stateStore.getCommandExecution(value.command.commandId)?.receiptOutbox?.state).toBe('pending');
    value.daemon.stop();
  });

  test('concurrent reconciled receipt drains share one snapshot and one HTTP mutation', async () => {
    const value = await createReconciledReceiptHarness({ snapshotRecipients: 'same-watch' });
    const snapshotStarted = deferred<void>();
    const release = deferred<void>();
    let snapshotReads = 0; let receiptHttp = 0;
    (value.daemon as any).relayClient = {
      recipientSnapshot: async () => {
        snapshotReads += 1; snapshotStarted.resolve(); await release.promise; return value.snapshot;
      },
      submitCommandReceipt: async (canonicalBody: string) => {
        expect(canonicalBody).toBe(value.outbox.canonicalBody); receiptHttp += 1;
      },
    };
    const first = (value.daemon as any).reconcileRecipientsAndDrainReceipts();
    await snapshotStarted.promise;
    const second = (value.daemon as any).reconcileRecipientsAndDrainReceipts();
    expect(second).toBe(first);
    release.resolve();
    expect(await Promise.all([first, second])).toEqual([1, 1]);
    expect({ snapshotReads, receiptHttp }).toEqual({ snapshotReads: 1, receiptHttp: 1 });
    value.daemon.stop();
  });

  test('composed pending-outbox state references retain the historical pin and Host key during prune', async () => {
    const value = await createReconciledReceiptHarness({ snapshotRecipients: 'same-watch' });
    const retainThrough = '2026-09-11T00:00:01.000Z';
    const references = value.stateStore.commandExecutionPinRetentionReferences();
    expect(references).toEqual({
      pendingOutboxRetainedThrough: {
        [`${value.retiring.linkId}:${value.retiring.linkGeneration}:${value.retiring.epoch}`]: retainThrough,
      },
    });
    expect(value.keyring.pruneRetiring(references, '2026-09-11T00:00:00.999Z')).toEqual([]);
    expect(value.identities.has(value.material.historicalHost.encryptionKeyId)).toBe(true);
    expect(value.pruneCalls).toEqual([]);
    value.daemon.stop();
  });

  test('production prune removes execution before its historical pin and Host key', async () => {
    const value = await createReconciledReceiptHarness({ snapshotRecipients: 'same-watch' });
    const order: string[] = [];
    (value.keyring as unknown as { pins: ActiveLinkPinV2[] }).pins =
      (value.keyring as unknown as { pins: ActiveLinkPinV2[] }).pins.filter((pin) => pin.watchDeviceId === value.retiring.watchDeviceId);
    const pruneExecutions = value.stateStore.pruneEligibleCommandExecutions.bind(value.stateStore);
    value.stateStore.pruneEligibleCommandExecutions = (now) => {
      const removed = pruneExecutions(now);
      if (removed.length) order.push('execution');
      return removed;
    };
    const pruneRetiring = value.keyring.pruneRetiring.bind(value.keyring);
    value.keyring.pruneRetiring = (references, now) => {
      const removed = pruneRetiring(references, now);
      if (removed.length) order.push('pin-key');
      return removed;
    };
    (value.daemon as any).pruneCommandRuntime('2026-09-11T00:00:01.001Z');
    expect(order).toEqual(['execution', 'pin-key']);
    expect(value.stateStore.getCommandExecution(value.command.commandId)).toBeUndefined();
    expect(value.identities.has(value.material.historicalHost.encryptionKeyId)).toBe(false);
    value.daemon.stop();
  });

  test('turns post-dispatch throw or invalid result into permanent outcome_unknown', async () => {
    for (const outcome of ['throw', 'invalid'] as const) {
      const { daemon, stateStore, command } = createCommandHarness();
      (daemon as any).relayClient = {
        recipientSnapshot: async () => ({ hostId: command.hostId, recipientSetVersion: 1, recipients: [] }),
        pullCommands: async () => [command],
      };
      (daemon as any).router = { handle: async (_command: unknown, options: { beforeDispatch(): void }) => {
        options.beforeDispatch();
        if (outcome === 'throw') throw new Error('private driver failure');
        return { result: { ...terminalResult(command), message: 'forbidden' }, followUpEvents: [] };
      } };
      expect(await (daemon as any).pullAndHandleCommands()).toEqual([]);
      expect(stateStore.getCommandExecution(command.commandId)).toMatchObject({ state: 'outcome_unknown' });
      expect(await (daemon as any).pullAndHandleCommands()).toEqual([]);
      daemon.stop();
    }
  });

  test('stop during dispatch durably records outcome_unknown before disposal and ignores the late result', async () => {
    const { daemon, stateStore, command } = createCommandHarness();
    (daemon as any).startupValidated = true;
    let dispatchStarted = false;
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    (daemon as any).relayClient = {
      recipientSnapshot: async () => ({ hostId: command.hostId, recipientSetVersion: 1, recipients: [] }),
      pullCommands: async () => [command],
    };
    (daemon as any).router = { handle: async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch();
      dispatchStarted = true;
      await blocked;
      return { result: terminalResult(command), followUpEvents: [] };
    } };

    const flight = (daemon as any).pullAndHandleCommands();
    await waitFor(() => dispatchStarted, 'active command dispatch');
    daemon.stop();
    const persisted = JSON.parse(readFileSync((daemon as any).config.statePath, 'utf8'));
    expect(persisted.commandExecutions[command.commandId]).toMatchObject({ state: 'outcome_unknown' });
    expect(persisted.commandExecutions[command.commandId]).not.toHaveProperty('terminalResult');
    expect(persisted.commandExecutions[command.commandId]).not.toHaveProperty('receiptOutbox');
    release();
    expect(await flight).toEqual([]);
    expect(JSON.parse(readFileSync((daemon as any).config.statePath, 'utf8')).commandExecutions[command.commandId].state)
      .toBe('outcome_unknown');
  });

  test('stop retains ownership when outcome_unknown persistence fails and restart never redispatches', async () => {
    const { daemon, stateStore, command } = createCommandHarness();
    (daemon as any).startupValidated = true;
    stateStore.claimCommandExecution({
      originalEncryptedCommand: command, commandDigest: await deriveEncryptedCommandDigest(command),
      pinReference: { version: 1, linkId: command.linkId, linkGeneration: command.linkGeneration, epoch: command.epoch,
        transcriptDigest: 'T'.repeat(43), hostEncryptionKeyId: command.payload.keyWrap.recipientEncryptionKeyId,
        watchEncryptionKeyId: command.payload.keyWrap.senderEncryptionKeyId },
      claimedAt: '2026-08-12T00:00:00.100Z',
    });
    stateStore.markCommandDispatchStarted(command.commandId, '2026-08-12T00:00:00.500Z');
    const originalRecover = stateStore.recoverOrphanedCommandExecutions.bind(stateStore);
    (stateStore as any).recoverOrphanedCommandExecutions = () => { throw new Error('injected disposal write failure'); };
    let stateDisposed = 0;
    const originalDispose = stateStore.dispose.bind(stateStore);
    (stateStore as any).dispose = () => { stateDisposed += 1; originalDispose(); };

    daemon.stop();
    expect(stateDisposed).toBe(0);
    expect((daemon as any).runtimeDisposed).toBe(false);
    expect(stateStore.getCommandExecution(command.commandId)?.state).toBe('dispatch_started');
    const expectedPinReference = stateStore.getCommandExecution(command.commandId)!.pinReference;
    (stateStore as any).recoverOrphanedCommandExecutions = originalRecover;
    daemon.stop();
    expect(stateDisposed).toBe(1);
    const restarted = new BridgeStateStore((daemon as any).config.statePath);
    restarted.validateCommandExecutionPins({ resolvePinReference: () => expectedPinReference });
    expect(restarted.recoverOrphanedCommandExecutions()).toBe(0);
    expect(restarted.getCommandExecution(command.commandId)).toMatchObject({ state: 'outcome_unknown' });
    expect(restarted.getCommandExecution(command.commandId)).not.toHaveProperty('terminalResult');
    expect(restarted.getCommandExecution(command.commandId)).not.toHaveProperty('receiptOutbox');
    restarted.dispose();
  });

  test('persists proven pre-dispatch rejection without marking dispatch started', async () => {
    const { daemon, stateStore, command } = createCommandHarness();
    const rejected: CommandResult = { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
      accepted: false, status: 'rejected', updatedAt: '2026-08-12T00:00:01.000Z' };
    (daemon as any).relayClient = {
      recipientSnapshot: async () => ({ hostId: command.hostId, recipientSetVersion: 1, recipients: [] }),
      pullCommands: async () => [command],
    };
    (daemon as any).router = { handle: async () => ({ result: rejected, followUpEvents: [] }) };
    expect(await (daemon as any).pullAndHandleCommands()).toEqual([rejected]);
    const execution = stateStore.getCommandExecution(command.commandId)!;
    expect(execution).toMatchObject({ state: 'terminal', terminalResult: rejected, receiptOutbox: { state: 'pending' } });
    expect(execution).not.toHaveProperty('dispatchStartedAt');
    daemon.stop();
  });

  test('fails closed on same Watch nonce rebound without dispatching the conflicting command', async () => {
    const { daemon, command } = createCommandHarness();
    const rebound = { ...structuredClone(command), commandId: `${command.commandId}_rebound` };
    let dispatches = 0;
    (daemon as any).relayClient = {
      recipientSnapshot: async () => ({ hostId: command.hostId, recipientSetVersion: 1, recipients: [] }),
      pullCommands: async () => [command, rebound],
    };
    (daemon as any).router = { handle: async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch(); dispatches += 1; return { result: terminalResult(command), followUpEvents: [] };
    } };
    await expect((daemon as any).pullAndHandleCommands()).rejects.toThrow(/replay nonce or body conflict/u);
    expect(dispatches).toBe(1);
    daemon.stop();
  });

  test('concurrent sync callers share one receipt mutation cycle', async () => {
    const { daemon } = createCommandHarness();
    (daemon as any).startupValidated = true;
    (daemon as any).ensureHostPresence = async () => {};
    (daemon as any).flushCurrentSessionsSnapshot = async () => true;
    let pulls = 0; let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    (daemon as any).relayClient = {
      recipientSnapshot: async () => ({ hostId: (daemon as any).config.hostId, recipientSetVersion: 1, recipients: [] }),
      submitCommandReceipt: async () => {},
      pullCommands: async () => { pulls += 1; await blocked; return []; },
    };
    const first = daemon.syncOnce();
    const second = daemon.syncOnce();
    expect(second).toBe(first);
    await waitFor(() => pulls === 1, 'single command pull');
    release();
    await Promise.all([first, second]);
    expect(pulls).toBe(1);
    daemon.stop();
  });

  test('atomic claim permits only one concurrent identical dispatch', async () => {
    const { daemon, stateStore, command } = createCommandHarness();
    let dispatches = 0; let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    (daemon as any).relayClient = {
      recipientSnapshot: async () => ({ hostId: command.hostId, recipientSetVersion: 1, recipients: [] }),
      pullCommands: async () => [command],
    };
    (daemon as any).router = { handle: async (_command: unknown, options: { beforeDispatch(): void }) => {
      options.beforeDispatch(); dispatches += 1; await blocked; return { result: terminalResult(command), followUpEvents: [] };
    } };
    const first = (daemon as any).pullAndHandleCommands();
    await waitFor(() => dispatches === 1, 'first command dispatch');
    const second = (daemon as any).pullAndHandleCommands();
    release();
    expect(await Promise.all([first, second])).toEqual([[terminalResult(command)], []]);
    expect(dispatches).toBe(1);
    expect(stateStore.getCommandExecution(command.commandId)?.state).toBe('terminal');
    daemon.stop();
  });



  test.each(['claimed', 'dispatch_started'] as const)(
    'normal startup recovers persisted orphan %s before the first Relay pull without redispatch',
    async (state) => {
      const root = join(tmpdir(), `bridge-daemon-orphan-${state}-${crypto.randomUUID()}`);
      roots.push(root);
      mkdirSync(root, { mode: 0o700 });
      const identityPath = join(root, 'identity.json');
      const statePath = join(root, 'state.json');
      const identityStore = new LinuxJsonHostIdentityStore(identityPath);
      const identity = await identityStore.createFirstRun();
      const material = await deterministicCommandKeyringMaterial();
      const encryptionStore = new LinuxEncryptionKeyStore(`${identityPath}.e2e.json`);
      const encryptionIdentity = encryptionStore.loadOrCreate(identity.hostId);
      const hostBinding = await createHostEncryptionBinding(identity, encryptionIdentity);
      const { bindingSignature: _hostSignature, ...unsignedHostBinding } = hostBinding;
      const { bindingSignature: _watchSignature, ...unsignedWatchBinding } = material.watchBinding;
      const hostBindingDigest = await contentSha256(buildEncryptionBindingBytes(unsignedHostBinding));
      const watchBindingDigest = await contentSha256(buildEncryptionBindingBytes(unsignedWatchBinding));
      const pin = {
        ...material.pin,
        hostId: identity.hostId,
        hostBinding,
        hostBindingDigest,
        transcriptDigest: await contentSha256(buildLinkTranscriptBytes({
          linkId: material.pin.linkId, hostId: identity.hostId, watchDeviceId: material.pin.watchDeviceId,
          linkGeneration: material.pin.linkGeneration, epoch: material.pin.epoch, hostBindingDigest, watchBindingDigest,
        })),
      };
      const command = structuredClone(commandFixture.interrupt.envelope) as EncryptedCommandEnvelopeV1;
      command.hostId = identity.hostId;
      command.payload.keyWrap.recipientEncryptionKeyId = encryptionIdentity.encryptionKeyId;
      writeFileSync(`${identityPath}.e2e-keyring.json`, `${JSON.stringify({
        version: 2, pins: [pin], pendingActivations: [],
      })}\n`, { mode: 0o600 });
      const config = loadBridgeConfig();
      const requests: string[] = [];
      let stateAtFirstPull: string | undefined;
      let pulled = false;
      let daemon!: BridgeDaemon;
      const server = Bun.serve({ port: 0, fetch: async (request) => {
        const path = new URL(request.url).pathname;
        requests.push(path);
        if (path === '/v2/bridge/enroll') return createEnrollmentResponse(await request.json() as EnrollmentRequest);
        if (path === '/v2/bridge/e2e/recipients') return Response.json({
          hostId: identity.hostId, recipientSetVersion: 1, recipients: [],
        });
        if (path === '/v2/bridge/e2e/sessions/current') {
          const body = await request.json() as { revision: number };
          return Response.json({ ok: true, hostId: identity.hostId, revision: body.revision, activeSessionCount: 0 });
        }
        if (path === '/v2/bridge/commands/pull') {
          pulled = true;
          stateAtFirstPull = JSON.parse(readFileSync(statePath, 'utf8')).commandExecutions[command.commandId]?.state;
          (daemon as any).keyring = { prepare: async (wire: EncryptedCommandEnvelopeV1) => ({
            pinReference: {
              version: 1, linkId: pin.linkId, linkGeneration: pin.linkGeneration, epoch: pin.epoch,
              transcriptDigest: pin.transcriptDigest, hostEncryptionKeyId: pin.hostBinding.encryptionKeyId,
              watchEncryptionKeyId: pin.watchBinding.encryptionKeyId,
            },
            loopbackCommand: {
              commandId: wire.commandId, hostId: wire.hostId, sessionId: wire.sessionId, type: wire.type, payload: {},
              issuedAt: wire.issuedAt, expiresAt: wire.expiresAt, nonce: wire.nonce, watchDeviceId: wire.watchDeviceId,
            },
          }) };
          return Response.json({ commands: [command] });
        }
        return Response.json({ ok: true });
      } });
      servers.push(server);
      Object.assign(config, {
        runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, identity: publicIdentityMetadata(identity),
        relayBaseUrl: `http://127.0.0.1:${server.port}`, configPath: join(root, 'config.json'), statePath, identityPath,
        agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
      });
      const spoolKey = new Uint8Array(32).fill(7);
      writeFileSync(`${identityPath}.spool-key.json`, `${JSON.stringify({
        version: 1, hostId: identity.hostId, key: Buffer.from(spoolKey).toString('base64url'),
      })}\n`, { mode: 0o600 });
      const seed = new BridgeStateStore(statePath);
      seed.initializeEncryptedSpool(identity.hostId, identityPath, 'linux');
      const seedKeyring = new LocalLinkKeyring(`${identityPath}.e2e-keyring.json`, encryptionIdentity);
      const pinReference = seedKeyring.resolvePinReference(command.linkId, command.linkGeneration, command.epoch)!;
      seed.validateCommandExecutionPins(seedKeyring);
      seed.claimCommandExecution({
        originalEncryptedCommand: command,
        commandDigest: await deriveEncryptedCommandDigest(command),
        pinReference,
        claimedAt: '2026-08-12T00:00:00.100Z',
      });
      if (state === 'dispatch_started') {
        seed.markCommandDispatchStarted(command.commandId, '2026-08-12T00:00:00.500Z');
      }
      seed.dispose();
      let driverDispatches = 0;
      const driver = {
        name: 'test',
        listSessions: async () => [],
        executeCommand: async () => {
          driverDispatches += 1;
          throw new Error('orphan command must not redispatch');
        },
      };
      daemon = new BridgeDaemon(config, [driver], identityStore);
      await withDeterministicCommandTime(async () => {
        expect((await daemon.syncOnce()).handledCommands).toEqual([]);
      });
      expect(pulled).toBe(true);
      expect(stateAtFirstPull).toBe('outcome_unknown');
      expect(requests.indexOf('/v2/bridge/commands/pull')).toBeGreaterThan(requests.indexOf('/v2/bridge/enroll'));
      expect(driverDispatches).toBe(0);
      expect(JSON.parse(readFileSync(statePath, 'utf8')).commandExecutions[command.commandId].state).toBe('outcome_unknown');
      expect((daemon as any).keyringMigrationContext.signedCurrentHostBinding).toEqual(hostBinding);
      daemon.stop();
    },
  );
  test('keeps startup not ready when post-keyring execution pin validation fails', async () => {
    const root = join(tmpdir(), `bridge-daemon-pin-preflight-${Date.now()}`); roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const identityStore = new LinuxJsonHostIdentityStore(identityPath);
    const identity = await identityStore.createFirstRun();
    const config = loadBridgeConfig();
    Object.assign(config, { runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId,
      identity: publicIdentityMetadata(identity), relayBaseUrl: 'http://relay.invalid', configPath: join(root, 'config.json'),
      statePath: join(root, 'state.json'), identityPath,
      agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') } });
    const daemon = new BridgeDaemon(config, [], identityStore);
    let validatedAfterKeyring = false;
    (daemon as any).stateStore.validateCommandExecutionPins = (resolver: unknown) => {
      validatedAfterKeyring = resolver === (daemon as any).keyring;
      throw new Error('pin validation failed');
    };
    await expect((daemon as any).validateStartup()).rejects.toThrow('pin validation failed');
    expect(validatedAfterKeyring).toBe(true);
    expect((daemon as any).startupValidated).toBe(false);
    expect((daemon as any).relayClient).toBeUndefined();
  });

  test('snapshot recovery reconstructs the keyring with the same signed migration context', async () => {
    const root = join(tmpdir(), `bridge-daemon-keyring-recovery-${Date.now()}`); roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const identityStore = new LinuxJsonHostIdentityStore(identityPath);
    const identity = await identityStore.createFirstRun();
    const config = loadBridgeConfig();
    Object.assign(config, { runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId,
      identity: publicIdentityMetadata(identity), relayBaseUrl: 'http://127.0.0.1:1', configPath: join(root, 'config.json'),
      statePath: join(root, 'state.json'), identityPath,
      agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') } });
    const daemon = new BridgeDaemon(config, [], identityStore);
    await (daemon as any).validateStartup();
    const context = (daemon as any).keyringMigrationContext;
    expect(context.currentHostIdentity.hostId).toBe(identity.hostId);
    expect(context.signedCurrentHostBinding.identityKeyId).toBe(identity.keyId);
    const original = (daemon as any).keyring;
    await (daemon as any).recoverCurrentSessionsSnapshotPipeline([]);
    expect((daemon as any).keyring).not.toBe(original);
    expect((daemon as any).keyringMigrationContext).toBe(context);
    daemon.stop();
  });

  test('rejects first-run and corrupt identity before any Relay call', async () => {
    const root = join(tmpdir(), `bridge-daemon-identity-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    let relayCalls = 0;
    const server = Bun.serve({ port: 0, fetch: () => { relayCalls += 1; return new Response('unexpected'); } });
    servers.push(server);
    const config = loadBridgeConfig();
    Object.assign(config, {
      runtimePlatform: 'linux', hostPlatform: 'linux', hostId: 'host-test', relayBaseUrl: `http://127.0.0.1:${server.port}`,
      configPath: join(root, 'config.json'), statePath: join(root, 'state.json'), identityPath: join(root, 'identity.json'),
      agentAdapter: { ...config.agentAdapter, configPath: join(root, 'adapter.json') },
    });
    await expect(new BridgeDaemon(config).syncOnce()).rejects.toMatchObject({ code: 'ERR_IDENTITY_NOT_INITIALIZED' });
    expect(relayCalls).toBe(0);
    writeFileSync(config.identityPath, '{bad json', { mode: 0o600 });
    await expect(new BridgeDaemon(config).syncOnce()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect(relayCalls).toBe(0);
  });

  test('rejects config hostId mismatch before any Relay call', async () => {
    const root = join(tmpdir(), `bridge-daemon-mismatch-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    let relayCalls = 0;
    const server = Bun.serve({ port: 0, fetch: () => { relayCalls += 1; return new Response('unexpected'); } });
    servers.push(server);
    const identityPath = join(root, 'identity.json');
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const config = loadBridgeConfig();
    Object.assign(config, {
      runtimePlatform: 'linux', hostPlatform: 'linux', hostId: 'host-wrong', relayBaseUrl: `http://127.0.0.1:${server.port}`,
      identity: publicIdentityMetadata(identity),
      configPath: join(root, 'config.json'), statePath: join(root, 'state.json'), identityPath,
      agentAdapter: { ...config.agentAdapter, configPath: join(root, 'adapter.json') },
    });
    await expect(new BridgeDaemon(config).syncOnce()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect(relayCalls).toBe(0);
  });

  test.each(['keyId', 'publicKey', 'publicKeyFingerprint', 'algorithm', 'createdAt', 'privateKeyStorage'] as const)('rejects full config identity %s mismatch before Relay writes', async (field) => {
    const root = join(tmpdir(), `bridge-daemon-full-mismatch-${field}-${Date.now()}`); roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    let relayCalls = 0;
    const server = Bun.serve({ port: 0, fetch: () => { relayCalls += 1; return new Response('unexpected'); } }); servers.push(server);
    const identityPath = join(root, 'identity.json');
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const metadata: any = publicIdentityMetadata(identity);
    if (field === 'algorithm') metadata.algorithm = 'RSA';
    else if (field === 'privateKeyStorage') metadata.privateKeyStorage = { type: 'linux-json', path: join(root, 'other.json') };
    else metadata[field] = `${metadata[field]}-wrong`;
    const config = loadBridgeConfig();
    Object.assign(config, { runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, identity: metadata,
      relayBaseUrl: `http://127.0.0.1:${server.port}`, configPath: join(root, 'config.json'), statePath: join(root, 'state.json'), identityPath,
      agentAdapter: { ...config.agentAdapter, configPath: join(root, 'adapter.json') } });
    await expect(new BridgeDaemon(config).syncOnce()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect(relayCalls).toBe(0);
  });

  test('logs redacted driver failures without persisting diagnostic Event or state', async () => {
    const root = join(tmpdir(), `bridge-daemon-redaction-${Date.now()}`);
    roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const statePath = join(root, 'state.json');
    const envSecret = 'daemon-env-super-secret';
    const persistedSecret = 'daemon-persisted-super-secret';
    const adapterSecret = 'daemon-adapter-super-secret';
    const relayRemnant = 'daemon-relay-remnant';
    const previousSecret = process.env.ARIAVA_TEST_PRIVATE_KEY;
    process.env.ARIAVA_TEST_PRIVATE_KEY = envSecret;
    try {
      const config = loadBridgeConfig();
      Object.assign(config, {
        runtimePlatform: 'linux', hostId: identity.hostId, relayBaseUrl: 'http://127.0.0.1:1',
        hostPlatform: 'linux', identity: publicIdentityMetadata(identity),
        configPath: join(root, 'config.json'), statePath, identityPath,
        agentAdapter: { ...config.agentAdapter, secret: adapterSecret, configPath: join(root, 'adapter.json') },
      });
      writeFileSync(config.configPath, JSON.stringify({
        hostAuthToken: persistedSecret, relayToken: relayRemnant, agentAdapterSecret: 'persisted-adapter-secret',
      }), { mode: 0o600 });
      const failingDriver = {
        name: 'failing',
        listSessions: async () => {
          throw new Error(`failed ${envSecret} ${persistedSecret} ${adapterSecret} ${relayRemnant} persisted-adapter-secret`);
        },
        executeCommand: async () => { throw new Error('not used'); },
      };
      const lines: string[] = [];
      const originalWrite = process.stderr.write.bind(process.stderr);
      process.stderr.write = ((chunk: string | Uint8Array) => { lines.push(String(chunk)); return true; }) as typeof process.stderr.write;
      try {
        const result = await new BridgeDaemon(config, [failingDriver]).syncOnce();
        expect(result.emittedEvents).toEqual([]);
      } finally {
        process.stderr.write = originalWrite;
      }
      const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : { recentEvents: [], sessions: {} };
      const persisted = existsSync(statePath) ? readFileSync(statePath, 'utf8') : '';
      expect(state.recentEvents).toEqual([]);
      expect(state).not.toHaveProperty('pendingEvents');
      expect(JSON.stringify(state.sessions)).not.toMatch(/driver:|host:/u);
      for (const secret of [envSecret, persistedSecret, adapterSecret, relayRemnant, 'persisted-adapter-secret']) {
        expect(persisted).not.toContain(secret);
        expect(lines.join('')).not.toContain(secret);
      }
      expect(lines.join('')).toContain('"component":"bridge_runtime_health"');
      expect(lines.join('')).toContain('"code":"driver_reconciliation_failed"');
      expect(lines.join('')).not.toContain('failed ');
    } finally {
      if (previousSecret === undefined) delete process.env.ARIAVA_TEST_PRIVATE_KEY;
      else process.env.ARIAVA_TEST_PRIVATE_KEY = previousSecret;
    }
  });

  test('refreshes Host presence while a full synchronization remains blocked', async () => {
    let enrollments = 0;
    const relay = Bun.serve({ port: 0, fetch: async (request) => {
      if (new URL(request.url).pathname !== '/v2/bridge/enroll') return new Response('unexpected', { status: 500 });
      const body = await request.json() as EnrollmentRequest;
      enrollments += 1;
      return createEnrollmentResponse(body);
    } });
    servers.push(relay);
    const scheduler = new ControllableScheduler();
    const sessionsStarted = deferred<void>();
    const sessions = deferred<[]>();
    const { daemon } = await createPresenceDaemon(`http://127.0.0.1:${relay.port}`, scheduler, () => {
      sessionsStarted.resolve();
      return sessions.promise;
    });
    let run: Promise<void> | undefined;
    try {
      await daemon.start();
      run = daemon.runForever();
      await waitForPromise(sessionsStarted.promise, 'initial synchronization to enter blocked session listing');
      expect(enrollments).toBe(1);
      scheduler.run(0);
      await waitFor(() => enrollments >= 2, 'heartbeat enrollment during blocked synchronization');
      expect(enrollments).toBe(2);
    } finally {
      daemon.stop();
      sessions.resolve([]);
      if (run) await waitForPromise(run.catch(() => {}), 'blocked synchronization cleanup');
    }
  });

  test('joins heartbeat and explicit synchronization into one presence flight', async () => {
    let enrollments = 0;
    let enrollment!: EnrollmentRequest;
    const enrollmentStarted = deferred<void>();
    const secondEnrollmentStarted = deferred<void>();
    const enrollmentResponse = deferred<Response>();
    const sessionsStarted = deferred<void>();
    const sessions = deferred<[]>();
    const relay = Bun.serve({ port: 0, fetch: async (request) => {
      if (new URL(request.url).pathname !== '/v2/bridge/enroll') return new Response('unexpected', { status: 500 });
      enrollment = await request.json() as EnrollmentRequest;
      enrollments += 1;
      if (enrollments === 1) enrollmentStarted.resolve();
      if (enrollments === 2) secondEnrollmentStarted.resolve();
      return enrollmentResponse.promise;
    } });
    servers.push(relay);
    const scheduler = new ControllableScheduler();
    const { daemon } = await createPresenceDaemon(`http://127.0.0.1:${relay.port}`, scheduler, async () => {
      sessionsStarted.resolve();
      return sessions.promise;
    });
    let sync: Promise<unknown> | undefined;
    try {
      await daemon.start();
      scheduler.run(0);
      await waitForPromise(enrollmentStarted.promise, 'heartbeat enrollment to start');
      sync = daemon.syncOnce();
      expect(await Promise.race([
        secondEnrollmentStarted.promise.then(() => 'second-enrollment'),
        Bun.sleep(50).then(() => 'shared-flight'),
      ])).toBe('shared-flight');
      expect(enrollments).toBe(1);
      enrollmentResponse.resolve(createEnrollmentResponse(enrollment, { hostName: 'Heartbeat host' }));
      await waitForPromise(sessionsStarted.promise, 'joined synchronization to enter session listing');
    } finally {
      daemon.stop();
      enrollmentResponse.resolve(new Response('stopped', { status: 503 }));
      sessions.resolve([]);
      if (sync) await waitForPromise(sync.catch(() => {}), 'joined synchronization cleanup');
    }
  });

  test('keeps background presence heartbeats single-flight and cancels scheduling on stop', async () => {
    let enrollments = 0;
    let enrollment!: EnrollmentRequest;
    const enrollmentStarted = deferred<void>();
    const heldEnrollment = deferred<Response>();
    const relay = Bun.serve({ port: 0, fetch: async (request) => {
      if (new URL(request.url).pathname === '/v2/bridge/e2e/recipients') {
        return Response.json({ hostId: 'host-test', recipientSetVersion: 1, recipients: [] });
      }
      enrollment = await request.json() as EnrollmentRequest;
      enrollments += 1;
      enrollmentStarted.resolve();
      return heldEnrollment.promise;
    } });
    servers.push(relay);
    const scheduler = new ControllableScheduler();
    const { daemon } = await createPresenceDaemon(`http://127.0.0.1:${relay.port}`, scheduler, async () => []);
    try {
      await daemon.start();
      expect(scheduler.scheduled[0]?.delayMs).toBe(30_000);
      scheduler.run(0);
      await waitForPromise(enrollmentStarted.promise, 'background heartbeat enrollment to start');
      scheduler.run(0);
      await Bun.sleep(0);
      expect(enrollments).toBe(1);
      heldEnrollment.resolve(createEnrollmentResponse(enrollment, { hostName: 'Heartbeat host' }));
      await waitFor(() => scheduler.scheduled.length >= 2, 'next presence heartbeat schedule');
      daemon.stop();
      expect(scheduler.scheduled[1]?.canceled).toBe(true);
      scheduler.run(1);
      await Bun.sleep(0);
      expect(enrollments).toBe(1);
    } finally {
      daemon.stop();
      heldEnrollment.resolve(new Response('stopped', { status: 503 }));
    }
  });

  test('degrades after a failed presence heartbeat and restores the authoritative Host projection on recovery', async () => {
    const initialLastSeenAt = '2026-08-01T00:00:00.000Z';
    const recoveredLastSeenAt = '2026-08-01T00:01:00.000Z';
    let enrollmentAttempt = 0;
    let enrollment!: EnrollmentRequest;
    const relay = Bun.serve({ port: 0, fetch: async (request) => {
      if (new URL(request.url).pathname !== '/v2/bridge/enroll') return new Response('unexpected', { status: 500 });
      enrollment = await request.json() as EnrollmentRequest;
      enrollmentAttempt += 1;
      if (enrollmentAttempt === 2 || enrollmentAttempt === 3) return new Response('offline', { status: 503 });
      const recovered = enrollmentAttempt === 4;
      return createEnrollmentResponse(enrollment, {
        hostName: recovered ? 'Relay authoritative host' : enrollment.hostName,
        registeredAt: '2026-07-01T00:00:00.000Z',
        lastSeenAt: recovered ? recoveredLastSeenAt : initialLastSeenAt,
      });
    } });
    servers.push(relay);
    const scheduler = new ControllableScheduler();
    const { daemon, statePath } = await createPresenceDaemon(`http://127.0.0.1:${relay.port}`, scheduler, async () => []);
    try {
      await daemon.start();
      scheduler.run(0);
      await waitFor(() => scheduler.scheduled.length >= 2, 'heartbeat schedule after initial presence');
      const initialState = await Bun.file(statePath).json() as { host: { hostId: string; bridgeStatus: string; lastSeenAt: string } };
      expect(initialState.host).toMatchObject({
        hostId: enrollment.hostId, bridgeStatus: 'online', lastSeenAt: initialLastSeenAt,
      });

      scheduler.run(1);
      await waitFor(() => scheduler.scheduled.length >= 3, 'heartbeat schedule after failed presence');
      const degradedState = await Bun.file(statePath).json() as { host: { bridgeStatus: string; lastSeenAt: string } };
      expect(degradedState.host).toMatchObject({ bridgeStatus: 'degraded', lastSeenAt: initialLastSeenAt });
      const operationalSync = await daemon.syncOnce();
      expect(operationalSync).toMatchObject({ offline: true, host: { bridgeStatus: 'degraded', lastSeenAt: initialLastSeenAt } });

      scheduler.run(2);
      await waitFor(() => scheduler.scheduled.length >= 4, 'heartbeat schedule after recovered presence');
      const recoveredState = await Bun.file(statePath).json() as { host: { hostName: string; bridgeStatus: string; lastSeenAt: string } };
      expect(recoveredState.host).toMatchObject({
        hostName: 'Relay authoritative host', bridgeStatus: 'online', lastSeenAt: recoveredLastSeenAt,
      });
    } finally {
      daemon.stop();
    }
  });

  test('flushes a durably bound handle and removes it only after Relay acknowledgement', async () => {
    const daemon = await createLongPollingDaemon('http://127.0.0.1:1');
    const registry = (daemon as any).adapterRegistry;
    const stateStore = (daemon as any).stateStore;
    stateStore.initializeEncryptedSpool(
      (daemon as any).config.hostId, (daemon as any).config.identityPath, 'linux',
      { loadOrCreate: () => new Uint8Array(32).fill(7) },
    );
    registry.register({ sessionId: 'sess-handle', provider: 'pi', projectName: 'project', cwd: '/' });
    stateStore.appendRecentEvent({
      eventId: 'evt-handle', hostId: (daemon as any).config.hostId, sessionId: 'sess-handle', provider: 'pi',
      type: 'done', status: 'idle', agentText: 'Done', createdAt: '2026-08-07T00:00:00.000Z',
    });
    registry.handleSession('sess-handle', { handledThroughEventId: 'evt-handle', action: 'pi_input' });
    const delivered: unknown[] = [];
    (daemon as any).relayClient = {
      handleSession: async (sessionId: string, request: unknown) => { delivered.push({ sessionId, request }); return { ok: true }; },
    };
    await expect((daemon as any).flushPendingHandles()).resolves.toBe(1);
    expect(delivered).toEqual([expect.objectContaining({ sessionId: 'sess-handle' })]);
    expect(stateStore.peekPendingSessionHandles()).toEqual([]);
    daemon.stop();
  });

  test('wakes single-flight reconciliation after a real debounced handle mutation', async () => {
    const templateDaemon = await createLongPollingDaemon('http://127.0.0.1:1');
    const config = (templateDaemon as any).config;
    const identityStore = (templateDaemon as any).identityStore;
    templateDaemon.stop();
    const scheduler = new ControllableScheduler();
    const pollCallbacks: Array<() => void> = [];
    let canceledPollCount = 0;
    const pollScheduler = {
      schedule(callback: () => void, delayMs: number) {
        expect(delayMs).toBe(60_000);
        const handle = Symbol('poll');
        pollCallbacks.push(callback);
        return handle;
      },
      cancel() { canceledPollCount += 1; },
    };
    const daemon = new BridgeDaemon(
      config,
      [{ name: 'test', listSessions: async () => [] }],
      identityStore,
      undefined,
      scheduler,
      pollScheduler,
    );
    const daemonInternals = daemon as any;
    const { adapterRegistry: registry, stateStore } = daemonInternals;
    stateStore.initializeEncryptedSpool(
      daemonInternals.config.hostId, daemonInternals.config.identityPath, 'linux',
      { loadOrCreate: () => new Uint8Array(32).fill(7) },
    );
    registry.register({ sessionId: 'sess-handle', provider: 'pi', projectName: 'project', cwd: '/' });
    stateStore.appendRecentEvent({
      eventId: 'evt-handle', hostId: daemonInternals.config.hostId, sessionId: 'sess-handle', provider: 'pi',
      type: 'done', status: 'idle', agentText: 'Done', createdAt: '2026-08-07T00:00:00.000Z',
    });
    scheduler.run(0);
    const reconciliationScheduleIndex = scheduler.scheduled.length;
    const blockedSecondSync = deferred<unknown>();
    let syncCallCount = 0;
    daemonInternals.startupValidated = true;
    daemonInternals.performSyncOnce = async () => {
      syncCallCount += 1;
      daemonInternals.reconciliationRequested = false;
      if (syncCallCount === 2) return blockedSecondSync.promise;
      return {};
    };

    const run = daemon.runForever();
    try {
      await waitFor(() => pollCallbacks.length === 1, 'initial poll wait');
      expect(syncCallCount).toBe(1);

      registry.handleSession('sess-handle', { handledThroughEventId: 'evt-handle', action: 'pi_input' });
      registry.handleSession('sess-handle', { handledThroughEventId: 'evt-handle', action: 'pi_input' });

      expect(scheduler.scheduled).toHaveLength(reconciliationScheduleIndex + 1);
      expect(scheduler.scheduled[reconciliationScheduleIndex]?.delayMs).toBe(300);
      expect(syncCallCount).toBe(1);
      scheduler.run(reconciliationScheduleIndex);
      await waitFor(() => syncCallCount === 2, 'handle-triggered reconciliation');
      expect(canceledPollCount).toBe(1);

      registry.handleSession('sess-handle', { handledThroughEventId: 'evt-handle', action: 'pi_input' });
      expect(scheduler.scheduled).toHaveLength(reconciliationScheduleIndex + 2);
      expect(scheduler.scheduled[reconciliationScheduleIndex + 1]?.delayMs).toBe(300);
      scheduler.run(reconciliationScheduleIndex + 1);
      await Bun.sleep(0);
      expect(syncCallCount).toBe(2);

      blockedSecondSync.resolve({});
      await waitFor(() => syncCallCount === 3, 'queued reconciliation after active sync');
    } finally {
      daemon.stop();
      blockedSecondSync.resolve({});
      await waitForPromise(run, 'handle reconciliation cleanup');
    }
  });

  test('stop disposes Registry retry lifecycle', async () => {
    const daemon = await createLongPollingDaemon('http://127.0.0.1:1');
    let disposed = 0;
    (daemon as any).adapterRegistry.dispose = () => { disposed += 1; };
    daemon.stop();
    daemon.stop();
    expect(disposed).toBe(1);
  });

  test('stop cancels the polling delay and runForever terminates', async () => {
    const daemon = await createLongPollingDaemon('http://127.0.0.1:1');
    await daemon.start();
    const run = daemon.runForever();
    await Bun.sleep(20);
    daemon.stop();
    await expect(Promise.race([run.then(() => 'stopped'), Bun.sleep(500).then(() => 'timeout')])).resolves.toBe('stopped');
  });

  test('stop cancels the owned long poll timer with an injected scheduler', async () => {
    const base = await createLongPollingDaemon('http://127.0.0.1:1');
    const baseConfig = (base as any).config;
    const baseIdentityStore = (base as any).identityStore;
    base.stop();
    const callbacks: Array<() => void> = [];
    const canceled: symbol[] = [];
    const pollScheduler = {
      schedule(callback: () => void, delayMs: number) {
        expect(delayMs).toBe(60_000);
        const handle = Symbol('poll');
        callbacks.push(callback);
        return handle;
      },
      cancel(handle: unknown) { canceled.push(handle as symbol); },
    };
    const daemon = new BridgeDaemon(
      baseConfig,
      [{ name: 'test', listSessions: async () => [] }],
      baseIdentityStore,
      undefined,
      undefined,
      pollScheduler,
    );
    (daemon as any).startupValidated = true;
    (daemon as any).performSyncOnce = async () => { (daemon as any).reconciliationRequested = false; return {}; };
    const run = daemon.runForever();
    await Promise.resolve();
    await Promise.resolve();
    expect(callbacks).toHaveLength(1);
    daemon.stop();
    await expect(run).resolves.toBeUndefined();
    expect(canceled).toHaveLength(1);
    callbacks[0]!();
    expect((daemon as any).pollWaitTimer).toBeUndefined();
  });

  test('stop aborts an in-flight Relay request and terminates the run loop', async () => {
    let requestStarted!: () => void;
    const started = new Promise<void>((resolveStarted) => { requestStarted = resolveStarted; });
    const relay = Bun.serve({ port: 0, fetch: (request) => {
      if (new URL(request.url).pathname === '/v2/bridge/e2e/recipients') {
        return Response.json({ hostId: 'host-test', recipientSetVersion: 1, recipients: [] });
      }
      return new Promise<Response>(() => {
        requestStarted();
      });
    } });
    servers.push(relay);
    const daemon = await createLongPollingDaemon(`http://127.0.0.1:${relay.port}`);
    await daemon.start();
    const run = daemon.runForever();
    await started;
    daemon.stop();
    await expect(Promise.race([run.then(() => 'stopped'), Bun.sleep(500).then(() => 'timeout')])).resolves.toBe('stopped');
  });

  test('rate-limits and redacts encrypted Event failure logs', () => {
    let now = 30_000;
    const lines: string[] = [];
    const logger = new EncryptedEventFailureLogger((line) => lines.push(line), () => now);

    logger.record({ eventId: 'event-secret', sessionId: 'session-secret', outcome: 'retry-deferred', status: 503, category: 'http' });
    now += 1_000;
    logger.record({ eventId: 'event-secret-2', sessionId: 'session-secret-2', outcome: 'quarantined', status: 409, category: 'event-content' });
    now += 30_000;
    logger.record({ eventId: 'event-secret-3', sessionId: 'session-secret-3', outcome: 'retry-deferred', category: 'network' });

    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('"outcome":"retry-deferred"');
    expect(lines[0]).toContain('"category":"http"');
    expect(lines[1]).toContain('"suppressed":1');
    const output = lines.join('');
    expect(output).not.toContain('event-secret');
    expect(output).not.toContain('session-secret');
  });

  test('CLI help advertises identity-safe pair and no claim-code flow', () => {
    const result = Bun.spawnSync({ cmd: [bunPath, 'run', cliPath], cwd: publicRoot, env: process.env });
    expect(result.exitCode).toBe(0);
    expect(decode(result.stdout)).toContain('pair <PAIRING_CODE>');
    expect(decode(result.stdout)).not.toContain('claim-code');
  });

  test('pairs through signed v2 enrollment and pairing without owner or bearer headers', async () => {
    const root = join(tmpdir(), `bridge-v2-pair-${Date.now()}`); roots.push(root);
    mkdirSync(root, { mode: 0o700 });
    const identityPath = join(root, 'identity.json');
    const identity = await new LinuxJsonHostIdentityStore(identityPath).createFirstRun();
    const paths: string[] = [];
    const server = Bun.serve({ port: 0, fetch: async (request) => {
      const url = new URL(request.url); paths.push(url.pathname);
      expect(request.headers.get('x-ariava-entity-id')).toBe(identity.hostId);
      expect(request.headers.get('x-ariava-key-id')).toBe(identity.keyId);
      expect(request.headers.has('x-host-auth')).toBe(false);
      expect(request.headers.has('authorization')).toBe(false);
      if (url.pathname === '/v2/bridge/e2e/recipients') {
        return Response.json({ hostId: identity.hostId, recipientSetVersion: 1, recipients: [] });
      }
      if (url.pathname === '/v2/bridge/enroll') {
        const body = await request.json() as any;
        expect(body).toMatchObject({ hostId: identity.hostId, platform: 'linux' });
        expect(body).not.toHaveProperty('ownerUserId');
        return Response.json({ host: { hostId: identity.hostId, hostName: 'Linux host', platform: 'linux', bridgeVersion: '0.1.2', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' } });
      }
      if (url.pathname === '/v2/bridge/pair-watch') {
        expect(await request.json()).toEqual({ pairingCode: 'PEYX7K' });
        return Response.json({
          host: { hostId: identity.hostId, hostName: 'Linux host', platform: 'linux', bridgeVersion: '0.1.2', registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), bridgeStatus: 'online' },
          watchDevice: { watchDeviceId: `watch_${'C'.repeat(43)}`, selectedHostIds: [identity.hostId], registeredAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), pairingStatus: 'paired' },
          link: { hostId: identity.hostId, watchDeviceId: `watch_${'C'.repeat(43)}`, pairedAt: new Date().toISOString(), generation: 1, updatedAt: new Date().toISOString() }, alreadyPaired: false,
        });
      }
      return new Response('not found', { status: 404 });
    } }); servers.push(server);
    const config = loadBridgeConfig();
    Object.assign(config, { runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, hostName: 'Linux host',
      identity: publicIdentityMetadata(identity),
      bridgeVersion: '0.1.2', relayBaseUrl: `http://127.0.0.1:${server.port}`, identityPath,
      configPath: join(root, 'config.json'), statePath: join(root, 'state.json'), agentAdapter: { ...config.agentAdapter, configPath: join(root, 'adapter.json') } });
    const result = await new BridgeDaemon(config).pairWatch('peyx7k');
    expect(result.watchDevice.watchDeviceId).toBe(`watch_${'C'.repeat(43)}`);
    expect(paths).toEqual(['/v2/bridge/e2e/recipients', '/v2/bridge/enroll', '/v2/bridge/pair-watch']);
  });
});
