import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmodSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { base64UrlEncode } from '../../../packages/protocol/dist/index.js';
import { BridgeDaemon } from '../dist/daemon.js';
import { spoolPathForState } from '../dist/e2e/local-spool.js';

const childScript = String.raw`
  import { mkdtempSync } from 'node:fs';
  import { tmpdir } from 'node:os';
  import { join } from 'node:path';
  import { BridgeDaemon } from './apps/bridge/dist/daemon.js';
  const runtimeRoot = mkdtempSync(join(tmpdir(), 'ariava-node-shutdown-'));

  const daemon = Object.create(BridgeDaemon.prototype);
  Object.assign(daemon, {
    stopped: false,
    reconciliationRequested: true,
    relayAbortController: new AbortController(),
    config: { pollIntervalMs: 60_000 },
    pollWaitScheduler: {
      schedule: (callback, delayMs) => setTimeout(callback, delayMs),
      cancel: (handle) => clearTimeout(handle),
    },
    adapterServer: { stop() {} },
    stateStore: { dispose() {} },
    runtimeCoordinator: { dispose() {} },
    syncOnce: async () => {
      daemon.reconciliationRequested = false;
      return {};
    },
  });

  const registry = Object.getOwnPropertyDescriptor(daemon, 'adapterRegistry')?.value;
  assert.equal(registry, undefined);
  const realDaemon = new BridgeDaemon({
    hostId: 'host-test',
    hostName: 'test',
    hostPlatform: 'linux',
    relayBaseUrl: 'http://relay.invalid',
    statePath: join(runtimeRoot, 'state.json'),
    identityPath: join(runtimeRoot, 'identity.json'),
    configPath: join(runtimeRoot, 'config.json'),
    runtimePlatform: 'linux',
    pollIntervalMs: 60_000,
    bridgeVersion: 'test',
    agentAdapter: { port: 0, secret: 'test', configPath: join(runtimeRoot, 'adapter.json') },
  }, []);
  const ownedRegistry = realDaemon.adapterRegistry;
  const waiter = ownedRegistry.waitForResult('command-long-wait', { timeoutMs: 60_000 });
  daemon.adapterRegistry = ownedRegistry;
  realDaemon.stop();

  const run = daemon.runForever();
  await new Promise((resolve) => setImmediate(resolve));
  daemon.stop();
  assert.equal(await waiter, undefined);
  await run;
  assert.equal(process.getActiveResourcesInfo().filter((type) => type === 'Timeout').length, 0);
  console.log('SHUTDOWN_OK');
`;

test('production Node exits after canceling long result-waiter and daemon poll timers', async () => {
  const child = spawn(process.execPath, ['--input-type=module', '--eval', childScript], {
    cwd: process.cwd(),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });

  let timeoutHandle;
  const outcome = await Promise.race([
    new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal }))),
    new Promise((resolve) => { timeoutHandle = setTimeout(() => resolve({ timeout: true }), 2_000); }),
  ]);
  clearTimeout(timeoutHandle);
  if ('timeout' in outcome) child.kill('SIGKILL');
  assert.deepEqual(outcome, { code: 0, signal: null }, stderr);
  assert.match(stdout, /SHUTDOWN_OK/u);
});

test('production daemon defers old-state decoding until startup preflight resets the runtime', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-daemon-startup-reset-'));
  chmodSync(dir, 0o700);
  const statePath = join(dir, 'state.json');
  const identityPath = join(dir, 'identity.json');
  const configPath = join(dir, 'config.json');
  const adapterPath = join(dir, 'adapter.json');
  const oldStateBytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, pendingEvents: [] })}\n`);
  const key = new Uint8Array(32).fill(7);
  const keyPath = `${identityPath}.spool-key.json`;
  const keyBytes = Buffer.from(`${JSON.stringify({ version: 1, hostId: 'host-test', key: base64UrlEncode(key) })}\n`);
  writeFileSync(statePath, oldStateBytes, { mode: 0o600 });
  writeFileSync(keyPath, keyBytes, { mode: 0o600 });
  writeFileSync(configPath, '{}\n', { mode: 0o600 });
  const identity = {
    identityVersion: 2, hostId: 'host-test', keyId: 'key-test', algorithm: 'Ed25519', publicKey: 'public-test',
    publicKeyFingerprint: 'fingerprint-test', createdAt: '2026-08-07T00:00:00.000Z',
    privateKeyStorage: { type: 'linux-json', path: identityPath },
    signer: { entityId: 'host-test', keyId: 'key-test', sign: async () => '', signRequest: async () => ({}) },
  };
  const identityStore = { load: async () => identity };
  const identityMetadata = { ...identity };
  delete identityMetadata.signer;
  const config = {
    hostId: identity.hostId, hostName: 'Test', hostPlatform: 'linux', relayBaseUrl: 'http://relay.invalid',
    statePath, identityPath, configPath, runtimePlatform: 'linux', identity: identityMetadata,
    pollIntervalMs: 60_000, bridgeVersion: 'test',
    agentAdapter: { port: 0, secret: 'test-secret', configPath: adapterPath },
  };

  try {
    const daemon = new BridgeDaemon(config, [], identityStore);
    assert.deepEqual(readFileSync(statePath), oldStateBytes);
    await daemon.validateStartup();
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    const spool = JSON.parse(readFileSync(spoolPathForState(statePath), 'utf8'));
    assert.equal(state.schemaVersion, 3);
    assert.equal(state.runtimeResetEpoch, spool.runtimeResetEpoch);
    assert.deepEqual(state.recentEvents, []);
    assert.deepEqual(spool.items, []);
    assert.deepEqual(readFileSync(keyPath), keyBytes);
    daemon.stop();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('unknown runtime state fails before E2E identity, keyring, spool key, or adapter creation', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-daemon-startup-unknown-'));
  chmodSync(dir, 0o700);
  const statePath = join(dir, 'state.json'); const identityPath = join(dir, 'identity.json');
  const configPath = join(dir, 'config.json'); const adapterPath = join(dir, 'adapter.json');
  const stateBytes = Buffer.from('{"schemaVersion":999,"protected":"UNKNOWN_STARTUP_BYTES"}\n');
  const configBytes = Buffer.from('{}\n');
  writeFileSync(statePath, stateBytes, { mode: 0o600 }); writeFileSync(configPath, configBytes, { mode: 0o600 });
  const identity = {
    identityVersion: 2, hostId: 'host-test', keyId: 'key-test', algorithm: 'Ed25519', publicKey: 'public-test',
    publicKeyFingerprint: 'fingerprint-test', createdAt: '2026-08-07T00:00:00.000Z',
    privateKeyStorage: { type: 'linux-json', path: identityPath },
    signer: { entityId: 'host-test', keyId: 'key-test', sign: async () => '', signRequest: async () => ({}) },
  };
  const identityMetadata = { ...identity }; delete identityMetadata.signer;
  const config = {
    hostId: identity.hostId, hostName: 'Test', hostPlatform: 'linux', relayBaseUrl: 'http://relay.invalid',
    statePath, identityPath, configPath, runtimePlatform: 'linux', identity: identityMetadata,
    pollIntervalMs: 60_000, bridgeVersion: 'test',
    agentAdapter: { port: 0, secret: 'test-secret', configPath: adapterPath },
  };
  const absent = [spoolPathForState(statePath), `${identityPath}.spool-key.json`, `${identityPath}.e2e.json`,
    `${identityPath}.e2e-keyring.json`, adapterPath, `${statePath}.runtime-reset.json`];
  try {
    const daemon = new BridgeDaemon(config, [], { load: async () => identity });
    await assert.rejects(daemon.validateStartup(), /preflight failed closed/i);
    assert.deepEqual(readFileSync(statePath), stateBytes); assert.deepEqual(readFileSync(configPath), configBytes);
    for (const path of absent) assert.equal(lstatSync(path, { throwIfNoEntry: false }), undefined, path);
    daemon.stop();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
