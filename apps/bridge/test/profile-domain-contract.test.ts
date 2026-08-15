import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'bun:test';
import { initializeProfile } from '../src/cli/operations/initialize';
import { inspectProfileIdentity, resetProfileIdentity } from '../src/cli/operations/identity';
import { pairProfile, type PairProfileDependencies } from '../src/cli/operations/pair';
import { watchesProfile, type WatchesProfileDependencies } from '../src/cli/operations/watches';
import { runConfigCommand } from '../src/cli/commands/config';
import { probeProfile } from '../src/cli/probes/profile';
import {
  base64UrlEncode,
  E2E_SUITE_V1,
  normalizePairingCode,
  type BridgePairWatchResponse,
  type E2EPendingLinkProjectionV1,
  type EncryptionKeyBindingV1,
} from '@ariava/protocol';
import {
  PROFILE_ACCESS_KINDS,
  createProfileCliHarness,
  type ProfileCliHarness,
} from './fixtures/profile-cli-harness';

const harnesses: ProfileCliHarness[] = [];

afterEach(() => {
  for (const harness of harnesses.splice(0)) harness.cleanup();
});

describe('shared profile status probes', () => {
  test.each(['default', 'dev'] as const)('%s probes config, identity, Relay, Adapter, paths, and runtime without counterpart access', async (profileId) => {
    const harness = createHarness();
    await initializeProfile(harness.contexts[profileId]);
    resetLog(harness);
    const unselected = profileId === 'default' ? 'dev' : 'default';
    const sentinel = harness.sentinelBytes(unselected);
    const evidence = await probeProfile({
      context: () => harness.contexts[profileId],
      pathExists: () => false,
      runtime: () => ({
        nodeFound: true,
        runtimeNameIsNode: true,
        runtimeVersionSupported: true,
        runtimeCryptoSelfTestPassed: true,
      }),
      readAdapter: () => null,
    });
    expect(evidence).toMatchObject({
      profile: profileId,
      configComplete: true,
      identity: { status: 'ready' },
      relay: { configured: true, baseUrl: harness.profiles[profileId].defaultRelayBaseUrl },
      adapter: { present: false, valid: false, url: null, port: harness.profiles[profileId].resources.agentAdapterPort },
      paths: {
        configPath: harness.profiles[profileId].resources.configPath,
        identityPath: harness.profiles[profileId].resources.identityMetadataPath,
        statePath: harness.profiles[profileId].resources.statePath,
        discoveryPath: harness.profiles[profileId].resources.agentAdapterConfigPath,
        piLogPath: harness.profiles[profileId].resources.piExtensionLogPath,
      },
      runtime: { nodeFound: true, runtimeNameIsNode: true, runtimeVersionSupported: true, runtimeCryptoSelfTestPassed: true },
    });
    expect(harness.counters[profileId].filesystemReads).toBeGreaterThan(0);
    expect(harness.counters[profileId].filesystemWrites).toBe(0);
    expect(harness.counters[profileId].keychainProbes).toBe(1);
    for (const kind of ['keychainReads', 'keychainWrites', 'keychainDeletes', 'relaySigners', 'relayRequests', 'childSpawns', 'serviceRunnerCalls'] as const) {
      expect(harness.counters[profileId][kind], `${profileId}.${kind}`).toBe(0);
    }
    expect(harness.sentinelBytes(unselected)).toEqual(sentinel);
    expectZeroAccess(harness, unselected);
  });

  test.each(['default', 'dev'] as const)('%s rejects discovery on the counterpart profile port without counterpart access', async (profileId) => {
    const harness = createHarness();
    await initializeProfile(harness.contexts[profileId]);
    const unselected = profileId === 'default' ? 'dev' : 'default';
    writeFileSync(
      harness.profiles[profileId].resources.agentAdapterConfigPath,
      JSON.stringify({
        url: `http://127.0.0.1:${harness.profiles[unselected].resources.agentAdapterPort}`,
        secret: `${profileId}-discovery-secret`,
      }),
      { mode: 0o600 },
    );
    resetLog(harness);
    const sentinel = harness.sentinelBytes(unselected);

    const evidence = await probeProfile({
      context: () => harness.contexts[profileId],
      pathExists: existsSync,
      runtime: () => ({
        nodeFound: true,
        runtimeNameIsNode: true,
        runtimeVersionSupported: true,
        runtimeCryptoSelfTestPassed: true,
      }),
    });

    expect(evidence.adapter).toEqual({
      configPath: harness.profiles[profileId].resources.agentAdapterConfigPath,
      present: true,
      valid: false,
      url: null,
      port: harness.profiles[profileId].resources.agentAdapterPort,
    });
    expect(harness.sentinelBytes(unselected)).toEqual(sentinel);
    expectZeroAccess(harness, unselected);
  });
});


describe('profile-aware config mutation policy', () => {
  test.each(['default', 'dev'] as const)('%s config command matrix uses only the selected profile and redacts secrets', async (profileId) => {
    const harness = createHarness();
    const context = harness.contexts[profileId];
    const profile = harness.profiles[profileId];
    const unselected = profileId === 'default' ? 'dev' : 'default';
    const unselectedSentinel = harness.sentinelBytes(unselected);
    await initializeProfile(context);

    resetLog(harness);
    const pathBytes = readFileSync(profile.resources.configPath);
    const path = await runConfigCommand(['path'], context);
    expect(path).toEqual({
      envelope: {
        ok: true,
        code: 'ok',
        message: 'Resolved Ariava config path.',
        data: { configPath: profile.resources.configPath },
      },
      human: profile.resources.configPath,
    });
    expect(readFileSync(profile.resources.configPath)).toEqual(pathBytes);
    expectSelectedConfigEffect(harness, profileId, 0, unselectedSentinel);

    resetLog(harness);
    const showBytes = readFileSync(profile.resources.configPath);
    const shown = await runConfigCommand(['show'], context);
    const shownData = shown.envelope.data as {
      config: Record<string, unknown>;
      resolved: Record<string, unknown>;
    };
    expect(shownData.config).toMatchObject({
      relayBaseUrl: profile.defaultRelayBaseUrl,
      hostName: profile.defaultHostName('fixture-host'),
    });
    expect(shownData.config).not.toHaveProperty('agentAdapterSecret');
    expect(shownData.resolved).toMatchObject({
      configPath: profile.resources.configPath,
      agentAdapterSecret: '<redacted>',
    });
    expect(shown.human).toContain(profile.resources.configPath);
    expect(JSON.stringify(shown)).not.toContain(`${profileId}-secret`);
    expect(readFileSync(profile.resources.configPath)).toEqual(showBytes);
    expectSelectedConfigEffect(harness, profileId, 0, unselectedSentinel);

    resetLog(harness);
    const getBytes = readFileSync(profile.resources.configPath);
    const hostName = await runConfigCommand(['get', 'hostName'], context);
    expect(hostName).toEqual({
      envelope: {
        ok: true,
        code: 'ok',
        message: 'Read config key hostName.',
        data: { key: 'hostName', value: profile.defaultHostName('fixture-host') },
      },
      human: profile.defaultHostName('fixture-host'),
    });
    expect(readFileSync(profile.resources.configPath)).toEqual(getBytes);
    expectSelectedConfigEffect(harness, profileId, 0, unselectedSentinel);

    for (const { key, input, stored, displayed } of [
      {
        key: 'relayBaseUrl',
        input: `https://${profileId}.relay.example.test`,
        stored: `https://${profileId}.relay.example.test`,
        displayed: `https://${profileId}.relay.example.test`,
      },
      {
        key: 'hostName',
        input: `${profileId} configured host`,
        stored: `${profileId} configured host`,
        displayed: `${profileId} configured host`,
      },
      { key: 'pollIntervalMs', input: '2500', stored: 2500, displayed: 2500 },
      {
        key: 'agentAdapterSecret',
        input: `${profileId}-set-secret`,
        stored: `${profileId}-set-secret`,
        displayed: '<redacted>',
      },
    ] as const) {
      resetLog(harness);
      const before = readFileSync(profile.resources.configPath);
      const updated = await runConfigCommand(['set', key, input], context);
      const after = readFileSync(profile.resources.configPath);

      expect(updated.envelope.data).toEqual({ key, value: displayed });
      expect(updated.human).toBe(`Updated ${key}`);
      expect(harness.config(profileId)[key]).toBe(stored);
      expect(after).not.toEqual(before);
      if (key === 'agentAdapterSecret') {
        expect(JSON.stringify(updated)).not.toContain(input);
      } else {
        expect(JSON.stringify(updated)).toContain(String(displayed));
      }
      expectSelectedConfigEffect(harness, profileId, 1, unselectedSentinel);
    }

    const withoutSecret = harness.config(profileId);
    delete withoutSecret.agentAdapterSecret;
    context.config.save(withoutSecret, profile.resources.configPath);
    const ensuredSecret = `${profileId}-ensured-secret`;
    const rotatedSecret = `${profileId}-rotated-secret`;
    const generatedSecrets = [ensuredSecret, rotatedSecret];
    context.generateSecret = () => {
      const generated = generatedSecrets.shift();
      if (!generated) throw new Error('Unexpected extra secret generation');
      return generated;
    };

    resetLog(harness);
    const ensureBefore = readFileSync(profile.resources.configPath);
    const ensured = await runConfigCommand(['agent-secret', 'ensure'], context);
    const ensureAfter = readFileSync(profile.resources.configPath);
    expect(ensured.envelope.data).toEqual({ generated: true, rotated: false });
    expect(ensured.human).toBe('Generated Agent Adapter secret.');
    expect(JSON.stringify(ensured)).not.toContain(ensuredSecret);
    expect(harness.config(profileId).agentAdapterSecret).toBe(ensuredSecret);
    expect(ensureAfter).not.toEqual(ensureBefore);
    expectSelectedConfigEffect(harness, profileId, 1, unselectedSentinel);

    resetLog(harness);
    const idempotentBefore = readFileSync(profile.resources.configPath);
    const ensuredAgain = await runConfigCommand(['agent-secret', 'ensure'], context);
    expect(ensuredAgain.envelope.data).toEqual({ generated: false, rotated: false });
    expect(ensuredAgain.human).toBe('Agent Adapter secret already configured.');
    expect(JSON.stringify(ensuredAgain)).not.toContain(ensuredSecret);
    expect(readFileSync(profile.resources.configPath)).toEqual(idempotentBefore);
    expect(harness.config(profileId).agentAdapterSecret).toBe(ensuredSecret);
    expectSelectedConfigEffect(harness, profileId, 0, unselectedSentinel);

    resetLog(harness);
    const rotateBefore = readFileSync(profile.resources.configPath);
    const rotated = await runConfigCommand(['agent-secret', 'rotate'], context);
    const rotateAfter = readFileSync(profile.resources.configPath);
    expect(rotated.envelope.data).toEqual({ generated: true, rotated: true });
    expect(rotated.human).toBe(profileId === 'dev'
      ? 'Rotated Agent Adapter secret. Restart the source Bridge and reload pi sessions.'
      : 'Rotated Agent Adapter secret. Restart the Ariava service and reload pi sessions.');
    expect(JSON.stringify(rotated)).not.toContain(ensuredSecret);
    expect(JSON.stringify(rotated)).not.toContain(rotatedSecret);
    expect(harness.config(profileId).agentAdapterSecret).toBe(rotatedSecret);
    expect(rotateAfter).not.toEqual(rotateBefore);
    expectSelectedConfigEffect(harness, profileId, 1, unselectedSentinel);

    resetLog(harness);
    const redactionBytes = readFileSync(profile.resources.configPath);
    const redacted = await runConfigCommand(['get', 'agentAdapterSecret'], context);
    expect(redacted.envelope.data).toEqual({ key: 'agentAdapterSecret', value: '<redacted>' });
    expect(redacted.human).toBe('<redacted>');
    expect(JSON.stringify(redacted)).not.toContain(rotatedSecret);
    expect(readFileSync(profile.resources.configPath)).toEqual(redactionBytes);
    expectSelectedConfigEffect(harness, profileId, 0, unselectedSentinel);
  });

  test('default preserves safe pre-existing custom resources without writes or dev access', async () => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.default);
    const configPath = harness.profiles.default.resources.configPath;
    const customRoot = join(harness.root, 'custom-default-resources');
    const customConfig = {
      ...harness.config('default'),
      statePath: join(customRoot, 'state', '..', 'bridge-state.json'),
      agentAdapterConfigPath: join(customRoot, 'adapter', '..', 'agent-adapter.json'),
      agentAdapterPort: 8123,
    };
    writeFileSync(configPath, `${JSON.stringify(customConfig, null, 2)}\n`, { mode: 0o600 });
    const before = readFileSync(configPath);
    const devSentinel = harness.sentinelBytes('dev');
    resetLog(harness);

    const shown = await runConfigCommand(['show'], harness.contexts.default);

    expect((shown.envelope.data as { resolved: Record<string, unknown> }).resolved).toMatchObject({
      statePath: join(customRoot, 'bridge-state.json'),
      agentAdapterConfigPath: join(customRoot, 'agent-adapter.json'),
      agentAdapterPort: 8123,
    });
    expect(readFileSync(configPath)).toEqual(before);
    expectSelectedConfigEffect(harness, 'default', 0, devSentinel);
    expect(harness.filesystemProbeReads.dev).toBe(0);
  });

  test('default config set supports safe custom state, discovery, and port resources', async () => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.default);
    const customRoot = join(harness.root, 'configured-default-resources');
    const devSentinel = harness.sentinelBytes('dev');
    const cases = [
      ['statePath', join(customRoot, 'state', '..', 'bridge-state.json'), join(customRoot, 'bridge-state.json')],
      ['agentAdapterConfigPath', join(customRoot, 'adapter', '..', 'agent-adapter.json'), join(customRoot, 'agent-adapter.json')],
      ['agentAdapterPort', '8124', 8124],
    ] as const;

    for (const [key, input, stored] of cases) {
      resetLog(harness);
      const updated = await runConfigCommand(['set', key, input], harness.contexts.default);

      expect(updated.envelope.data).toEqual({ key, value: stored });
      expect(harness.config('default')[key]).toBe(stored);
      expectSelectedConfigEffect(harness, 'default', 1, devSentinel);
      expect(harness.filesystemProbeReads.dev).toBe(0);
    }
  });

  test('default rejects invalid custom resource mutations with bytes unchanged and no dev access', async () => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.default);
    const configPath = harness.profiles.default.resources.configPath;
    const outside = join(harness.root, 'default-resource-symlink-target');
    mkdirSync(outside, { recursive: true, mode: 0o700 });
    const link = join(harness.profiles.default.resources.root, 'custom-resource-link');
    symlinkSync(outside, link);
    const dev = harness.profiles.dev.resources;
    const cases = [
      ['statePath', 'relative-state.json'],
      ['statePath', dev.statePath],
      ['statePath', join(link, 'bridge-state.json')],
      ['agentAdapterConfigPath', 'relative-adapter.json'],
      ['agentAdapterConfigPath', dev.agentAdapterConfigPath],
      ['agentAdapterConfigPath', join(link, 'agent-adapter.json')],
      ['agentAdapterPort', 'not-a-port'],
      ['agentAdapterPort', '0'],
      ['agentAdapterPort', '65536'],
      ['agentAdapterPort', String(dev.agentAdapterPort)],
    ] as const;

    for (const [key, value] of cases) {
      const before = readFileSync(configPath);
      const devSentinel = harness.sentinelBytes('dev');
      resetLog(harness);

      await expect(runConfigCommand(['set', key, value], harness.contexts.default)).rejects.toThrow();

      expect(readFileSync(configPath)).toEqual(before);
      expectSelectedConfigEffect(harness, 'default', 0, devSentinel);
      expect(harness.filesystemProbeReads.dev).toBe(0);
    }
  });

  test('default rejects unsafe pre-existing custom resources before mutation with bytes unchanged', async () => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.default);
    const configPath = harness.profiles.default.resources.configPath;
    const current = harness.config('default');
    const outside = join(harness.root, 'default-preexisting-symlink-target');
    mkdirSync(outside, { recursive: true, mode: 0o700 });
    const link = join(harness.profiles.default.resources.root, 'preexisting-resource-link');
    symlinkSync(outside, link);
    const cases = [
      { ...current, statePath: harness.profiles.dev.resources.statePath },
      { ...current, statePath: join(link, 'bridge-state.json') },
      { ...current, agentAdapterConfigPath: harness.profiles.dev.resources.agentAdapterConfigPath },
      { ...current, agentAdapterConfigPath: join(link, 'agent-adapter.json') },
      { ...current, agentAdapterPort: harness.profiles.dev.resources.agentAdapterPort },
    ];

    for (const candidate of cases) {
      writeFileSync(configPath, `${JSON.stringify(candidate, null, 2)}\n`, { mode: 0o600 });
      const before = readFileSync(configPath);
      const devSentinel = harness.sentinelBytes('dev');
      resetLog(harness);

      await expect(runConfigCommand(['set', 'hostName', 'updated'], harness.contexts.default)).rejects.toThrow();

      expect(readFileSync(configPath)).toEqual(before);
      expectSelectedConfigEffect(harness, 'default', 0, devSentinel);
      expect(harness.filesystemProbeReads.dev).toBe(0);
    }
  });

  test('dev continues to deny all fixed resource mutations with bytes unchanged', async () => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.dev);
    const configPath = harness.profiles.dev.resources.configPath;
    const before = readFileSync(configPath);
    const defaultSentinel = harness.sentinelBytes('default');

    for (const [key, value] of [
      ['identityPath', harness.profiles.dev.resources.identityMetadataPath],
      ['statePath', harness.profiles.dev.resources.statePath],
      ['agentAdapterConfigPath', harness.profiles.dev.resources.agentAdapterConfigPath],
      ['agentAdapterPort', String(harness.profiles.dev.resources.agentAdapterPort)],
    ] as const) {
      resetLog(harness);
      await expect(runConfigCommand(['set', key, value], harness.contexts.dev)).rejects.toThrow(/managed/);
      expect(readFileSync(configPath)).toEqual(before);
      expectSelectedConfigEffect(harness, 'dev', 0, defaultSentinel);
    }
  });

  test.each(['default', 'dev'] as const)('%s rejects a truly unknown ambiguous mutation before write', async (profileId) => {
    const harness = createHarness();
    const unselected = profileId === 'default' ? 'dev' : 'default';
    const unselectedSentinel = harness.sentinelBytes(unselected);
    await initializeProfile(harness.contexts[profileId]);
    const configPath = harness.profiles[profileId].resources.configPath;
    const before = readFileSync(configPath);
    resetLog(harness);

    let failure: unknown;
    try {
      await runConfigCommand(
        ['set', 'ambiguousResourcePath', harness.profiles[unselected].resources.root],
        harness.contexts[profileId],
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toMatchObject({
      code: 'ERR_IDENTITY_MANAGED_CONFIG',
      message: 'ambiguousResourcePath is managed by the profile or identity subsystem and cannot be set manually.',
    });
    expect(readFileSync(configPath)).toEqual(before);
    expectSelectedConfigEffect(harness, profileId, 0, unselectedSentinel);
  });
});

describe('profile-aware initialization and identity inspection', () => {
  test.each(['default', 'dev'] as const)('%s initialization validates before effects and isolates the other profile', async (profileId) => {
    const harness = createHarness();
    const unselected = profileId === 'default' ? 'dev' : 'default';
    const sentinelBefore = harness.sentinelBytes(unselected);

    const result = await initializeProfile(harness.contexts[profileId]);

    expect(result.config).toMatchObject({
      relayBaseUrl: profileId === 'default' ? 'https://ariava-relay.noyx.io' : 'http://127.0.0.1:8790',
      hostName: profileId === 'default' ? 'fixture-host' : 'fixture-host (Dev)',
      agentAdapterPort: profileId === 'default' ? 7272 : 7273,
      agentAdapterSecret: `${profileId}-secret`,
      identityPath: harness.profiles[profileId].resources.identityMetadataPath,
      statePath: harness.profiles[profileId].resources.statePath,
      agentAdapterConfigPath: harness.profiles[profileId].resources.agentAdapterConfigPath,
    });
    expect(result.inspection).toMatchObject({ status: 'ready', path: harness.profiles[profileId].resources.identityMetadataPath });
    expect(firstAction(harness, profileId)).toBe('descriptor.validate');
    expect(actionIndex(harness, profileId, 'descriptor.validate')).toBeLessThan(actionIndex(harness, profileId, 'filesystemReads'));
    expect(actionIndex(harness, profileId, 'descriptor.validate')).toBeLessThan(actionIndex(harness, profileId, 'filesystemProbeReads'));
    expect(actionIndex(harness, profileId, 'resolved.validate')).toBeLessThan(actionIndex(harness, profileId, 'filesystemWrites'));
    expect(actionIndex(harness, profileId, 'resolved.validate')).toBeLessThan(actionIndex(harness, profileId, 'keychainProbes'));
    if (profileId === 'default') {
      expect(actionIndex(harness, profileId, 'filesystemWrites')).toBeLessThan(actionIndex(harness, profileId, 'keychainProbes'));
    }
    expect(harness.config(profileId).identity?.hostId).toBe(result.inspection.hostId);
    expect(harness.sentinelBytes(unselected)).toEqual(sentinelBefore);
    expect(harness.filesystemProbeReads[profileId]).toBeGreaterThan(0);
    expect(harness.filesystemProbeReads[unselected], `${unselected}.filesystemProbeReads`).toBe(0);
    expectZeroAccess(harness, unselected);
  });

  test.each(['default', 'dev'] as const)('%s identity inspection validates before store access and isolates the other profile', async (profileId) => {
    const harness = createHarness();
    const unselected = profileId === 'default' ? 'dev' : 'default';
    await initializeProfile(harness.contexts[profileId]);
    resetLog(harness);
    const sentinelBefore = harness.sentinelBytes(unselected);

    const inspection = await inspectProfileIdentity(harness.contexts[profileId]);

    expect(inspection).toMatchObject({ status: 'ready', path: harness.profiles[profileId].resources.identityMetadataPath });
    expect(firstAction(harness, profileId)).toBe('descriptor.validate');
    expect(actionIndex(harness, profileId, 'descriptor.validate')).toBeLessThan(actionIndex(harness, profileId, 'filesystemReads'));
    expect(actionIndex(harness, profileId, 'descriptor.validate')).toBeLessThan(actionIndex(harness, profileId, 'filesystemProbeReads'));
    expect(actionIndex(harness, profileId, 'resolved.validate')).toBeLessThan(actionIndex(harness, profileId, 'keychainProbes'));
    expect(harness.sentinelBytes(unselected)).toEqual(sentinelBefore);
    expect(harness.filesystemProbeReads[profileId]).toBeGreaterThan(0);
    expect(harness.filesystemProbeReads[unselected], `${unselected}.filesystemProbeReads`).toBe(0);
    expectZeroAccess(harness, unselected);
  });
});

describe('profile-aware identity reset', () => {
  test.each(['default', 'dev'] as const)('%s confirmed reset replaces and enrolls only selected profile resources', async (profileId) => {
    const harness = createHarness();
    const unselected = profileId === 'default' ? 'dev' : 'default';
    await initializeProfile(harness.contexts[profileId]);
    resetLog(harness);
    const sentinelBefore = harness.sentinelBytes(unselected);
    let enrollment: Record<string, unknown> | undefined;

    const result = await resetProfileIdentity(harness.contexts[profileId], {
      bridgeVersion: '1.2.3-test',
      revoke: async (_identity, relayBaseUrl) => (relayBaseUrl.startsWith('http') ? 'revoked' : 'identity-already-revoked'),
      replace: (store, operationId) => store.resetAfterExplicitConfirmation(operationId),
      enroll: async (relayBaseUrl, identity, metadata, encryptionIdentity) => {
        enrollment = {
          relayBaseUrl,
          signerEntityId: identity.signer.entityId,
          hostName: metadata.hostName,
          platform: metadata.platform,
          bridgeVersion: metadata.bridgeVersion,
          encryptionHostId: encryptionIdentity.hostId,
        };
      },
    });

    expect(result.links).toEqual([]);
    expect(enrollment).toMatchObject({
      relayBaseUrl: profileId === 'default' ? 'https://ariava-relay.noyx.io' : 'http://127.0.0.1:8790',
      signerEntityId: result.hostId,
      hostName: profileId === 'default' ? 'fixture-host' : 'fixture-host (Dev)',
      platform: 'macos',
      bridgeVersion: '1.2.3-test',
    });
    expect(harness.config(profileId).identity).toMatchObject({ hostId: result.hostId, keyId: result.keyId });
    expect(enrollment).toMatchObject({ encryptionHostId: result.hostId });
    expect(harness.sentinelBytes(unselected)).toEqual(sentinelBefore);
    expectZeroAccess(harness, unselected);
  });

  test.each([
    {
      name: 'ambient cross-profile identity path',
      expectedError: /overlaps the dev profile/,
      identityPath(harness: ProfileCliHarness) {
        return harness.profiles.dev.resources.identityMetadataPath;
      },
    },
    {
      name: 'ambient symlink-escape identity path',
      expectedError: /symlink|escape/,
      identityPath(harness: ProfileCliHarness) {
        const outside = join(harness.root, 'ambient-identity-target');
        const link = join(harness.profiles.default.resources.root, 'ambient-identity-link');
        mkdirSync(outside, { recursive: true, mode: 0o700 });
        symlinkSync(outside, link);
        return join(link, 'host-identity.json');
      },
    },
  ])('default reset rejects $name before every effect when persisted identityPath is omitted', async ({
    expectedError,
    identityPath,
  }) => {
    const harness = createHarness();
    const context = harness.contexts.default;
    await initializeProfile(context);
    const persisted = harness.config('default');
    delete persisted.identityPath;
    context.config.save(persisted, harness.profiles.default.resources.configPath);
    context.environment.ARIAVA_HOST_IDENTITY_PATH = identityPath(harness);
    resetLog(harness);

    let resetCalls = 0;
    let encryptionReplacementCalls = 0;
    let configWrites = 0;
    let enrollmentCalls = 0;
    const originalEncryptionCreate = context.encryptionIdentity.create;
    context.encryptionIdentity.create = (resources, platform) => {
      const store = originalEncryptionCreate(resources, platform);
      const originalReplaceForReset = store.replaceForReset.bind(store);
      store.replaceForReset = (hostId) => {
        encryptionReplacementCalls += 1;
        return originalReplaceForReset(hostId);
      };
      return store;
    };
    const originalConfigSave = context.config.save;
    context.config.save = (config, path) => {
      configWrites += 1;
      originalConfigSave(config, path);
    };

    await expect(resetProfileIdentity(context, {
      bridgeVersion: '1.2.3-test',
      revoke: async () => {
        resetCalls += 1;
        return 'revoked';
      },
      replace: (store, operationId) => store.resetAfterExplicitConfirmation(operationId),
      enroll: async () => {
        enrollmentCalls += 1;
        context.access?.('relayRequests');
      },
    })).rejects.toThrow(expectedError);

    expect(resetCalls).toBe(0);
    expect(encryptionReplacementCalls).toBe(0);
    expect(configWrites).toBe(0);
    expect(enrollmentCalls).toBe(0);
    expect(harness.counters.default.keychainDeletes).toBe(0);
    expect(harness.counters.default.keychainWrites).toBe(0);
    expect(harness.counters.default.filesystemWrites).toBe(0);
    expect(harness.counters.default.relaySigners).toBe(0);
    expect(harness.counters.default.relayRequests).toBe(0);
    expect(harness.counters.default.childSpawns).toBe(0);
    expect(harness.counters.default.serviceRunnerCalls).toBe(0);
    expectZeroAccess(harness, 'dev');
  });
});

describe('profile-aware watches operations', () => {
  test.each(['default', 'dev'] as const)('%s list/remove use only selected Host, Watch link, signer, and keyring', async (profileId) => {
    const harness = createHarness();
    const unselected = profileId === 'default' ? 'dev' : 'default';
    await initializeProfile(harness.contexts[profileId]);
    resetLog(harness);
    const sentinelBefore = harness.sentinelBytes(unselected);
    const accesses: string[] = [];
    const watchDeviceId = `watch_${(profileId === 'default' ? 'D' : 'V').repeat(43)}`;
    const dependencies = watchesDependencies(harness, profileId, accesses);

    const listed = await watchesProfile(harness.contexts[profileId], { action: 'list' }, dependencies);
    const removed = await watchesProfile(
      harness.contexts[profileId],
      { action: 'remove', watchDeviceId },
      dependencies,
    );

    const suffix = profileId === 'default' ? 'D' : 'V';
    expect(listed).toEqual({ action: 'list', watches: [{ watchDeviceId, pairedAt: '2026-07-15T00:00:00.000Z', lastSeenAt: '2026-07-15T00:00:00.000Z', linkGeneration: 7 }] });
    expect(removed).toEqual({ action: 'remove', watchDeviceId });
    expect(accesses).toEqual([
      `enroll:${profileId}:host_${suffix.repeat(43)}`,
      `list:${profileId}:host_${suffix.repeat(43)}`,
      `enroll:${profileId}:host_${suffix.repeat(43)}`,
      `list:${profileId}:host_${suffix.repeat(43)}`,
      `keyring:${profileId}:${harness.profiles[profileId].resources.linkKeyringPath}`,
      `remove:${profileId}:host_${suffix.repeat(43)}:${watchDeviceId}:7`,
      `revoke:${profileId}:${watchDeviceId}:7`,
    ]);
    expect(harness.counters[profileId].relaySigners).toBe(2);
    expect(harness.counters[profileId].relayRequests).toBe(5);
    expect(harness.sentinelBytes(unselected)).toEqual(sentinelBefore);
    expectZeroAccess(harness, unselected);
  });

  test('remove sends the generation captured by its authoritative list without later inference', async () => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.default);
    resetLog(harness);
    const accesses: string[] = [];
    const dependencies = watchesDependencies(harness, 'default', accesses);
    const originalCreateRelay = dependencies.createRelay;
    dependencies.createRelay = (relayBaseUrl, identity) => {
      const relay = originalCreateRelay(relayBaseUrl, identity);
      return {
        ...relay,
        async listWatches() {
          const listed = await relay.listWatches();
          return { watches: listed.watches.map((watch) => ({ ...watch, linkGeneration: 41 })) };
        },
        async removeWatch(watchDeviceId, linkGeneration) {
          expect(linkGeneration).toBe(41);
          return relay.removeWatch(watchDeviceId, linkGeneration);
        },
      };
    };
    await watchesProfile(harness.contexts.default, {
      action: 'remove', watchDeviceId: `watch_${'D'.repeat(43)}`,
    }, dependencies);
    expect(accesses.some((entry) => entry.endsWith(':41'))).toBe(true);
  });

  test.each([
    ['Relay error', async () => { throw new Error('unlink outcome uncertain'); }],
    ['malformed success', async () => ({ ok: true, extra: true }) as never],
  ] as const)('%s prepares the selected keyring but never reports local revocation', async (_name, removeWatch) => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.default);
    resetLog(harness);
    const accesses: string[] = [];
    const dependencies = watchesDependencies(harness, 'default', accesses);
    const originalCreateRelay = dependencies.createRelay;
    dependencies.createRelay = (relayBaseUrl, identity) => ({
      ...originalCreateRelay(relayBaseUrl, identity),
      removeWatch,
    });
    const watchDeviceId = `watch_${'D'.repeat(43)}`;

    await expect(watchesProfile(
      harness.contexts.default, { action: 'remove', watchDeviceId }, dependencies,
    )).rejects.toThrow();

    expect(accesses.some((entry) => entry.startsWith('keyring:'))).toBe(true);
    expect(accesses.some((entry) => entry.startsWith('revoke:'))).toBe(false);
    expectZeroAccess(harness, 'dev');
  });

  test('local revoke failure rejects after exact Relay success instead of claiming unlink completion', async () => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.default);
    resetLog(harness);
    const accesses: string[] = [];
    const dependencies = watchesDependencies(harness, 'default', accesses);
    dependencies.createKeyring = () => {
      accesses.push('keyring:default:injected');
      return {
        revokeWatchGeneration() { accesses.push('revoke.failed'); throw new Error('durable local revoke failed'); },
      };
    };

    await expect(watchesProfile(harness.contexts.default, {
      action: 'remove', watchDeviceId: `watch_${'D'.repeat(43)}`,
    }, dependencies)).rejects.toThrow('durable local revoke failed');
    expect(accesses.at(-3)).toStartWith('keyring:default:');
    expect(accesses.at(-2)).toStartWith('remove:default:');
    expect(accesses.at(-1)).toBe('revoke.failed');
    expectZeroAccess(harness, 'dev');
  });
});

describe('profile-aware pairing security transaction', () => {
  test.each(['default', 'dev'] as const)('%s pairing follows the security order and isolates the other profile', async (profileId) => {
    const harness = createHarness();
    const unselected = profileId === 'default' ? 'dev' : 'default';
    await initializeProfile(harness.contexts[profileId]);
    resetLog(harness);
    const sentinelBefore = harness.sentinelBytes(unselected);
    const callOrder: string[] = [];
    const keyringPaths: string[] = [];
    const relaySelections: PairRelaySelection[] = [];
    const result = await pairProfile(
      harness.contexts[profileId],
      {
        pairingCode: 'peyx7k',
        confirmMatch: async () => true,
        presentAccepted: () => callOrder.push('accepted.present'),
      },
      pairDependencies(harness, profileId, callOrder, keyringPaths, 'activated', relaySelections),
    );

    expect(firstAction(harness, profileId)).toBe('descriptor.validate');
    const identityReadIndex = harness.events.findIndex(
      (event) => event.profile === profileId && event.action === 'keychainReads',
    );
    expect(identityReadIndex).toBeGreaterThanOrEqual(0);
    expect(actionIndex(harness, profileId, 'selected.validate')).toBeLessThan(identityReadIndex);
    expect(actionIndex(harness, profileId, 'resolved.validate')).toBeLessThan(identityReadIndex);
    expect(result).toMatchObject({ status: 'paired', safetyCodeActivation: 'activated' });
    expect(callOrder).toEqual([
      'normalize',
      'identity.load',
      'encryption.loadOrCreate',
      'enroll',
      'relay.create',
      'pairWatch:PEYX7K',
      'accepted.present',
      'hostBinding.create',
      'keyring.create',
      'safetyCode.activate',
    ]);
    expect(keyringPaths).toEqual([harness.profiles[profileId].resources.linkKeyringPath]);
    const suffix = profileId === 'default' ? 'D' : 'V';
    expect(relaySelections).toEqual([{
      relayBaseUrl: profileId === 'default' ? 'https://ariava-relay.noyx.io' : 'http://127.0.0.1:8790',
      signerEntityId: `host_${suffix.repeat(43)}`,
      signerKeyId: `key_${suffix.repeat(43)}`,
    }]);
    expect(harness.sentinelBytes(unselected)).toEqual(sentinelBefore);
    expectZeroAccess(harness, unselected);
  });

  test.each([
    ['activated', 'paired'],
    ['already-active', 'paired'],
    ['skipped-no-e2e', 'paired'],
    ['waiting-for-watch', 'paired'],
    ['cancelled', 'cancelled'],
  ] as const)('returns typed %s activation outcome', async (outcome, status) => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.dev);
    resetLog(harness);
    const result = await pairProfile(
      harness.contexts.dev,
      { pairingCode: 'PEYX7K', confirmMatch: async () => outcome !== 'cancelled' },
      pairDependencies(harness, 'dev', [], [], outcome),
    );
    expect(result.status).toBe(status);
    expect(result.safetyCodeActivation).toBe(outcome);
  });

  test.each(['bad', 'PEYX7I', 'PEYX7K-secret-material'])("invalid code '%s' fails before profile, identity, or Relay access", async (pairingCode) => {
    const harness = createHarness();
    await expect(pairProfile(
      harness.contexts.default,
      { pairingCode, confirmMatch: async () => true },
      pairDependencies(harness, 'default', [], [], 'activated'),
    )).rejects.toThrow();
    expect(harness.events).toEqual([]);
    expectZeroAccess(harness, 'default');
    expectZeroAccess(harness, 'dev');
  });

  test.each(['default', 'dev'] as const)('%s rejects a mismatched Relay Host before keyring access', async (profileId) => {
    const harness = createHarness();
    await initializeProfile(harness.contexts[profileId]);
    resetLog(harness);
    const callOrder: string[] = [];
    const dependencies = pairDependencies(harness, profileId, callOrder, [], 'activated');
    dependencies.pairWatch = async () => ({
      ...pairResponse(profileId),
      host: { ...pairResponse(profileId).host, hostId: `host_${'X'.repeat(43)}` },
    });

    await expect(pairProfile(
      harness.contexts[profileId],
      { pairingCode: 'PEYX7K', confirmMatch: async () => true },
      dependencies,
    )).rejects.toThrow('Pairing response Host does not match the selected profile identity');
    expect(callOrder).not.toContain('keyring.create');
    expectZeroAccess(harness, profileId === 'default' ? 'dev' : 'default');
  });
  test('Relay pair failures stop before accepted presentation and keyring access', async () => {
    const harness = createHarness();
    await initializeProfile(harness.contexts.default);
    resetLog(harness);
    const callOrder: string[] = [];
    const keyringPaths: string[] = [];
    const dependencies = pairDependencies(harness, 'default', callOrder, keyringPaths, 'activated');
    dependencies.pairWatch = async () => { throw new Error('relay unavailable'); };
    await expect(pairProfile(
      harness.contexts.default,
      {
        pairingCode: 'PEYX7K',
        confirmMatch: async () => true,
        presentAccepted: () => callOrder.push('accepted.present'),
      },
      dependencies,
    )).rejects.toThrow('relay unavailable');
    expectPairFailureBeforePresentationAndKeyring(harness, callOrder, keyringPaths);
    expectZeroAccess(harness, 'dev');
  });

  test.each(malformedPairingCases())(
    'matching-ID malformed pair response rejects $name before accepted presentation and keyring access',
    async ({ mutate }) => {
      const harness = createHarness();
      await initializeProfile(harness.contexts.default);
      resetLog(harness);
      const callOrder: string[] = [];
      const keyringPaths: string[] = [];
      const dependencies = pairDependencies(harness, 'default', callOrder, keyringPaths, 'activated');
      dependencies.pairWatch = async () => mutate(pairResponse('default', true)) as BridgePairWatchResponse;
      await expect(pairProfile(
        harness.contexts.default,
        {
          pairingCode: 'PEYX7K',
          confirmMatch: async () => true,
          presentAccepted: () => callOrder.push('accepted.present'),
        },
        dependencies,
      )).rejects.toThrow('malformed pairing response');
      expectPairFailureBeforePresentationAndKeyring(harness, callOrder, keyringPaths);
      expectZeroAccess(harness, 'dev');
    },
  );

});

function watchesDependencies(
  harness: ProfileCliHarness,
  profileId: 'default' | 'dev',
  accesses: string[],
): WatchesProfileDependencies {
  const context = harness.contexts[profileId];
  const selectedEncryptionStores: unknown[] = [];
  const originalEncryptionCreate = context.encryptionIdentity.create;
  context.encryptionIdentity.create = (resources, platform) => {
    const store = originalEncryptionCreate(resources, platform);
    selectedEncryptionStores.push(store);
    return store;
  };
  const hostBinding = {} as EncryptionKeyBindingV1;
  return {
    bridgeVersion: '1.2.3-test',
    async createHostBinding() { return hostBinding; },
    createRelay(_relayBaseUrl, identity) {
      context.access?.('relaySigners');
      const signer = identity.signer.entityId;
      return {
        async enrollHost() {
          accesses.push(`enroll:${profileId}:${signer}`);
          context.access?.('relayRequests');
          return {} as never;
        },
        async listWatches() {
          accesses.push(`list:${profileId}:${signer}`);
          context.access?.('relayRequests');
          return { watches: [{
            watchDeviceId: `watch_${(profileId === 'default' ? 'D' : 'V').repeat(43)}`,
            pairedAt: '2026-07-15T00:00:00.000Z',
            lastSeenAt: '2026-07-15T00:00:00.000Z',
            linkGeneration: 7,
          }] };
        },
        async removeWatch(watchDeviceId, linkGeneration) {
          accesses.push(`remove:${profileId}:${signer}:${watchDeviceId}:${linkGeneration}`);
          context.access?.('relayRequests');
          return { ok: true as const };
        },
      };
    },
    createKeyring(resources, identities, migrationContext) {
      accesses.push(`keyring:${profileId}:${resources.linkKeyringPath}`);
      expect(resources.linkKeyringPath).toBe(harness.profiles[profileId].resources.linkKeyringPath);
      expect(identities).toBe(selectedEncryptionStores.at(-1));
      expect(migrationContext.currentHostIdentity.signer.entityId).toBe(`host_${(profileId === 'default' ? 'D' : 'V').repeat(43)}`);
      expect(migrationContext.signedCurrentHostBinding).toBe(hostBinding);
      return {
        revokeWatchGeneration(watchDeviceId: string, linkGeneration: number) {
          accesses.push(`revoke:${profileId}:${watchDeviceId}:${linkGeneration}`);
        },
      };
    },
  };
}

function pairDependencies(
  harness: ProfileCliHarness,
  profileId: 'default' | 'dev',
  callOrder: string[],
  keyringPaths: string[],
  outcome: 'activated' | 'already-active' | 'skipped-no-e2e' | 'waiting-for-watch' | 'cancelled',
  relaySelections: PairRelaySelection[] = [],
): PairProfileDependencies {
  const context = harness.contexts[profileId];
  const originalIdentityCreate = context.identity.create;
  const originalEncryptionCreate = context.encryptionIdentity.create;
  context.identity.create = (resources, platform) => {
    const store = originalIdentityCreate(resources, platform);
    const originalLoad = store.load.bind(store);
    store.load = async () => { callOrder.push('identity.load'); return originalLoad(); };
    return store;
  };
  let selectedEncryptionStore: unknown;
  context.encryptionIdentity.create = (resources, platform) => {
    const store = originalEncryptionCreate(resources, platform);
    selectedEncryptionStore = store;
    const originalLoadOrCreate = store.loadOrCreate.bind(store);
    store.loadOrCreate = (hostId) => {
      callOrder.push('encryption.loadOrCreate');
      return originalLoadOrCreate(hostId);
    };
    return store;
  };
  const hostBinding = {} as never;
  return {
    bridgeVersion: '1.2.3-test',
    normalizePairingCode(value) { callOrder.push('normalize'); return normalizePairingCode(value); },
    async enroll() { callOrder.push('enroll'); context.access?.('relayRequests'); },
    createRelay(relayBaseUrl, identity) {
      callOrder.push('relay.create');
      relaySelections.push({
        relayBaseUrl,
        signerEntityId: identity.signer.entityId,
        signerKeyId: identity.signer.keyId,
      });
      context.access?.('relaySigners');
      return {} as never;
    },
    async pairWatch(_relay, pairingCode) {
      callOrder.push(`pairWatch:${pairingCode}`);
      context.access?.('relayRequests');
      return pairResponse(profileId);
    },
    createKeyring(resources, identities, migrationContext) {
      callOrder.push('keyring.create');
      keyringPaths.push(resources.linkKeyringPath);
      expect(migrationContext.signedCurrentHostBinding).toBe(hostBinding);
      expect(migrationContext.currentHostIdentity.signer.entityId).toBe(`host_${(profileId === 'default' ? 'D' : 'V').repeat(43)}`);
      expect(identities).toBe(selectedEncryptionStore);
      context.access?.('filesystemReads', resources.linkKeyringPath);
      return {} as never;
    },
    async createHostBinding() { callOrder.push('hostBinding.create'); return hostBinding; },
    async activate() { callOrder.push('safetyCode.activate'); return outcome; },
  };
}

interface PairRelaySelection {
  relayBaseUrl: string;
  signerEntityId: string;
  signerKeyId: string;
}

function pairResponse(profileId: 'default' | 'dev', includeE2E = false): BridgePairWatchResponse {
  const identity = profileId === 'default' ? `host_${'D'.repeat(43)}` : `host_${'V'.repeat(43)}`;
  const now = '2026-08-05T00:00:00.000Z';
  return {
    host: {
      hostId: identity,
      hostName: profileId === 'default' ? 'fixture-host' : 'fixture-host (Dev)',
      platform: 'macos',
      bridgeVersion: '1.2.3-test',
      registeredAt: now,
      lastSeenAt: now,
      bridgeStatus: 'online',
      status: 'active',
    },
    watchDevice: {
      watchDeviceId: `watch_${'W'.repeat(43)}`,
      selectedHostIds: [identity],
      registeredAt: now,
      lastSeenAt: now,
      pairingStatus: 'paired',
    },
    link: {
      hostId: identity,
      watchDeviceId: `watch_${'W'.repeat(43)}`,
      pairedAt: now,
      generation: 1,
      updatedAt: now,
    },
    alreadyPaired: false,
    ...(includeE2E ? { e2e: e2eProjection(identity, `watch_${'W'.repeat(43)}`) } : {}),
  };
}

type MalformedPairingCase = {
  name: string;
  mutate(response: Record<string, any>): Record<string, any>;
};

function malformedPairingCases(): MalformedPairingCase[] {
  const set = (name: string, path: string, value: unknown): MalformedPairingCase => ({
    name,
    mutate(response) {
      const clone = structuredClone(response);
      const segments = path.split('.');
      let target = clone;
      for (const segment of segments.slice(0, -1)) target = target[segment];
      target[segments.at(-1)!] = value;
      return clone;
    },
  });
  const remove = (name: string, path: string): MalformedPairingCase => ({
    name,
    mutate(response) {
      const clone = structuredClone(response);
      const segments = path.split('.');
      let target = clone;
      for (const segment of segments.slice(0, -1)) target = target[segment];
      delete target[segments.at(-1)!];
      return clone;
    },
  });
  const otherHostId = `host_${'X'.repeat(43)}`;
  const otherWatchId = `watch_${'X'.repeat(43)}`;
  return [
    remove('missing host', 'host'),
    set('non-object host', 'host', []),
    remove('missing watchDevice', 'watchDevice'),
    set('non-object watchDevice', 'watchDevice', []),
    remove('missing link', 'link'),
    set('non-object link', 'link', []),
    remove('missing alreadyPaired', 'alreadyPaired'),
    set('non-boolean alreadyPaired', 'alreadyPaired', 'false'),
    set('invalid Host ID', 'host.hostId', 'host-invalid'),
    set('empty Host name', 'host.hostName', ''),
    set('invalid Host platform', 'host.platform', 'darwin'),
    set('empty Bridge version', 'host.bridgeVersion', ''),
    set('non-canonical Host registration timestamp', 'host.registeredAt', '2026-08-05'),
    set('non-canonical Host last-seen timestamp', 'host.lastSeenAt', 'yesterday'),
    set('invalid Bridge status', 'host.bridgeStatus', 'ready'),
    remove('omitted active Host status', 'host.status'),
    set('revoked Host status', 'host.status', 'revoked'),
    {
      name: 'invalid Watch ID with matching link ID',
      mutate(response) {
        const clone = structuredClone(response);
        clone.watchDevice.watchDeviceId = 'watch-invalid';
        clone.link.watchDeviceId = 'watch-invalid';
        clone.e2e.watchDeviceId = 'watch-invalid';
        return clone;
      },
    },
    set('non-array selected Host IDs', 'watchDevice.selectedHostIds', otherHostId),
    set('invalid selected Host ID', 'watchDevice.selectedHostIds', ['host-invalid']),
    set('selected Host IDs omit paired Host', 'watchDevice.selectedHostIds', [otherHostId]),
    set('non-canonical Watch registration timestamp', 'watchDevice.registeredAt', '2026-08-05'),
    set('non-canonical Watch last-seen timestamp', 'watchDevice.lastSeenAt', 'yesterday'),
    set('invalid Watch pairing status', 'watchDevice.pairingStatus', 'pending'),
    set('unpaired Watch pairing status', 'watchDevice.pairingStatus', 'unpaired'),
    set('invalid link Host ID', 'link.hostId', 'host-invalid'),
    set('invalid link Watch ID', 'link.watchDeviceId', 'watch-invalid'),
    set('non-canonical paired timestamp', 'link.pairedAt', 'today'),
    set('zero link generation', 'link.generation', 0),
    set('fractional link generation', 'link.generation', 1.5),
    set('non-canonical link update timestamp', 'link.updatedAt', 'today'),
    set('revoked link timestamp', 'link.revokedAt', '2026-08-05T00:00:01.000Z'),
    set('revoked link actor', 'link.revokedBy', 'host'),
    {
      name: 'revoked link timestamp and actor',
      mutate(response) {
        const clone = structuredClone(response);
        clone.link.revokedAt = '2026-08-05T00:00:01.000Z';
        clone.link.revokedBy = 'host';
        return clone;
      },
    },
    set('revoked link state', 'link.state', 'revoked'),
    set('revoked link status', 'link.status', 'revoked'),
    set('non-object E2E projection', 'e2e', []),
    set('empty E2E link ID', 'e2e.linkId', ''),
    set('mismatched E2E Host ID', 'e2e.hostId', otherHostId),
    set('mismatched E2E Watch ID', 'e2e.watchDeviceId', otherWatchId),
    set('mismatched E2E link generation', 'e2e.linkGeneration', 2),
    set('zero E2E epoch', 'e2e.epoch', 0),
    set('invalid E2E Host binding', 'e2e.hostBinding', {}),
    set('invalid E2E Host identity public key', 'e2e.hostIdentityPublicKey', 'invalid'),
    set('invalid E2E Watch binding', 'e2e.watchBinding', {}),
    set('invalid E2E Watch identity public key', 'e2e.watchIdentityPublicKey', 'invalid'),
    set('invalid E2E transcript digest', 'e2e.transcriptDigest', 'invalid'),
    set('non-canonical E2E confirmation expiry', 'e2e.confirmationExpiresAt', 'tomorrow'),
    set('invalid E2E state', 'e2e.state', 'active'),
  ];
}

function e2eProjection(hostId: string, watchDeviceId: string): E2EPendingLinkProjectionV1 {
  return {
    linkId: 'link_fixture',
    hostId,
    watchDeviceId,
    linkGeneration: 1,
    epoch: 1,
    hostBinding: encryptionBinding('host', hostId, 'D'),
    hostIdentityPublicKey: base64UrlEncode(new Uint8Array(32)),
    watchBinding: encryptionBinding('watch', watchDeviceId, 'W'),
    watchIdentityPublicKey: base64UrlEncode(new Uint8Array(32)),
    transcriptDigest: base64UrlEncode(new Uint8Array(32)),
    confirmationExpiresAt: '2026-08-05T00:05:00.000Z',
    state: 'pending_confirmation',
  };
}

function encryptionBinding(
  entityType: 'host' | 'watch',
  entityId: string,
  suffix: string,
): EncryptionKeyBindingV1 {
  return {
    version: 1,
    entityType,
    entityId,
    identityKeyId: `key_${suffix.repeat(43)}`,
    encryptionKeyId: `ekey_${suffix.repeat(43)}`,
    suite: E2E_SUITE_V1,
    publicKey: base64UrlEncode(new Uint8Array(32)),
    sequence: 1,
    createdAt: '2026-08-05T00:00:00.000Z',
    bindingSignature: base64UrlEncode(new Uint8Array(64)),
  };
}

function expectPairFailureBeforePresentationAndKeyring(
  harness: ProfileCliHarness,
  callOrder: string[],
  keyringPaths: string[],
): void {
  expect(callOrder).not.toContain('accepted.present');
  expect(callOrder).not.toContain('keyring.create');
  expect(callOrder).not.toContain('hostBinding.create');
  expect(callOrder).not.toContain('safetyCode.activate');
  expect(keyringPaths).toEqual([]);
  expect(harness.events).not.toContainEqual(expect.objectContaining({
    action: 'filesystemReads',
    path: harness.profiles.default.resources.linkKeyringPath,
  }));
}

function createHarness(): ProfileCliHarness {
  const harness = createProfileCliHarness();
  harnesses.push(harness);
  return harness;
}

function firstAction(harness: ProfileCliHarness, profile: 'default' | 'dev'): string | undefined {
  return harness.events.find((event) => event.profile === profile)?.action;
}

function actionIndex(harness: ProfileCliHarness, profile: 'default' | 'dev', action: string): number {
  const index = harness.events.findIndex((event) => event.profile === profile && event.action === action);
  expect(index, `${profile} missing ${action}: ${JSON.stringify(harness.events)}`).toBeGreaterThanOrEqual(0);
  return index;
}

function expectSelectedConfigEffect(
  harness: ProfileCliHarness,
  profileId: 'default' | 'dev',
  filesystemWrites: number,
  unselectedSentinel: Buffer,
): void {
  const unselected = profileId === 'default' ? 'dev' : 'default';
  expect(harness.counters[profileId].filesystemReads, `${profileId}.filesystemReads`).toBeGreaterThan(0);
  expect(harness.counters[profileId].filesystemWrites, `${profileId}.filesystemWrites`).toBe(filesystemWrites);
  for (const kind of PROFILE_ACCESS_KINDS) {
    if (kind === 'filesystemReads' || kind === 'filesystemWrites') continue;
    expect(harness.counters[profileId][kind], `${profileId}.${kind}`).toBe(0);
  }
  expect(harness.sentinelBytes(unselected)).toEqual(unselectedSentinel);
  expectZeroAccess(harness, unselected);
}

function expectZeroAccess(harness: ProfileCliHarness, profile: 'default' | 'dev'): void {
  for (const kind of PROFILE_ACCESS_KINDS) {
    expect(harness.counters[profile][kind], `${profile}.${kind}`).toBe(0);
  }
}

function resetLog(harness: ProfileCliHarness): void {
  harness.events.length = 0;
  for (const counters of Object.values(harness.counters)) {
    for (const kind of PROFILE_ACCESS_KINDS) counters[kind] = 0;
  }
  harness.filesystemProbeReads.default = 0;
  harness.filesystemProbeReads.dev = 0;
  harness.filesystemProbeReads.other = 0;
}
