import { describe, expect, test } from 'bun:test';
import { AGENT_ADAPTER_PROTOCOL_VERSION } from '@ariava/protocol';
import type { HostEncryptionIdentity } from '../src/identity/host-encryption-key';
import type { HostIdentity, HostIdentityInspection, HostIdentityStore } from '../src/identity/types';
import type {
  AriavaInstallMetadata,
  AriavaUserConfig,
  ResolvedAriavaConfig,
} from '../src/host-manager/config';
import type { HostInitializationDependencies } from '../src/host-manager/initialization';
import type { OnboardingResult } from '../src/host-manager/onboarding/types';
import type { PiExtensionStatus } from '../src/host-manager/pi-extension';
import type {
  AriavaServiceInstallRecord,
  CommandResult,
  ServiceManager,
  ServiceStatus,
} from '../src/host-manager/service/types';
import {
  createDefaultOnboardingAdapter,
  decodeStableOnboardingChild,
  type DefaultOnboardingAdapterDependencies,
  type DefaultOnboardingAdapterRuntimePorts,
  type OnboardingChildResult,
} from '../src/cli/lifecycle/onboarding-adapter';

const version = '1.2.3';
const prefix = '/isolated/npm';
const stableCliPath = `${prefix}/bin/ariava`;
const packageRoot = `${prefix}/lib/node_modules/ariava`;
const runtimePath = '/isolated/node/bin/node';
const configPath = '/isolated/product/config.json';
const installPath = '/isolated/product/install.json';
const identityPath = '/isolated/product/host-identity.json';
const devConfigPath = '/isolated/dev/config.json';
const storage = { type: 'linux-json' as const, path: identityPath };
const identity: HostIdentity = {
  identityVersion: 2,
  hostId: 'host_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  keyId: 'key_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  algorithm: 'Ed25519',
  publicKey: 'public-isolated',
  publicKeyFingerprint: 'fingerprint-isolated',
  createdAt: '2026-08-13T00:00:00.000Z',
  privateKeyStorage: storage,
  signer: {
    entityId: 'host_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    keyId: 'key_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
    sign: async () => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    signRequest: async () => ({}) as never,
  },
};
const encryptionIdentity: HostEncryptionIdentity = {
  version: 1,
  hostId: identity.hostId,
  encryptionKeyId: 'ekey_cs1uhCLEB_ttCYaQ8RMLfe1-wvf14dML2dUh8BU2N5M',
  publicKey: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
  privateKeyPkcs8: new Uint8Array(),
  sequence: 1,
  createdAt: '2026-08-13T00:00:00.000Z',
};
const readyInspection: HostIdentityInspection = {
  status: 'ready',
  storageType: 'linux-json',
  storageReference: storage,
  path: identityPath,
  hostId: identity.hostId,
  keyId: identity.keyId,
  algorithm: identity.algorithm,
  publicKeyFingerprint: identity.publicKeyFingerprint,
  ownerIntegrity: true,
  permissionIntegrity: true,
  metadataIntegrity: true,
};
const notInitializedInspection: HostIdentityInspection = {
  status: 'not-initialized',
  storageType: 'linux-json',
  storageReference: storage,
  path: identityPath,
  ownerIntegrity: false,
  permissionIntegrity: false,
  metadataIntegrity: false,
};

function resolvedConfig(relayBaseUrl: string, initialized: boolean): ResolvedAriavaConfig {
  return {
    relayBaseUrl,
    hostName: 'Isolated Host',
    agentAdapterPort: 7272,
    agentAdapterConfigPath: '/isolated/product/agent-adapter.json',
    agentAdapterSecret: 'isolated-secret',
    statePath: '/isolated/product/state.json',
    identityPath,
    configPath,
    installPath,
    logDir: '/isolated/product/logs',
    stdoutLogPath: '/isolated/product/logs/stdout.log',
    stderrLogPath: '/isolated/product/logs/stderr.log',
    tmpDir: '/isolated/product/tmp',
    environmentOverrides: [],
    ...(initialized ? { identity } : {}),
  };
}

function exactPiStatus(): PiExtensionStatus {
  return {
    installed: true,
    installPath: '/isolated/pi/npm/node_modules/@ariava/pi-extension',
    expectedManagedPath: '/isolated/pi/npm/node_modules/@ariava/pi-extension',
    managed: true,
    managedMetadataPath: '/isolated/pi/settings.json',
    registeredSource: `npm:@ariava/pi-extension@${version}`,
    expectedSource: `npm:@ariava/pi-extension@${version}`,
    manifestName: '@ariava/pi-extension',
    manifestVersion: version,
    sourceOwnership: 'managed-exact',
    mismatchReasons: [],
  };
}

function serviceRecord(input: {
  runtimePath: string;
  ariavaBinPath: string;
  configPath?: string;
  identityReference?: typeof storage;
  installedAt?: string;
}): AriavaServiceInstallRecord {
  return {
    backend: 'systemd-user',
    installedAt: input.installedAt ?? '2026-08-13T00:00:00.000Z',
    runtimePath: input.runtimePath,
    ariavaBinPath: input.ariavaBinPath,
    configPath: input.configPath,
    identityReference: input.identityReference,
    definitionPath: '/isolated/product/systemd/ariava.service',
    serviceId: 'ariava.service',
  };
}

function childResult(
  target: OnboardingResult['target'] = 'host-ready',
  readiness: OnboardingResult['readiness'] = 'host-ready',
): OnboardingResult {
  return {
    target,
    readiness,
    steps: readiness === 'failed'
      ? [{ id: 'preflight', status: 'failed', detail: { code: 'ERR_ONBOARDING_NOT_READY' } }]
      : [],
    nextActions: readiness === 'failed'
      ? [{ id: 'retry-onboarding', command: 'ariava setup --resume' }]
      : [],
  };
}

function jsonEnvelope(result: OnboardingResult): string {
  const failed = result.readiness === 'failed';
  return JSON.stringify({
    ok: !failed,
    code: failed ? 'ERR_ONBOARDING_NOT_READY' : 'ok',
    message: failed ? 'Ariava onboarding is incomplete.' : 'Ariava onboarding completed.',
    data: result,
  });
}

function fixture(options: { ephemeralCli?: boolean; initialized?: boolean; persistedRelay?: string } = {}) {
  const calls: string[] = [];
  const writeCalls: string[] = [];
  let initialized = options.initialized ?? true;
  let installed = !options.ephemeralCli;
  let running = false;
  let bootstrapLocked = false;
  let onboardingLocked = false;
  let userConfig: AriavaUserConfig = options.persistedRelay
    ? { relayBaseUrl: options.persistedRelay }
    : {};
  let metadata: AriavaInstallMetadata = {};
  let spawnResponse: OnboardingChildResult = {
    status: 0,
    stdout: jsonEnvelope(childResult()),
    stderr: '',
  };
  let readinessInput: Parameters<DefaultOnboardingAdapterRuntimePorts['checkReadiness']>[0] | undefined;
  let readinessDependencies: Parameters<DefaultOnboardingAdapterRuntimePorts['checkReadiness']>[1] | undefined;
  let initializationInput: Parameters<DefaultOnboardingAdapterRuntimePorts['initializeHost']>[0] | undefined;
  let initializationDependencies: HostInitializationDependencies | undefined;
  const runner = {
    run(command: string, args: string[]): CommandResult {
      calls.push(`command:${command}:${args.join(' ')}`);
      if (command === 'npm' && args.join(' ') === 'prefix --global') {
        return { status: 0, stdout: `${prefix}\n`, stderr: '' };
      }
      if (command === 'npm' && args[0] === 'install') {
        installed = true;
        return { status: 0, stdout: '', stderr: '' };
      }
      if (command === 'npm' && args[0] === '--version') {
        return { status: 0, stdout: '11.0.0\n', stderr: '' };
      }
      if (command === 'pi' && args[0] === '--version') {
        return { status: 0, stdout: 'pi 0.50.0\n', stderr: '' };
      }
      throw new Error(`unexpected command ${command} ${args.join(' ')}`);
    },
  };
  const support = {
    platform: 'linux' as const,
    backend: 'systemd-user' as const,
    supported: true,
    isWsl: false,
    reason: 'supported' as const,
    definitionPath: '/isolated/product/systemd/ariava.service',
  };
  const status = (record: AriavaServiceInstallRecord | undefined): ServiceStatus => ({
    backend: 'systemd-user',
    support,
    definitionPath: record?.definitionPath,
    serviceId: record?.serviceId,
    installed: Boolean(record),
    enabled: Boolean(record),
    loaded: Boolean(record),
    processRunning: Boolean(record) && running,
    runtimePath: record?.runtimePath,
    ariavaBinPath: record?.ariavaBinPath,
    runtimePathMatchesCurrent: Boolean(record),
    ariavaBinPathMatchesCurrent: Boolean(record),
    logBackend: 'journald',
  });
  const manager: ServiceManager = {
    backend: 'systemd-user',
    support,
    install(input) {
      calls.push(`service.install:${JSON.stringify(input)}`);
      writeCalls.push('service-definition');
      return serviceRecord(input);
    },
    uninstall() { throw new Error('not used'); },
    start(record) {
      calls.push(`service.start:${record?.serviceId}`);
      running = true;
    },
    stop() { throw new Error('not used'); },
    restart() { throw new Error('not used'); },
    status(record, currentRuntimePath, currentAriavaBinPath) {
      calls.push(`service.status:${record?.serviceId ?? 'none'}:${currentRuntimePath}:${currentAriavaBinPath}`);
      return status(record);
    },
    logsAvailable: () => true,
    logs: () => ({ backend: 'systemd-user', source: 'journald', text: '' }),
  };
  const store: HostIdentityStore = {
    async inspect() {
      calls.push('identity.inspect');
      return initialized ? readyInspection : notInitializedInspection;
    },
    async load() {
      calls.push('identity.load');
      return initialized ? identity : null;
    },
    createFirstRun: async () => identity,
    resetAfterExplicitConfirmation: async () => identity,
  };
  const deps: DefaultOnboardingAdapterDependencies = {
    createServiceManager() {
      calls.push('service.manager');
      return manager;
    },
    currentRuntimePath: () => runtimePath,
    currentAriavaBinPath: () => options.ephemeralCli ? '/isolated/npm-cache/_npx/ariava' : stableCliPath,
    pathExists(path) {
      calls.push(`path.exists:${path}`);
      if (path === devConfigPath) return false;
      if (path === stableCliPath) return installed;
      return false;
    },
    realpath(path) {
      calls.push(`realpath:${path}`);
      return path;
    },
    loadUserConfig() {
      calls.push('config.load');
      return userConfig;
    },
    saveUserConfig(config) {
      calls.push(`config.save:${config.relayBaseUrl}`);
      writeCalls.push('product-config');
      userConfig = config;
    },
    loadInstallMetadata() {
      calls.push('metadata.load');
      return metadata;
    },
    saveInstallMetadata(value) {
      calls.push('metadata.save');
      writeCalls.push('install-metadata');
      metadata = value;
    },
    async spawnAsync(command, args) {
      calls.push(`child.spawn:${command}:${args.join(' ')}`);
      expect(bootstrapLocked).toBe(true);
      expect(onboardingLocked).toBe(false);
      expect(writeCalls).toEqual([]);
      return spawnResponse;
    },
    createHostIdentityStore(path, platform) {
      calls.push(`identity.store:${path}:${platform}`);
      return {
        ...store,
        createFirstRun: async () => {
          calls.push('identity.create');
          writeCalls.push('identity');
          initialized = true;
          return identity;
        },
      };
    },
    createProfile() {
      calls.push('profile.create');
      return { id: 'default' } as never;
    },
  };
  const readinessClock = { now: () => 17, sleep: async () => {} };
  const readinessFetch = async () => Response.json({ ok: true });
  const readinessReadDiscovery = () => null;
  const readinessCreateRelayClient = () => ({ enrollHost: async () => ({}) as never });
  const readinessNonce = () => 'isolated-nonce';
  const runtime: Partial<DefaultOnboardingAdapterRuntimePorts> = {
    architecture: 'arm64',
    nodeVersion: 'v24.18.0',
    environment: {
      HOME: '/must-not-be-used',
      ARIAVA_RELAY_BASE_URL: 'https://ambient.invalid',
      ARIAVA_HOST_IDENTITY_PATH: '/ambient/identity.json',
    },
    configPath,
    devConfigPath,
    createCommandRunner: () => runner,
    readPackageVersion(root) {
      calls.push(`package.version:${root}`);
      return version;
    },
    assertPrefixWritable(path) {
      calls.push(`prefix.writable:${path}`);
    },
    acquireBootstrapLock() {
      calls.push('bootstrap-lock.acquire');
      bootstrapLocked = true;
      return {
        path: '/isolated/runtime/bootstrap.lock',
        record: {} as never,
        release() {
          calls.push('bootstrap-lock.release');
          bootstrapLocked = false;
        },
      };
    },
    acquireOnboardingLock() {
      calls.push('onboarding-lock.acquire');
      writeCalls.push('onboarding-lock');
      onboardingLocked = true;
      return {
        path: '/isolated/product/onboarding.lock',
        record: {} as never,
        release() {
          calls.push('onboarding-lock.release');
          onboardingLocked = false;
        },
      };
    },
    async initializeHost(input, dependencies) {
      calls.push(`host.initialize:${input.relayBaseUrl}`);
      writeCalls.push('host-state');
      initializationInput = input;
      initializationDependencies = dependencies;
      initialized = true;
      return { config: { relayBaseUrl: input.relayBaseUrl }, identityCreated: true };
    },
    resolveConfig(_overrides, path, useEnvironment) {
      calls.push(`config.resolve:${path}:${String(useEnvironment)}`);
      return resolvedConfig(userConfig.relayBaseUrl ?? 'https://ariava-relay.noyx.io', initialized);
    },
    createEncryptionIdentityStore(path, platform) {
      calls.push(`encryption.store:${path}:${platform}`);
      return { load: () => encryptionIdentity } as never;
    },
    hostName: () => 'Isolated Host',
    generateSecret: () => 'generated-isolated-secret',
    async proveBridgeHealth(input, dependencies) {
      calls.push(`bridge.health:${input.identity.hostId}:${input.config.agentAdapterConfigPath}`);
      expect(dependencies.clock).toBe(readinessClock);
      expect(dependencies.fetch).toBe(readinessFetch);
      expect(dependencies.readDiscovery).toBe(readinessReadDiscovery);
      return {
        discovery: {
          url: 'http://127.0.0.1:7272',
          secret: 'isolated-secret',
          protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
        },
        health: { status: 'healthy', drivers: [] },
      };
    },
    healthDependencies: {
      clock: readinessClock,
      fetch: readinessFetch,
      readDiscovery: readinessReadDiscovery,
    },
    installPi(exactVersion) {
      calls.push(`pi.install:${exactVersion}`);
      const piStatus = exactPiStatus();
      return {
        action: 'installed',
        status: piStatus,
        record: {
          installedAt: '2026-08-13T00:00:00.000Z',
          version: exactVersion,
          managedPath: piStatus.installPath,
          source: {
            kind: 'npm-package',
            package: `npm:@ariava/pi-extension@${exactVersion}`,
            updatedAt: '2026-08-13T00:00:00.000Z',
          },
        },
      };
    },
    async checkReadiness(input, dependencies) {
      calls.push('readiness.check');
      readinessInput = input;
      readinessDependencies = dependencies;
      return { ready: true, readiness: 'reload-pending', checks: [], nextActions: [{ id: 'reload-pi', command: '/reload' }] };
    },
    readinessDependencies: {
      clock: readinessClock,
      fetch: readinessFetch,
      readDiscovery: readinessReadDiscovery,
      createRelayClient: readinessCreateRelayClient,
      nonce: readinessNonce,
    },
    now: () => '2026-08-13T00:00:00.000Z',
    sleep: async () => { calls.push('clock.sleep'); },
  };
  const adapter = createDefaultOnboardingAdapter(deps, { cliVersion: version, packageRoot }, runtime);
  return {
    adapter,
    calls,
    writeCalls,
    manager,
    get metadata() { return metadata; },
    get userConfig() { return userConfig; },
    get readinessInput() { return readinessInput; },
    get readinessDependencies() { return readinessDependencies; },
    get initializationInput() { return initializationInput; },
    get initializationDependencies() { return initializationDependencies; },
    setSpawnResponse(value: OnboardingChildResult) { spawnResponse = value; },
  };
}

describe('default production onboarding adapter', () => {
  test('installs exact stable CLI, forwards selected public args, and enforces the bootstrap write barrier', async () => {
    const scenario = fixture({ ephemeralCli: true });
    const child = childResult('adapter-installed', 'reload-pending');
    scenario.setSpawnResponse({ status: 0, stdout: jsonEnvelope(child), stderr: 'diagnostic ignored' });

    const result = await scenario.adapter.run({
      target: 'adapter-installed',
      publicArgs: [
        '--extension', 'pi',
        '--relay-base-url', 'https://relay.selected.example',
        '--yes',
        '--resume',
        '--bootstrap-version', 'stale',
        '--bootstrap-once',
      ],
      resumed: true,
    });

    expect(result).toEqual(child);
    expect(scenario.calls).toContain(`command:npm:install --global ariava@${version}`);
    expect(scenario.calls.join('\n')).not.toMatch(/sudo|shim|\.local\/share\/ariava/);
    expect(scenario.calls).toContain(
      `child.spawn:${stableCliPath}:setup --extension pi --relay-base-url https://relay.selected.example --yes --resume --bootstrap-version ${version} --bootstrap-once --json`,
    );
    expect(scenario.calls.indexOf('bootstrap-lock.acquire')).toBeLessThan(
      scenario.calls.findIndex((call) => call.startsWith('child.spawn:')),
    );
    expect(scenario.calls.indexOf('bootstrap-lock.release')).toBeGreaterThan(
      scenario.calls.findIndex((call) => call.startsWith('child.spawn:')),
    );
    expect(scenario.calls).not.toContain('onboarding-lock.acquire');
    expect(scenario.writeCalls).toEqual([]);
  });

  test('maps Host initialization, service, health, exact Pi, and strict readiness in production order', async () => {
    const scenario = fixture({ initialized: false });

    const result = await scenario.adapter.run({
      target: 'adapter-installed',
      publicArgs: ['--extension', 'pi'],
      resumed: true,
      bootstrapVersion: version,
    });

    expect(result.readiness).toBe('reload-pending');
    expect(result.nextActions).toEqual([
      { id: 'reload-pi', command: '/reload' },
      { id: 'pair-watch', command: 'ariava pair <PAIRING_CODE>' },
    ]);
    expect(scenario.userConfig.relayBaseUrl).toBe('https://ariava-relay.noyx.io');
    expect(scenario.initializationInput).toEqual({
      relayBaseUrl: 'https://ariava-relay.noyx.io',
      useEnvironmentIdentityPath: false,
    });
    expect(scenario.initializationDependencies).toMatchObject({
      environment: {
        HOME: '/must-not-be-used',
        ARIAVA_RELAY_BASE_URL: 'https://ambient.invalid',
        ARIAVA_HOST_IDENTITY_PATH: '/ambient/identity.json',
      },
      platform: 'linux',
    });
    expect(scenario.calls).toContain(`config.resolve:${configPath}:false`);
    expect(scenario.calls).toContain(`identity.store:${identityPath}:linux`);
    expect(scenario.calls).toContain(`pi.install:${version}`);

    const serviceInstallIndex = scenario.calls.findIndex((call) => call.startsWith('service.install:'));
    const serviceStartIndex = scenario.calls.findIndex((call) => call.startsWith('service.start:'));
    const healthIndex = scenario.calls.findIndex((call) => call.startsWith('bridge.health:'));
    const piIndex = scenario.calls.indexOf(`pi.install:${version}`);
    const readinessIndex = scenario.calls.indexOf('readiness.check');
    expect(serviceInstallIndex).toBeGreaterThan(-1);
    expect(serviceInstallIndex).toBeLessThan(serviceStartIndex);
    expect(serviceStartIndex).toBeLessThan(healthIndex);
    expect(healthIndex).toBeLessThan(piIndex);
    expect(piIndex).toBeLessThan(readinessIndex);

    const installedService = scenario.metadata.service!;
    expect(installedService).toMatchObject({
      backend: 'systemd-user',
      runtimePath,
      ariavaBinPath: stableCliPath,
      configPath,
      identityReference: storage,
      definitionPath: '/isolated/product/systemd/ariava.service',
      serviceId: 'ariava.service',
    });
    expect(scenario.metadata.installer).toMatchObject({
      manager: 'npm',
      ariavaBinRealPath: stableCliPath,
    });
    expect(scenario.metadata.bridgeSource).toMatchObject({
      kind: 'npm-package',
      package: `ariava@${version}`,
    });
  });

  test('constructs exact strict-readiness evidence and dependency ports', async () => {
    const scenario = fixture({ persistedRelay: 'https://persisted.example' });
    await scenario.adapter.run({
      target: 'adapter-installed',
      publicArgs: ['--extension', 'pi'],
      resumed: true,
      bootstrapVersion: version,
      relayBaseUrl: 'https://requested-must-not-win.example',
    });

    const readiness = scenario.readinessInput!;
    expect(readiness).toMatchObject({
      target: 'adapter-installed',
      cliVersion: version,
      stableCli: {
        executablePath: stableCliPath,
        packageRoot,
        packageVersion: version,
        npmPrefix: prefix,
        npmBinPath: `${prefix}/bin`,
      },
      config: {
        relayBaseUrl: 'https://persisted.example',
        configPath,
        identityPath,
        environmentOverrides: [],
      },
      identityInspection: readyInspection,
      identity,
      encryptionBinding: {
        version: 1,
        entityType: 'host',
        entityId: identity.hostId,
        identityKeyId: identity.keyId,
        encryptionKeyId: encryptionIdentity.encryptionKeyId,
        suite: 'x25519-hkdf-sha256-chachapoly-v1',
        publicKey: encryptionIdentity.publicKey,
        sequence: encryptionIdentity.sequence,
        createdAt: encryptionIdentity.createdAt,
        bindingSignature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
      serviceRecord: {
        backend: 'systemd-user',
        runtimePath,
        ariavaBinPath: stableCliPath,
        configPath,
        identityReference: storage,
        definitionPath: '/isolated/product/systemd/ariava.service',
        serviceId: 'ariava.service',
      },
      expectedRuntimePath: runtimePath,
      expectedAriavaBinPath: stableCliPath,
      hostMetadata: {
        hostName: 'Isolated Host',
        platform: 'linux',
        bridgeVersion: version,
      },
      piStatus: exactPiStatus(),
    });
    expect(readiness.installMetadata).toBe(scenario.metadata);
    expect(readiness.config.identity?.hostId).toBe(identity.hostId);
    expect(readiness.signal).toBeUndefined();

    const dependencies = scenario.readinessDependencies!;
    expect(typeof dependencies.clock).toBe('object');
    expect(typeof dependencies.fetch).toBe('function');
    expect(typeof dependencies.readDiscovery).toBe('function');
    expect(typeof dependencies.createRelayClient).toBe('function');
    expect(typeof dependencies.nonce).toBe('function');
    expect(typeof dependencies.serviceStatus).toBe('function');
    expect(dependencies.nonce!()).toBe('isolated-nonce');
    expect(dependencies.readDiscovery!('/any')).toBeNull();
    expect(dependencies.serviceStatus?.()).toMatchObject({
      installed: true,
      enabled: true,
      loaded: true,
      processRunning: true,
      runtimePath,
      ariavaBinPath: stableCliPath,
    });
  });

  test('maps machine detection without product effects', () => {
    const scenario = fixture({ persistedRelay: 'https://persisted.example' });
    const detection = scenario.adapter.detect(true, false);

    expect(detection).toMatchObject({
      platform: 'linux',
      architecture: 'arm64',
      nodeVersion: 'v24.18.0',
      npm: { present: true, version: '11.0.0' },
      pi: { present: true, version: 'pi 0.50.0' },
      serviceSupport: { backend: 'systemd-user', supported: true },
      interactive: false,
      machineOutput: true,
      configPath,
      config: { relayBaseUrl: 'https://persisted.example' },
      currentCli: {
        executablePath: stableCliPath,
        packageRoot,
        packageVersion: version,
        npmPrefix: prefix,
        npmBinPath: `${prefix}/bin`,
      },
    });
    expect(scenario.writeCalls).toEqual([]);
  });

  test('decodes success and cancellation results from the owning output channel at any child status', () => {
    const success = childResult('host-ready', 'host-ready');
    const cancelled = childResult('host-ready', 'failed');
    expect(decodeStableOnboardingChild({
      status: 0,
      stdout: jsonEnvelope(success),
      stderr: 'diagnostic text',
    })).toEqual(success);
    expect(decodeStableOnboardingChild({
      status: 130,
      stdout: 'non-json diagnostic',
      stderr: jsonEnvelope(cancelled),
    })).toEqual(cancelled);
    expect(decodeStableOnboardingChild({
      status: 7,
      stdout: jsonEnvelope(cancelled),
      stderr: '',
    })).toEqual(cancelled);
  });

  test('preserves structured child failures from stdout or stderr on nonzero and null exits', () => {
    const structured = JSON.stringify({
      ok: false,
      code: 'ERR_RELAY_UNREACHABLE',
      message: 'Relay remained unavailable.',
      data: {
        step: 'strict-readiness',
        retryable: true,
        remediation: { command: 'ariava setup --resume' },
        childExit: 23,
      },
    });
    for (const child of [
      { status: 23, stdout: structured, stderr: 'diagnostic' },
      { status: null, stdout: 'not-json', stderr: structured },
    ]) {
      expect(() => decodeStableOnboardingChild(child)).toThrow(expect.objectContaining({
        code: 'ERR_RELAY_UNREACHABLE',
        message: 'Relay remained unavailable.',
        data: {
          step: 'strict-readiness',
          retryable: true,
          remediation: { command: 'ariava setup --resume' },
          childExit: 23,
        },
      }));
    }
  });
  test('rejects malformed, missing, and invalid child envelope fields without accepting diagnostics', () => {
    const valid = childResult();
    const invalidEnvelopes = [
      '{not-json',
      JSON.stringify({ ok: true }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: null }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, target: 'invalid' } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, readiness: 'unknown' } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, readiness: 'adapter-ready' } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, readiness: 'collaboration-ready' } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, readiness: 'reload-pending' } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, steps: {} } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, steps: [{ id: 'unknown', status: 'ready' }] } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, steps: [{ id: 'preflight', status: 'unknown' }] } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, steps: [{ id: 'preflight', status: 'ready', detail: [] }] } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, nextActions: {} } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, nextActions: [{ id: '' }] } }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: { ...valid, nextActions: [{ id: 'retry', command: 1 }] } }),
      JSON.stringify({ ok: false, code: 'ok', message: 'Ariava onboarding completed.', data: valid }),
      JSON.stringify({ ok: true, code: 'wrong', message: 'Ariava onboarding completed.', data: valid }),
      JSON.stringify({ ok: true, code: 'ok', message: 'wrong', data: valid }),
      JSON.stringify({ ok: true, code: 'ok', message: 'Ariava onboarding completed.', data: valid, extra: true }),
      JSON.stringify({ ok: false, code: '', message: 'failed', data: {} }),
      JSON.stringify({ ok: false, code: 'ERR_CLI', message: '', data: {} }),
      JSON.stringify({ ok: false, code: 'ERR_CLI', message: 'failed', data: [] }),
    ];
    for (const stdout of invalidEnvelopes) {
      expect(() => decodeStableOnboardingChild({ status: 0, stdout, stderr: 'plain diagnostic' }))
        .toThrow(expect.objectContaining({
          code: 'ERR_STABLE_CLI_PATH',
          message: 'Stable Ariava CLI re-entry returned malformed output.',
          data: { step: 'stable-cli', retryable: true },
        }));
    }
    expect(() => decodeStableOnboardingChild({
      status: 9,
      stdout: 'plain stdout',
      stderr: 'plain stderr',
      error: new Error('spawn failed exactly'),
    })).toThrow(expect.objectContaining({
      code: 'ERR_STABLE_CLI_PATH',
      message: 'spawn failed exactly',
      data: { step: 'stable-cli', retryable: true },
    }));
  });
});
