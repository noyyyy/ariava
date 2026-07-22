import { describe, expect, test } from 'bun:test';
import type { HostIdentity, HostIdentityInspection } from '../src/identity/types';
import {
  runOnboardingOrchestrator,
  type AriavaInstallMetadata,
  type AriavaUserConfig,
  type AriavaServiceInstallRecord,
  type OnboardingDetection,
  type OnboardingOrchestratorDependencies,
  type OnboardingOrchestratorInput,
  type OnboardingResult,
  type OnboardingHostState,
  type PiExtensionStatus,
  type ServiceManager,
  type ServiceStatus,
} from '../src/host-manager';

const version = '1.2.3';
const cli = '/prefix/bin/ariava';
const runtime = '/usr/bin/node';
const storage = { type: 'linux-json' as const, path: '/home/test/.config/ariava/host-identity.json' };
const signer = { entityId: 'host-1', keyId: 'key-1', sign: async () => '', signRequest: async () => ({}) as never };
const identity: HostIdentity = {
  identityVersion: 2, hostId: 'host-1', keyId: 'key-1', algorithm: 'Ed25519', publicKey: 'public',
  publicKeyFingerprint: 'fingerprint', createdAt: '2026-07-20T00:00:00.000Z', privateKeyStorage: storage, signer,
};
const inspection: HostIdentityInspection = {
  status: 'ready', storageType: 'linux-json', storageReference: storage, path: storage.path,
  hostId: identity.hostId, keyId: identity.keyId, algorithm: 'Ed25519', publicKeyFingerprint: identity.publicKeyFingerprint,
  ownerIntegrity: true, permissionIntegrity: true, metadataIntegrity: true, pendingRotation: false,
};

function serviceRecord(backend: 'launchd' | 'systemd-user' = 'systemd-user'): AriavaServiceInstallRecord {
  return {
    backend, installedAt: '2026-07-20T00:00:00.000Z', runtimePath: runtime, ariavaBinPath: cli,
    configPath: '/home/test/.config/ariava/config.json', identityReference: storage,
    definitionPath: backend === 'launchd' ? '/home/test/Library/LaunchAgents/io.noyx.ariava.bridge.plist' : '/home/test/.config/systemd/user/ariava.service',
    serviceId: backend === 'launchd' ? 'io.noyx.ariava.bridge' : 'ariava.service',
  };
}

function hostState(): OnboardingHostState {
  return {
    identity, identityInspection: inspection,
    config: {
      relayBaseUrl: 'https://ariava-relay.noyx.io', hostName: 'Test Host', agentAdapterPort: 7272,
      agentAdapterConfigPath: '/home/test/.config/ariava/agent-adapter.json', agentAdapterSecret: 'secret',
      statePath: '/home/test/.config/ariava/state/bridge-state.json', identityPath: storage.path,
      configPath: '/home/test/.config/ariava/config.json', installPath: '/home/test/.config/ariava/install.json',
      logDir: '/home/test/.config/ariava/logs', stdoutLogPath: '/home/test/.config/ariava/logs/out',
      stderrLogPath: '/home/test/.config/ariava/logs/err', tmpDir: '/home/test/.config/ariava/tmp',
      environmentOverrides: [], identity,
    },
  };
}

function piStatus(): PiExtensionStatus {
  return {
    installed: true, installPath: '/home/test/.pi/agent/npm/node_modules/@ariava/pi-extension',
    expectedManagedPath: '/home/test/.pi/agent/npm/node_modules/@ariava/pi-extension', managed: true,
    managedMetadataPath: '/home/test/.pi/agent/settings.json', registeredSource: `npm:@ariava/pi-extension@${version}`,
    expectedSource: `npm:@ariava/pi-extension@${version}`, manifestName: '@ariava/pi-extension', manifestVersion: version,
    sourceOwnership: 'managed-exact', mismatchReasons: [],
  };
}

function fixture(options: {
  target?: 'host-ready' | 'adapter-installed';
  backend?: 'launchd' | 'systemd-user';
  supported?: boolean;
  isWsl?: boolean;
  existingHost?: boolean;
  existingService?: boolean;
  running?: boolean;
  stalePaths?: boolean;
  piAction?: 'reused' | 'installed' | 'upgraded';
  piFailure?: boolean;
  cancelAt?: string;
} = {}) {
  const calls: string[] = [];
  const backend = options.backend ?? 'systemd-user';
  const support = options.supported === false
    ? { platform: 'linux' as const, backend, supported: false, isWsl: options.isWsl ?? false, reason: 'systemd-user-manager-unavailable' as const, message: 'Enable systemd in /etc/wsl.conf and run wsl.exe --shutdown.' }
    : { platform: backend === 'launchd' ? 'darwin' as const : 'linux' as const, backend, supported: true, isWsl: options.isWsl ?? false, reason: 'supported' as const };
  let userConfig: AriavaUserConfig = options.existingHost === false ? {} : { relayBaseUrl: 'https://ariava-relay.noyx.io' };
  let state: OnboardingHostState | undefined = options.existingHost === false ? undefined : hostState();
  let metadata: AriavaInstallMetadata = {
    ...(options.existingService === false ? {} : {
      installer: { manager: 'npm' as const, ariavaBinRealPath: cli, recordedAt: '2026-07-20T00:00:00.000Z' },
      bridgeSource: { kind: 'npm-package' as const, package: `ariava@${version}`, updatedAt: '2026-07-20T00:00:00.000Z' },
      service: serviceRecord(backend),
    }),
  };
  let running = options.running ?? options.existingService !== false;
  const status = (record: AriavaServiceInstallRecord | undefined): ServiceStatus => ({
    backend, support, installed: Boolean(record), enabled: Boolean(record), loaded: Boolean(record), processRunning: Boolean(record) && running,
    runtimePath: options.stalePaths ? '/old/node' : record?.runtimePath,
    ariavaBinPath: options.stalePaths ? '/old/ariava' : record?.ariavaBinPath,
    runtimePathMatchesCurrent: options.stalePaths ? false : Boolean(record),
    ariavaBinPathMatchesCurrent: options.stalePaths ? false : Boolean(record), logBackend: backend === 'launchd' ? 'files' : 'journald',
  });
  const manager: ServiceManager = {
    backend, support,
    install(input) { calls.push('service.install'); running = false; return { ...serviceRecord(backend), ...input }; },
    uninstall() { calls.push('service.uninstall'); },
    start() { calls.push('service.start'); running = true; },
    stop() { calls.push('service.stop'); running = false; },
    restart() { calls.push('service.restart'); running = true; },
    status(record) { calls.push('service.status'); return status(record); },
    logsAvailable: () => true, logs: () => ({ backend, source: backend === 'launchd' ? 'files' : 'journald', text: '' }),
  };
  let locked = false;
  let bootstrapLocked = false;
  const deps: OnboardingOrchestratorDependencies = {
    detect() {
      calls.push('detect');
      return {
        platform: support.platform, architecture: 'arm64', nodeVersion: '22', npm: { present: true }, pi: { present: true },
        serviceSupport: support, interactive: false, machineOutput: true, configPath: '/home/test/.config/ariava/config.json',
        config: userConfig, installMetadata: metadata,
        currentCli: { executablePath: cli, packageRoot: '/prefix/lib/node_modules/ariava', packageVersion: version, npmPrefix: '/prefix', npmBinPath: '/prefix/bin' },
      } as OnboardingDetection;
    },
    bootstrap() { calls.push('bootstrap'); return { status: 'reused', evidence: { executablePath: cli, packageRoot: '/prefix/lib/node_modules/ariava', packageVersion: version, npmPrefix: '/prefix', npmBinPath: '/prefix/bin' } }; },
    reenter: async () => { throw new Error('unexpected reentry'); },
    acquireBootstrapLock() {
      calls.push('bootstrap-lock.acquire');
      if (bootstrapLocked) throw new Error('bootstrap lock already held');
      bootstrapLocked = true;
      return { path: '/bootstrap-lock', record: {} as never, release() { calls.push('bootstrap-lock.release'); bootstrapLocked = false; } };
    },
    acquireLock() {
      calls.push('lock.acquire');
      if (locked) throw new Error('lock already held');
      locked = true;
      return { path: '/lock', record: {} as never, release() { calls.push('lock.release'); locked = false; } };
    },
    loadUserConfig: () => userConfig,
    saveUserConfig(config) { calls.push('config.save'); userConfig = config; },
    async initializeHost() { calls.push('host.initialize'); state = hostState(); return { config: state.config, identityCreated: true }; },
    async loadHostState() { calls.push('host.load'); return state; },
    loadInstallMetadata: () => metadata,
    saveInstallMetadata(value) { calls.push('metadata.save'); metadata = value; },
    serviceManager: manager,
    adapterProbe() { calls.push('adapter.detect'); return { present: true, version: version }; },
    async proveBridgeHealth() { calls.push('bridge.health'); if (!running) throw new Error('bridge not running'); },
    installPi() {
      calls.push('pi.install');
      if (options.piFailure) throw new Error('registry unavailable');
      return {
        action: options.piAction ?? 'installed', status: piStatus(),
        record: { installedAt: '2026-07-20T00:00:00.000Z', version, managedPath: piStatus().installPath, source: { kind: 'npm-package', package: piStatus().expectedSource, updatedAt: '2026-07-20T00:00:00.000Z' } },
      };
    },
    async checkReadiness({ target }) {
      calls.push('readiness');
      return { ready: true, readiness: target === 'host-ready' ? 'host-ready' : 'reload-pending', checks: [], nextActions: [] };
    },
    cancellation: { throwIfCancelled() { calls.push('cancel.check'); if (options.cancelAt && calls.includes(options.cancelAt)) throw new Error('cancelled'); } },
    sleep: async () => {}, serviceTimeoutMs: 5, servicePollIntervalMs: 1,
  };
  const input: OnboardingOrchestratorInput = {
    target: options.target ?? 'adapter-installed', cliVersion: version, publicArgs: ['--extension', 'pi'], resumed: true,
    bootstrapVersion: version, runtimePath: runtime,
  };
  return { calls, deps, input, get metadata() { return metadata; }, get running() { return running; }, get locked() { return locked; }, get bootstrapLocked() { return bootstrapLocked; } };
}

describe('onboarding orchestrator', () => {
  test('orders fresh launchd Host health before exact Pi installation and returns deterministic completion', async () => {
    const scenario = fixture({ backend: 'launchd', existingHost: false, existingService: false, running: false });
    const result = await runOnboardingOrchestrator(scenario.input, scenario.deps);
    expect(result.readiness).toBe('reload-pending');
    expect(result.steps.map(({ id }) => id)).toEqual([
      'preflight', 'stable-cli', 'relay-config', 'host-init', 'bridge-service',
      'adapter-detect', 'adapter-install', 'strict-readiness', 'completion',
    ]);
    expect(scenario.calls.indexOf('bridge.health')).toBeLessThan(scenario.calls.indexOf('pi.install'));
    expect(scenario.calls).toContain('service.install');
    expect(scenario.calls).toContain('service.start');
    expect(scenario.calls).not.toContain('service.restart');
    expect(result.nextActions).toEqual([
      { id: 'reload-pi', command: '/reload' },
      { id: 'pair-watch', command: 'ariava pair <PAIRING_CODE>' },
    ]);
    expect(scenario.locked).toBe(false);
    expect(scenario.metadata.installer).toMatchObject({ manager: 'npm', ariavaBinRealPath: cli });
    expect(scenario.metadata.bridgeSource).toMatchObject({ kind: 'npm-package', package: `ariava@${version}` });
    expect(scenario.calls.indexOf('metadata.save')).toBeLessThan(scenario.calls.indexOf('readiness'));
  });

  test('supports capable native Linux and WSL while unsupported WSL fails before writes', async () => {
    for (const isWsl of [false, true]) {
      const supported = fixture({ isWsl, target: 'host-ready', existingService: false, running: false });
      expect((await runOnboardingOrchestrator(supported.input, supported.deps)).readiness).toBe('host-ready');
    }
    const unavailable = fixture({ supported: false, isWsl: true, existingHost: false, existingService: false });
    const result = await runOnboardingOrchestrator(unavailable.input, unavailable.deps);
    expect(result.readiness).toBe('failed');
    expect(unavailable.calls).toEqual(['detect']);
    expect(result.steps[0]).toMatchObject({ id: 'preflight', status: 'failed' });
  });

  test('healthy rerun is reality-derived no-op and Bridge-only skips Pi', async () => {
    const scenario = fixture({ target: 'host-ready', piAction: 'reused' });
    const result = await runOnboardingOrchestrator(scenario.input, scenario.deps);
    expect(result.readiness).toBe('host-ready');
    expect(result.steps.find((step) => step.id === 'host-init')?.status).toBe('reused');
    expect(result.steps.find((step) => step.id === 'bridge-service')?.status).toBe('reused');
    expect(result.steps.find((step) => step.id === 'adapter-install')?.status).toBe('skipped');
    expect(scenario.calls).not.toContain('service.install');
    expect(scenario.calls).not.toContain('service.start');
    expect(scenario.calls).not.toContain('pi.install');
  });

  test('healthy Pi rerun reuses exact package without rewriting metadata', async () => {
    const scenario = fixture({ target: 'adapter-installed', piAction: 'reused' });
    scenario.calls.length = 0;
    const before = structuredClone(scenario.metadata);
    const result = await runOnboardingOrchestrator(scenario.input, scenario.deps);
    expect(result.readiness).toBe('reload-pending');
    expect(result.steps.find((step) => step.id === 'adapter-install')?.status).toBe('reused');
    expect(scenario.calls).toContain('pi.install');
    expect(scenario.calls).not.toContain('metadata.save');
    expect(scenario.metadata).toEqual(before);
  });

  test('reconciles stale release-owned service through the one ServiceManager', async () => {
    const scenario = fixture({ stalePaths: true });
    const result = await runOnboardingOrchestrator(scenario.input, scenario.deps);
    expect(result.readiness).toBe('reload-pending');
    expect(scenario.calls.filter((call) => call === 'service.install')).toHaveLength(1);
    expect(scenario.calls).not.toContain('service.uninstall');
    expect(scenario.calls).not.toContain('service.restart');
    expect(scenario.metadata.service?.runtimePath).toBe(runtime);
    expect(scenario.metadata.service?.ariavaBinPath).toBe(cli);
  });

  test('Pi failure is retryable incomplete and preserves the healthy running Bridge', async () => {
    const scenario = fixture({ piFailure: true });
    const result = await runOnboardingOrchestrator(scenario.input, scenario.deps);
    expect(result.readiness).toBe('failed');
    expect(scenario.running).toBe(true);
    expect(scenario.calls.indexOf('bridge.health')).toBeLessThan(scenario.calls.indexOf('pi.install'));
    expect(scenario.calls).not.toContain('service.stop');
    expect(scenario.calls).not.toContain('service.uninstall');
    expect(result.steps.find((step) => step.id === 'adapter-install')).toMatchObject({ status: 'failed' });
    expect(result.nextActions[0]?.id).toBe('retry-onboarding');
  });

  test('preserves structured remediation from an orchestrator failure', async () => {
    const scenario = fixture({ supported: false, isWsl: true, existingHost: false, existingService: false });
    const originalDetect = scenario.deps.detect;
    scenario.deps.detect = () => ({
      ...originalDetect(),
      serviceSupport: {
        platform: 'linux', backend: 'systemd-user', supported: false, isWsl: true,
        reason: 'systemd-user-manager-unavailable', detail: 'Enable systemd, then run wsl.exe --shutdown.',
      },
    });
    const result = await runOnboardingOrchestrator(scenario.input, scenario.deps);
    expect(result.steps[0]?.detail).toMatchObject({
      code: 'ERR_SYSTEMD_USER_UNAVAILABLE',
      remediation: { message: 'Enable systemd, then run wsl.exe --shutdown.' },
    });
  });

  test('cancellation releases only its lock and leaves completed service state intact', async () => {
    const scenario = fixture({ existingService: false, running: false, cancelAt: 'service.start' });
    const result = await runOnboardingOrchestrator(scenario.input, scenario.deps);
    expect(result.readiness).toBe('failed');
    expect(scenario.locked).toBe(false);
    expect(scenario.metadata.service).toBeDefined();
    expect(scenario.calls).not.toContain('service.stop');
    expect(scenario.calls).not.toContain('service.uninstall');
  });

  test('bootstrap re-entry is enclosed by the ephemeral lock and returns before product-state writes', async () => {
    const scenario = fixture();
    scenario.input.bootstrapVersion = undefined;
    const child: OnboardingResult = { target: 'host-ready', readiness: 'host-ready', steps: [], nextActions: [] };
    scenario.deps.bootstrap = () => {
      expect(scenario.bootstrapLocked).toBe(true);
      return { status: 'installed', evidence: { executablePath: cli }, reentry: { command: cli, args: ['setup', '--resume'] } };
    };
    scenario.deps.reenter = async (command, args) => {
      expect(scenario.bootstrapLocked).toBe(true);
      scenario.calls.push(`reenter:${command}:${args.join(' ')}`);
      return child;
    };
    expect(await runOnboardingOrchestrator(scenario.input, scenario.deps)).toBe(child);
    expect(scenario.bootstrapLocked).toBe(false);
    expect(scenario.calls).toContain('bootstrap-lock.release');
    expect(scenario.calls).not.toContain('lock.acquire');
    expect(scenario.calls).not.toContain('config.save');
  });

  test('stable child proves its path without reacquiring the parent bootstrap lock', async () => {
    const scenario = fixture();
    scenario.input.bootstrapVersion = version;
    await runOnboardingOrchestrator(scenario.input, scenario.deps);
    expect(scenario.calls).not.toContain('bootstrap-lock.acquire');
    expect(scenario.calls).toContain('lock.acquire');
  });
});
