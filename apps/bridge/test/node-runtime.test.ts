import { describe, expect, test } from 'bun:test';
import { isSupportedNodeVersion, probeNodeRuntime } from '../src/runtime/node-runtime';
import { runPublicCli, type PublicCliDependencies } from '../src/public-cli-app';
import type { ServiceManager, ServiceSupport } from '../src/host-manager';

function sink() {
  let value = '';
  return {
    stream: { write(chunk: string | Uint8Array) { value += chunk.toString(); return true; } } as NodeJS.WritableStream,
    text: () => value,
  };
}

describe('production Node runtime contract', () => {
  test('accepts only Node 22 or newer version strings', () => {
    expect(isSupportedNodeVersion('v22.0.0')).toBe(true);
    expect(isSupportedNodeVersion('24.3.0')).toBe(true);
    expect(isSupportedNodeVersion('v21.9.0')).toBe(false);
    expect(isSupportedNodeVersion('bun 1.3.14')).toBe(false);
  });

  test('probes the exact runtime path with an argument array', () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const inspection = probeNodeRuntime('/absolute/node', {
      run(command, args) { calls.push({ command, args }); return { status: 0, stdout: 'v22.1.0\n', stderr: '' }; },
    });
    expect(calls).toEqual([{ command: '/absolute/node', args: ['--version'] }]);
    expect(inspection).toMatchObject({ runtimeName: 'node', runtimeVersion: 'v22.1.0', runtimeVersionSupported: true });
    expect(() => probeNodeRuntime('/absolute/node21', {
      run: () => ({ status: 0, stdout: 'v21.9.0\n', stderr: '' }),
    })).toThrow('Node.js 22 or newer');
  });

  test.each([
    { command: 'init', argv: ['init', '--json'] },
    { command: 'identity status', argv: ['identity', 'status', '--json'] },
    { command: 'host rotate-key', argv: ['host', 'rotate-key', '--json'] },
    { command: 'host reset --confirm', argv: ['host', 'reset', '--confirm', '--json'] },
    { command: 'pair', argv: ['pair', 'PEYX7K', '--json'] },
  ])('$command fails its production runtime precondition before shared domain or effects', async ({ argv }) => {
    const fixture = preconditionFixture(unsupportedRuntime);

    expect(await runPublicCli(argv, fixture.deps)).toBe(1);
    expect(fixture.runtimeInspections).toBe(1);
    expect(fixture.serviceManagerCreations).toBe(0);
    expect(fixture.effects).toEqual(zeroEffects());
    expect(fixture.errors.text()).toContain('ERR_NODE_RUNTIME_UNSUPPORTED');
    expect(fixture.errors.text()).toContain('Current runtime: bun 1.3.14');
  });


  test.each([
    { command: 'service', argv: ['service', 'status', '--json'] },
    { command: 'install pi', argv: ['install', 'pi', '--json'] },
    { command: 'upgrade pi', argv: ['upgrade', 'pi', '--json'] },
    { command: 'upgrade', argv: ['upgrade', '--json'] },
    { command: 'remove pi', argv: ['remove', 'pi', '--json'] },
    { command: 'production dev source', argv: ['dev', 'status', '--json'] },
    { command: 'logs', argv: ['logs', '--json'] },
    { command: 'uninstall', argv: ['uninstall', '--json'] },
    { command: 'internal', argv: ['internal', 'bridge-daemon', '--config', '/tmp/config.json', '--json'] },
  ])('$command fails its production runtime gate before lifecycle effects', async ({ argv }) => {
    const fixture = preconditionFixture(unsupportedRuntime);

    expect(await runPublicCli(argv, fixture.deps)).toBe(1);
    expect(fixture.runtimeInspections).toBe(1);
    expect(fixture.serviceManagerCreations).toBe(0);
    expect(fixture.effects).toEqual(zeroEffects());
    expect(fixture.errors.text()).toContain('ERR_NODE_RUNTIME_UNSUPPORTED');
  });
  test('init fails its existing platform precondition before shared domain or effects', async () => {
    const fixture = preconditionFixture(supportedRuntime, unsupportedPlatform);

    expect(await runPublicCli(['init', '--json'], fixture.deps)).toBe(1);
    expect(fixture.runtimeInspections).toBe(1);
    expect(fixture.serviceManagerCreations).toBe(1);
    expect(fixture.effects).toEqual(zeroEffects());
    expect(fixture.errors.text()).toContain('ERR_UNSUPPORTED_PLATFORM');
  });

  test.each([
    { command: 'implicit help', argv: [], runtimeInspections: 1, onboardingRuns: 0 },
    { command: 'help', argv: ['help', '--json'], runtimeInspections: 1, onboardingRuns: 0 },
    { command: '--help', argv: ['--help', '--json'], runtimeInspections: 1, onboardingRuns: 0 },
    { command: '--version', argv: ['--version', '--json'], runtimeInspections: 0, onboardingRuns: 0 },
    { command: 'setup', argv: ['setup', '--no-extensions', '--json'], runtimeInspections: 0, onboardingRuns: 1 },
  ])('$command retains its exact production runtime exemption', async ({ argv, runtimeInspections, onboardingRuns }) => {
    const fixture = preconditionFixture(unsupportedRuntime);
    let observedOnboardingRuns = 0;

    expect(await runPublicCli(argv, fixture.deps, {
      terminal: { stdout: fixture.output.stream, stderr: fixture.errors.stream, interactive: false, color: false },
      detect: () => ({ pi: { present: true } } as never),
      run: async () => {
        observedOnboardingRuns += 1;
        return { target: 'host-ready', readiness: 'host-ready', steps: [], nextActions: [] };
      },
    })).toBe(0);
    expect(fixture.runtimeInspections).toBe(runtimeInspections);
    expect(fixture.serviceManagerCreations).toBe(0);
    expect(fixture.effects).toEqual(zeroEffects());
    expect(observedOnboardingRuns).toBe(onboardingRuns);
  });
});

const unsupportedRuntime = {
  runtimeName: 'bun',
  runtimeVersion: '1.3.14',
  runtimePath: '/bun',
  runtimeNameIsNode: false,
  runtimeVersionSupported: false,
};

const supportedRuntime = {
  runtimeName: 'node',
  runtimeVersion: 'v22.18.0',
  runtimePath: '/usr/bin/node',
  runtimeNameIsNode: true,
  runtimeVersionSupported: true,
};

const unsupportedPlatform: ServiceSupport = {
  platform: 'win32',
  supported: false,
  isWsl: false,
  reason: 'unsupported-platform',
};

interface PreconditionEffects {
  domainCalls: number;
  profileConfigReads: number;
  profileConfigWrites: number;
  profileFilesystemReads: number;
  profileFilesystemWrites: number;
  keychainCalls: number;
  relayCalls: number;
  childSpawns: number;
  serviceActions: number;
}

function zeroEffects(): PreconditionEffects {
  return {
    domainCalls: 0,
    profileConfigReads: 0,
    profileConfigWrites: 0,
    profileFilesystemReads: 0,
    profileFilesystemWrites: 0,
    keychainCalls: 0,
    relayCalls: 0,
    childSpawns: 0,
    serviceActions: 0,
  };
}

function preconditionFixture(
  runtime: ReturnType<PublicCliDependencies['inspectRuntime']>,
  support: ServiceSupport = unsupportedPlatform,
): {
  deps: Partial<PublicCliDependencies>;
  effects: PreconditionEffects;
  output: ReturnType<typeof sink>;
  errors: ReturnType<typeof sink>;
  readonly runtimeInspections: number;
  readonly serviceManagerCreations: number;
} {
  const output = sink();
  const errors = sink();
  const effects = zeroEffects();
  let runtimeInspections = 0;
  let serviceManagerCreations = 0;
  const serviceManager = {
    backend: support.backend,
    support,
    install: () => { effects.serviceActions += 1; return null as never; },
    uninstall: () => { effects.serviceActions += 1; },
    start: () => { effects.serviceActions += 1; },
    stop: () => { effects.serviceActions += 1; },
    restart: () => { effects.serviceActions += 1; },
    status: () => { effects.serviceActions += 1; return null as never; },
    logsAvailable: () => { effects.serviceActions += 1; return false; },
    logs: () => { effects.serviceActions += 1; return null; },
  } as ServiceManager;
  const deps: Partial<PublicCliDependencies> = {
    stdout: output.stream,
    stderr: errors.stream,
    inspectRuntime: () => { runtimeInspections += 1; return runtime; },
    probeRuntimePath: () => runtime,
    createServiceManager: () => { serviceManagerCreations += 1; return serviceManager; },
    createProfile: () => { effects.domainCalls += 1; return null as never; },
    loadUserConfig: () => { effects.profileConfigReads += 1; return {}; },
    saveUserConfig: () => { effects.profileConfigWrites += 1; },
    resolveAriavaConfig: () => { effects.profileConfigReads += 1; return null as never; },
    loadInstallMetadata: () => { effects.profileFilesystemReads += 1; return {}; },
    loadInstallMetadataDetailed: () => { effects.profileFilesystemReads += 1; return null as never; },
    mergeInstallMetadata: () => { effects.profileFilesystemWrites += 1; return {}; },
    saveInstallMetadata: () => { effects.profileFilesystemWrites += 1; },
    pathExists: () => { effects.profileFilesystemReads += 1; return false; },
    realpath: () => { effects.profileFilesystemReads += 1; return ''; },
    removePath: () => { effects.profileFilesystemWrites += 1; },
    createHostIdentityStore: () => { effects.keychainCalls += 1; return null as never; },
    createPairDependencies: () => { effects.relayCalls += 1; return null as never; },
    spawn: () => { effects.childSpawns += 1; return null as never; },
    spawnAsync: async () => { effects.childSpawns += 1; return null as never; },
  };
  return {
    deps,
    effects,
    output,
    errors,
    get runtimeInspections() { return runtimeInspections; },
    get serviceManagerCreations() { return serviceManagerCreations; },
  };
}
