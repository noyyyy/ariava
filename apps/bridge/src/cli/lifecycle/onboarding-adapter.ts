import { randomBytes } from 'node:crypto';
import { spawn as spawnChild } from 'node:child_process';
import { accessSync, constants, readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { createHostEncryptionBinding } from '../../identity/host-encryption-key';
import { createRuntimeHostEncryptionIdentityStore } from '../../identity/runtime-store';
import type { HostIdentityStore } from '../../identity/types';
import { probeHostPlatform } from '../../host-platform';
import type { AriavaProfileDescriptor } from '../profile';
import {
  loadInstallMetadata,
  loadUserConfig,
  resolveAriavaConfig,
  saveInstallMetadata,
  saveUserConfig,
  type AriavaInstallMetadata,
  type AriavaUserConfig,
} from '../../host-manager/config';
import { resolveAriavaDevProfilePaths } from '../../host-manager/dev-profile';
import { initializeHost } from '../../host-manager/initialization';
import { bootstrapStableCli } from '../../host-manager/onboarding/bootstrap';
import { detectOnboardingEnvironment } from '../../host-manager/onboarding/detector';
import type { OnboardingHostState } from '../../host-manager/onboarding/host-state-policy';
import {
  acquireOnboardingLock,
  ephemeralBootstrapLockPath,
  type OwnedOnboardingLock,
} from '../../host-manager/onboarding/lock';
import {
  runOnboardingOrchestrator,
  type OnboardingOrchestratorDependencies,
} from '../../host-manager/onboarding/orchestrator';
import {
  checkStrictOnboardingReadiness,
  type StrictReadinessDependencies,
  type StrictReadinessInput,
} from '../../host-manager/onboarding/readiness/check';
import {
  pollForDiscoveryAndHealth,
  type LocalHealthDependencies,
} from '../../host-manager/onboarding/readiness/local-bridge';
import {
  isProductionOnboardingResult,
  ONBOARDING_SUCCESS_CODE,
  ONBOARDING_SUCCESS_MESSAGE,
  type OnboardingDetection,
  type OnboardingResult,
} from '../../host-manager/onboarding/types';
import {
  ARIAVA_CONFIG_PATH,
  ARIAVA_ONBOARDING_LOCK_PATH,
} from '../../host-manager/paths';
import { ensureExactPiPackage } from '../../host-manager/pi-extension';
import { SpawnSyncCommandRunner } from '../../host-manager/service/command-runner';
import { AriavaCliError } from '../../host-manager/service/errors';
import type { CommandRunner } from '../../host-manager/service/types';
import type { OnboardingServiceManager } from '../../host-manager/onboarding/service-reconcile';

type AdapterServiceManager = OnboardingServiceManager & Pick<
  import('../../host-manager/service/types').ServiceManager,
  'start'
>;

export interface OnboardingChildResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

export interface DefaultOnboardingAdapterDependencies {
  createServiceManager(): AdapterServiceManager;
  currentRuntimePath(): string;
  currentAriavaBinPath(): string;
  pathExists(path: string): boolean;
  realpath(path: string): string;
  loadUserConfig(): AriavaUserConfig;
  saveUserConfig(config: AriavaUserConfig): void;
  loadInstallMetadata(): AriavaInstallMetadata;
  saveInstallMetadata(metadata: AriavaInstallMetadata): void;
  spawnAsync(command: string, args: string[], options: { signal?: AbortSignal }): Promise<OnboardingChildResult>;
  createHostIdentityStore(
    path: string,
    platform: NodeJS.Platform | string,
    identityProfile?: AriavaProfileDescriptor['resources']['identityProfile'],
  ): HostIdentityStore;
  createProfile(): AriavaProfileDescriptor;
}

export interface DefaultOnboardingAdapterOptions {
  cliVersion: string;
  packageRoot: string;
}

export interface DefaultOnboardingAdapterRuntimePorts {
  architecture: string;
  nodeVersion: string;
  environment: NodeJS.ProcessEnv;
  configPath: string;
  devConfigPath: string;
  createCommandRunner(): CommandRunner;
  readPackageVersion(packageRoot: string): string | undefined;
  assertPrefixWritable(prefix: string): void;
  acquireBootstrapLock(version: string): OwnedOnboardingLock;
  acquireOnboardingLock(): OwnedOnboardingLock;
  initializeHost: typeof initializeHost;
  resolveConfig: typeof resolveAriavaConfig;
  createEncryptionIdentityStore: typeof createRuntimeHostEncryptionIdentityStore;
  hostName(): string;
  generateSecret(): string;
  proveBridgeHealth: typeof pollForDiscoveryAndHealth;
  healthDependencies: Partial<LocalHealthDependencies>;
  installPi: typeof ensureExactPiPackage;
  checkReadiness: typeof checkStrictOnboardingReadiness;
  readinessDependencies: Partial<StrictReadinessDependencies>;
  now?(): string;
  sleep?(milliseconds: number): Promise<void>;
}

export interface DefaultOnboardingAdapter {
  detect(machineOutput: boolean, interactive: boolean): OnboardingDetection;
  run(input: {
    target: 'host-ready' | 'adapter-installed';
    publicArgs: readonly string[];
    resumed: boolean;
    bootstrapVersion?: string;
    relayBaseUrl?: string;
    signal?: AbortSignal;
  }): Promise<OnboardingResult>;
}

const defaultRuntimePorts: DefaultOnboardingAdapterRuntimePorts = {
  architecture: process.arch,
  nodeVersion: process.version,
  environment: process.env,
  configPath: ARIAVA_CONFIG_PATH,
  devConfigPath: resolveAriavaDevProfilePaths().configPath,
  createCommandRunner: () => new SpawnSyncCommandRunner(),
  readPackageVersion: readVersionAtRoot,
  assertPrefixWritable: (path) => accessSync(path, constants.W_OK | constants.X_OK),
  acquireBootstrapLock: (version) => acquireOnboardingLock(ephemeralBootstrapLockPath(version)),
  acquireOnboardingLock: () => acquireOnboardingLock(ARIAVA_ONBOARDING_LOCK_PATH),
  initializeHost,
  resolveConfig: resolveAriavaConfig,
  createEncryptionIdentityStore: createRuntimeHostEncryptionIdentityStore,
  hostName: hostname,
  generateSecret: () => randomBytes(32).toString('hex'),
  proveBridgeHealth: pollForDiscoveryAndHealth,
  healthDependencies: {},
  installPi: ensureExactPiPackage,
  checkReadiness: checkStrictOnboardingReadiness,
  readinessDependencies: {},
};

export function createDefaultOnboardingAdapter(
  deps: DefaultOnboardingAdapterDependencies,
  options: DefaultOnboardingAdapterOptions,
  overrides: Partial<DefaultOnboardingAdapterRuntimePorts> = {},
): DefaultOnboardingAdapter {
  const runtime = { ...defaultRuntimePorts, ...overrides };
  return {
    detect: (machineOutput, interactive) => createOnboardingDetection(
      deps,
      options,
      runtime,
      machineOutput,
      interactive,
    ),
    run: (input) => runDefaultOnboarding(deps, options, runtime, input),
  };
}

export function spawnOnboardingChild(
  command: string,
  args: string[],
  options: { signal?: AbortSignal },
): Promise<OnboardingChildResult> {
  return new Promise((resolveChild) => {
    const child = spawnChild(command, args, { stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let error: Error | undefined;
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', (cause) => { error = cause; });
    const abort = () => child.kill('SIGTERM');
    if (options.signal?.aborted) abort();
    else options.signal?.addEventListener('abort', abort, { once: true });
    child.once('close', (status) => {
      options.signal?.removeEventListener('abort', abort);
      resolveChild({
        status,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
        ...(error ? { error } : {}),
      });
    });
  });
}

export function decodeStableOnboardingChild(child: OnboardingChildResult): OnboardingResult {
  const envelope = parseStableChildEnvelope(child.stdout, child.stderr);
  if (isStableOnboardingEnvelope(envelope)) return envelope.data;
  if (isStructuredFailureEnvelope(envelope)) {
    throw new AriavaCliError(
      envelope.code as AriavaCliError['code'],
      envelope.message,
      envelope.data,
    );
  }
  if ((child.status ?? 1) !== 0 && !envelope && child.error) {
    throw new AriavaCliError(
      'ERR_STABLE_CLI_PATH',
      child.error.message,
      { step: 'stable-cli', retryable: true },
    );
  }
  throwMalformedStableChild();
}

function createOnboardingDetection(
  deps: DefaultOnboardingAdapterDependencies,
  options: DefaultOnboardingAdapterOptions,
  runtime: DefaultOnboardingAdapterRuntimePorts,
  machineOutput: boolean,
  interactive: boolean,
): OnboardingDetection {
  const runner = runtime.createCommandRunner();
  const manager = deps.createServiceManager();
  const binPath = deps.realpath(deps.currentAriavaBinPath());
  const prefix = resolveNpmPrefix(runner);
  return detectOnboardingEnvironment({
    platform: manager.support.platform as NodeJS.Platform,
    architecture: runtime.architecture,
    nodeVersion: runtime.nodeVersion,
    runner,
    detectServiceSupport: () => manager.support,
    isTty: interactive,
    machineOutput,
    configPath: runtime.configPath,
    devConfigPath: runtime.devConfigPath,
    pathExists: deps.pathExists,
    loadConfig: () => deps.loadUserConfig(),
    loadInstallMetadata: deps.loadInstallMetadata,
    currentCli: {
      executablePath: binPath,
      packageRoot: options.packageRoot,
      packageVersion: options.cliVersion,
      npmPrefix: prefix,
      npmBinPath: prefix ? join(prefix, 'bin') : undefined,
    },
  });
}

async function runDefaultOnboarding(
  deps: DefaultOnboardingAdapterDependencies,
  options: DefaultOnboardingAdapterOptions,
  runtime: DefaultOnboardingAdapterRuntimePorts,
  input: Parameters<DefaultOnboardingAdapter['run']>[0],
): Promise<OnboardingResult> {
  const manager = deps.createServiceManager();
  const runner = runtime.createCommandRunner();
  const detectMachineEnvironment = () => createOnboardingDetection(deps, options, runtime, true, false);
  const orchestratorDeps: OnboardingOrchestratorDependencies = {
    detect: detectMachineEnvironment,
    bootstrap: (bootstrapInput) => bootstrapStableCli(bootstrapInput, {
      runner,
      realpath: deps.realpath,
      readPackageVersion: runtime.readPackageVersion,
      assertPrefixWritable: runtime.assertPrefixWritable,
      resolveGlobalPrefix: () => resolveNpmPrefix(runner),
      resolveStableExecutable: (prefix) => {
        const path = join(prefix, 'bin', 'ariava');
        return deps.pathExists(path) ? deps.realpath(path) : undefined;
      },
      currentCli: detectMachineEnvironment().currentCli,
    }),
    reenter: async (command, args) => {
      throwIfOnboardingAborted(input.signal);
      const child = await deps.spawnAsync(command, [...args, '--json'], { signal: input.signal });
      const result = decodeStableOnboardingChild(child);
      throwIfOnboardingAborted(input.signal);
      return result;
    },
    acquireBootstrapLock: () => runtime.acquireBootstrapLock(options.cliVersion),
    acquireLock: runtime.acquireOnboardingLock,
    loadUserConfig: deps.loadUserConfig,
    saveUserConfig: deps.saveUserConfig,
    initializeHost: (relayBaseUrl) => runtime.initializeHost(
      { relayBaseUrl, useEnvironmentIdentityPath: false },
      {
        loadUserConfig: deps.loadUserConfig,
        saveUserConfig: deps.saveUserConfig,
        createIdentityStore: (path) => deps.createHostIdentityStore(path, manager.support.platform),
        createEncryptionIdentityStore: (path) => runtime.createEncryptionIdentityStore(path, manager.support.platform),
        hostName: runtime.hostName,
        generateSecret: runtime.generateSecret,
        environment: runtime.environment,
        profile: deps.createProfile(),
        platform: manager.support.platform,
      },
    ),
    loadHostState: () => loadOnboardingHostState(deps, manager, runtime),
    loadInstallMetadata: deps.loadInstallMetadata,
    saveInstallMetadata: deps.saveInstallMetadata,
    serviceManager: manager,
    adapterProbe: () => detectMachineEnvironment().pi,
    proveBridgeHealth: async (state) => {
      await runtime.proveBridgeHealth(
        { config: state.config, identity: state.identity, signal: input.signal },
        runtime.healthDependencies,
      );
    },
    installPi: (version) => runtime.installPi(version),
    checkReadiness: ({ target, stableCli, state, installMetadata, service, pi }) => runtime.checkReadiness(
      {
        ...buildReadinessInput(deps, manager, options, state, target, stableCli, installMetadata, service, pi),
        signal: input.signal,
      },
      {
        ...runtime.readinessDependencies,
        serviceStatus: () => manager.status(
          deps.loadInstallMetadata().service,
          deps.realpath(deps.currentRuntimePath()),
          deps.realpath(deps.currentAriavaBinPath()),
        ),
      },
    ),
    cancellation: { throwIfCancelled: () => throwIfOnboardingAborted(input.signal) },
    ...(runtime.now ? { now: runtime.now } : {}),
    ...(runtime.sleep ? { sleep: runtime.sleep } : {}),
  };
  return runOnboardingOrchestrator({
    ...input,
    cliVersion: options.cliVersion,
    runtimePath: deps.realpath(deps.currentRuntimePath()),
  }, orchestratorDeps);
}

async function loadOnboardingHostState(
  deps: DefaultOnboardingAdapterDependencies,
  manager: AdapterServiceManager,
  runtime: DefaultOnboardingAdapterRuntimePorts,
): Promise<OnboardingHostState | undefined> {
  const config = runtime.resolveConfig({}, runtime.configPath, false);
  const store = deps.createHostIdentityStore(config.identityPath, manager.support.platform);
  const identityInspection = await store.inspect();
  if (identityInspection.status === 'not-initialized') return undefined;
  const identity = await store.load();
  if (!identity) return undefined;
  const encryptionIdentity = runtime.createEncryptionIdentityStore(
    config.identityPath,
    manager.support.platform,
  ).load();
  if (!encryptionIdentity || encryptionIdentity.hostId !== identity.hostId) {
    throw new AriavaCliError(
      'ERR_IDENTITY_INVALID',
      'Persisted Host encryption identity is missing or belongs to another Host.',
      { step: 'host-init', retryable: false, remediation: { command: 'ariava identity reset --confirm' } },
    );
  }
  return {
    config,
    identityInspection,
    identity,
    encryptionBinding: await createHostEncryptionBinding(identity, encryptionIdentity),
  };
}

function buildReadinessInput(
  deps: DefaultOnboardingAdapterDependencies,
  manager: AdapterServiceManager,
  options: DefaultOnboardingAdapterOptions,
  state: OnboardingHostState,
  target: StrictReadinessInput['target'],
  stableCli: StrictReadinessInput['stableCli'],
  installMetadata: AriavaInstallMetadata,
  service: NonNullable<AriavaInstallMetadata['service']>,
  pi: StrictReadinessInput['piStatus'],
): StrictReadinessInput {
  return {
    target,
    cliVersion: options.cliVersion,
    stableCli,
    installMetadata,
    config: state.config,
    identityInspection: state.identityInspection,
    identity: state.identity,
    encryptionBinding: state.encryptionBinding,
    serviceRecord: service,
    expectedRuntimePath: deps.realpath(deps.currentRuntimePath()),
    expectedAriavaBinPath: stableCli.executablePath,
    hostMetadata: {
      hostName: state.config.hostName,
      platform: probeHostPlatform(manager.support.platform),
      bridgeVersion: options.cliVersion,
    },
    piStatus: pi,
  };
}

function resolveNpmPrefix(runner: CommandRunner): string | undefined {
  const result = runner.run('npm', ['prefix', '--global']);
  const value = result.status === 0 ? result.stdout.trim() : '';
  return value && isAbsolute(value) ? resolve(value) : undefined;
}

function readVersionAtRoot(root: string): string | undefined {
  try {
    return (JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: string }).version;
  } catch {
    return undefined;
  }
}

function throwIfOnboardingAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  throw new AriavaCliError('ERR_ONBOARDING_NOT_READY', 'Ariava onboarding was cancelled.', {
    step: 'preflight',
    retryable: true,
    remediation: { command: 'ariava setup --resume' },
  });
}

function parseStableChildEnvelope(stdout: unknown, stderr: unknown): Record<string, unknown> | undefined {
  for (const raw of [stdout, stderr]) {
    const text = String(raw ?? '').trim();
    if (!text) continue;
    try {
      const value = JSON.parse(text) as unknown;
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return value as Record<string, unknown>;
      }
    } catch {
      // Stable children return one JSON envelope; the other stream may own it.
    }
  }
  return undefined;
}

function isStableOnboardingEnvelope(
  value: Record<string, unknown> | undefined,
): value is Record<string, unknown> & { data: OnboardingResult } {
  if (!value || !hasExactKeys(value, ['ok', 'code', 'message', 'data'])) return false;
  if (!isProductionOnboardingResult(value.data)) return false;
  if (value.data.readiness === 'failed') {
    return value.ok === false
      && isNonemptyString(value.code)
      && value.code !== ONBOARDING_SUCCESS_CODE
      && isNonemptyString(value.message);
  }
  return value.ok === true
    && value.code === ONBOARDING_SUCCESS_CODE
    && value.message === ONBOARDING_SUCCESS_MESSAGE;
}

function isStructuredFailureEnvelope(
  value: Record<string, unknown> | undefined,
): value is { ok: false; code: string; message: string; data: Record<string, unknown> } {
  return Boolean(value
    && hasExactKeys(value, ['ok', 'code', 'message', 'data'])
    && value.ok === false
    && isNonemptyString(value.code)
    && isNonemptyString(value.message)
    && isPlainRecord(value.data)
    && !isProductionOnboardingResult(value.data));
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isNonemptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function throwMalformedStableChild(): never {
  throw new AriavaCliError(
    'ERR_STABLE_CLI_PATH',
    'Stable Ariava CLI re-entry returned malformed output.',
    { step: 'stable-cli', retryable: true },
  );
}
