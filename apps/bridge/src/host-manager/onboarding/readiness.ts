import { randomBytes } from 'node:crypto';
import type { HostPlatform, HostEnrollmentResponse } from '@ariava/protocol';
import { base64UrlEncode, isCanonicalTimestamp } from '@ariava/protocol';
import { readAgentAdapterConfig, type AgentAdapterDiscoveryFile } from '../../agent-adapter/config';
import type { HostIdentity, HostIdentityInspection, HostPrivateKeyStorage } from '../../identity/types';
import { RelayClient, RelayClientError } from '../../relay-client';
import type { AriavaInstallMetadata, ResolvedAriavaConfig } from '../config';
import type { PiExtensionStatus } from '../pi-extension';
import { AriavaCliError } from '../service/errors';
import type { AriavaServiceInstallRecord, ServiceStatus } from '../service/types';
import type { HostReadinessCheck, OnboardingCliEvidence, OnboardingTarget, StrictReadinessResult } from './types';

export interface ReadinessClock {
  now(): number;
  sleep(milliseconds: number): Promise<void>;
}

export interface StrictReadinessDependencies {
  fetch: typeof fetch;
  clock: ReadinessClock;
  readDiscovery(path: string): AgentAdapterDiscoveryFile | null;
  serviceStatus(): ServiceStatus;
  createRelayClient(options: ConstructorParameters<typeof RelayClient>[0], requestSignal?: () => AbortSignal | undefined): Pick<RelayClient, 'enrollHost'>;
  nonce(): string;
}

export interface StrictReadinessInput {
  target: OnboardingTarget;
  cliVersion: string;
  stableCli: OnboardingCliEvidence;
  installMetadata: AriavaInstallMetadata;
  config: ResolvedAriavaConfig;
  identityInspection: HostIdentityInspection;
  identity: HostIdentity;
  serviceRecord?: AriavaServiceInstallRecord;
  expectedRuntimePath: string;
  expectedAriavaBinPath: string;
  hostMetadata: { hostName: string; platform: HostPlatform; bridgeVersion: string };
  piStatus?: PiExtensionStatus;
  timeoutMs?: number;
  pollIntervalMs?: number;
  requestTimeoutMs?: number;
  signal?: AbortSignal;
}

const defaultClock: ReadinessClock = {
  now: () => Date.now(),
  sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
};

const defaultDependencies: StrictReadinessDependencies = {
  fetch,
  clock: defaultClock,
  readDiscovery: readAgentAdapterConfig,
  serviceStatus: () => { throw new Error('A service status dependency is required'); },
  createRelayClient: (options, requestSignal) => new RelayClient(options, requestSignal),
  // Signed-request nonces must be canonical base64url of exactly 16 bytes.
  nonce: () => base64UrlEncode(randomBytes(16)),
};

export async function checkStrictOnboardingReadiness(
  input: StrictReadinessInput,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<StrictReadinessResult> {
  const deps = { ...defaultDependencies, ...overrides };
  const checks: HostReadinessCheck[] = [];
  const add = (id: HostReadinessCheck['id'], ready: boolean, code?: string): boolean => {
    checks.push({ id, ready, ...(ready || !code ? {} : { code }) });
    return ready;
  };

  add('stable-cli', stableCliMatches(input), 'ERR_STABLE_CLI_PATH');
  add('persisted-config', persistedConfigReady(input), 'ERR_RELAY_CONFIG_REQUIRED');
  add('identity', identityReady(input), 'ERR_IDENTITY_INVALID');

  const service = await pollForService(input, deps);
  add('service-support', service.support.supported, 'ERR_UNSUPPORTED_PLATFORM');
  add('service-installed', service.installed, 'ERR_SERVICE_NOT_INSTALLED');
  add('service-enabled', service.enabled, 'ERR_ONBOARDING_NOT_READY');
  add('service-loaded', service.loaded, 'ERR_ONBOARDING_NOT_READY');
  add('service-running', service.processRunning, 'ERR_ONBOARDING_NOT_READY');
  add('service-paths', servicePathsReady(input, service), 'ERR_SERVICE_METADATA');
  add('service-references', serviceReferencesReady(input), 'ERR_SERVICE_METADATA');

  try {
    await pollForDiscoveryAndHealth(input, deps);
    add('agent-adapter-discovery', true);
    add('agent-adapter-health', true);
  } catch (error) {
    const code = errorCode(error, 'ERR_AGENT_ADAPTER_DISCOVERY');
    add('agent-adapter-discovery', false, code);
    add('agent-adapter-health', false, code);
  }

  // Keep health and enrollment independent so an enrollment-only failure does not
  // misreport Relay health as unreachable.
  try {
    await checkRelayHealth(input, deps);
    add('relay-health', true);
    try {
      await checkRelayEnrollment(input, deps);
      add('relay-enrollment', true);
    } catch (error) {
      const code = errorCode(error, 'ERR_RELAY_UNREACHABLE');
      add('relay-enrollment', false, code);
    }
  } catch (error) {
    const code = errorCode(error, 'ERR_RELAY_UNREACHABLE');
    add('relay-health', false, code);
    add('relay-enrollment', false, code);
  }

  const hostReady = checks.every((check) => check.ready);
  if (!hostReady) return { ready: false, readiness: 'failed', checks, nextActions: [] };
  if (input.target === 'host-ready') return { ready: true, readiness: 'host-ready', checks, nextActions: [] };

  if (!exactPiPackageReady(input.piStatus, input.cliVersion)) {
    return { ready: false, readiness: 'failed', checks, nextActions: [] };
  }
  // Current session registration contains neither extension version nor capability
  // evidence, so even a visible Pi provider session cannot prove adapter readiness.
  return {
    ready: true,
    readiness: 'reload-pending',
    checks,
    nextActions: [{ id: 'reload-pi', command: '/reload' }],
  };
}

export async function pollForDiscoveryAndHealth(
  input: Pick<StrictReadinessInput, 'config' | 'identity' | 'timeoutMs' | 'pollIntervalMs' | 'requestTimeoutMs' | 'signal'>,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<AgentAdapterDiscoveryFile> {
  const deps = { ...defaultDependencies, ...overrides };
  const timeoutMs = boundedPositive(input.timeoutMs, 10_000);
  const intervalMs = boundedPositive(input.pollIntervalMs, 100);
  const deadline = deps.clock.now() + timeoutMs;
  let lastCode = 'ERR_AGENT_ADAPTER_DISCOVERY';

  throwIfAborted(input.signal);
  while (true) {
    try {
      const discovery = deps.readDiscovery(input.config.agentAdapterConfigPath);
      if (discovery) {
        const parsed = new URL(discovery.url);
        if (!isLoopbackUrl(parsed)) {
          throw readinessError('ERR_AGENT_ADAPTER_NOT_LOOPBACK', 'Agent Adapter discovery URL is not a loopback HTTP origin.');
        }
        if (Number(parsed.port) !== input.config.agentAdapterPort) {
          throw readinessError('ERR_AGENT_ADAPTER_DISCOVERY', 'Agent Adapter discovery port does not match persisted configuration.');
        }
        const response = await fetchBounded(new URL('/v1/health', parsed.origin), {
          headers: { authorization: `Bearer ${discovery.secret}` },
        }, boundedPositive(input.requestTimeoutMs, Math.min(timeoutMs, 2_000)), deps);
        if (response.status === 401 || response.status === 403) {
          throw readinessError('ERR_AGENT_ADAPTER_DISCOVERY', 'Agent Adapter authentication failed.');
        }
        if (!response.ok) throw readinessError('ERR_AGENT_ADAPTER_DISCOVERY', 'Agent Adapter health probe failed.');
        const body = await response.json() as unknown;
        if (!isAgentAdapterHealth(body, input.identity.hostId)) {
          throw readinessError('ERR_AGENT_ADAPTER_DISCOVERY', 'Agent Adapter returned mismatched health evidence.');
        }
        return discovery;
      }
    } catch (error) {
      lastCode = errorCode(error, 'ERR_AGENT_ADAPTER_DISCOVERY');
    }
    throwIfAborted(input.signal);
    if (deps.clock.now() >= deadline) {
      throw readinessError(lastCode as 'ERR_AGENT_ADAPTER_DISCOVERY' | 'ERR_AGENT_ADAPTER_NOT_LOOPBACK', 'Timed out waiting for authenticated Agent Adapter health.');
    }
    await deps.clock.sleep(Math.min(intervalMs, Math.max(1, deadline - deps.clock.now())));
  }
}

export async function checkRelay(
  input: Pick<StrictReadinessInput, 'config' | 'identity' | 'hostMetadata' | 'requestTimeoutMs' | 'signal'>,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<void> {
  const deps = { ...defaultDependencies, ...overrides };
  await checkRelayHealth(input, deps);
  await checkRelayEnrollment(input, deps);
}

export async function checkRelayHealth(
  input: Pick<StrictReadinessInput, 'config' | 'requestTimeoutMs' | 'signal'>,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<void> {
  const deps = { ...defaultDependencies, ...overrides };
  const timeoutMs = boundedPositive(input.requestTimeoutMs, 5_000);
  let health: Response;
  try {
    health = await fetchBounded(new URL('/health', input.config.relayBaseUrl), { signal: input.signal }, timeoutMs, deps);
  } catch (error) {
    if (input.signal?.aborted) throw error;
    throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay health could not be reached.');
  }
  if (health.status === 401 || health.status === 403) throw readinessError('ERR_RELAY_AUTH_FAILED', 'Relay rejected health access.');
  if (!health.ok) throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay health is unavailable.');
  try {
    const healthBody = await health.json() as unknown;
    if (!isExactOk(healthBody)) throw new Error('malformed health');
  } catch {
    throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay returned malformed health evidence.');
  }
}

export async function checkRelayEnrollment(
  input: Pick<StrictReadinessInput, 'config' | 'identity' | 'hostMetadata' | 'requestTimeoutMs' | 'signal'>,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<void> {
  const deps = { ...defaultDependencies, ...overrides };
  const timeoutMs = boundedPositive(input.requestTimeoutMs, 5_000);
  const controller = linkedAbortController(input.signal);
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await deps.createRelayClient({
      baseUrl: input.config.relayBaseUrl,
      signer: input.identity.signer,
      fetch: deps.fetch,
      nonce: deps.nonce,
    }, () => controller.signal).enrollHost({
      hostId: input.identity.hostId,
      keyId: input.identity.keyId,
      algorithm: input.identity.algorithm,
      publicKey: input.identity.publicKey,
      ...input.hostMetadata,
    });
    assertEnrollmentResponse(response, input.identity.hostId, input.hostMetadata);
  } catch (error) {
    if (error instanceof RelayClientError) {
      if (error.status === 401 || error.status === 403) throw readinessError('ERR_RELAY_AUTH_FAILED', 'Relay rejected signed Host enrollment.');
      if (error.status === 409 || error.status === 410) throw readinessError('ERR_IDENTITY_INVALID', 'Relay rejected the persisted Host identity.', false);
      throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay signed Host enrollment is unavailable.');
    }
    if (error instanceof AriavaCliError) throw error;
    if (error instanceof TypeError || (error instanceof Error && error.name === 'AbortError')) {
      if (input.signal?.aborted) throw error;
      throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay signed Host enrollment could not be reached.');
    }
    throw readinessError('ERR_IDENTITY_INVALID', 'Relay returned malformed Host enrollment evidence.', false);
  } finally {
    clearTimeout(timeout);
  }
}

function stableCliMatches(input: StrictReadinessInput): boolean {
  const installer = input.installMetadata.installer;
  return input.stableCli.packageVersion === input.cliVersion
    && Boolean(input.stableCli.packageRoot && input.stableCli.npmPrefix && input.stableCli.npmBinPath)
    && installer?.ariavaBinRealPath === input.stableCli.executablePath;
}

function persistedConfigReady(input: StrictReadinessInput): boolean {
  const config = input.config;
  return Boolean(config.relayBaseUrl && config.hostName && config.agentAdapterSecret
    && config.identity?.hostId === input.identity.hostId
    && config.identityPath && config.configPath && config.environmentOverrides.length === 0);
}

function identityReady(input: StrictReadinessInput): boolean {
  const inspected = input.identityInspection;
  return inspected.status === 'ready' && inspected.ownerIntegrity && inspected.permissionIntegrity
    && inspected.metadataIntegrity && !inspected.pendingRotation
    && inspected.hostId === input.identity.hostId && inspected.keyId === input.identity.keyId;
}

async function pollForService(input: StrictReadinessInput, deps: StrictReadinessDependencies): Promise<ServiceStatus> {
  const timeoutMs = boundedPositive(input.timeoutMs, 10_000);
  const intervalMs = boundedPositive(input.pollIntervalMs, 100);
  const deadline = deps.clock.now() + timeoutMs;
  let status = deps.serviceStatus();
  throwIfAborted(input.signal);
  while (status.support.supported && status.installed && !status.processRunning && deps.clock.now() < deadline) {
    throwIfAborted(input.signal);
    await deps.clock.sleep(Math.min(intervalMs, Math.max(1, deadline - deps.clock.now())));
    status = deps.serviceStatus();
  }
  return status;
}

function servicePathsReady(input: StrictReadinessInput, status: ServiceStatus): boolean {
  return status.runtimePath === input.expectedRuntimePath && status.ariavaBinPath === input.expectedAriavaBinPath
    && status.runtimePathMatchesCurrent === true && status.ariavaBinPathMatchesCurrent === true;
}

function serviceReferencesReady(input: StrictReadinessInput): boolean {
  const record = input.serviceRecord;
  return Boolean(record && record.configPath === input.config.configPath
    && sameStorage(record.identityReference, input.config.identity?.privateKeyStorage));
}

function sameStorage(left: HostPrivateKeyStorage | undefined, right: HostPrivateKeyStorage | undefined): boolean {
  return Boolean(left && right && JSON.stringify(left) === JSON.stringify(right));
}

function exactPiPackageReady(status: PiExtensionStatus | undefined, version: string): boolean {
  return Boolean(status?.installed && status.managed && status.sourceOwnership === 'managed-exact'
    && status.registeredSource === status.expectedSource
    && status.manifestName === '@ariava/pi-extension' && status.manifestVersion === version
    && status.installPath === status.expectedManagedPath && status.mismatchReasons.length === 0);
}

function isAgentAdapterHealth(value: unknown, hostId: string): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).sort().join(',') === 'hostId,ok' && record.ok === true && record.hostId === hostId;
}

function isExactOk(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).sort().join(',') === 'ok' && record.ok === true;
}

function assertEnrollmentResponse(response: HostEnrollmentResponse, hostId: string, metadata: StrictReadinessInput['hostMetadata']): void {
  const host = response?.host;
  if (!host || host.hostId !== hostId || host.hostName !== metadata.hostName || host.platform !== metadata.platform
    || host.bridgeVersion !== metadata.bridgeVersion || host.status === 'revoked'
    || !isCanonicalTimestamp(host.registeredAt) || !isCanonicalTimestamp(host.lastSeenAt)) {
    throw new Error('malformed enrollment');
  }
}

async function fetchBounded(url: URL, init: RequestInit, timeoutMs: number, deps: StrictReadinessDependencies): Promise<Response> {
  const externalSignal = init.signal ?? undefined;
  throwIfAborted(externalSignal);
  const controller = linkedAbortController(externalSignal);
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await deps.fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  const error = new Error('Onboarding cancelled');
  error.name = 'AbortError';
  throw error;
}

function linkedAbortController(signal: AbortSignal | null | undefined): AbortController {
  const controller = new AbortController();
  if (signal?.aborted) controller.abort(signal.reason);
  else signal?.addEventListener('abort', () => controller.abort(signal.reason), { once: true });
  return controller;
}

function isLoopbackUrl(url: URL): boolean {
  const hostname = url.hostname.toLowerCase();
  return url.protocol === 'http:' && !url.username && !url.password && !url.search && !url.hash
    && (url.pathname === '/' || url.pathname === '')
    && (hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1');
}

function boundedPositive(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && value! > 0 ? Math.min(value!, 60_000) : fallback;
}

function errorCode(error: unknown, fallback: string): string {
  return error instanceof AriavaCliError ? error.code : fallback;
}

function readinessError(
  code: 'ERR_AGENT_ADAPTER_DISCOVERY' | 'ERR_AGENT_ADAPTER_NOT_LOOPBACK' | 'ERR_RELAY_UNREACHABLE' | 'ERR_RELAY_AUTH_FAILED' | 'ERR_IDENTITY_INVALID',
  message: string,
  retryable = true,
): AriavaCliError {
  return new AriavaCliError(code, message, {
    step: 'strict-readiness',
    retryable,
    remediation: { message: 'Retry onboarding after correcting the reported readiness condition.' },
  });
}
