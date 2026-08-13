import type { HostPlatform } from '@ariava/protocol';
import { readAgentAdapterConfig, type AgentAdapterDiscoveryFile } from '../../../agent-adapter/config';
import type { HostIdentity, HostIdentityInspection } from '../../../identity/types';
import { RelayClient } from '../../../relay-client';
import type { AriavaInstallMetadata, ResolvedAriavaConfig } from '../../config';
import type { PiExtensionStatus } from '../../pi-extension';
import type { AriavaServiceInstallRecord, ServiceStatus } from '../../service/types';
import type { OnboardingCliEvidence, OnboardingTarget, StrictReadinessResult } from '../types';
import {
  exactPiPackageReady,
  identityReady,
  persistedConfigReady,
  servicePathsReady,
  serviceReferencesReady,
  stableCliMatches,
} from './evidence';
import { pollForDiscoveryAndHealth } from './local-bridge';
import { errorCode, errorMessage, piPackageNotReadyAction, readinessFailureActions } from './remediation';
import { checkRelayEnrollment, checkRelayHealth, defaultNonce } from './relay';
import { boundedPositive, throwIfAborted } from './bounded-fetch';

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

const defaultReadinessDependencies: StrictReadinessDependencies = {
  fetch,
  clock: defaultClock,
  readDiscovery: readAgentAdapterConfig,
  serviceStatus: () => { throw new Error('A service status dependency is required'); },
  createRelayClient: (options, requestSignal) => new RelayClient(options, requestSignal),
  nonce: defaultNonce,
};

function resolveReadinessDependencies(
  overrides: Partial<StrictReadinessDependencies>,
): StrictReadinessDependencies {
  return { ...defaultReadinessDependencies, ...overrides };
}

export async function checkStrictOnboardingReadiness(
  input: StrictReadinessInput,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<StrictReadinessResult> {
  const deps = resolveReadinessDependencies(overrides);
  const checks: StrictReadinessResult['checks'] = [];
  const add = (
    id: StrictReadinessResult['checks'][number]['id'],
    ready: boolean,
    code?: string,
    message?: string,
  ): boolean => {
    checks.push({
      id,
      ready,
      ...(ready || !code ? {} : { code }),
      ...(ready || !message ? {} : { message }),
    });
    return ready;
  };

  add(
    'stable-cli',
    stableCliMatches(input),
    'ERR_STABLE_CLI_PATH',
    'Stable Ariava CLI path or version evidence does not match the executing CLI.',
  );
  add(
    'persisted-config',
    persistedConfigReady(input),
    'ERR_RELAY_CONFIG_REQUIRED',
    'Persisted Host configuration is incomplete, or ambient environment overrides are present.',
  );
  add(
    'identity',
    identityReady(input),
    'ERR_IDENTITY_INVALID',
    'Host identity is not ready (invalid, pending rotation, or integrity checks failed).',
  );

  const service = await pollForService(input, deps);
  add(
    'service-support',
    service.support.supported,
    'ERR_UNSUPPORTED_PLATFORM',
    service.support.message ?? 'A supported user service backend is not available.',
  );
  add('service-installed', service.installed, 'ERR_SERVICE_NOT_INSTALLED', 'Bridge service is not installed.');
  add('service-enabled', service.enabled, 'ERR_ONBOARDING_NOT_READY', 'Bridge service is installed but not enabled.');
  add('service-loaded', service.loaded, 'ERR_ONBOARDING_NOT_READY', 'Bridge service is not loaded by the user service manager.');
  add('service-running', service.processRunning, 'ERR_ONBOARDING_NOT_READY', 'Bridge service process is not running.');
  add(
    'service-paths',
    servicePathsReady(input, service),
    'ERR_SERVICE_METADATA',
    'Bridge service runtime or CLI paths do not match the current stable install.',
  );
  add(
    'service-references',
    serviceReferencesReady(input),
    'ERR_SERVICE_METADATA',
    'Bridge service metadata does not reference the current config or Host identity storage.',
  );

  try {
    const evidence = await pollForDiscoveryAndHealth(input, deps);
    add('agent-adapter-discovery', true);
    add('agent-adapter-health', true);
    add(
      'bridge-runtime-health',
      evidence.health.status === 'healthy',
      'ERR_BRIDGE_DEGRADED',
      'Bridge is reachable but Driver or Relay presence reconciliation is degraded.',
    );
  } catch (error) {
    const code = errorCode(error, 'ERR_AGENT_ADAPTER_DISCOVERY');
    const message = errorMessage(error, 'Agent Adapter discovery or authenticated health failed.');
    add('agent-adapter-discovery', false, code, message);
    add('agent-adapter-health', false, code, message);
    add('bridge-runtime-health', false, code, message);
  }

  try {
    await checkRelayHealth(input, deps);
    add('relay-health', true);
    try {
      await checkRelayEnrollment(input, deps);
      add('relay-enrollment', true);
    } catch (error) {
      const code = errorCode(error, 'ERR_RELAY_UNREACHABLE');
      add('relay-enrollment', false, code, errorMessage(error, 'Relay signed Host enrollment failed.'));
    }
  } catch (error) {
    const code = errorCode(error, 'ERR_RELAY_UNREACHABLE');
    const message = errorMessage(error, 'Relay health is unavailable.');
    add('relay-health', false, code, message);
    add('relay-enrollment', false, code, message);
  }

  const hostReady = checks.every((check) => check.ready);
  if (!hostReady) {
    return {
      ready: false,
      readiness: 'failed',
      checks,
      nextActions: readinessFailureActions(checks),
    };
  }
  if (input.target === 'host-ready') return { ready: true, readiness: 'host-ready', checks, nextActions: [] };

  if (!exactPiPackageReady(input.piStatus, input.cliVersion)) {
    return {
      ready: false,
      readiness: 'failed',
      checks,
      nextActions: [piPackageNotReadyAction(input.piStatus, input.cliVersion)],
    };
  }
  return {
    ready: true,
    readiness: 'reload-pending',
    checks,
    nextActions: [{ id: 'reload-pi', command: '/reload' }],
  };
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
