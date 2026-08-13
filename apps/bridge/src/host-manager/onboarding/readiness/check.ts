import type { HostPlatform } from '@ariava/protocol';
import type { HostIdentity, HostIdentityInspection } from '../../../identity/types';
import type { AriavaInstallMetadata, ResolvedAriavaConfig } from '../../config';
import type { PiExtensionStatus } from '../../pi-extension';
import type { AriavaServiceInstallRecord } from '../../service/types';
import type {
  HostReadinessCheck,
  OnboardingCliEvidence,
  OnboardingTarget,
  StrictReadinessResult,
} from '../types';
import {
  exactPiPackageReady,
  identityReady,
  persistedConfigReady,
  servicePathsReady,
  serviceReferencesReady,
  stableCliMatches,
} from './evidence';
import {
  defaultLocalBridgeDependencies,
  pollForDiscoveryAndHealth,
  pollForService,
  type LocalBridgeDependencies,
  type ReadinessClock,
} from './local-bridge';
import {
  errorCode,
  errorMessage,
  piPackageNotReadyMessage,
  readinessFailureActions,
} from './remediation';
import {
  checkRelayEnrollment,
  checkRelayHealth,
  defaultRelayReadinessDependencies,
  type RelayReadinessDependencies,
} from './relay';

export type { ReadinessClock } from './local-bridge';

export interface StrictReadinessDependencies extends LocalBridgeDependencies, RelayReadinessDependencies {}

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

export interface ReadinessDomainChecks {
  stable: readonly HostReadinessCheck[];
  service: readonly HostReadinessCheck[];
  localAdapter: readonly HostReadinessCheck[];
  relay: readonly HostReadinessCheck[];
}

export interface ReadinessEvidence {
  domains: ReadinessDomainChecks;
  piStatus: PiExtensionStatus | undefined;
  cliVersion: string;
}

const defaultDependencies: StrictReadinessDependencies = {
  ...defaultLocalBridgeDependencies,
  ...defaultRelayReadinessDependencies,
};

export async function checkStrictOnboardingReadiness(
  input: StrictReadinessInput,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<StrictReadinessResult> {
  const deps = { ...defaultDependencies, ...overrides };

  const stable: HostReadinessCheck[] = [
    readinessCheck(
      'stable-cli',
      stableCliMatches(input),
      'ERR_STABLE_CLI_PATH',
      'Stable Ariava CLI path or version evidence does not match the executing CLI.',
    ),
    readinessCheck(
      'persisted-config',
      persistedConfigReady(input),
      'ERR_RELAY_CONFIG_REQUIRED',
      'Persisted Host configuration is incomplete, or ambient environment overrides are present.',
    ),
    readinessCheck(
      'identity',
      identityReady(input),
      'ERR_IDENTITY_INVALID',
      'Host identity is not ready (invalid, pending rotation, or integrity checks failed).',
    ),
  ];

  const serviceStatus = await pollForService(input, deps);
  const service: HostReadinessCheck[] = [
    readinessCheck(
      'service-support',
      serviceStatus.support.supported,
      'ERR_UNSUPPORTED_PLATFORM',
      serviceStatus.support.message ?? 'A supported user service backend is not available.',
    ),
    readinessCheck('service-installed', serviceStatus.installed, 'ERR_SERVICE_NOT_INSTALLED', 'Bridge service is not installed.'),
    readinessCheck('service-enabled', serviceStatus.enabled, 'ERR_ONBOARDING_NOT_READY', 'Bridge service is installed but not enabled.'),
    readinessCheck('service-loaded', serviceStatus.loaded, 'ERR_ONBOARDING_NOT_READY', 'Bridge service is not loaded by the user service manager.'),
    readinessCheck('service-running', serviceStatus.processRunning, 'ERR_ONBOARDING_NOT_READY', 'Bridge service process is not running.'),
    readinessCheck(
      'service-paths',
      servicePathsReady(input, serviceStatus),
      'ERR_SERVICE_METADATA',
      'Bridge service runtime or CLI paths do not match the current stable install.',
    ),
    readinessCheck(
      'service-references',
      serviceReferencesReady(input),
      'ERR_SERVICE_METADATA',
      'Bridge service metadata does not reference the current config or Host identity storage.',
    ),
  ];

  const localAdapter: HostReadinessCheck[] = [];
  try {
    const evidence = await pollForDiscoveryAndHealth(input, deps);
    localAdapter.push(
      readinessCheck('agent-adapter-discovery', true),
      readinessCheck('agent-adapter-health', true),
      readinessCheck(
        'bridge-runtime-health',
        evidence.health.status === 'healthy',
        'ERR_BRIDGE_DEGRADED',
        'Bridge is reachable but Driver or Relay presence reconciliation is degraded.',
      ),
    );
  } catch (error) {
    const code = errorCode(error, 'ERR_AGENT_ADAPTER_DISCOVERY');
    const message = errorMessage(error, 'Agent Adapter discovery or authenticated health failed.');
    localAdapter.push(
      readinessCheck('agent-adapter-discovery', false, code, message),
      readinessCheck('agent-adapter-health', false, code, message),
      readinessCheck('bridge-runtime-health', false, code, message),
    );
  }

  const relay: HostReadinessCheck[] = [];
  try {
    await checkRelayHealth(input, deps);
    relay.push(readinessCheck('relay-health', true));
    try {
      await checkRelayEnrollment(input, deps);
      relay.push(readinessCheck('relay-enrollment', true));
    } catch (error) {
      const code = errorCode(error, 'ERR_RELAY_UNREACHABLE');
      relay.push(readinessCheck(
        'relay-enrollment',
        false,
        code,
        errorMessage(error, 'Relay signed Host enrollment failed.'),
      ));
    }
  } catch (error) {
    const code = errorCode(error, 'ERR_RELAY_UNREACHABLE');
    const message = errorMessage(error, 'Relay health is unavailable.');
    relay.push(
      readinessCheck('relay-health', false, code, message),
      readinessCheck('relay-enrollment', false, code, message),
    );
  }

  return assembleStrictReadiness({
    domains: { stable, service, localAdapter, relay },
    piStatus: input.piStatus,
    cliVersion: input.cliVersion,
  }, input.target);
}

export function assembleStrictReadiness(
  evidence: ReadinessEvidence,
  target: OnboardingTarget,
): StrictReadinessResult {
  const checks = [
    ...evidence.domains.stable,
    ...evidence.domains.service,
    ...evidence.domains.localAdapter,
    ...evidence.domains.relay,
  ];
  const hostReady = checks.every((check) => check.ready);
  if (!hostReady) {
    return {
      ready: false,
      readiness: 'failed',
      checks,
      nextActions: readinessFailureActions(checks),
    };
  }
  if (target === 'host-ready') return { ready: true, readiness: 'host-ready', checks, nextActions: [] };

  if (!exactPiPackageReady(evidence.piStatus, evidence.cliVersion)) {
    const message = piPackageNotReadyMessage(evidence.piStatus, evidence.cliVersion);
    return {
      ready: false,
      readiness: 'failed',
      checks,
      nextActions: [{
        id: 'retry-onboarding',
        message,
        command: 'ariava setup --extension pi',
      }],
    };
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

function readinessCheck(
  id: HostReadinessCheck['id'],
  ready: boolean,
  code?: string,
  message?: string,
): HostReadinessCheck {
  return {
    id,
    ready,
    ...(ready || !code ? {} : { code }),
    ...(ready || !message ? {} : { message }),
  };
}
