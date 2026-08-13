import { describe, expect, test } from 'bun:test';
import {
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
  type HostEnrollmentResponse,
  type SignedRequestHeaders,
} from '@ariava/protocol';
import { validateAgentAdapterDiscovery } from '../src/agent-adapter/config';
import type {
  HostIdentity,
  HostIdentityInspection,
  HostPrivateKeyStorage,
} from '../src/identity/types';
import { RelayClientError } from '../src/relay-client';
import type { ResolvedAriavaConfig } from '../src/host-manager/config';
import type { PiExtensionStatus } from '../src/host-manager/pi-extension';
import {
  checkRelay,
  checkRelayEnrollment,
  checkStrictOnboardingReadiness,
  pollForDiscoveryAndHealth,
  type ReadinessClock,
  type StrictReadinessDependencies,
  type StrictReadinessInput,
} from '../src/host-manager/onboarding/readiness';
import { HOST_READINESS_CHECK_IDS } from '../src/host-manager/onboarding/types';
import {
  exactPiPackageReady,
  identityReady,
  persistedConfigReady,
  sameStorage,
  servicePathsReady,
  serviceReferencesReady,
  stableCliMatches,
} from '../src/host-manager/onboarding/readiness/evidence';
import { parseAgentAdapterHealth } from '../src/host-manager/onboarding/readiness/runtime-health-codec';
import {
  defaultReadinessRemediation,
  piPackageNotReadyMessage,
  readinessError,
  readinessFailureActions,
} from '../src/host-manager/onboarding/readiness/remediation';
import * as compatibilityReadiness from '../src/host-manager/onboarding/readiness';
import * as canonicalReadiness from '../src/host-manager/onboarding/readiness/index';
import { pollForDiscoveryAndHealth as pollLocalBridgeHealth } from '../src/host-manager/onboarding/readiness/local-bridge';
import {
  checkRelayEnrollment as checkRelayDomainEnrollment,
  checkRelayHealth as checkRelayDomainHealth,
} from '../src/host-manager/onboarding/readiness/relay';

const EXPECTED_HOST_READINESS_CHECK_IDS = [
  'stable-cli',
  'persisted-config',
  'identity',
  'service-support',
  'service-installed',
  'service-enabled',
  'service-loaded',
  'service-running',
  'service-paths',
  'service-references',
  'agent-adapter-discovery',
  'agent-adapter-health',
  'bridge-runtime-health',
  'relay-health',
  'relay-enrollment',
] as const;

function clock(): ReadinessClock {
  let now = 0;
  return { now: () => now, sleep: async (milliseconds) => { now += milliseconds; } };
}

const storage = { type: 'linux-json' as const, path: '/home/test/.config/ariava/host-identity.json' };
const signer = {
  entityId: 'host-1', keyId: 'key-1',
  sign: async () => 'signature',
  signRequest: async () => ({}) as SignedRequestHeaders,
};
const identity: HostIdentity = {
  identityVersion: 2, hostId: 'host-1', keyId: 'key-1', algorithm: 'Ed25519', publicKey: 'public-key',
  publicKeyFingerprint: 'fingerprint', createdAt: '2026-07-20T00:00:00.000Z', privateKeyStorage: storage, signer,
};
const inspection: HostIdentityInspection = {
  status: 'ready', storageType: 'linux-json', storageReference: storage, path: storage.path,
  hostId: identity.hostId, keyId: identity.keyId, algorithm: 'Ed25519', publicKeyFingerprint: identity.publicKeyFingerprint,
  ownerIntegrity: true, permissionIntegrity: true, metadataIntegrity: true, pendingRotation: false,
};
const config: ResolvedAriavaConfig = {
  relayBaseUrl: 'https://relay.example', hostName: 'Test Host', agentAdapterPort: 7272,
  agentAdapterConfigPath: '/home/test/.config/ariava/agent-adapter.json', agentAdapterSecret: 'secret-value',
  statePath: '/home/test/.config/ariava/bridge-state.json', identity, identityPath: storage.path,
  configPath: '/home/test/.config/ariava/config.json', installPath: '/home/test/.config/ariava/install.json',
  logDir: '/home/test/.config/ariava/logs', stdoutLogPath: '/tmp/out', stderrLogPath: '/tmp/err', tmpDir: '/tmp',
  environmentOverrides: [],
};
const piStatus: PiExtensionStatus = {
  installed: true, installPath: '/home/test/.pi/agent/extensions/npm/@ariava/pi-extension',
  expectedManagedPath: '/home/test/.pi/agent/extensions/npm/@ariava/pi-extension', managed: true,
  managedMetadataPath: '/home/test/.pi/agent/settings.json', registeredSource: 'npm:@ariava/pi-extension@1.2.3',
  expectedSource: 'npm:@ariava/pi-extension@1.2.3', manifestName: '@ariava/pi-extension', manifestVersion: '1.2.3',
  sourceOwnership: 'managed-exact', mismatchReasons: [],
};

function enrollment(): HostEnrollmentResponse {
  return { host: {
    hostId: 'host-1', hostName: 'Test Host', platform: 'linux', bridgeVersion: '1.2.3',
    registeredAt: '2026-07-20T00:00:00.000Z', lastSeenAt: '2026-07-20T00:00:01.000Z', bridgeStatus: 'online', status: 'active',
  } };
}

function fixture(overrides: Partial<StrictReadinessInput> = {}, depOverrides: Partial<StrictReadinessDependencies> = {}) {
  const input: StrictReadinessInput = {
    target: 'adapter-installed', cliVersion: '1.2.3',
    stableCli: { executablePath: '/prefix/bin/ariava', packageRoot: '/prefix/lib/node_modules/ariava', packageVersion: '1.2.3', npmPrefix: '/prefix', npmBinPath: '/prefix/bin' },
    installMetadata: { installer: { manager: 'npm', ariavaBinRealPath: '/prefix/bin/ariava', recordedAt: '2026-07-20T00:00:00.000Z' } },
    config, identityInspection: inspection, identity,
    serviceRecord: { backend: 'systemd-user', installedAt: '2026-07-20T00:00:00.000Z', runtimePath: '/usr/bin/node', ariavaBinPath: '/prefix/bin/ariava', configPath: config.configPath, identityReference: storage, definitionPath: '/home/test/.config/systemd/user/ariava.service', serviceId: 'ariava.service' },
    expectedRuntimePath: '/usr/bin/node', expectedAriavaBinPath: '/prefix/bin/ariava',
    hostMetadata: { hostName: 'Test Host', platform: 'linux', bridgeVersion: '1.2.3' }, piStatus,
    timeoutMs: 20, pollIntervalMs: 5, requestTimeoutMs: 5,
    ...overrides,
  };
  const deps: Partial<StrictReadinessDependencies> = {
    clock: clock(), readDiscovery: () => ({
      url: 'http://127.0.0.1:7272', secret: 'secret-value', protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
    }),
    serviceStatus: () => ({ backend: 'systemd-user', support: { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' }, installed: true, enabled: true, loaded: true, processRunning: true, runtimePath: '/usr/bin/node', ariavaBinPath: '/prefix/bin/ariava', runtimePathMatchesCurrent: true, ariavaBinPathMatchesCurrent: true, logBackend: 'journald' }),
    fetch: async (request) => {
      const url = String(request);
      return Response.json(url.endsWith('/health') && url.includes('127.0.0.1')
        ? { ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [] } }
        : { ok: true });
    },
    createRelayClient: () => ({ enrollHost: async () => enrollment() }), nonce: () => 'fresh-nonce',
    ...depOverrides,
  };
  return { input, deps };
}

describe('strict onboarding readiness', () => {
  test('validates exact secure loopback discovery shape', () => {
    const v2 = { url: 'http://127.0.0.1:7272', secret: 's', protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION };
    expect(validateAgentAdapterDiscovery(v2, 7272)).toEqual(v2);
    expect(validateAgentAdapterDiscovery({ ...v2, url: 'http://[::1]:7272' }, 7272).url).toBe('http://[::1]:7272');
    for (const value of [
      { url: 'http://localhost:7272', secret: 's', protocolVersion: 2 },
      { url: 'http://10.0.0.1:7272', secret: 's', protocolVersion: 2 },
      { url: 'https://127.0.0.1:7272', secret: 's', protocolVersion: 2 },
      { url: 'http://user@127.0.0.1:7272', secret: 's', protocolVersion: 2 },
      { url: 'http://127.0.0.1:7272/path', secret: 's', protocolVersion: 2 },
      { url: 'http://127.0.0.1:7272', secret: '', protocolVersion: 2 },
      { url: 'http://127.0.0.1:7272', secret: 's' },
      { url: 'http://127.0.0.1:7272', secret: 's', protocolVersion: 1 },
      { url: 'http://127.0.0.1:7272', secret: 's', protocolVersion: 2, extra: true },
    ]) expect(() => validateAgentAdapterDiscovery(value, 7272)).toThrow();
  });

  test('polls boundedly and authenticates exact health evidence', async () => {
    const observedHeaders: Headers[] = [];
    const { input, deps } = fixture({}, {
      fetch: async (_url, init) => {
        observedHeaders.push(new Headers(init?.headers));
        return Response.json({ ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [] } });
      },
    });
    await expect(pollForDiscoveryAndHealth(input, deps)).resolves.toEqual({
      discovery: {
        url: 'http://127.0.0.1:7272', secret: 'secret-value', protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
      },
      health: { status: 'healthy', drivers: [] },
    });
    expect(observedHeaders[0]?.get('authorization')).toBe('Bearer secret-value');
    expect(observedHeaders[0]?.get(AGENT_ADAPTER_PROTOCOL_HEADER)).toBe(String(AGENT_ADAPTER_PROTOCOL_VERSION));

    const timed = fixture({}, { readDiscovery: () => null });
    await expect(pollForDiscoveryAndHealth(timed.input, timed.deps)).rejects.toMatchObject({ code: 'ERR_AGENT_ADAPTER_DISCOVERY' });

    const controller = new AbortController();
    controller.abort();
    const cancelled = fixture({ signal: controller.signal });
    await expect(pollForDiscoveryAndHealth(cancelled.input, cancelled.deps)).rejects.toMatchObject({
      name: 'AbortError',
      message: 'Onboarding cancelled',
    });
  });

  test('keeps authenticated reachability ready while degraded runtime health blocks strict readiness', async () => {
    const degraded = fixture({}, {
      fetch: async (request) => String(request).includes('127.0.0.1')
        ? Response.json({
          ok: true, hostId: 'host-1', health: {
            status: 'degraded',
            drivers: [{
              driver: 'pi', code: 'driver_reconciliation_failed', count: 2,
              firstSeenAt: '2026-08-10T00:00:00.000Z', lastSeenAt: '2026-08-10T00:00:15.000Z',
              nextRetryAt: '2026-08-10T00:00:30.000Z',
            }],
          },
        })
        : Response.json({ ok: true }),
    });
    const result = await checkStrictOnboardingReadiness(degraded.input, degraded.deps);
    expect(result.ready).toBe(false);
    expect(result.checks.find((check) => check.id === 'agent-adapter-health')).toEqual({ id: 'agent-adapter-health', ready: true });
    expect(result.checks.find((check) => check.id === 'bridge-runtime-health')).toMatchObject({
      ready: false, code: 'ERR_BRIDGE_DEGRADED', message: expect.stringMatching(/reachable.*degraded/i),
    });
    expect(result.nextActions[0]).toMatchObject({ command: 'ariava doctor' });
  });

  test('dev discovery cannot satisfy production strict readiness', async () => {
    const candidate = fixture({}, {
      readDiscovery: () => ({ url: 'http://127.0.0.1:7273', secret: 'dev-secret', protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION }),
    });

    const result = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);

    expect(result).toMatchObject({ ready: false, readiness: 'failed' });
    expect(result.checks.find((check) => check.id === 'agent-adapter-discovery')).toMatchObject({
      ready: false,
      code: 'ERR_AGENT_ADAPTER_DISCOVERY',
      message: 'Agent Adapter discovery port does not match persisted configuration.',
    });
    expect(result.checks.find((check) => check.id === 'agent-adapter-health')?.ready).toBe(false);
  });

  test('requires every Host condition independently and never consults bridge state', async () => {
    const healthy = fixture();
    const result = await checkStrictOnboardingReadiness(healthy.input, healthy.deps);
    expect(result.ready).toBe(true);
    expect(result.checks.every((check) => check.ready)).toBe(true);
    expect(result.readiness).toBe('reload-pending');
    expect(result.checks.map((check) => check.id)).toEqual([
      'stable-cli',
      'persisted-config',
      'identity',
      'service-support',
      'service-installed',
      'service-enabled',
      'service-loaded',
      'service-running',
      'service-paths',
      'service-references',
      'agent-adapter-discovery',
      'agent-adapter-health',
      'bridge-runtime-health',
      'relay-health',
      'relay-enrollment',
    ]);

    const cases: Array<[string, Partial<StrictReadinessInput>, RegExp]> = [
      ['stable-cli', { stableCli: { ...healthy.input.stableCli, packageVersion: 'old' } }, /Stable Ariava CLI/i],
      ['persisted-config', { config: { ...config, environmentOverrides: ['ARIAVA_RELAY_BASE_URL'] } }, /Persisted Host configuration/i],
      ['identity', { identityInspection: { ...inspection, pendingRotation: true, status: 'rotation-pending' } }, /Host identity is not ready/i],
      ['service-references', { serviceRecord: { ...healthy.input.serviceRecord!, configPath: '/wrong' } }, /service metadata/i],
    ];
    for (const [id, override, messagePattern] of cases) {
      const candidate = fixture(override);
      const failed = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);
      expect(failed.ready).toBe(false);
      const check = failed.checks.find((entry) => entry.id === id);
      expect(check?.ready).toBe(false);
      expect(check?.message).toMatch(messagePattern);
      expect(failed.nextActions[0]?.message).toMatch(messagePattern);
    }
  });

  test('first failed check controls exact remediation in complete readiness order', async () => {
    const candidate = fixture({
      stableCli: { ...fixture().input.stableCli, packageVersion: 'old' },
      config: { ...config, environmentOverrides: ['ARIAVA_RELAY_BASE_URL'] },
    });
    const failed = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);
    expect(failed.checks.slice(0, 2)).toEqual([
      {
        id: 'stable-cli',
        ready: false,
        code: 'ERR_STABLE_CLI_PATH',
        message: 'Stable Ariava CLI path or version evidence does not match the executing CLI.',
      },
      {
        id: 'persisted-config',
        ready: false,
        code: 'ERR_RELAY_CONFIG_REQUIRED',
        message: 'Persisted Host configuration is incomplete, or ambient environment overrides are present.',
      },
    ]);
    expect(failed.nextActions).toEqual([{
      id: 'retry-onboarding',
      message: 'Stable Ariava CLI path or version evidence does not match the executing CLI.',
      command: 'npx --yes ariava@latest setup',
    }]);
  });

  test('classifies Relay network, auth, identity, rate limit, server, and malformed responses without changing identity', async () => {
    const before = structuredClone({ hostId: identity.hostId, keyId: identity.keyId, publicKey: identity.publicKey });
    const cases: Array<[number | 'throw' | 'malformed', string]> = [
      ['throw', 'ERR_RELAY_UNREACHABLE'], [401, 'ERR_RELAY_AUTH_FAILED'], [403, 'ERR_RELAY_AUTH_FAILED'],
      [409, 'ERR_IDENTITY_INVALID'], [410, 'ERR_IDENTITY_INVALID'], [429, 'ERR_RELAY_UNREACHABLE'], [500, 'ERR_RELAY_UNREACHABLE'],
      ['malformed', 'ERR_IDENTITY_INVALID'],
    ];
    for (const [failure, code] of cases) {
      const candidate = fixture({}, {
        createRelayClient: () => ({ enrollHost: async () => {
          if (failure === 'throw') throw new TypeError('connect ECONNREFUSED secret-value');
          if (failure === 'malformed') return { host: {} } as HostEnrollmentResponse;
          throw new RelayClientError(failure, 'sensitive upstream detail');
        } }),
      });
      await expect(checkRelay(candidate.input, candidate.deps)).rejects.toMatchObject({ code });
    }
    expect({ hostId: identity.hostId, keyId: identity.keyId, publicKey: identity.publicKey }).toEqual(before);
  });

  test('default readiness nonce is canonical 16-byte base64url and enrollment-only failures keep health ready', async () => {
    const { base64UrlDecode } = await import('@ariava/protocol');
    let capturedNonce: string | undefined;
    const { input } = fixture();
    // Omit nonce so defaultDependencies.nonce (base64url of 16 random bytes) is used.
    const depsWithoutNonce: Partial<StrictReadinessDependencies> = {
      clock: clock(),
      readDiscovery: () => ({ url: 'http://127.0.0.1:7272', secret: 'secret-value', protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION }),
      serviceStatus: () => ({
        backend: 'systemd-user',
        support: { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' },
        installed: true, enabled: true, loaded: true, processRunning: true,
        runtimePath: '/usr/bin/node', ariavaBinPath: '/prefix/bin/ariava',
        runtimePathMatchesCurrent: true, ariavaBinPathMatchesCurrent: true, logBackend: 'journald',
      }),
      fetch: async (request) => {
        const url = String(request);
        return Response.json(url.endsWith('/health') && url.includes('127.0.0.1')
          ? { ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [] } }
          : { ok: true });
      },
      createRelayClient: (options) => {
        capturedNonce = options.nonce?.();
        return { enrollHost: async () => enrollment() };
      },
    };
    await expect(checkRelay(input, depsWithoutNonce)).resolves.toBeUndefined();
    expect(typeof capturedNonce).toBe('string');
    expect(base64UrlDecode(capturedNonce!).byteLength).toBe(16);

    const failedEnrollment = fixture({}, {
      createRelayClient: () => ({
        enrollHost: async () => {
          throw new RelayClientError(400, 'nonce must contain exactly 16 bytes');
        },
      }),
    });
    const result = await checkStrictOnboardingReadiness(failedEnrollment.input, failedEnrollment.deps);
    expect(result.ready).toBe(false);
    expect(result.checks.find((check) => check.id === 'relay-health')).toMatchObject({ ready: true });
    expect(result.checks.find((check) => check.id === 'relay-enrollment')).toMatchObject({
      ready: false,
      code: 'ERR_RELAY_UNREACHABLE',
      message: expect.stringMatching(/enrollment|Relay/i),
    });
    expect(result.nextActions[0]).toMatchObject({
      message: expect.stringMatching(/enrollment|Relay/i),
      command: 'ariava doctor',
    });
  });

  test('exact Pi evidence remains honestly reload-pending and cannot claim adapter-ready', async () => {
    const candidate = fixture();
    const result = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);
    expect(result).toMatchObject({ ready: true, readiness: 'reload-pending', nextActions: [{ id: 'reload-pi', command: '/reload' }] });
    expect(result.readiness).not.toBe('adapter-ready');

    const mismatch = fixture({ piStatus: { ...piStatus, manifestVersion: '1.2.2', mismatchReasons: ['manifest-version-mismatch'] } });
    const failedPi = await checkStrictOnboardingReadiness(mismatch.input, mismatch.deps);
    expect(failedPi).toMatchObject({ ready: false, readiness: 'failed' });
    expect(failedPi.nextActions[0]).toMatchObject({
      message: expect.stringMatching(/Pi extension|manifest|version/i),
      command: 'ariava setup --extension pi',
    });
  });

  test('malformed runtime health remains a concrete authenticated-health failure', async () => {
    const candidate = fixture({}, {
      fetch: async (request) => String(request).includes('127.0.0.1')
        ? Response.json({ ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [], extra: true } })
        : Response.json({ ok: true }),
    });
    const failed = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);
    expect(failed.checks.slice(10, 13)).toEqual([
      { id: 'agent-adapter-discovery', ready: false, code: 'ERR_AGENT_ADAPTER_DISCOVERY', message: 'Agent Adapter returned mismatched health evidence.' },
      { id: 'agent-adapter-health', ready: false, code: 'ERR_AGENT_ADAPTER_DISCOVERY', message: 'Agent Adapter returned mismatched health evidence.' },
      { id: 'bridge-runtime-health', ready: false, code: 'ERR_AGENT_ADAPTER_DISCOVERY', message: 'Agent Adapter returned mismatched health evidence.' },
    ]);
    expect(failed.nextActions).toEqual([{
      id: 'retry-onboarding',
      message: 'Agent Adapter returned mismatched health evidence.',
      command: 'ariava service restart',
    }]);
  });

  test('adapter discovery failures preserve concrete message on both related checks', async () => {
    const candidate = fixture({}, {
      readDiscovery: () => ({ url: 'http://10.0.0.1:7272', secret: 'secret-value', protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION }),
    });
    const failed = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);
    expect(failed.ready).toBe(false);
    for (const id of ['agent-adapter-discovery', 'agent-adapter-health'] as const) {
      expect(failed.checks.find((check) => check.id === id)).toMatchObject({
        ready: false,
        code: 'ERR_AGENT_ADAPTER_NOT_LOOPBACK',
        message: expect.stringMatching(/loopback/i),
      });
    }
    expect(failed.nextActions[0]).toMatchObject({
      message: expect.stringMatching(/loopback/i),
      command: 'ariava service restart',
    });
  });

  test('freezes the exact Host check order and first-failure remediation priority', async () => {
    expect(HOST_READINESS_CHECK_IDS).toEqual(EXPECTED_HOST_READINESS_CHECK_IDS);

    const healthy = fixture({ target: 'host-ready' });
    const result = await checkStrictOnboardingReadiness(healthy.input, healthy.deps);
    expect(result.checks.map((check) => check.id)).toEqual(EXPECTED_HOST_READINESS_CHECK_IDS);
    expect(JSON.stringify(result)).toBe(JSON.stringify({
      ready: true,
      readiness: 'host-ready',
      checks: EXPECTED_HOST_READINESS_CHECK_IDS.map((id) => ({ id, ready: true })),
      nextActions: [],
    }));

    const remediationCases: Array<{
      id: (typeof EXPECTED_HOST_READINESS_CHECK_IDS)[number];
      code: string;
      actionId: 'retry-onboarding' | 'resolve-failure';
      command: string;
    }> = [
      { id: 'stable-cli', code: 'ERR_STABLE_CLI_PATH', actionId: 'retry-onboarding', command: 'npx --yes ariava@latest setup' },
      { id: 'persisted-config', code: 'ERR_RELAY_CONFIG_REQUIRED', actionId: 'retry-onboarding', command: 'ariava doctor' },
      { id: 'identity', code: 'ERR_IDENTITY_INVALID', actionId: 'resolve-failure', command: 'ariava host reset --confirm' },
      { id: 'service-support', code: 'ERR_UNSUPPORTED_PLATFORM', actionId: 'retry-onboarding', command: 'ariava setup --resume' },
      { id: 'service-installed', code: 'ERR_SERVICE_NOT_INSTALLED', actionId: 'retry-onboarding', command: 'ariava service reinstall' },
      { id: 'service-enabled', code: 'ERR_ONBOARDING_NOT_READY', actionId: 'retry-onboarding', command: 'ariava setup --resume' },
      { id: 'service-loaded', code: 'ERR_ONBOARDING_NOT_READY', actionId: 'retry-onboarding', command: 'ariava setup --resume' },
      { id: 'service-running', code: 'ERR_ONBOARDING_NOT_READY', actionId: 'retry-onboarding', command: 'ariava setup --resume' },
      { id: 'service-paths', code: 'ERR_SERVICE_METADATA', actionId: 'retry-onboarding', command: 'ariava service reinstall' },
      { id: 'service-references', code: 'ERR_SERVICE_METADATA', actionId: 'retry-onboarding', command: 'ariava service reinstall' },
      { id: 'agent-adapter-discovery', code: 'ERR_AGENT_ADAPTER_DISCOVERY', actionId: 'retry-onboarding', command: 'ariava service restart' },
      { id: 'agent-adapter-health', code: 'ERR_AGENT_ADAPTER_DISCOVERY', actionId: 'retry-onboarding', command: 'ariava service restart' },
      { id: 'bridge-runtime-health', code: 'ERR_BRIDGE_DEGRADED', actionId: 'retry-onboarding', command: 'ariava doctor' },
      { id: 'relay-health', code: 'ERR_RELAY_UNREACHABLE', actionId: 'retry-onboarding', command: 'ariava doctor' },
      { id: 'relay-enrollment', code: 'ERR_RELAY_UNREACHABLE', actionId: 'retry-onboarding', command: 'ariava doctor' },
    ];
    for (const [index, candidate] of remediationCases.entries()) {
      const checks = EXPECTED_HOST_READINESS_CHECK_IDS.map((id, checkIndex) => {
        const ready = checkIndex !== index && checkIndex !== index + 1;
        return ready ? { id, ready } : { id, ready, code: candidate.code, message: `${id} failed` };
      });
      expect(readinessFailureActions(checks)).toEqual([{
        id: candidate.actionId,
        message: `${candidate.id} failed`,
        command: candidate.command,
      }]);
    }
    expect(readinessFailureActions([])).toEqual([{
      id: 'retry-onboarding',
      message: 'Strict readiness checks failed.',
    }]);

    const multipleFailures = fixture({
      target: 'host-ready',
      stableCli: { ...healthy.input.stableCli, packageVersion: 'old' },
      identityInspection: { ...healthy.input.identityInspection, pendingRotation: true },
    });
    const failed = await checkStrictOnboardingReadiness(multipleFailures.input, multipleFailures.deps);
    expect(failed.nextActions).toEqual([{
      id: 'retry-onboarding',
      message: 'Stable Ariava CLI path or version evidence does not match the executing CLI.',
      command: 'npx --yes ariava@latest setup',
    }]);
  });

  test('rejects every required persisted evidence field independently without I/O', () => {
    const { input, deps } = fixture();
    const status = deps.serviceStatus!();
    expect(stableCliMatches(input)).toBe(true);
    expect(persistedConfigReady(input)).toBe(true);
    expect(identityReady(input)).toBe(true);
    expect(servicePathsReady(input, status)).toBe(true);
    expect(serviceReferencesReady(input)).toBe(true);

    const stableCliMismatches: Array<[string, StrictReadinessInput]> = [
      ['cli version', { ...input, cliVersion: 'old' }],
      ['package version', { ...input, stableCli: { ...input.stableCli, packageVersion: 'old' } }],
      ['package root', { ...input, stableCli: { ...input.stableCli, packageRoot: '' } }],
      ['npm prefix', { ...input, stableCli: { ...input.stableCli, npmPrefix: '' } }],
      ['npm bin path', { ...input, stableCli: { ...input.stableCli, npmBinPath: '' } }],
      ['executable path', { ...input, stableCli: { ...input.stableCli, executablePath: '/wrong' } }],
      ['installer metadata', { ...input, installMetadata: { ...input.installMetadata, installer: undefined } }],
      ['installer CLI reference', { ...input, installMetadata: { installer: { ...input.installMetadata.installer!, ariavaBinRealPath: '/wrong' } } }],
    ];
    for (const [label, candidate] of stableCliMismatches) {
      expect(stableCliMatches(candidate), label).toBe(false);
    }

    const persistedConfigMismatches: Array<[string, StrictReadinessInput]> = [
      ['Relay URL', { ...input, config: { ...input.config, relayBaseUrl: '' } }],
      ['Host name', { ...input, config: { ...input.config, hostName: '' } }],
      ['Agent Adapter secret', { ...input, config: { ...input.config, agentAdapterSecret: '' } }],
      ['persisted identity', { ...input, config: { ...input.config, identity: undefined } }],
      ['persisted Host ID', { ...input, config: { ...input.config, identity: { ...input.config.identity!, hostId: 'other-host' } } }],
      ['identity path', { ...input, config: { ...input.config, identityPath: '' } }],
      ['config path', { ...input, config: { ...input.config, configPath: '' } }],
      ['environment override', { ...input, config: { ...input.config, environmentOverrides: ['ARIAVA_RELAY_BASE_URL'] } }],
    ];
    for (const [label, candidate] of persistedConfigMismatches) {
      expect(persistedConfigReady(candidate), label).toBe(false);
    }

    const identityMismatches: Array<[string, HostIdentityInspection]> = [
      ['status', { ...input.identityInspection, status: 'invalid' }],
      ['owner integrity', { ...input.identityInspection, ownerIntegrity: false }],
      ['permission integrity', { ...input.identityInspection, permissionIntegrity: false }],
      ['metadata integrity', { ...input.identityInspection, metadataIntegrity: false }],
      ['pending rotation', { ...input.identityInspection, pendingRotation: true }],
      ['Host ID binding', { ...input.identityInspection, hostId: 'other-host' }],
      ['key ID binding', { ...input.identityInspection, keyId: 'other-key' }],
    ];
    for (const [label, identityInspection] of identityMismatches) {
      expect(identityReady({ ...input, identityInspection }), label).toBe(false);
    }

    const servicePathMismatches = [
      ['runtime path', { ...status, runtimePath: '/wrong' }],
      ['Ariava CLI path', { ...status, ariavaBinPath: '/wrong' }],
      ['current runtime match', { ...status, runtimePathMatchesCurrent: false }],
      ['current CLI match', { ...status, ariavaBinPathMatchesCurrent: false }],
    ] as const;
    for (const [label, serviceStatus] of servicePathMismatches) {
      expect(servicePathsReady(input, serviceStatus), label).toBe(false);
    }

    const macosStorage: HostPrivateKeyStorage = {
      type: 'macos-keychain',
      service: 'io.noyx.ariava.host-identity',
      account: 'host-1',
    };
    const storageMismatches: Array<[
      string,
      HostPrivateKeyStorage | undefined,
      HostPrivateKeyStorage | undefined,
    ]> = [
      ['missing recorded storage', undefined, storage],
      ['missing current storage', storage, undefined],
      ['Linux path mismatch', storage, { ...storage, path: '/wrong' }],
      ['Linux storage versus macOS Keychain storage', storage, macosStorage],
      ['macOS Keychain storage versus Linux storage', macosStorage, storage],
      ['macOS Keychain account mismatch', macosStorage, { ...macosStorage, account: 'other-host' }],
    ];
    for (const [label, left, right] of storageMismatches) {
      expect(sameStorage(left, right), label).toBe(false);
    }
    expect(sameStorage(storage, { path: storage.path, type: 'linux-json' })).toBe(true);
    expect(sameStorage(macosStorage, {
      account: macosStorage.account,
      service: macosStorage.service,
      type: 'macos-keychain',
    })).toBe(true);

    const serviceReferenceMismatches: Array<[string, StrictReadinessInput]> = [
      ['service record', { ...input, serviceRecord: undefined }],
      ['recorded config reference', { ...input, serviceRecord: { ...input.serviceRecord!, configPath: '/wrong' } }],
      ['current config reference', { ...input, config: { ...input.config, configPath: '/wrong' } }],
      ['recorded identity storage', { ...input, serviceRecord: { ...input.serviceRecord!, identityReference: undefined } }],
      ['current identity storage', { ...input, config: { ...input.config, identity: undefined } }],
      ['identity storage equality', { ...input, serviceRecord: { ...input.serviceRecord!, identityReference: { ...storage, path: '/wrong' } } }],
    ];
    for (const [label, candidate] of serviceReferenceMismatches) {
      expect(serviceReferencesReady(candidate), label).toBe(false);
    }
  });

  test('rejects every exact Pi mismatch after preserving all Host checks', async () => {
    expect(exactPiPackageReady(piStatus, '1.2.3')).toBe(true);
    const mismatches: Array<[string, PiExtensionStatus | undefined]> = [
      ['missing status', undefined],
      ['not installed', { ...piStatus, installed: false }],
      ['not managed', { ...piStatus, managed: false }],
      ['source ownership', { ...piStatus, sourceOwnership: 'managed-upgrade' }],
      ['registered source', { ...piStatus, registeredSource: 'npm:@ariava/pi-extension@old' }],
      ['expected source', { ...piStatus, expectedSource: 'npm:@ariava/pi-extension@other' }],
      ['manifest name', { ...piStatus, manifestName: '@other/pi-extension' }],
      ['manifest version', { ...piStatus, manifestVersion: '1.2.2' }],
      ['install path', { ...piStatus, installPath: '/wrong' }],
      ['expected managed path', { ...piStatus, expectedManagedPath: '/wrong' }],
      ['mismatch reasons', { ...piStatus, mismatchReasons: ['foreign-source'] }],
    ];
    for (const [label, status] of mismatches) {
      expect(exactPiPackageReady(status, '1.2.3'), label).toBe(false);
      const candidate = fixture({ piStatus: status });
      const result = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);
      expect(result).toMatchObject({ ready: false, readiness: 'failed' });
      expect(result.checks).toHaveLength(15);
      expect(result.checks.map((check) => check.id)).toEqual(EXPECTED_HOST_READINESS_CHECK_IDS);
      expect(result.checks.every((check) => check.ready)).toBe(true);
      expect(result.nextActions).toHaveLength(1);
      expect(result.nextActions[0]?.command).toBe('ariava setup --extension pi');
    }
  });

  test('decodes exact runtime health without field-order assumptions or relaxed evidence', () => {
    const driver = {
      driver: 'pi',
      code: 'driver_reconciliation_failed',
      count: 2,
      firstSeenAt: '2026-08-10T00:00:00.000Z',
      lastSeenAt: '2026-08-10T00:00:15.000Z',
      nextRetryAt: '2026-08-10T00:00:30.000Z',
    };
    const relayPresence = {
      code: 'relay_presence_refresh_failed',
      count: 1,
      firstSeenAt: '2026-08-10T00:00:00.000Z',
      lastSeenAt: '2026-08-10T00:00:15.000Z',
      nextRetryAt: '2026-08-10T00:00:30.000Z',
      lastSuccessAt: '2026-08-09T23:59:00.000Z',
    };
    expect(parseAgentAdapterHealth({
      hostId: 'host-1',
      health: { drivers: [], status: 'healthy' },
      ok: true,
    }, 'host-1')).toEqual({ drivers: [], status: 'healthy' });
    expect(parseAgentAdapterHealth({
      health: { status: 'degraded', drivers: [{ ...driver, driver: 'alpha' }, driver], relayPresence },
      ok: true,
      hostId: 'host-1',
    }, 'host-1')).toEqual({
      status: 'degraded',
      drivers: [{ ...driver, driver: 'alpha' }, driver],
      relayPresence,
    });

    const malformed: unknown[] = [
      null,
      { ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [] }, extra: true },
      { ok: true, hostId: 'other', health: { status: 'healthy', drivers: [] } },
      { ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [], extra: true } },
      { ok: true, hostId: 'host-1', health: { status: 'degraded', drivers: [] } },
      { ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [driver] } },
      { ok: true, hostId: 'host-1', health: { status: 'degraded', drivers: [driver, driver] } },
      { ok: true, hostId: 'host-1', health: { status: 'degraded', drivers: [driver, { ...driver, driver: 'alpha' }] } },
      { ok: true, hostId: 'host-1', health: { status: 'degraded', drivers: [{ ...driver, firstSeenAt: 'not-a-time' }] } },
      { ok: true, hostId: 'host-1', health: { status: 'degraded', drivers: [{ ...driver, driver: 'invalid driver' }] } },
      { ok: true, hostId: 'host-1', health: { status: 'degraded', drivers: Array.from({ length: 33 }, (_, index) => ({ ...driver, driver: `driver-${String(index).padStart(2, '0')}` })) } },
      { ok: true, hostId: 'host-1', health: { status: 'degraded', drivers: [], relayPresence: { ...relayPresence, count: 0 } } },
    ];
    for (const value of malformed) expect(parseAgentAdapterHealth(value, 'host-1')).toBeUndefined();
  });

  test('preserves exact Pi mismatch messages and AriavaCliError shaping', () => {
    const variants: Array<[PiExtensionStatus | undefined, string]> = [
      [undefined, 'Exact Pi extension package @ariava/pi-extension@1.2.3 is not installed.'],
      [{ ...piStatus, managed: false }, 'Pi extension is present but not managed by Ariava at the exact CLI version.'],
      [{ ...piStatus, manifestVersion: '1.2.2' }, 'Pi extension version 1.2.2 does not match CLI version 1.2.3.'],
      [{ ...piStatus, mismatchReasons: ['manifest-name-mismatch', 'foreign-source'] }, 'Pi extension readiness failed: manifest-name-mismatch, foreign-source.'],
      [{ ...piStatus, installPath: '/wrong' }, 'Exact Pi extension package evidence for @ariava/pi-extension@1.2.3 is not ready.'],
    ];
    for (const [status, message] of variants) {
      expect(exactPiPackageReady(status, '1.2.3')).toBe(false);
      expect(piPackageNotReadyMessage(status, '1.2.3')).toBe(message);
    }

    const error = readinessError('ERR_IDENTITY_INVALID', 'invalid identity', false);
    expect(error).toMatchObject({
      name: 'AriavaCliError',
      code: 'ERR_IDENTITY_INVALID',
      message: 'invalid identity',
      data: {
        step: 'strict-readiness',
        retryable: false,
        remediation: { message: 'invalid identity', command: 'ariava host reset --confirm' },
      },
    });

    const commandCases: Array<[string | undefined, string]> = [
      ['ERR_IDENTITY_KEYCHAIN_LOCKED', 'security unlock-keychain "$HOME/Library/Keychains/login.keychain-db"'],
      ['ERR_IDENTITY_MISSING', 'ariava host reset --confirm'],
      ['ERR_IDENTITY_PERMISSIONS', 'ariava host reset --confirm'],
      ['ERR_IDENTITY_RESET_REQUIRED', 'ariava host reset --confirm'],
      ['ERR_SERVICE_NOT_INSTALLED', 'ariava service reinstall'],
      ['ERR_SERVICE_METADATA', 'ariava service reinstall'],
      ['ERR_AGENT_ADAPTER_DISCOVERY', 'ariava service restart'],
      ['ERR_AGENT_ADAPTER_NOT_LOOPBACK', 'ariava service restart'],
      ['ERR_BRIDGE_DEGRADED', 'ariava doctor'],
      ['ERR_RELAY_UNREACHABLE', 'ariava doctor'],
      ['ERR_RELAY_AUTH_FAILED', 'ariava doctor'],
      ['ERR_RELAY_CONFIG_REQUIRED', 'ariava doctor'],
      ['ERR_STABLE_CLI_PATH', 'npx --yes ariava@latest setup'],
      [undefined, 'ariava setup --resume'],
    ];
    for (const [code, command] of commandCases) {
      expect(defaultReadinessRemediation(code, 'message')).toEqual({ message: 'message', command });
    }
  });

  test('distinguishes external cancellation from internal request timeouts', async () => {
    const externallyCancelled = new AbortController();
    externallyCancelled.abort('cancelled');
    const cancelled = fixture({ signal: externallyCancelled.signal });
    await expect(pollForDiscoveryAndHealth(cancelled.input, cancelled.deps)).rejects.toMatchObject({ name: 'AbortError' });

    const healthTimeout = fixture({ requestTimeoutMs: 1 }, {
      fetch: async (_request, init) => await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          const error = new Error('request aborted');
          error.name = 'AbortError';
          reject(error);
        }, { once: true });
      }),
    });
    await expect(checkRelay(healthTimeout.input, healthTimeout.deps)).rejects.toMatchObject({
      code: 'ERR_RELAY_UNREACHABLE',
      message: 'Relay health could not be reached.',
    });

    const signalAwareClient = (abortError: Error): StrictReadinessDependencies['createRelayClient'] =>
      (_options, requestSignal) => ({
        enrollHost: async () => await new Promise<HostEnrollmentResponse>((_resolve, reject) => {
          const signal = requestSignal?.();
          if (signal?.aborted) reject(abortError);
          else signal?.addEventListener('abort', () => reject(abortError), { once: true });
        }),
      });

    const enrollmentAbortError = new Error('external enrollment cancellation');
    enrollmentAbortError.name = 'AbortError';
    const enrollmentController = new AbortController();
    const enrollmentCancelled = fixture({ signal: enrollmentController.signal }, {
      createRelayClient: signalAwareClient(enrollmentAbortError),
    });
    const externalEnrollment = checkRelayEnrollment(enrollmentCancelled.input, enrollmentCancelled.deps);
    enrollmentController.abort('cancelled');
    await expect(externalEnrollment).rejects.toBe(enrollmentAbortError);

    const enrollmentTimeoutError = new Error('internal enrollment timeout');
    enrollmentTimeoutError.name = 'AbortError';
    const enrollmentTimeout = fixture({ requestTimeoutMs: 1 }, {
      createRelayClient: signalAwareClient(enrollmentTimeoutError),
    });
    await expect(checkRelayEnrollment(enrollmentTimeout.input, enrollmentTimeout.deps)).rejects.toMatchObject({
      code: 'ERR_RELAY_UNREACHABLE',
      message: 'Relay signed Host enrollment could not be reached.',
    });
  });

  test('exposes only the exact compatibility readiness runtime API', () => {
    const runtimeKeys = [
      'checkRelay',
      'checkRelayEnrollment',
      'checkRelayHealth',
      'checkStrictOnboardingReadiness',
      'pollForDiscoveryAndHealth',
    ];
    expect(Object.keys(compatibilityReadiness).sort()).toEqual(runtimeKeys);
    expect(Object.keys(canonicalReadiness).sort()).toEqual(runtimeKeys);
    for (const name of runtimeKeys) {
      expect(compatibilityReadiness[name as keyof typeof compatibilityReadiness]).toBe(
        canonicalReadiness[name as keyof typeof canonicalReadiness],
      );
    }
  });

  test('executes local Bridge and Relay trust domains independently', async () => {
    const observedUrls: string[] = [];
    const candidate = fixture({}, {
      fetch: async (request) => {
        const url = String(request);
        observedUrls.push(url);
        return Response.json(url.includes('127.0.0.1')
          ? { ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [] } }
          : { ok: true });
      },
    });

    await expect(pollLocalBridgeHealth(candidate.input, candidate.deps)).resolves.toMatchObject({
      health: { status: 'healthy', drivers: [] },
    });
    await expect(checkRelayDomainHealth(candidate.input, candidate.deps)).resolves.toBeUndefined();
    await expect(checkRelayDomainEnrollment(candidate.input, candidate.deps)).resolves.toBeUndefined();
    expect(observedUrls).toEqual([
      'http://127.0.0.1:7272/v1/health',
      'https://relay.example/health',
    ]);
  });

  test('rejects malformed Relay health while collecting later domains after early failures', async () => {
    let enrollmentCalls = 0;
    const candidate = fixture({
      stableCli: {
        executablePath: '/wrong',
        packageRoot: '/prefix/lib/node_modules/ariava',
        packageVersion: 'old',
        npmPrefix: '/prefix',
        npmBinPath: '/prefix/bin',
      },
    }, {
      fetch: async (request) => String(request).includes('127.0.0.1')
        ? Response.json({ ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [] } })
        : Response.json({ ok: true, extra: true }),
      createRelayClient: () => ({
        enrollHost: async () => {
          enrollmentCalls += 1;
          return enrollment();
        },
      }),
    });

    const result = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);
    expect(result.checks.map((check) => check.id)).toEqual(EXPECTED_HOST_READINESS_CHECK_IDS);
    expect(result.checks.find((check) => check.id === 'stable-cli')?.ready).toBe(false);
    expect(result.checks.find((check) => check.id === 'agent-adapter-health')?.ready).toBe(true);
    expect(result.checks.find((check) => check.id === 'relay-health')).toMatchObject({
      ready: false,
      code: 'ERR_RELAY_UNREACHABLE',
      message: 'Relay returned malformed health evidence.',
    });
    expect(result.checks.find((check) => check.id === 'relay-enrollment')).toMatchObject({
      ready: false,
      code: 'ERR_RELAY_UNREACHABLE',
      message: 'Relay returned malformed health evidence.',
    });
    expect(enrollmentCalls).toBe(0);
    expect(result.nextActions[0]?.command).toBe('npx --yes ariava@latest setup');
  });

  test('propagates cancellation before service polling starts', async () => {
    const controller = new AbortController();
    controller.abort('cancelled');
    const candidate = fixture({ signal: controller.signal });
    await expect(checkStrictOnboardingReadiness(candidate.input, candidate.deps)).rejects.toMatchObject({
      name: 'AbortError',
      message: 'Onboarding cancelled',
    });
  });

  test('preserves the full failed aggregate when cancellation occurs during the local Adapter probe', async () => {
    const controller = new AbortController();
    const probeAbort = new Error('local probe cancelled');
    probeAbort.name = 'AbortError';
    let localRequestSignal: AbortSignal | null | undefined;
    const candidate = fixture({ target: 'host-ready', signal: controller.signal }, {
      fetch: async (request, init) => {
        if (String(request).includes('127.0.0.1')) {
          localRequestSignal = init?.signal;
          controller.abort('cancelled');
          throw probeAbort;
        }
        throw new Error('Relay fetch must observe the already-cancelled signal before dispatch');
      },
    });

    const result = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);

    expect(localRequestSignal).toBeDefined();
    expect(localRequestSignal?.aborted).toBe(false);

    expect(result).toEqual({
      ready: false,
      readiness: 'failed',
      checks: [
        ...EXPECTED_HOST_READINESS_CHECK_IDS.slice(0, 10).map((id) => ({ id, ready: true })),
        ...EXPECTED_HOST_READINESS_CHECK_IDS.slice(10, 13).map((id) => ({
          id,
          ready: false,
          code: 'ERR_AGENT_ADAPTER_DISCOVERY',
          message: 'Onboarding cancelled',
        })),
        ...EXPECTED_HOST_READINESS_CHECK_IDS.slice(13).map((id) => ({
          id,
          ready: false,
          code: 'ERR_RELAY_UNREACHABLE',
          message: 'Onboarding cancelled',
        })),
      ],
      nextActions: [{
        id: 'retry-onboarding',
        message: 'Onboarding cancelled',
        command: 'ariava service restart',
      }],
    });
  });

  test('preserves the full failed aggregate when cancellation occurs during the Relay health probe', async () => {
    const controller = new AbortController();
    const relayAbort = new Error('relay health cancelled');
    relayAbort.name = 'AbortError';
    const candidate = fixture({ target: 'host-ready', signal: controller.signal }, {
      fetch: async (request, init) => {
        if (String(request).includes('127.0.0.1')) {
          return Response.json({ ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [] } });
        }
        controller.abort('cancelled');
        expect(init?.signal?.aborted).toBe(true);
        throw relayAbort;
      },
    });

    const result = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);

    expect(result).toEqual({
      ready: false,
      readiness: 'failed',
      checks: [
        ...EXPECTED_HOST_READINESS_CHECK_IDS.slice(0, 13).map((id) => ({ id, ready: true })),
        ...EXPECTED_HOST_READINESS_CHECK_IDS.slice(13).map((id) => ({
          id,
          ready: false,
          code: 'ERR_RELAY_UNREACHABLE',
          message: 'relay health cancelled',
        })),
      ],
      nextActions: [{
        id: 'retry-onboarding',
        message: 'relay health cancelled',
        command: 'ariava doctor',
      }],
    });
  });

  test('preserves Relay health success when cancellation occurs during aggregate enrollment', async () => {
    const controller = new AbortController();
    const enrollmentAbort = new Error('relay enrollment cancelled');
    enrollmentAbort.name = 'AbortError';
    const candidate = fixture({ target: 'host-ready', signal: controller.signal }, {
      createRelayClient: (_options, requestSignal) => ({
        enrollHost: async () => {
          controller.abort('cancelled');
          expect(requestSignal?.().aborted).toBe(true);
          throw enrollmentAbort;
        },
      }),
    });

    const result = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);

    expect(result.checks).toHaveLength(15);
    expect(result.checks.slice(0, 14).every((check) => check.ready)).toBe(true);
    expect(result.checks[14]).toEqual({
      id: 'relay-enrollment',
      ready: false,
      code: 'ERR_RELAY_UNREACHABLE',
      message: 'relay enrollment cancelled',
    });
    expect(result.nextActions).toEqual([{
      id: 'retry-onboarding',
      message: 'relay enrollment cancelled',
      command: 'ariava doctor',
    }]);
  });
});
