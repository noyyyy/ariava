import { describe, expect, test } from 'bun:test';
import {
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
  type HostEnrollmentResponse,
  type SignedRequestHeaders,
} from '@ariava/protocol';
import { validateAgentAdapterDiscovery } from '../src/agent-adapter/config';
import type { HostIdentity, HostIdentityInspection } from '../src/identity/types';
import { RelayClientError } from '../src/relay-client';
import type { ResolvedAriavaConfig } from '../src/host-manager/config';
import type { PiExtensionStatus } from '../src/host-manager/pi-extension';
import {
  checkRelay,
  checkStrictOnboardingReadiness,
  pollForDiscoveryAndHealth,
  type ReadinessClock,
  type StrictReadinessDependencies,
  type StrictReadinessInput,
} from '../src/host-manager/onboarding/readiness';

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
});
