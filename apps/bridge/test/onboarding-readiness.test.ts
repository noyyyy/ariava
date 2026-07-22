import { describe, expect, test } from 'bun:test';
import type { HostEnrollmentResponse, SignedRequestHeaders } from '@ariava/protocol';
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
    clock: clock(), readDiscovery: () => ({ url: 'http://127.0.0.1:7272', secret: 'secret-value' }),
    serviceStatus: () => ({ backend: 'systemd-user', support: { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' }, installed: true, enabled: true, loaded: true, processRunning: true, runtimePath: '/usr/bin/node', ariavaBinPath: '/prefix/bin/ariava', runtimePathMatchesCurrent: true, ariavaBinPathMatchesCurrent: true, logBackend: 'journald' }),
    fetch: async (request) => {
      const url = String(request);
      return Response.json(url.endsWith('/health') && url.includes('127.0.0.1') ? { ok: true, hostId: 'host-1' } : { ok: true });
    },
    createRelayClient: () => ({ enrollHost: async () => enrollment() }), nonce: () => 'fresh-nonce',
    ...depOverrides,
  };
  return { input, deps };
}

describe('strict onboarding readiness', () => {
  test('validates exact secure loopback discovery shape', () => {
    expect(validateAgentAdapterDiscovery({ url: 'http://127.0.0.1:7272', secret: 's' }, 7272)).toEqual({ url: 'http://127.0.0.1:7272', secret: 's' });
    expect(validateAgentAdapterDiscovery({ url: 'http://[::1]:7272', secret: 's' }, 7272).url).toBe('http://[::1]:7272');
    for (const value of [
      { url: 'http://localhost:7272', secret: 's' }, { url: 'http://10.0.0.1:7272', secret: 's' },
      { url: 'https://127.0.0.1:7272', secret: 's' }, { url: 'http://user@127.0.0.1:7272', secret: 's' },
      { url: 'http://127.0.0.1:7272/path', secret: 's' }, { url: 'http://127.0.0.1:7272', secret: '' },
      { url: 'http://127.0.0.1:7272', secret: 's', extra: true },
    ]) expect(() => validateAgentAdapterDiscovery(value, 7272)).toThrow();
  });

  test('polls boundedly and authenticates exact health evidence', async () => {
    const headers: string[] = [];
    const { input, deps } = fixture({}, {
      fetch: async (_url, init) => { headers.push(new Headers(init?.headers).get('authorization') ?? ''); return Response.json({ ok: true, hostId: 'host-1' }); },
    });
    await expect(pollForDiscoveryAndHealth(input, deps)).resolves.toMatchObject({ url: 'http://127.0.0.1:7272' });
    expect(headers).toEqual(['Bearer secret-value']);

    const timed = fixture({}, { readDiscovery: () => null });
    await expect(pollForDiscoveryAndHealth(timed.input, timed.deps)).rejects.toMatchObject({ code: 'ERR_AGENT_ADAPTER_DISCOVERY' });
  });

  test('requires every Host condition independently and never consults bridge state', async () => {
    const healthy = fixture();
    const result = await checkStrictOnboardingReadiness(healthy.input, healthy.deps);
    expect(result.ready).toBe(true);
    expect(result.checks.every((check) => check.ready)).toBe(true);
    expect(result.readiness).toBe('reload-pending');

    const cases: Array<[string, Partial<StrictReadinessInput>]> = [
      ['stable-cli', { stableCli: { ...healthy.input.stableCli, packageVersion: 'old' } }],
      ['persisted-config', { config: { ...config, environmentOverrides: ['ARIAVA_RELAY_BASE_URL'] } }],
      ['identity', { identityInspection: { ...inspection, pendingRotation: true, status: 'rotation-pending' } }],
      ['service-references', { serviceRecord: { ...healthy.input.serviceRecord!, configPath: '/wrong' } }],
    ];
    for (const [id, override] of cases) {
      const candidate = fixture(override);
      const failed = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);
      expect(failed.ready).toBe(false);
      expect(failed.checks.find((check) => check.id === id)?.ready).toBe(false);
    }
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

  test('exact Pi evidence remains honestly reload-pending and cannot claim adapter-ready', async () => {
    const candidate = fixture();
    const result = await checkStrictOnboardingReadiness(candidate.input, candidate.deps);
    expect(result).toMatchObject({ ready: true, readiness: 'reload-pending', nextActions: [{ id: 'reload-pi', command: '/reload' }] });
    expect(result.readiness).not.toBe('adapter-ready');

    const mismatch = fixture({ piStatus: { ...piStatus, manifestVersion: '1.2.2', mismatchReasons: ['manifest-version-mismatch'] } });
    expect(await checkStrictOnboardingReadiness(mismatch.input, mismatch.deps)).toMatchObject({ ready: false, readiness: 'failed' });
  });
});
