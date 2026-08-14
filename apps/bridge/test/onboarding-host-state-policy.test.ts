import { E2E_SUITE_V1, type EncryptionKeyBindingV1 } from '@ariava/protocol';
import { describe, expect, test } from 'bun:test';
import type { HostIdentity, HostIdentityInspection } from '../src/identity/types';
import type {
  AriavaInstallMetadata,
  ResolvedAriavaConfig,
} from '../src/host-manager/config';
import {
  decideOnboardingHostState,
  evaluateHostIdentityReadiness,
  proposeRelaySelection,
  proposeStableInstallerMetadata,
  type OnboardingHostState,
} from '../src/host-manager/onboarding/host-state-policy';

const storage = {
  type: 'linux-json' as const,
  path: '/home/test/.config/ariava/host-identity.json',
};
const identity: HostIdentity = {
  identityVersion: 2,
  hostId: 'host-1',
  keyId: 'key-1',
  algorithm: 'Ed25519',
  publicKey: 'public',
  publicKeyFingerprint: 'fingerprint',
  createdAt: '2026-08-13T00:00:00.000Z',
  privateKeyStorage: storage,
  signer: {
    entityId: 'host-1',
    keyId: 'key-1',
    sign: async () => '',
    signRequest: async () => ({}) as never,
  },
};
const inspection: OnboardingHostState['identityInspection'] = {
  status: 'ready',
  storageType: 'linux-json',
  storageReference: storage,
  path: storage.path,
  hostId: identity.hostId,
  keyId: identity.keyId,
  algorithm: 'Ed25519',
  publicKeyFingerprint: identity.publicKeyFingerprint,
  ownerIntegrity: true,
  permissionIntegrity: true,
  metadataIntegrity: true,
};
const encryptionBinding: EncryptionKeyBindingV1 = {
  version: 1,
  entityType: 'host',
  entityId: identity.hostId,
  identityKeyId: identity.keyId,
  encryptionKeyId: 'ekey-test',
  suite: E2E_SUITE_V1,
  publicKey: 'public-encryption-key',
  sequence: 1,
  createdAt: identity.createdAt,
  bindingSignature: 'binding-signature',
};
const config: ResolvedAriavaConfig = {
  relayBaseUrl: 'https://persisted.example',
  hostName: 'Test Host',
  agentAdapterPort: 7272,
  agentAdapterConfigPath: '/home/test/.config/ariava/agent-adapter.json',
  agentAdapterSecret: 'adapter-secret',
  statePath: '/home/test/.config/ariava/state/bridge-state.json',
  identityPath: storage.path,
  configPath: '/home/test/.config/ariava/config.json',
  installPath: '/home/test/.config/ariava/install.json',
  logDir: '/home/test/.config/ariava/logs',
  stdoutLogPath: '/home/test/.config/ariava/logs/out',
  stderrLogPath: '/home/test/.config/ariava/logs/err',
  tmpDir: '/home/test/.config/ariava/tmp',
  environmentOverrides: [],
  identity,
};

function hostState(overrides: {
  config?: ResolvedAriavaConfig;
  identityInspection?: OnboardingHostState['identityInspection'];
  identity?: HostIdentity;
} = {}): OnboardingHostState {
  return {
    config: overrides.config ?? config,
    identityInspection: overrides.identityInspection ?? inspection,
    identity: overrides.identity ?? identity,
    encryptionBinding,
  };
}

function inspectionWith(overrides: Partial<HostIdentityInspection>): HostIdentityInspection {
  return { ...inspection, ...overrides };
}

function loadedInspectionWith(
  overrides: Partial<OnboardingHostState['identityInspection']>,
): OnboardingHostState['identityInspection'] {
  return { ...inspection, ...overrides };
}

describe('onboarding Host state policy', () => {
  test('reuses a valid ready identity with complete persisted configuration', () => {
    expect(evaluateHostIdentityReadiness(inspection, identity)).toEqual({ ready: true });
    expect(decideOnboardingHostState(hostState())).toEqual({ kind: 'reuse' });
  });

  test('initializes missing Host state while preserving the pure not-initialized readiness reason', () => {
    expect(decideOnboardingHostState(undefined)).toEqual({
      kind: 'initialize',
      reason: 'missing-state',
    });
    expect(evaluateHostIdentityReadiness(
      inspectionWith({ status: 'not-initialized' }),
      identity,
    )).toEqual({
      ready: false,
      reason: 'Host identity is not initialized.',
      identityStatus: 'not-initialized',
    });
  });

  test.each([
    {
      name: 'invalid evidence',
      inspection: inspectionWith({ status: 'invalid' }),
      reason: 'Host identity evidence exists but is invalid or unreadable (for example a locked or inaccessible Keychain private key). Explicit reset is required.',
    },
    {
      name: 'integrity failure',
      inspection: inspectionWith({ ownerIntegrity: false }),
      reason: 'Host identity integrity checks failed; the persisted identity is not safe to reuse.',
    },
    {
      name: 'loaded identity mismatch',
      inspection: inspectionWith({ hostId: 'other-host' }),
      reason: 'Persisted Host identity metadata does not match the loaded Host key material.',
    },
  ])('$name returns the stable unsafe-reuse reason', ({ inspection: unsafeInspection, reason }) => {
    expect(evaluateHostIdentityReadiness(unsafeInspection, identity)).toEqual({
      ready: false,
      reason,
      identityStatus: unsafeInspection.status,
    });
  });

  test('initializes an otherwise valid Host when persisted configuration is incomplete', () => {
    expect(decideOnboardingHostState(hostState({
      config: { ...config, agentAdapterSecret: undefined },
    }))).toEqual({
      kind: 'initialize',
      reason: 'incomplete-config',
    });
  });

  test('preserves persisted Relay precedence and proposes requested or production defaults only when absent', () => {
    expect(proposeRelaySelection({ relayBaseUrl: '  https://persisted.example  ' }, 'https://requested.example')).toEqual({
      value: 'https://persisted.example',
      changed: false,
    });
    expect(proposeRelaySelection({}, '  https://requested.example  ')).toEqual({
      value: 'https://requested.example',
      changed: true,
    });
    expect(proposeRelaySelection({}, '   ')).toEqual({
      value: 'https://ariava-relay.noyx.io',
      changed: true,
    });
  });

  test('proposes stable installer metadata with one supplied recordedAt when metadata changes', () => {
    const recordedAt = '2026-08-13T12:34:56.000Z';
    const proposal = proposeStableInstallerMetadata(
      {},
      '/prefix/bin/ariava',
      '1.2.3',
      recordedAt,
    );
    expect(proposal).toEqual({
      changed: true,
      metadata: {
        installer: {
          manager: 'npm',
          ariavaBinRealPath: '/prefix/bin/ariava',
          recordedAt,
        },
        bridgeSource: {
          kind: 'npm-package',
          package: 'ariava@1.2.3',
          updatedAt: recordedAt,
        },
      },
    });
  });

  test('returns unchanged stable metadata by reference without replacing its recordedAt', () => {
    const metadata: AriavaInstallMetadata = {
      installer: {
        manager: 'npm',
        ariavaBinRealPath: '/prefix/bin/ariava',
        recordedAt: '2026-07-20T00:00:00.000Z',
      },
      bridgeSource: {
        kind: 'npm-package',
        package: 'ariava@1.2.3',
        updatedAt: '2026-07-20T00:00:00.000Z',
      },
    };
    const proposal = proposeStableInstallerMetadata(
      metadata,
      '/prefix/bin/ariava',
      '9.9.9',
      '2026-08-13T12:34:56.000Z',
    );
    expect(proposal).toEqual({ metadata, changed: false });
    expect(proposal.metadata).toBe(metadata);
    expect(proposal.metadata.installer?.recordedAt).toBe('2026-07-20T00:00:00.000Z');
  });
});
