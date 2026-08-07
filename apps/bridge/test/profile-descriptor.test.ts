import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { resolveProfileAriavaConfig, saveUserConfig } from '../src/host-manager/config';
import { MACOS_IDENTITY_EVIDENCE_ACCOUNTS } from '../src/identity/macos-keychain-store';
import {
  assertProfileDescriptor,
  type AriavaProfileDescriptor,
  type ProfileResourceSet,
} from '../src/cli/profile';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';

const temporaryRoots: string[] = [];

function temporaryHome(label: string): string {
  const path = mkdtempSync(join(tmpdir(), `ariava-${label}-`));
  temporaryRoots.push(path);
  return path;
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('trusted profile descriptors', () => {
  test('default and dev expose complete immutable non-overlapping resources', () => {
    const home = temporaryHome('profiles');
    const { defaultProfile, devProfile } = withProfileEnvironment(home, join(home, 'xdg'), () => ({
      defaultProfile: createDefaultProfile(),
      devProfile: createDevProfile(),
    }));

    expect(defaultProfile).toMatchObject({
      id: 'default',
      displayName: 'Default',
      defaultRelayBaseUrl: 'https://ariava-relay.noyx.io',
      resources: {
        root: resolve(home, 'xdg', 'ariava'),
        configPath: resolve(home, 'xdg', 'ariava', 'config.json'),
        identityMetadataPath: resolve(home, 'xdg', 'ariava', 'host-identity.json'),
        identityProfile: 'default',
        identityEvidenceAccount: MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default,
        encryptionIdentityPath: resolve(home, 'xdg', 'ariava', 'host-identity.json.e2e.json'),
        linkKeyringPath: resolve(home, 'xdg', 'ariava', 'host-identity.json.e2e-keyring.json'),
        statePath: resolve(home, 'xdg', 'ariava', 'state', 'bridge-state.json'),
        agentAdapterConfigPath: resolve(home, 'xdg', 'ariava', 'agent-adapter.json'),
        agentAdapterPort: 7272,
        piExtensionLogPath: resolve(home, 'xdg', 'ariava', 'pi-extension.log'),
      },
    });
    expect(defaultProfile.defaultHostName('workstation')).toBe('workstation');

    expect(devProfile).toMatchObject({
      id: 'dev',
      displayName: 'Development',
      defaultRelayBaseUrl: 'http://127.0.0.1:8787',
      resources: {
        root: resolve(home, '.config', 'ariava-dev'),
        configPath: resolve(home, '.config', 'ariava-dev', 'config.json'),
        identityMetadataPath: resolve(home, '.config', 'ariava-dev', 'host-identity.json'),
        identityProfile: 'dev',
        identityEvidenceAccount: MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev,
        encryptionIdentityPath: resolve(home, '.config', 'ariava-dev', 'host-identity.json.e2e.json'),
        linkKeyringPath: resolve(home, '.config', 'ariava-dev', 'host-identity.json.e2e-keyring.json'),
        statePath: resolve(home, '.config', 'ariava-dev', 'state', 'bridge-state.json'),
        agentAdapterConfigPath: resolve(home, '.config', 'ariava-dev', 'agent-adapter.json'),
        agentAdapterPort: 7273,
        piExtensionLogPath: resolve(home, '.config', 'ariava-dev', 'pi-extension.log'),
      },
    });
    expect(devProfile.defaultHostName('workstation')).toBe('workstation (Dev)');

    expect(Object.isFrozen(defaultProfile)).toBe(true);
    expect(Object.isFrozen(defaultProfile.resources)).toBe(true);
    expect(Object.isFrozen(devProfile)).toBe(true);
    expect(Object.isFrozen(devProfile.resources)).toBe(true);
    defaultProfile.assertDescriptor();
    devProfile.assertDescriptor();

    const defaultPaths = new Set(resourcePaths(defaultProfile.resources));
    for (const path of resourcePaths(devProfile.resources)) expect(defaultPaths.has(path)).toBe(false);
  });

  test('descriptor-only validation rejects forged IDs, ports, namespaces, paths, and derivations without I/O', () => {
    const home = resolve('/definitely-missing', 'ariava-profile-test-home');
    const profile = withProfileEnvironment(home, resolve(home, 'xdg'), () => createDevProfile());
    const cases: Array<[string, AriavaProfileDescriptor]> = [
      ['profile ID', forged(profile, { id: 'default' })],
      ['Adapter port', forged(profile, { resources: { ...profile.resources, agentAdapterPort: 7272 } })],
      ['identity profile', forged(profile, { resources: { ...profile.resources, identityProfile: 'default' } })],
      ['identity evidence account', forged(profile, { resources: { ...profile.resources, identityEvidenceAccount: MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default } })],
      ['absolute', forged(profile, { resources: { ...profile.resources, statePath: 'relative/state.json' } })],
      ['configPath', forged(profile, { resources: { ...profile.resources, configPath: join(profile.resources.root, 'other.json') } })],
      ['encryptionIdentityPath', forged(profile, { resources: { ...profile.resources, encryptionIdentityPath: join(profile.resources.root, 'other.e2e.json') } })],
      ['linkKeyringPath', forged(profile, { resources: { ...profile.resources, linkKeyringPath: join(profile.resources.root, 'other-keyring.json') } })],
      ['profile root', forged(profile, { resources: { ...profile.resources, root: resolve(home, '.config', 'ariava') } })],
    ];

    for (const [label, candidate] of cases) {
      expect(() => assertProfileDescriptor(candidate), label).toThrow();
    }
  });

  test('rejects spread and callback-spoofed descriptors before reading foreign config', () => {
    const home = temporaryHome('forged-load');
    const profile = withProfileEnvironment(home, undefined, () => createDevProfile());
    const foreignConfigPath = join(home, 'foreign-config.json');
    writeFileSync(foreignConfigPath, '{ malformed foreign config', { mode: 0o600 });
    const candidate = forged(profile, {
      resources: { ...profile.resources, configPath: foreignConfigPath },
      assertDescriptor: () => {},
      assertResolvedResources: () => {},
    });

    expect(() => resolveProfileAriavaConfig(candidate)).toThrow(/authentic|trusted factory/i);
  });


  test('rejects default and dev resource overlap caused by an adversarial XDG root', () => {
    const home = temporaryHome('overlap');
    const overlappingXdg = resolve(home, '.config', 'ariava-dev');
    withProfileEnvironment(home, overlappingXdg, () => {
      expect(() => createDefaultProfile()).toThrow(/overlap/i);
      expect(() => createDevProfile()).toThrow(/overlap/i);
    });
  });

  test('rejects canonical default and dev overlap before config reads through symlinked ancestors', () => {
    const home = temporaryHome('canonical-profile-overlap');
    const devRoot = join(home, '.config', 'ariava-dev');
    mkdirSync(devRoot, { recursive: true, mode: 0o700 });
    const xdgLink = join(home, 'xdg-link');
    symlinkSync(devRoot, xdgLink);
    const defaultProfile = withProfileEnvironment(home, xdgLink, () => createDefaultProfile());
    mkdirSync(defaultProfile.resources.root, { recursive: true, mode: 0o700 });
    writeFileSync(defaultProfile.resources.configPath, '{ malformed default config', { mode: 0o600 });

    expect(() => resolveProfileAriavaConfig(defaultProfile)).toThrow(/overlap/i);

    const realHome = temporaryHome('canonical-home-target');
    const defaultRoot = join(realHome, '.config', 'ariava');
    mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });
    const homeLink = join(home, 'home-link');
    symlinkSync(defaultRoot, homeLink);
    const devProfile = withProfileEnvironment(homeLink, join(realHome, '.config'), () => createDevProfile());
    mkdirSync(devProfile.resources.root, { recursive: true, mode: 0o700 });
    writeFileSync(devProfile.resources.configPath, '{ malformed dev config', { mode: 0o600 });

    expect(() => resolveProfileAriavaConfig(devProfile)).toThrow(/overlap/i);
  });


  test('profile-bound config loading ignores ambient overrides and rejects cross-profile resources', () => {
    const home = temporaryHome('config');
    const profile = withProfileEnvironment(home, undefined, () => createDevProfile());
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    saveUserConfig({
      relayBaseUrl: 'https://persisted.example',
      hostName: 'Persisted Dev',
      agentAdapterPort: profile.resources.agentAdapterPort,
      agentAdapterConfigPath: profile.resources.agentAdapterConfigPath,
      statePath: profile.resources.statePath,
      identityPath: profile.resources.identityMetadataPath,
    }, profile.resources.configPath);

    const previous = {
      relay: process.env.ARIAVA_RELAY_BASE_URL,
      identity: process.env.ARIAVA_HOST_IDENTITY_PATH,
      state: process.env.ARIAVA_STATE_PATH,
      adapter: process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH,
      port: process.env.ARIAVA_AGENT_ADAPTER_PORT,
    };
    Object.assign(process.env, {
      ARIAVA_RELAY_BASE_URL: 'https://ambient.invalid',
      ARIAVA_HOST_IDENTITY_PATH: resolve(home, '.config', 'ariava', 'host-identity.json'),
      ARIAVA_STATE_PATH: resolve(home, '.config', 'ariava', 'state', 'bridge-state.json'),
      ARIAVA_AGENT_ADAPTER_CONFIG_PATH: resolve(home, '.config', 'ariava', 'agent-adapter.json'),
      ARIAVA_AGENT_ADAPTER_PORT: '7272',
    });
    try {
      const resolved = resolveProfileAriavaConfig(profile);
      expect(resolved.relayBaseUrl).toBe('https://persisted.example');
      expect(resolved.identityPath).toBe(profile.resources.identityMetadataPath);
      expect(resolved.statePath).toBe(profile.resources.statePath);
      expect(resolved.agentAdapterConfigPath).toBe(profile.resources.agentAdapterConfigPath);
      expect(resolved.agentAdapterPort).toBe(7273);
      expect(resolved.environmentOverrides).toEqual([]);

      saveUserConfig({
        ...loadPersistedFields(resolved),
        identityPath: resolve(home, '.config', 'ariava', 'host-identity.json'),
      }, profile.resources.configPath);
      expect(() => resolveProfileAriavaConfig(profile)).toThrow(/identityPath/);
    } finally {
      restoreEnvironment('ARIAVA_RELAY_BASE_URL', previous.relay);
      restoreEnvironment('ARIAVA_HOST_IDENTITY_PATH', previous.identity);
      restoreEnvironment('ARIAVA_STATE_PATH', previous.state);
      restoreEnvironment('ARIAVA_AGENT_ADAPTER_CONFIG_PATH', previous.adapter);
      restoreEnvironment('ARIAVA_AGENT_ADAPTER_PORT', previous.port);
    }
  });

  test('resolved validation canonicalizes existing ancestors, accepts missing leaves, and rejects symlink escape', () => {
    const home = temporaryHome('canonical');
    const profile = withProfileEnvironment(home, undefined, () => createDevProfile());
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    const valid = resolvedResources(profile);

    expect(() => profile.assertResolvedResources(valid)).not.toThrow();

    const outside = temporaryHome('outside');
    mkdirSync(outside, { recursive: true, mode: 0o700 });
    symlinkSync(outside, join(profile.resources.root, 'state'));
    expect(() => profile.assertResolvedResources(valid)).toThrow(/symlink|escape|root/i);
  });

  test('derives complete safe custom default state, discovery, and port resources', () => {
    const home = temporaryHome('default-custom-runtime-resources');
    const defaultProfile = withProfileEnvironment(home, undefined, () => createDefaultProfile());
    const customRoot = join(home, 'custom-runtime');
    const statePath = join(customRoot, 'bridge-state.json');
    const agentAdapterConfigPath = join(customRoot, 'agent-adapter.json');
    const resolved = {
      ...resolvedResources(defaultProfile),
      statePath,
      agentAdapterConfigPath,
      agentAdapterPort: 8123,
    };

    expect(defaultProfile.resolveResources(resolved)).toMatchObject({
      statePath,
      agentAdapterConfigPath,
      agentAdapterPort: 8123,
      identityMetadataPath: defaultProfile.resources.identityMetadataPath,
    });
  });

  test('preserves safe custom default identity paths and derives their complete identity resource set', () => {
    const home = temporaryHome('default-custom');
    const defaultProfile = withProfileEnvironment(home, undefined, () => createDefaultProfile());
    const customRoot = join(home, 'custom-identity');
    mkdirSync(customRoot, { recursive: true, mode: 0o700 });
    const customIdentityPath = join(customRoot, 'host.json');
    const resolved = { ...resolvedResources(defaultProfile), identityPath: customIdentityPath };

    expect(() => defaultProfile.assertResolvedResources(resolved)).not.toThrow();
    expect(defaultProfile.resolveResources(resolved)).toMatchObject({
      identityMetadataPath: customIdentityPath,
      encryptionIdentityPath: `${customIdentityPath}.e2e.json`,
      linkKeyringPath: `${customIdentityPath}.e2e-keyring.json`,
    });

    const devProfile = withProfileEnvironment(home, undefined, () => createDevProfile());
    expect(() => defaultProfile.assertResolvedResources({
      ...resolved,
      identityPath: devProfile.resources.identityMetadataPath,
    })).toThrow(/overlaps the dev profile/);
  });

  test('rejects custom default identity traversal through complete existing symlink chains', () => {
    const home = temporaryHome('default-custom-symlinks');
    const defaultProfile = withProfileEnvironment(home, undefined, () => createDefaultProfile());
    const outside = temporaryHome('default-custom-outside');
    const outsideNested = join(outside, 'nested');
    mkdirSync(outsideNested, { recursive: true, mode: 0o700 });
    writeFileSync(join(outside, 'existing-target.json'), '{}', { mode: 0o600 });

    const directParentLink = join(home, 'direct-link');
    symlinkSync(outside, directParentLink);
    const intermediateRoot = join(home, 'intermediate');
    mkdirSync(intermediateRoot, { recursive: true, mode: 0o700 });
    symlinkSync(outside, join(intermediateRoot, 'link'));
    const existingLeafLink = join(home, 'existing-leaf.json');
    symlinkSync(join(outside, 'existing-target.json'), existingLeafLink);
    const missingLeafRoot = join(home, 'missing-leaf');
    mkdirSync(missingLeafRoot, { recursive: true, mode: 0o700 });
    symlinkSync(outside, join(missingLeafRoot, 'link'));

    const cases = [
      join(directParentLink, 'host.json'),
      join(intermediateRoot, 'link', 'nested', 'host.json'),
      existingLeafLink,
      join(missingLeafRoot, 'link', 'missing', 'nested', 'host.json'),
    ];
    for (const identityPath of cases) {
      expect(() => defaultProfile.assertResolvedResources({
        ...resolvedResources(defaultProfile),
        identityPath,
      }), identityPath).toThrow(/symlink/);
    }
  });

  test('rejects custom default identity collisions with every fixed profile resource', () => {
    const home = temporaryHome('default-custom-collisions');
    const defaultProfile = withProfileEnvironment(home, undefined, () => createDefaultProfile());
    const fixedResources = [
      ['root', defaultProfile.resources.root],
      ['config', defaultProfile.resources.configPath],
      ['state', defaultProfile.resources.statePath],
      ['discovery', defaultProfile.resources.agentAdapterConfigPath],
      ['Pi log', defaultProfile.resources.piExtensionLogPath],
    ] as const;

    for (const [label, identityPath] of fixedResources) {
      expect(() => defaultProfile.assertResolvedResources({
        ...resolvedResources(defaultProfile),
        identityPath,
      }), label).toThrow(/overlap|collision/i);
    }
  });
});

function resourcePaths(resources: ProfileResourceSet): string[] {
  return [
    resources.root,
    resources.configPath,
    resources.identityMetadataPath,
    resources.encryptionIdentityPath,
    resources.linkKeyringPath,
    resources.statePath,
    resources.agentAdapterConfigPath,
    resources.piExtensionLogPath,
  ];
}

function forged(
  profile: AriavaProfileDescriptor,
  patch: Partial<AriavaProfileDescriptor> & { resources?: ProfileResourceSet },
): AriavaProfileDescriptor {
  return { ...profile, ...patch, resources: patch.resources ?? profile.resources } as AriavaProfileDescriptor;
}

function resolvedResources(profile: AriavaProfileDescriptor) {
  return {
    relayBaseUrl: profile.defaultRelayBaseUrl,
    hostName: profile.defaultHostName('host'),
    agentAdapterPort: profile.resources.agentAdapterPort,
    agentAdapterConfigPath: profile.resources.agentAdapterConfigPath,
    statePath: profile.resources.statePath,
    identityPath: profile.resources.identityMetadataPath,
    configPath: profile.resources.configPath,
    installPath: join(profile.resources.root, 'install.json'),
    logDir: join(profile.resources.root, 'logs'),
    stdoutLogPath: join(profile.resources.root, 'logs', 'bridge.stdout.log'),
    stderrLogPath: join(profile.resources.root, 'logs', 'bridge.stderr.log'),
    tmpDir: join(profile.resources.root, 'tmp'),
    environmentOverrides: [],
  };
}

function loadPersistedFields(resolved: ReturnType<typeof resolveProfileAriavaConfig>) {
  return {
    relayBaseUrl: resolved.relayBaseUrl,
    hostName: resolved.hostName,
    agentAdapterPort: resolved.agentAdapterPort,
    agentAdapterConfigPath: resolved.agentAdapterConfigPath,
    statePath: resolved.statePath,
  };
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function withProfileEnvironment<T>(home: string, xdgConfigHome: string | undefined, run: () => T): T {
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = home;
  if (xdgConfigHome === undefined) delete process.env.XDG_CONFIG_HOME;
  else process.env.XDG_CONFIG_HOME = xdgConfigHome;
  try {
    return run();
  } finally {
    restoreEnvironment('HOME', previousHome);
    restoreEnvironment('XDG_CONFIG_HOME', previousXdg);
  }
}
