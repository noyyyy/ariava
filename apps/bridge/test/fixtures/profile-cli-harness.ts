import type { ProcessAwareLockDependencies } from '../../src/host-manager/process-aware-lock';
import { withHostIdentityOperationLock } from '../../src/cli/operations/host-identity-operation-lock';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, sep } from 'node:path';
import {
  createProfileCliContext,
  type AriavaProfileCliContext,
  type ProfileAccessKind,
} from '../../src/cli/context';
import { createDefaultProfile } from '../../src/cli/profiles/default';
import { createDevProfile } from '../../src/cli/profiles/dev';
import { loadUserConfig, saveUserConfig, type AriavaUserConfig } from '../../src/host-manager/config';
import type {
  HostIdentity,
  HostIdentityInspection,
  HostIdentityStore,
} from '../../src/identity';
import type { AriavaProfileDescriptor, AriavaProfileId } from '../../src/cli/profile';

export const PROFILE_ACCESS_KINDS = [
  'filesystemReads',
  'filesystemWrites',
  'keychainProbes',
  'keychainReads',
  'keychainWrites',
  'keychainDeletes',
  'relaySigners',
  'relayRequests',
  'childSpawns',
  'serviceRunnerCalls',
] as const satisfies readonly ProfileAccessKind[];

export type ProfileAccessCounters = Record<ProfileAccessKind, number>;
export type ProfileFilesystemProbeCounters = Record<AriavaProfileId | 'other', number>;

export interface ProfileAccessEvent {
  profile: AriavaProfileId | 'other';
  initiatedBy: AriavaProfileId;
  action: string;
  path?: string;
}

export interface ProfileCliHarness {
  root: string;
  profiles: Record<AriavaProfileId, AriavaProfileDescriptor>;
  contexts: Record<AriavaProfileId, AriavaProfileCliContext>;
  counters: Record<AriavaProfileId, ProfileAccessCounters>;
  filesystemProbeReads: ProfileFilesystemProbeCounters;
  events: ProfileAccessEvent[];
  config(profile: AriavaProfileId): AriavaUserConfig;
  sentinelBytes(profile: AriavaProfileId): Buffer;
  cleanup(): void;
}

export function createProfileCliHarness(): ProfileCliHarness {
  const root = mkdtempSync(join(tmpdir(), 'ariava-profile-cli-'));
  const profiles = withProfileEnvironment(root, () => ({
    default: createDefaultProfile(),
    dev: createDevProfile(),
  }));
  const counters = {
    default: emptyCounters(),
    dev: emptyCounters(),
  };
  const filesystemProbeReads: ProfileFilesystemProbeCounters = { default: 0, dev: 0, other: 0 };
  const events: ProfileAccessEvent[] = [];
  const identities = {
    default: fakeIdentity('default'),
    dev: fakeIdentity('dev'),
  };

  for (const profile of Object.values(profiles)) {
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    writeFileSync(sentinelPath(profile), Buffer.from(`sentinel:${profile.id}:\u0000\u0001`, 'utf8'), { mode: 0o600 });
  }

  const contexts = {
    default: contextFor(profiles.default),
    dev: contextFor(profiles.dev),
  };

  return {
    root,
    profiles,
    contexts,
    counters,
    filesystemProbeReads,
    events,
    config: (profile) => loadUserConfig(profiles[profile].resources.configPath),
    sentinelBytes: (profile) => readFileSync(sentinelPath(profiles[profile])),
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };

  function contextFor(profile: AriavaProfileDescriptor): AriavaProfileCliContext {
    return createProfileCliContext({
      profile,
      platform: 'darwin',
      hostName: () => 'fixture-host',
      generateSecret: () => `${profile.id}-secret`,
      access: (kind, path) => recordAccess(kind, path, profile.id),
      observeValidation: (phase) => {
        events.push({ profile: profile.id, initiatedBy: profile.id, action: `${phase}.validate` });
      },
      observeFilesystemProbe: (path) => recordProbe(path, profile.id),
      config: {
        load(path) {
          return loadUserConfig(path);
        },
        save(config, path) {
          saveUserConfig(config, path);
        },
      },
      hostIdentityOperationLock: {
        run(resources, operation) {
          events.push({ profile: profile.id, initiatedBy: profile.id, action: 'hostIdentityOperationLock.run', path: resources.hostDomainResetJournalPath });
          return withHostIdentityOperationLock(resources, operation, testLockDependencies());
        },
      },
      identity: {
        create() {
          return fakeIdentityStore(
            profile, identities[profile.id], counters[profile.id], events,
            () => identities[profile.id],
            (replacement) => { identities[profile.id] = replacement; },
          );
        },
      },
      encryptionIdentity: {
        create(resources) {
          // Mirrors the real stores: replaceForReset persists, so a subsequent load() returns the replacement.
          let replaced: HostEncryptionIdentity | null = null;
          return {
            load: () => replaced,
            loadOrCreate: () => {
              counters[profile.id].filesystemReads += 1;
              counters[profile.id].filesystemWrites += 1;
              events.push({ profile: profile.id, initiatedBy: profile.id, action: 'encryption.loadOrCreate', path: resources.encryptionIdentityPath });
              return fakeEncryptionIdentity(profile.id);
            },
            replaceForReset: () => {
              counters[profile.id].filesystemWrites += 1;
              events.push({ profile: profile.id, initiatedBy: profile.id, action: 'encryption.replace', path: resources.encryptionIdentityPath });
              replaced = fakeEncryptionIdentity(profile.id, identities[profile.id].hostId);
              return replaced;
            },
          };
        },
      },
    });
  }

  function recordProbe(path: string, initiatedBy: AriavaProfileId): void {
    const profile = classifyPath(path);
    filesystemProbeReads[profile] += 1;
    counters[profile === 'other' ? initiatedBy : profile].filesystemReads += 1;
    events.push({ profile, initiatedBy, action: 'filesystemProbeReads', path });
  }

  function recordAccess(kind: ProfileAccessKind, path: string | undefined, initiatedBy: AriavaProfileId): void {
    const profile = path === undefined ? initiatedBy : classifyPath(path);
    counters[profile === 'other' ? initiatedBy : profile][kind] += 1;
    events.push({ profile, initiatedBy, action: kind, ...(path ? { path } : {}) });
  }

  function classifyPath(path: string): AriavaProfileId | 'other' {
    for (const profile of Object.values(profiles)) {
      if (isWithin(profile.resources.root, path)) return profile.id;
    }
    return 'other';
  }
}

function fakeIdentityStore(
  profile: AriavaProfileDescriptor,
  identity: HostIdentity,
  counters: ProfileAccessCounters,
  events: ProfileAccessEvent[],
  readIdentity: () => HostIdentity = () => identity,
  persistIdentity: (identity: HostIdentity) => void = () => {},
): HostIdentityStore {
  return {
    async inspect() {
      counters.keychainProbes += 1;
      events.push({ profile: profile.id, initiatedBy: profile.id, action: 'keychainProbes', path: profile.resources.identityMetadataPath });
      return fakeInspection(profile, readIdentity());
    },
    async load() {
      counters.keychainReads += 1;
      events.push({ profile: profile.id, initiatedBy: profile.id, action: 'keychainReads', path: profile.resources.identityMetadataPath });
      return readIdentity();
    },
    async createFirstRun() {
      counters.keychainWrites += 1;
      events.push({ profile: profile.id, initiatedBy: profile.id, action: 'keychainWrites', path: profile.resources.identityMetadataPath });
      return readIdentity();
    },
    async resetAfterExplicitConfirmation() {
      counters.keychainDeletes += 1;
      counters.keychainWrites += 1;
      events.push({ profile: profile.id, initiatedBy: profile.id, action: 'keychainDeletes', path: profile.resources.identityMetadataPath });
      events.push({ profile: profile.id, initiatedBy: profile.id, action: 'keychainWrites', path: profile.resources.identityMetadataPath });
      const replacementSuffix = profile.id === 'default' ? 'R' : 'W';
      const currentIdentity = fakeIdentityWithSuffix(profile.id, replacementSuffix);
      persistIdentity(currentIdentity);
      return currentIdentity;
    },
  };
}

function fakeIdentity(profile: AriavaProfileId): HostIdentity {
  const suffix = profile === 'default' ? 'D' : 'V';
  return fakeIdentityWithSuffix(profile, suffix);
}

function fakeIdentityWithSuffix(profile: AriavaProfileId, suffix: string): HostIdentity {
  const hostId = `host_${suffix.repeat(43)}`;
  return {
    identityVersion: 2,
    hostId,
    keyId: `key_${suffix.repeat(43)}`,
    algorithm: 'Ed25519',
    publicKey: `public-${profile}`,
    publicKeyFingerprint: `fingerprint-${profile}`,
    createdAt: '2026-08-05T00:00:00.000Z',
    privateKeyStorage: {
      type: 'macos-keychain',
      service: 'io.noyx.ariava.host-identity',
      account: hostId,
    },
    signer: {
      entityId: hostId,
      keyId: `key_${suffix.repeat(43)}`,
      async sign() { return `signature-${profile}`; },
      async signRequest() { return {} as never; },
    },
  };
}

function fakeInspection(profile: AriavaProfileDescriptor, identity: HostIdentity): HostIdentityInspection {
  return {
    status: 'ready',
    storageType: 'macos-keychain',
    storageReference: identity.privateKeyStorage,
    path: profile.resources.identityMetadataPath,
    hostId: identity.hostId,
    keyId: identity.keyId,
    algorithm: identity.algorithm,
    publicKeyFingerprint: identity.publicKeyFingerprint,
    ownerIntegrity: true,
    permissionIntegrity: true,
    metadataIntegrity: true,
  };
}

function fakeEncryptionIdentity(profile: AriavaProfileId, hostId = fakeIdentity(profile).hostId) {
  const suffix = profile === 'default' ? 1 : 2;
  return {
    version: 1 as const,
    hostId,
    encryptionKeyId: `ekey_${profile}`,
    publicKey: `encryption-public-${profile}`,
    privateKeyPkcs8: new Uint8Array([suffix]),
    sequence: 1,
    createdAt: '2026-08-05T00:00:00.000Z',
  };
}

function sentinelPath(profile: AriavaProfileDescriptor): string {
  return join(profile.resources.root, 'profile-sentinel.bin');
}

function emptyCounters(): ProfileAccessCounters {
  return Object.fromEntries(PROFILE_ACCESS_KINDS.map((kind) => [kind, 0])) as ProfileAccessCounters;
}

function testLockDependencies(): Partial<ProcessAwareLockDependencies> {
  return {
    platform: 'linux',
    uid: process.getuid?.(),
    pid: process.pid,
    now: () => new Date(),
    ownerToken: () => 'a'.repeat(48),
    currentProcessStart: () => 'profile-harness-process-start',
    inspector: { inspect: () => ({ status: 'alive', processStart: 'profile-harness-process-start' }) },
  };
}

function withProfileEnvironment<T>(home: string, run: () => T): T {
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, '.config');
  try {
    return run();
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousXdg;
  }
}

function isWithin(root: string, path: string): boolean {
  const remainder = relative(root, path);
  return remainder === '' || (!remainder.startsWith(`..${sep}`) && remainder !== '..' && !isAbsolute(remainder));
}
