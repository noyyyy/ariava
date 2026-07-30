import { probeHostPlatform } from '../host-platform';
import { LinuxJsonHostIdentityStore } from './linux-json-store';
import { LinuxEncryptionKeyStore } from './linux-encryption-key-store';
import { MacOSEncryptionKeyStore } from './macos-encryption-key-store';
import { MacOSKeychainHostIdentityStore, type MacOSIdentityProfile } from './macos-keychain-store';
import type { HostEncryptionIdentity } from './host-encryption-key';
import type { HostIdentityStore } from './types';

export function createRuntimeHostIdentityStore(
  identityPath: string,
  platform: NodeJS.Platform | string = process.platform,
  identityProfile: MacOSIdentityProfile = 'default',
): HostIdentityStore {
  const hostPlatform = probeHostPlatform(platform);
  return hostPlatform === 'macos'
    ? new MacOSKeychainHostIdentityStore(identityPath, undefined, undefined, identityProfile)
    : new LinuxJsonHostIdentityStore(identityPath);
}

export interface HostEncryptionIdentityStore {
  load(): HostEncryptionIdentity | null;
  loadOrCreate(hostId: string): HostEncryptionIdentity;
  replaceForReset(hostId: string): HostEncryptionIdentity;
}

export function hostEncryptionIdentityPath(identityPath: string): string {
  return `${identityPath}.e2e.json`;
}

export function createRuntimeHostEncryptionIdentityStore(
  identityPath: string,
  platform: NodeJS.Platform | string = process.platform,
  _identityProfile: MacOSIdentityProfile = 'default',
): HostEncryptionIdentityStore {
  const path = hostEncryptionIdentityPath(identityPath);
  return probeHostPlatform(platform) === 'macos' ? new MacOSEncryptionKeyStore(path) : new LinuxEncryptionKeyStore(path);
}
