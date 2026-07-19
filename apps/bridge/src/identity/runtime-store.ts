import { probeHostPlatform } from '../host-platform';
import { LinuxJsonHostIdentityStore } from './linux-json-store';
import { MacOSKeychainHostIdentityStore, type MacOSIdentityProfile } from './macos-keychain-store';
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
