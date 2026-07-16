import { probeHostPlatform } from '../host-platform';
import { LinuxJsonHostIdentityStore } from './linux-json-store';
import { MacOSKeychainHostIdentityStore } from './macos-keychain-store';
import type { HostIdentityStore } from './types';

export function createRuntimeHostIdentityStore(
  identityPath: string,
  platform: NodeJS.Platform | string = process.platform,
): HostIdentityStore {
  const hostPlatform = probeHostPlatform(platform);
  return hostPlatform === 'macos'
    ? new MacOSKeychainHostIdentityStore(identityPath)
    : new LinuxJsonHostIdentityStore(identityPath);
}
