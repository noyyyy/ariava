import type { HostPlatform } from '@ariava/protocol';

export class UnsupportedHostPlatformError extends Error {
  readonly code = 'ERR_UNSUPPORTED_PLATFORM';

  constructor(readonly platform: NodeJS.Platform | string) {
    super(`Unsupported Host runtime platform: ${platform}`);
    this.name = 'UnsupportedHostPlatformError';
  }
}

export function probeHostPlatform(platform: NodeJS.Platform | string = process.platform): HostPlatform {
  if (platform === 'darwin') return 'macos';
  if (platform === 'linux') return 'linux';
  throw new UnsupportedHostPlatformError(platform);
}
