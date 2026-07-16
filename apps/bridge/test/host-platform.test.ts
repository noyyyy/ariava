import { describe, expect, test } from 'bun:test';
import { probeHostPlatform, UnsupportedHostPlatformError } from '../src/host-platform';

describe('Host runtime platform', () => {
  test('maps Darwin and Linux to protocol platforms', () => {
    expect(probeHostPlatform('darwin')).toBe('macos');
    expect(probeHostPlatform('linux')).toBe('linux');
  });

  test('rejects unsupported platforms with a typed error', () => {
    expect(() => probeHostPlatform('win32')).toThrow(UnsupportedHostPlatformError);
    try { probeHostPlatform('freebsd'); } catch (error) {
      expect(error).toMatchObject({ code: 'ERR_UNSUPPORTED_PLATFORM', platform: 'freebsd' });
    }
  });
});
