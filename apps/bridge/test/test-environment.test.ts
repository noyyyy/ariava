import { expect, test } from 'bun:test';
import { join } from 'node:path';
import { ARIAVA_CONFIG_ROOT, ARIAVA_HOST_IDENTITY_PATH } from '../src/host-manager/paths';

test('Bun preload isolates module-load production paths from the real user home', () => {
  expect(ARIAVA_CONFIG_ROOT).toContain('ariava-test-lane-');
  expect(ARIAVA_CONFIG_ROOT).not.toStartWith('/Users/real-user/');
  expect(ARIAVA_CONFIG_ROOT).toEndWith(join('.config', 'ariava'));
  expect(ARIAVA_HOST_IDENTITY_PATH).toBe(join(ARIAVA_CONFIG_ROOT, 'host-identity.json'));
});
