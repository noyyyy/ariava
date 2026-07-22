import { describe, expect, test } from 'bun:test';
import {
  ONBOARDING_STEP_IDS,
  PRODUCTION_ADAPTER_CATALOG,
  getProductionAdapter,
} from '../src/host-manager/onboarding';
import { AriavaCliError } from '../src/host-manager/service/errors';

describe('onboarding contracts and adapter catalog', () => {
  test('defines the stable ordered step IDs', () => {
    expect(ONBOARDING_STEP_IDS).toEqual([
      'preflight',
      'stable-cli',
      'relay-config',
      'host-init',
      'bridge-service',
      'adapter-detect',
      'adapter-install',
      'strict-readiness',
      'completion',
    ]);
  });

  test('contains exactly the production Pi adapter with the exact CLI version policy', () => {
    expect(PRODUCTION_ADAPTER_CATALOG).toEqual([{
      id: 'pi',
      displayName: 'Pi',
      availability: 'production',
      detect: { commands: ['pi'] },
      installer: {
        kind: 'pi-package',
        package: 'npm:@ariava/pi-extension',
        versionPolicy: 'exact-cli-version',
      },
      readiness: { requiresReload: true },
    }]);
    expect(getProductionAdapter('pi')).toBe(PRODUCTION_ADAPTER_CATALOG[0]);
  });

  test('rejects unknown adapters without search or network behavior', () => {
    expect(() => getProductionAdapter('codex')).toThrow(AriavaCliError);
    try {
      getProductionAdapter('codex');
    } catch (error) {
      expect(error).toMatchObject({
        code: 'ERR_ADAPTER_UNKNOWN',
        data: { step: 'adapter-detect', retryable: false },
      });
    }
  });
});
