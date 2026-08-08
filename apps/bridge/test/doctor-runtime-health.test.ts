import { describe, expect, test } from 'bun:test';
import { runDoctorCommand } from '../src/cli/commands/doctor';
import { createProfileCliContext } from '../src/cli/context';
import { createDefaultProfile } from '../src/cli/profile';

function dependencies(runtimeHealth: 'healthy' | 'degraded') {
  const profile = createDefaultProfile();
  const context = createProfileCliContext({
    profile,
    platform: 'linux',
    hostName: () => 'Host',
    generateSecret: () => 'secret',
    environment: {},
    config: { load: () => ({}), save: () => {} },
    identity: {
      create: () => ({
        inspect: async () => ({
          status: 'not-initialized', storageType: 'linux-json',
          storageReference: { type: 'linux-json', path: profile.resources.identityMetadataPath },
          path: profile.resources.identityMetadataPath, ownerIntegrity: false, permissionIntegrity: false,
          metadataIntegrity: false, pendingRotation: false,
        }),
      }) as never,
    },
  });
  return {
    context: () => context,
    pathExists: () => false,
    runtime: () => ({ nodeFound: true, runtimeNameIsNode: true, runtimeVersionSupported: true, runtimeCryptoSelfTestPassed: true }),
    lifecycle: {
      buildChecks: () => ({
        requiredFormulaInput: true,
        bridgeRuntimeHealth: { status: runtimeHealth, drivers: runtimeHealth === 'healthy' ? [] : [{ driver: 'pi', code: 'driver_reconciliation_failed', count: 1 }] },
      }),
      healthy: (checks: Record<string, unknown>) => checks.requiredFormulaInput === true,
      formatDoctor: (checks: Record<string, unknown>) => JSON.stringify(checks),
    },
  };
}

describe('doctor runtime health evidence', () => {
  test('reports degraded evidence without changing the existing aggregate or exit behavior', async () => {
    const healthy = await runDoctorCommand([], dependencies('healthy'));
    const degraded = await runDoctorCommand([], dependencies('degraded'));
    expect(healthy).toMatchObject({ envelope: { ok: true, code: 'ok' }, exitCode: 0 });
    expect(degraded).toMatchObject({ envelope: { ok: true, code: 'ok', data: { bridgeRuntimeHealth: { status: 'degraded' } } }, exitCode: 0 });
  });
});
