import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runStatusCommand } from '../src/cli/commands/status';
import { runDoctorCommand } from '../src/cli/commands/doctor';
import { createProfileCliContext } from '../src/cli/context';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import { HOST_DOMAIN_RESET_PHASES } from '../src/cli/operations/host-domain-reset-journal';
import {
  buildJournal,
  writeJournalFixture,
} from './helpers/host-domain-reset-journal-fixture';

const roots: string[] = [];
const originalHome = process.env.HOME;
const originalXdg = process.env.XDG_CONFIG_HOME;

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME; else process.env.HOME = originalHome;
  if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = originalXdg;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function dependencies(profileId: 'default' | 'dev', phase: typeof HOST_DOMAIN_RESET_PHASES[number]) {
  const home = mkdtempSync(join(tmpdir(), `ariava-${profileId}-reset-status-`));
  roots.push(home);
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  const profile = profileId === 'default' ? createDefaultProfile() : createDevProfile();
  mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
  const servicePatch = profileId === 'default'
    ? { service: { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'systemd-user' } }
    : {};
  writeJournalFixture(profile.resources, buildJournal(profile.resources, phase, servicePatch));
  const context = createProfileCliContext({
    profile, platform: 'linux', hostName: () => 'Host', generateSecret: () => 'secret',
    config: { load: () => ({}), save: () => {} },
    identity: { create: () => ({ inspect: async () => ({ status: 'not-initialized', storageType: 'linux-json', storageReference: { type: 'linux-json', path: profile.resources.identityMetadataPath }, path: profile.resources.identityMetadataPath, ownerIntegrity: false, permissionIntegrity: false, metadataIntegrity: false }) }) as never },
  });
  const common = {
    context: () => context, pathExists: () => true,
    runtime: () => ({ nodeFound: true, runtimeNameIsNode: true, runtimeVersionSupported: true, runtimeCryptoSelfTestPassed: true }),
  };
  return {
    status: {
      ...common,
      lifecycle: {
        buildStatus: (shared: any) => ({ staleReady: shared.paths.statePresent, staleRuntimeHealth: { status: 'healthy' } }),
        formatStatus: () => 'Host status',
      },
    },
    doctor: {
      ...common,
      lifecycle: {
        buildChecks: () => ({ existingHealthyInput: true }),
        healthy: (checks: Record<string, unknown>) => checks.existingHealthyInput === true,
        formatDoctor: () => 'Doctor status',
      },
    },
  };
}

describe('Host-domain reset status and doctor evidence', () => {
  test.each(['default', 'dev'] as const)('%s status reports every phase in JSON and human output', async (profileId) => {
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      const value = dependencies(profileId, phase);
      const result = await runStatusCommand([], value.status);
      expect(result.envelope.data).toMatchObject({ hostDomainReset: { pending: true, phase } });
      expect(result.human).toContain(phase);
      expect(result.human).toContain(profileId === 'dev' ? 'bun run dev:cli -- identity reset --confirm' : 'ariava identity reset --confirm');
      expect(JSON.stringify(result)).not.toMatch(/secret|identity\.json|host-domain-reset\.json/i);
    }
  });

  test.each(['default', 'dev'] as const)('%s doctor keeps aggregate semantics while reporting pending reset', async (profileId) => {
    const value = dependencies(profileId, 'service-restore-pending');
    const result = await runDoctorCommand([], value.doctor);
    expect(result).toMatchObject({ envelope: { ok: true, code: 'ok', data: { hostDomainReset: { pending: true, phase: 'service-restore-pending' } } }, exitCode: 0 });
    expect(result.human).toContain('service-restore-pending');
    expect(result.human).toContain(profileId === 'dev' ? 'bun run dev:cli -- identity reset --confirm' : 'ariava identity reset --confirm');
  });
});
