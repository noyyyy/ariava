import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeDaemon, loadBridgeConfig } from '../src/daemon';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { HOST_DOMAIN_RESET_PHASES, loadHostDomainResetJournal } from '../src/cli/operations/host-domain-reset-journal';
import {
  buildJournal,
  removeJournalFixture,
  writeJournalFixture,
} from './helpers/host-domain-reset-journal-fixture';
import { LinuxJsonHostIdentityStore, publicIdentityMetadata } from '../src/identity';

const roots: string[] = [];
const originalHome = process.env.HOME;
const originalXdg = process.env.XDG_CONFIG_HOME;

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME; else process.env.HOME = originalHome;
  if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = originalXdg;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function fixture(phase: typeof HOST_DOMAIN_RESET_PHASES[number]) {
  const home = mkdtempSync(join(tmpdir(), 'ariava-daemon-reset-'));
  roots.push(home);
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  const profile = createDefaultProfile();
  const resources = profile.resources;
  mkdirSync(resources.root, { recursive: true, mode: 0o700 });
  const identityStore = new LinuxJsonHostIdentityStore(resources.identityMetadataPath);
  const identity = await identityStore.createFirstRun();
  const configValue = {
    relayBaseUrl: 'http://127.0.0.1:1', hostName: 'reset-daemon',
    statePath: resources.statePath, identityPath: resources.identityMetadataPath,
    agentAdapterConfigPath: resources.agentAdapterConfigPath, agentAdapterPort: 7272,
    agentAdapterSecret: 'a'.repeat(64), identity: publicIdentityMetadata(identity),
  };
  writeFileSync(resources.configPath, JSON.stringify(configValue), { mode: 0o600 });
  writeJournalFixture(resources, buildJournal(resources, phase, {
    oldHostId: ['quarantine-pending', 'quarantined'].includes(phase) ? null : identity.hostId,
    oldKeyId: ['quarantine-pending', 'quarantined'].includes(phase) ? null : identity.keyId,
    service: { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'systemd-user' },
  }));
  const config = loadBridgeConfig(resources.configPath);
  return { resources, identityStore, config };
}

describe('BridgeDaemon Host-domain reset guard', () => {
  test.each(HOST_DOMAIN_RESET_PHASES.filter((phase) => phase !== 'service-restore-pending'))(
    'phase %s refuses before runtime, E2E, adapter, Relay, or driver effects', async (phase) => {
      const value = await fixture(phase);
      let driverEffects = 0;
      expect(() => new BridgeDaemon(value.config, [{ name: 'probe', listSessions: async () => { driverEffects += 1; return []; } }], value.identityStore))
        .toThrow(/reset recovery required/i);
      expect(driverEffects).toBe(0);
      expect(existsSync(value.resources.statePath)).toBe(false);
      expect(existsSync(value.resources.encryptedSpoolPath)).toBe(false);
      expect(existsSync(value.resources.linkKeyringPath)).toBe(false);
      expect(existsSync(value.resources.encryptionIdentityPath)).toBe(false);
      expect(existsSync(value.resources.agentAdapterConfigPath)).toBe(false);
    },
  );

  test('running daemon releases runtime ownership when quarantine intent appears', async () => {
    const value = await fixture('quarantine-pending');
    const pendingJournal = loadHostDomainResetJournal(value.resources)!;
    removeJournalFixture(value.resources);
    const daemon = new BridgeDaemon(value.config, [], value.identityStore);
    expect(existsSync(value.resources.runtimeLockPath)).toBe(true);
    writeJournalFixture(value.resources, pendingJournal);

    await expect(daemon.syncOnce()).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED', phase: 'quarantine-pending',
    });
    expect(existsSync(value.resources.runtimeLockPath)).toBe(false);
    removeJournalFixture(value.resources);
  });

  test('service-restore-pending is allowed through construction without external effects', async () => {
    const value = await fixture('service-restore-pending');
    const daemon = new BridgeDaemon(value.config, [], value.identityStore);
    expect(daemon.driverNames).toEqual([]);
    daemon.stop();
    removeJournalFixture(value.resources);
  });
});
