import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeDaemon, loadBridgeConfig } from '../src/daemon';
import { createDefaultProfile } from '../src/cli/profiles/default';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
  hostDomainResourceDigest,
  loadHostDomainResetJournal,
} from '../src/cli/operations/host-domain-reset-journal';
import { removeJournalFixture, writeJournalFixture } from './fixtures/host-domain-reset-journal-fixtures';
import { LinuxJsonHostIdentityStore, publicIdentityMetadata } from '../src/identity';

const roots: string[] = [];
const originalHome = process.env.HOME;
const originalXdg = process.env.XDG_CONFIG_HOME;

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME; else process.env.HOME = originalHome;
  if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = originalXdg;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function phaseAtLeast(
  phase: typeof HOST_DOMAIN_RESET_PHASES[number], required: typeof HOST_DOMAIN_RESET_PHASES[number],
): boolean {
  return HOST_DOMAIN_RESET_PHASES.indexOf(phase) >= HOST_DOMAIN_RESET_PHASES.indexOf(required);
}

function phaseTimestamp(
  phase: typeof HOST_DOMAIN_RESET_PHASES[number], required: typeof HOST_DOMAIN_RESET_PHASES[number],
): string | null {
  return phaseAtLeast(phase, required) ? '2026-08-11T00:00:00.000Z' : null;
}


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
  writeJournalFixture(resources, {
    version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
    operationId: 'reset_0123456789abcdef', profile: 'default', phase,
    oldHostId: ['quarantine-pending', 'quarantined'].includes(phase) ? null : identity.hostId,
    oldKeyId: ['quarantine-pending', 'quarantined'].includes(phase) ? null : identity.keyId,
    newHostId: phaseAtLeast(phase, 'signing-identity-replaced') ? `host_${'C'.repeat(43)}` : null,
    newKeyId: phaseAtLeast(phase, 'signing-identity-replaced') ? `key_${'D'.repeat(43)}` : null,
    oldEncryptionKeyId: null,
    signingCleanup: null,
    signingReplacementAttemptedAt: phaseTimestamp(phase, 'signing-replacement-pending'),
    encryptionIdentityReplacedAt: phaseTimestamp(phase, 'encryption-identity-replaced'),
    runtimeArtifactsClearedAt: phaseTimestamp(phase, 'runtime-artifacts-cleared'),
    configSavedAt: phaseTimestamp(phase, 'config-saved'),
    enrolledAt: phaseTimestamp(phase, 'enrolled'),
    serviceMetadataSynchronizedAt: phaseTimestamp(phase, 'service-metadata-synchronized'),
    resourceDigest: hostDomainResourceDigest(resources),
    createdAt: '2026-08-11T00:00:00.000Z', updatedAt: '2026-08-11T00:00:00.000Z',
    revoke: phase === 'quarantine-pending' || phase === 'quarantined' || phase === 'prepared'
      ? { state: 'not-attempted', outcome: null }
      : phase === 'revoke-pending' ? { state: 'pending', outcome: null }
        : { state: 'complete', outcome: 'revoked' },
    service: { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'systemd-user' },
  });
  const config = loadBridgeConfig(resources.configPath);
  return { resources, identityStore, config };
}

describe('BridgeDaemon Host-domain reset guard', () => {
  test.each(HOST_DOMAIN_RESET_PHASES)(
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

});
