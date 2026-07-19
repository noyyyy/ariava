import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadInstallMetadata,
  loadInstallMetadataDetailed,
  mergeInstallMetadata,
  saveInstallMetadata,
  type AriavaServiceInstallRecord,
} from '../src/host-manager';
import { AriavaCliError } from '../src/host-manager/service/errors';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function installPath(): string {
  const root = mkdtempSync(join(tmpdir(), 'ariava-service-migration-'));
  chmodSync(root, 0o700);
  roots.push(root);
  return join(root, 'install.json');
}

function writeInstallFixture(path: string, contents: string): void {
  writeFileSync(path, contents, { mode: 0o600 });
  chmodSync(path, 0o600);
}

const bridgeSource = { kind: 'release-bundle' as const, updatedAt: '2026-07-14T00:00:00Z' };
const piSource = { kind: 'dev-repo' as const, path: '/repo/pi', updatedAt: '2026-07-14T01:00:00Z' };
const piExtension = {
  installedAt: '2026-07-14T02:00:00Z',
  version: '0.1.4',
  managedPath: '/home/user/.pi/agent/extensions/ariava-pi',
  source: piSource,
};

const legacyService = {
  installedAt: '2026-07-14T03:00:00Z',
  nodePath: '/opt/homebrew/bin/node',
  ariavaBinPath: '/usr/local/bin/ariava',
  plistPath: '/Users/user/Library/LaunchAgents/io.noyx.ariava.bridge.plist',
  label: 'io.noyx.ariava.bridge',
};

const normalizedLegacyService: AriavaServiceInstallRecord = {
  backend: 'launchd',
  installedAt: legacyService.installedAt,
  runtimePath: legacyService.nodePath,
  ariavaBinPath: legacyService.ariavaBinPath,
  definitionPath: legacyService.plistPath,
  serviceId: legacyService.label,
};

const v2Fields = {
  configPath: '/Users/user/.config/ariava/config.json',
  identityReference: { type: 'macos-keychain' as const, service: 'io.noyx.ariava.host-identity' as const, account: 'host_test' },
};

describe('install metadata migration', () => {
  test('normalizes a complete legacy launchd record in memory without rewriting on read', () => {
    const path = installPath();
    const raw = JSON.stringify({ bridgeSource, service: legacyService }, null, 2);
    writeInstallFixture(path, raw);

    expect(loadInstallMetadata(path)).toEqual({ bridgeSource, service: normalizedLegacyService });
    expect(readFileSync(path, 'utf8')).toBe(raw);
  });

  test('persists only neutral service keys on the next save or merge', () => {
    const savePath = installPath();
    writeInstallFixture(savePath, JSON.stringify({ bridgeSource, service: legacyService }));
    saveInstallMetadata(loadInstallMetadata(savePath), savePath);

    const saved = JSON.parse(readFileSync(savePath, 'utf8'));
    expect(saved.service).toEqual(normalizedLegacyService);
    expect(saved.service.nodePath).toBeUndefined();
    expect(saved.service.plistPath).toBeUndefined();
    expect(saved.service.label).toBeUndefined();

    const mergePath = installPath();
    writeInstallFixture(mergePath, JSON.stringify({ bridgeSource, service: legacyService }));
    mergeInstallMetadata({ piSource }, mergePath);
    const merged = JSON.parse(readFileSync(mergePath, 'utf8'));
    expect(merged.service).toEqual(normalizedLegacyService);
    expect(merged.piSource).toEqual(piSource);
    expect(merged.service.nodePath).toBeUndefined();
    expect(merged.service.plistPath).toBeUndefined();
    expect(merged.service.label).toBeUndefined();
  });

  test('drops only an incomplete legacy service and reports invalid diagnostics', () => {
    const path = installPath();
    writeInstallFixture(path, JSON.stringify({
      bridgeSource,
      piSource,
      piExtension,
      service: { ...legacyService, label: '' },
    }));

    expect(loadInstallMetadataDetailed(path)).toEqual({
      metadata: { bridgeSource, piSource, piExtension },
      diagnostics: { serviceMetadataValid: false, serviceMetadataIssue: 'invalid-service-record' },
    });
  });

  test('drops only malformed new service records and validates backend and non-empty strings', () => {
    const invalidServices = [
      { ...normalizedLegacyService, backend: 'openrc' },
      { ...normalizedLegacyService, runtimePath: '  ' },
      { ...normalizedLegacyService, configPath: '/config.json' },
      { ...normalizedLegacyService, identityReference: v2Fields.identityReference },
      { ...normalizedLegacyService, ...v2Fields, identityReference: { ...v2Fields.identityReference, account: '' } },
      { ...normalizedLegacyService, serviceId: 42 },
      { ...legacyService, backend: 'launchd' },
    ];

    for (const service of invalidServices) {
      const path = installPath();
      writeInstallFixture(path, JSON.stringify({ bridgeSource, piSource, piExtension, service }));
      const result = loadInstallMetadataDetailed(path);
      expect(result.metadata).toEqual({ bridgeSource, piSource, piExtension });
      expect(result.diagnostics).toEqual({
        serviceMetadataValid: false,
        serviceMetadataIssue: 'invalid-service-record',
      });
    }
  });

  test('round-trips valid neutral launchd and systemd records unchanged', () => {
    const records: AriavaServiceInstallRecord[] = [
      normalizedLegacyService,
      {
        backend: 'systemd-user',
        installedAt: '2026-07-14T04:00:00Z',
        runtimePath: '/usr/bin/node',
        ariavaBinPath: '/usr/bin/ariava',
        definitionPath: '/home/user/.config/systemd/user/ariava.service',
        serviceId: 'ariava.service',
      },
    ];

    for (const service of records) {
      const path = installPath();
      saveInstallMetadata({ bridgeSource, service }, path);
      expect(loadInstallMetadataDetailed(path)).toEqual({
        metadata: { bridgeSource, service },
        diagnostics: { serviceMetadataValid: true },
      });
      expect(JSON.parse(readFileSync(path, 'utf8')).service).toEqual(service);
    }
  });

  test('adds runtime metadata for new records while preserving old records without fabricated versions', () => {
    const path = installPath();
    const oldService = normalizedLegacyService;
    saveInstallMetadata({ service: oldService }, path);
    expect(loadInstallMetadata(path).service).toEqual(oldService);

    const currentService = { ...oldService, runtimeName: 'node' as const, runtimeVersion: 'v22.1.0' };
    saveInstallMetadata({ service: currentService }, path);
    expect(loadInstallMetadata(path).service).toEqual(currentService);
  });

  test('round-trips v2 config path, public identity reference, and installer metadata without private material', () => {
    const path = installPath();
    const service = { ...normalizedLegacyService, ...v2Fields };
    const installer = { manager: 'npm' as const, ariavaBinRealPath: '/opt/npm/lib/node_modules/ariava/apps/bridge/dist/public-cli.js', recordedAt: '2026-07-15T10:00:00.000Z' };
    saveInstallMetadata({ service, identityPath: '/public/reference.json', installer }, path);
    expect(loadInstallMetadata(path)).toEqual({ service, identityPath: '/public/reference.json', installer });
    const serialized = readFileSync(path, 'utf8');
    expect(serialized).not.toMatch(/privateKey|pkcs8/i);
  });

  test('fails closed for malformed JSON and non-object roots', () => {
    const malformed = installPath();
    writeInstallFixture(malformed, '{not-json');
    expect(() => loadInstallMetadataDetailed(malformed)).toThrow();
    for (const raw of ['null', '[]', '"bad"']) {
      const path = installPath();
      writeInstallFixture(path, raw);
      expect(() => loadInstallMetadata(path)).toThrow(AriavaCliError);
      expect(readFileSync(path, 'utf8')).toBe(raw);
    }
  });

  test('fails closed for invalid service and installer metadata without rewriting bytes', () => {
    for (const value of [
      { service: { backend: 'systemd-user' }, bridgeSource },
      { installer: { manager: 'npm', ariavaBinRealPath: 'relative/bin', recordedAt: '2026-07-15T10:00:00.000Z' }, bridgeSource },
      { installer: { manager: 'npm', ariavaBinRealPath: '/absolute/bin', recordedAt: 'not-a-time' }, bridgeSource },
    ]) {
      const path = installPath();
      const raw = JSON.stringify(value);
      writeInstallFixture(path, raw);
      expect(() => loadInstallMetadata(path)).toThrow(AriavaCliError);
      try { loadInstallMetadata(path); } catch (error) {
        expect((error as AriavaCliError).code).toBe('ERR_SERVICE_METADATA');
      }
      expect(readFileSync(path, 'utf8')).toBe(raw);
    }
  });

  test('fails closed for invalid identity and source records without rewriting bytes', () => {
    for (const value of [
      { identityPath: 'relative/identity.json' },
      { bridgeSource: { kind: 'dev-repo', path: 'relative/repo', updatedAt: 'now' } },
      { piExtension: { installedAt: 'now', version: '1', managedPath: 'relative/pi', source: piSource } },
    ]) {
      const path = installPath();
      const raw = JSON.stringify(value);
      writeInstallFixture(path, raw);
      expect(() => loadInstallMetadata(path)).toThrow(AriavaCliError);
      expect(readFileSync(path, 'utf8')).toBe(raw);
    }
  });
});
