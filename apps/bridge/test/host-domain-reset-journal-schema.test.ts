import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ProfileResourceSet } from '../src/cli/profile';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import {
  HOST_DOMAIN_RESET_JOURNAL_VERSION,
  HOST_DOMAIN_RESET_PHASES,
  encodeHostDomainResetJournal,
  hostDomainResourceDigest,
  identityResourceDigest,
  parseHostDomainResetJournal,
  type HostDomainResetJournalV1,
} from '../src/cli/operations/host-domain-reset-journal-schema';

const roots: string[] = [];

function temporaryHome(): string {
  const root = mkdtempSync(join(tmpdir(), 'ariava-host-reset-journal-schema-'));
  roots.push(root);
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function resourcesFor(profileId: 'default' | 'dev'): ProfileResourceSet {
  const home = temporaryHome();
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  try {
    const profile = profileId === 'default' ? createDefaultProfile() : createDevProfile();
    mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
    return profile.resources;
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousXdg;
  }
}

function journalFor(
  resources: ProfileResourceSet,
  patch: Partial<HostDomainResetJournalV1> = {},
): HostDomainResetJournalV1 {
  return {
    version: HOST_DOMAIN_RESET_JOURNAL_VERSION,
    operationId: 'reset_0123456789abcdef',
    profile: resources.identityProfile,
    phase: 'prepared',
    oldHostId: `host_${'A'.repeat(43)}`,
    oldKeyId: `key_${'B'.repeat(43)}`,
    newHostId: null,
    newKeyId: null,
    oldEncryptionKeyId: `ekey_${'C'.repeat(43)}`,
    signingCleanup: null,
    signingReplacementAttemptedAt: null,
    encryptionIdentityReplacedAt: null,
    runtimeArtifactsClearedAt: null,
    configSavedAt: null,
    enrolledAt: null,
    serviceMetadataSynchronizedAt: null,
    resourceDigest: hostDomainResourceDigest(resources),
    createdAt: '2026-08-11T00:00:00.000Z',
    updatedAt: '2026-08-11T00:00:00.000Z',
    revoke: { state: 'not-attempted', outcome: null },
    service: {
      managed: resources.identityProfile === 'default',
      installed: false,
      enabled: false,
      wasRunning: false,
      backend: resources.identityProfile === 'default' ? 'launchd' : 'none',
    },
    ...patch,
  };
}

describe('Host-domain reset journal schema/codec', () => {
  test('exact-decodes a complete v1 journal into an equal clone', () => {
    const resources = resourcesFor('default');
    const journal = journalFor(resources);

    const decoded = parseHostDomainResetJournal(journal, resources);

    expect(decoded).toEqual(journal);
    expect(decoded).not.toBe(journal);
  });

  test('rejects unknown top-level keys', () => {
    const resources = resourcesFor('default');
    const journal = journalFor(resources) as unknown as Record<string, unknown>;

    journal.unknownField = 'intruder';

    expect(() => parseHostDomainResetJournal(journal, resources)).toThrow(TypeError);
  });

  test('rejects missing required keys', () => {
    const resources = resourcesFor('default');
    const journal = journalFor(resources) as unknown as Record<string, unknown>;

    delete journal.service;

    expect(() => parseHostDomainResetJournal(journal, resources)).toThrow(TypeError);
  });

  test('rejects wrong version and unknown phase values', () => {
    const resources = resourcesFor('default');

    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { version: 2 as 1 }), resources,
    )).toThrow(TypeError);
    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { phase: 'completed' as never }), resources,
    )).toThrow(TypeError);
  });

  test('rejects malformed operation/Host/key/digest/timestamp values', () => {
    const resources = resourcesFor('default');

    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { operationId: 'bad operation id!' }), resources,
    )).toThrow(TypeError);
    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { oldHostId: 'not-a-host-id' }), resources,
    )).toThrow(TypeError);
    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { oldEncryptionKeyId: 'not-an-ekey' }), resources,
    )).toThrow(TypeError);
    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { resourceDigest: 'abc123' }), resources,
    )).toThrow(TypeError);
    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { createdAt: 'not-a-timestamp' }), resources,
    )).toThrow(TypeError);
    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { updatedAt: '2026-08-10T00:00:00.000Z' }), resources,
    )).toThrow(TypeError);
  });

  test('rejects a profile field that does not match the selected profile resources', () => {
    const resources = resourcesFor('default');
    const devResources = resourcesFor('dev');

    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { profile: devResources.identityProfile }), resources,
    )).toThrow(TypeError);
  });

  test('rejects malformed revoke and service shapes', () => {
    const resources = resourcesFor('default');

    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { revoke: { state: 'complete', outcome: null } }), resources,
    )).toThrow(TypeError);
    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { service: { managed: false, installed: false, enabled: false, wasRunning: false, backend: 'launchd' } }), resources,
    )).toThrow(TypeError);
  });

  test('rejects an out-of-profile managed service for the dev profile', () => {
    const resources = resourcesFor('dev');

    expect(() => parseHostDomainResetJournal(
      journalFor(resources, { service: { managed: true, installed: false, enabled: false, wasRunning: false, backend: 'launchd' } }), resources,
    )).toThrow(TypeError);
  });

  test('rejects journals that violate phase invariants', () => {
    const resources = resourcesFor('default');

    expect(() => parseHostDomainResetJournal(
      journalFor(resources, {
        phase: 'revoke-pending',
        oldHostId: null,
        oldKeyId: null,
        revoke: { state: 'pending', outcome: null },
      }), resources,
    )).toThrow(TypeError);
    expect(() => parseHostDomainResetJournal(
      journalFor(resources, {
        phase: 'signing-identity-replaced',
        newHostId: `host_${'D'.repeat(43)}`,
        newKeyId: `key_${'E'.repeat(43)}`,
        signingReplacementAttemptedAt: null,
        revoke: { state: 'complete', outcome: 'revoked' },
        updatedAt: '2026-08-11T00:00:01.000Z',
      }), resources,
    )).toThrow(TypeError);
  });

  test('still decodes historical schema-valid nondecreasing v1 bytes at a late phase', () => {
    const resources = resourcesFor('default');
    const journal = journalFor(resources, {
      phase: 'service-metadata-synchronized',
      newHostId: `host_${'D'.repeat(43)}`,
      newKeyId: `key_${'E'.repeat(43)}`,
      signingReplacementAttemptedAt: '2026-08-11T00:00:01.000Z',
      encryptionIdentityReplacedAt: '2026-08-11T00:00:02.000Z',
      runtimeArtifactsClearedAt: '2026-08-11T00:00:03.000Z',
      configSavedAt: '2026-08-11T00:00:03.500Z',
      enrolledAt: '2026-08-11T00:00:04.000Z',
      serviceMetadataSynchronizedAt: '2026-08-11T00:00:04.500Z',
      revoke: { state: 'complete', outcome: 'revoked' },
      updatedAt: '2026-08-11T00:00:05.000Z',
    });

    const decoded = parseHostDomainResetJournal(journal, resources);

    expect(decoded.phase).toBe('service-metadata-synchronized');
    expect(decoded).toEqual(journal);
  });

  test('encodes the exact canonical v1 byte shape the writer produces', () => {
    const resources = resourcesFor('default');
    const journal = journalFor(resources);

    const encoded = encodeHostDomainResetJournal(journal, resources);

    expect(encoded).toBe(`${JSON.stringify(parseHostDomainResetJournal(journal, resources), null, 2)}\n`);
    expect(encoded.endsWith('\n')).toBe(true);
  });

  test('encode is canonical and round-trips through decode', () => {
    const resources = resourcesFor('default');
    const journal = journalFor(resources, {
      phase: 'signing-identity-replaced',
      newHostId: `host_${'D'.repeat(43)}`,
      newKeyId: `key_${'E'.repeat(43)}`,
      signingReplacementAttemptedAt: '2026-08-11T00:00:01.000Z',
      revoke: { state: 'complete', outcome: 'revoked' },
      updatedAt: '2026-08-11T00:00:01.000Z',
    });

    const encoded = encodeHostDomainResetJournal(journal, resources);
    const decoded = parseHostDomainResetJournal(JSON.parse(encoded), resources);

    expect(decoded).toEqual(journal);
    expect(encodeHostDomainResetJournal(decoded, resources)).toBe(encoded);
  });

  test('rejects encoding an invalid journal', () => {
    const resources = resourcesFor('default');
    const journal = journalFor(resources) as unknown as HostDomainResetJournalV1;

    (journal as unknown as Record<string, unknown>).unknownField = 'intruder';

    expect(() => encodeHostDomainResetJournal(journal, resources)).toThrow(TypeError);
  });

  test('decodes the recognized unreadable signing-cleanup evidence path', () => {
    const resources = resourcesFor('dev');
    const journal = journalFor(resources, {
      oldHostId: null,
      oldKeyId: null,
      oldEncryptionKeyId: null,
      signingCleanup: {
        kind: 'linux-json',
        resourceDigest: identityResourceDigest(resources.identityMetadataPath),
        profile: resources.identityProfile,
        previousAccount: null,
        previousPendingAccount: null,
        interruptedCreationAccount: null,
      },
      revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
    });

    const decoded = parseHostDomainResetJournal(journal, resources);

    expect(decoded.revoke).toEqual({ state: 'skipped', outcome: 'old-identity-unreadable' });
    expect(decoded.signingCleanup?.kind).toBe('linux-json');
  });
});
