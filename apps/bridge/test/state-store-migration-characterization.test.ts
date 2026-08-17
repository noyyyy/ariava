import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spoolPathForState } from '../src/e2e/local-spool';
import {
  migrateSpoolV3ToV4,
  migrateStateV3ToV4,
  parseCurrentState,
} from '../src/state-store/state-codec';
import {
  beginRuntimeMigration,
  resumeRuntimeMigration,
  runtimeMigrationIntentPathForState,
  runtimeSchemaFloorPathForState,
} from '../src/state-store/runtime-reset';

/**
 * Phase 0 characterization of the unpublished RuntimeMigrationIntentV1 3→4
 * writer (spec 08-16 §9.2, plan Task 00.2). These tests freeze the APPROVED
 * preserve/discard table against the exact writer implementation. They are a
 * characterization of the existing target-to-extend writer; they add NO
 * schema 5 and NO second migration intent.
 *
 * Frozen table:
 *  preserve: Host/Session source fields, sessionRevisions, recipientSetVersion,
 *            out-of-runtime identity/E2E/link/receipt/outbox/nonce
 *  discard unconditionally: entire schema3 spool items (all *-v2 kinds),
 *            recentEvents, pendingHandles, commandExecutions; omit
 *            eventUploadCompletions/producerEventReservations/
 *            terminalCancellations/commandResults/seenCommands; zero accepted
 *            snapshot to { version:1, lastAllocatedRevision:
 *            max(alloc,accepted), lastAcceptedRevision:0 }
 *  remap later (Phase 3): proven sessionDrivers='pi' → 'agent-adapter';
 *            never forge instance/lease.
 */

const V3_AT = '2026-08-07T00:00:00.000Z';
const V3_EPOCH = '12345678-1234-4123-8123-123456789abc';

const paths: string[] = [];

afterEach(() => {
  for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true });
});

/** Base64url nonce/ciphertext with the exact decoded lengths the codec requires. */
function spoolNonce(): string {
  return Buffer.alloc(12, 1).toString('base64url');
}
function spoolCiphertext(): string {
  return Buffer.alloc(20, 2).toString('base64url');
}

interface V2SpoolItem {
  version: 1;
  spoolItemId: string;
  hostId: string;
  sessionId: string;
  payloadKind: string;
  nonce: string;
  ciphertext: string;
  aadVersion: 1;
  createdAt: string;
  eventId?: string;
}

function v2Item(payloadKind: string, spoolItemId: string, eventId?: string): V2SpoolItem {
  return {
    version: 1, spoolItemId, hostId: 'host-1', sessionId: 'sess-1', payloadKind,
    nonce: spoolNonce(), ciphertext: spoolCiphertext(), aadVersion: 1, createdAt: V3_AT,
    ...(eventId === undefined ? {} : { eventId }),
  };
}

/** Every *-v2 kind that a production schema-3 spool can hold (spec §9.2 item 6). */
function v3SpoolFixture(): Record<string, unknown> {
  return {
    version: 2,
    runtimeStateSchemaVersion: 3,
    runtimeResetEpoch: V3_EPOCH,
    hostId: 'host-1',
    keyId: 'K'.repeat(43),
    items: [
      v2Item('event-source-v2', 'evt-1', 'evt-1'),
      v2Item('event-reservation-v2', 'evt-1', 'evt-1'),
      v2Item('event-dead-letter-v2', 'dead-letter:event:evt-2', 'evt-2'),
      v2Item('session-source-v2', 'sess-1'),
      v2Item('event-upload-v2', 'inflight:event:evt-3', 'evt-3'),
      v2Item('session-upload-v2', 'inflight:session:sess-1'),
      v2Item('terminal-cancellation-v2', 'cancel:terminal:evt-4', 'evt-4'),
    ],
  };
}

/** Production schema-3 runtime state with every preserved and discarded family populated. */
function v3StateFixture(): Record<string, unknown> {
  const session = {
    sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Task',
    status: 'idle', updatedAt: V3_AT, lastEventId: 'evt-1',
  };
  const event = {
    eventId: 'evt-1', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
    agentText: 'done', createdAt: V3_AT,
  };
  return {
    schemaVersion: 3,
    runtimeResetEpoch: V3_EPOCH,
    host: null,
    sessions: { 'sess-1': session },
    sessionDrivers: { 'sess-1': 'pi' },
    reconciledDrivers: { pi: true },
    recentEvents: [event],
    sessionRevisions: { 'sess-1': 6 },
    pendingHandles: {
      'host-1:sess-1': {
        hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-1',
        handledAt: V3_AT, action: 'pi_input', updatedAt: V3_AT,
      },
    },
    commandResults: {
      'command-1': { commandId: 'command-1', hostId: 'host-1', sessionId: 'sess-1',
        accepted: true, status: 'executed', message: 'done', updatedAt: V3_AT },
    },
    seenCommands: { 'command-1': V3_AT },
    currentSessionsSnapshot: {
      version: 1, lastAllocatedRevision: 9, lastAcceptedRevision: 8,
      lastAcceptedDigest: 'digest', lastAcceptedContentDigest: 'content', lastAcceptedRecipientSetVersion: 2,
    },
    recipientSetVersion: 2,
    eventUploadCompletions: {
      'evt-1': { version: 1, eventId: 'evt-1', sessionId: 'sess-1', revision: 6,
        eventContentId: 'e-content', sessionContentId: 's-content', committedAt: V3_AT },
    },
    producerEventReservations: {
      'sess-1\nev-fingerprint': { version: 1, eventId: 'evt-1', sessionId: 'sess-1',
        fingerprint: 'ev-fingerprint', createdAt: V3_AT },
    },
    terminalCancellations: {},
    runtimeHealth: { status: 'healthy', drivers: [] },
  };
}

describe('Phase 0 schema3→4 V1 writer characterization (Task 00.2)', () => {
  test('fixtures are exact recognized schema-3 inputs for the writer', () => {
    const state = v3StateFixture();
    const spool = v3SpoolFixture();
    // The writer itself rejects anything that is not exact schema 3; a valid
    // migration run proves the fixture is recognized.
    const migratedState = migrateStateV3ToV4(state, 'host-1');
    const migratedSpool = migrateSpoolV3ToV4(spool, 'host-1', V3_EPOCH);
    expect(migratedState.schemaVersion).toBe(4);
    expect(migratedSpool.runtimeStateSchemaVersion).toBe(4);
  });

  test('preserves Host/Session source fields, sessionRevisions, recipientSetVersion, runtimeHealth', () => {
    const migrated = migrateStateV3ToV4(v3StateFixture(), 'host-1');
    expect(migrated.host).toBeNull();
    expect(migrated.runtimeResetEpoch).toBe(V3_EPOCH);
    expect(migrated.sessions).toEqual({
      'sess-1': {
        sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Task',
        status: 'idle', updatedAt: V3_AT,
      },
    });
    // Canonical source `provider` is preserved for the producer identity; the
    // driver map is remapped 'pi' → 'agent-adapter' (Phase 3 cutover).
    expect(migrated.sessionDrivers).toEqual({ 'sess-1': 'agent-adapter' });
    expect(migrated.reconciledDrivers).toEqual({ pi: true });
    expect(migrated.sessionRevisions).toEqual({ 'sess-1': 6 });
    expect(migrated.recipientSetVersion).toBe(2);
    expect(migrated.runtimeHealth).toEqual({ status: 'healthy', drivers: [] });
  });

  test('discards unconditionally: spool items, recentEvents, pendingHandles, commandExecutions (omit lists too)', () => {
    const migrated = migrateStateV3ToV4(v3StateFixture(), 'host-1');
    expect(migrated.recentEvents).toEqual([]);
    expect(migrated.pendingHandles).toEqual({});
    expect(migrated.commandExecutions).toEqual({});
    // Schema-3 command journal and runtime Event/upload state are omitted, not
    // emptied: their presence would be an unknown key at schema 4.
    expect('commandResults' in migrated).toBe(false);
    expect('seenCommands' in migrated).toBe(false);
    expect('eventUploadCompletions' in migrated).toBe(false);
    expect('producerEventReservations' in migrated).toBe(false);
    expect('terminalCancellations' in migrated).toBe(false);
    // Legacy Session-only cursor field is not a schema-4 source field.
    const session = migrated.sessions['sess-1'] as Record<string, unknown>;
    expect('lastEventId' in session).toBe(false);
  });

  test('zeroes the accepted snapshot to max(allocated, accepted) allocator with accepted=0', () => {
    const migrated = migrateStateV3ToV4(v3StateFixture(), 'host-1');
    expect(migrated.currentSessionsSnapshot).toEqual({
      version: 1,
      lastAllocatedRevision: 9, // max(9, 8)
      lastAcceptedRevision: 0,
    });
    // Accepted cursor with a larger allocator than accepted.
    const source = v3StateFixture();
    (source.currentSessionsSnapshot as Record<string, unknown>).lastAllocatedRevision = 5;
    (source.currentSessionsSnapshot as Record<string, unknown>).lastAcceptedRevision = 7;
    const second = migrateStateV3ToV4(source, 'host-1');
    expect(second.currentSessionsSnapshot).toEqual({
      version: 1,
      lastAllocatedRevision: 7, // max(5, 7)
      lastAcceptedRevision: 0,
    });
  });

  test('discards the entire schema-3 spool items (all *-v2 kinds) without decoding or re-publishing', () => {
    const migrated = migrateSpoolV3ToV4(v3SpoolFixture(), 'host-1', V3_EPOCH);
    expect(migrated.items).toEqual([]);
    expect(migrated.version).toBe(2);
    expect(migrated.keyId).toBe('K'.repeat(43));
    expect(migrated.hostId).toBe('host-1');
    expect(migrated.runtimeResetEpoch).toBe(V3_EPOCH);
    expect(migrated.runtimeStateSchemaVersion).toBe(4);
  });

  test('remapped agent-adapter driver binds to the canonical pi provider and loads; unknown drivers still fail closed', () => {
    const migrated = migrateStateV3ToV4(v3StateFixture(), 'host-1');
    // The remapped driver loads at schema 4 because the codec binds only the
    // canonical provider to the producer and allows the agent-adapter driver
    // as the sole driver-side identity.
    expect(migrated.sessionDrivers).toEqual({ 'sess-1': 'agent-adapter' });
    expect(() => parseCurrentState(structuredClone(migrated), 'host-1')).not.toThrow();
    // A truly unknown driver value is still rejected fail-closed.
    const unknown = structuredClone(migrated) as unknown as Record<string, unknown>;
    (unknown.sessionDrivers as Record<string, string>)['sess-1'] = 'mystery-driver';
    expect(() => parseCurrentState(unknown, 'host-1'))
      .toThrow('Bridge runtime Session driver binding is invalid');
    const absent = structuredClone(migrated) as unknown as Record<string, unknown>;
    delete (absent.sessionDrivers as Record<string, string>)['sess-1'];
    // Missing sessionDrivers[sessionId] remains loadable: a persisted Session
    // without a live owner is still valid runtime state.
    expect(() => parseCurrentState(absent, 'host-1')).not.toThrow();
  });

  test('V1 writer intent machine: begin → crash after intent → resume completes deterministically (no schema 5)', () => {
    const root = join(tmpdir(), `phase0-v1-writer-${Date.now()}`);
    paths.push(root);
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const statePath = join(root, 'state.json');
    const spoolPath = spoolPathForState(statePath);
    const state = v3StateFixture();
    const spool = v3SpoolFixture();
    writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    writeFileSync(spoolPath, `${JSON.stringify(spool, null, 2)}\n`, { mode: 0o600 });
    const stateSourceBytes = readFileSync(statePath);
    const spoolSourceBytes = readFileSync(spoolPath);

    // Crash after the exclusive intent write and before any composite member
    // (spool/state/floor) is committed. resetStep('after-intent') is the
    // writer's published boundary; afterDirectorySync of the spool path is
    // too late (the spool file is already promoted).
    expect(() => beginRuntimeMigration(
      { filePath: statePath }, 'host-1', state, spool, stateSourceBytes, spoolSourceBytes,
      (phase) => { if (phase === 'after-intent') throw new Error('crash-injected'); },
    )).toThrow('crash-injected');

    // Intent is durable; source members are still exact schema 3.
    expect(existsSync(runtimeMigrationIntentPathForState(statePath))).toBe(true);
    expect((JSON.parse(readFileSync(statePath, 'utf8')) as { schemaVersion: number }).schemaVersion).toBe(3);
    expect((JSON.parse(readFileSync(spoolPath, 'utf8')) as { runtimeStateSchemaVersion: number }).runtimeStateSchemaVersion).toBe(3);

    // Restart-safe resume completes the same composite commit: spool → state →
    // floor → cleanup, deleting the intent last.
    const resumed = resumeRuntimeMigration({ filePath: statePath }, 'host-1');
    expect((resumed as { schemaVersion: number }).schemaVersion).toBe(4);
    expect((JSON.parse(readFileSync(statePath, 'utf8')) as { schemaVersion: number }).schemaVersion).toBe(4);
    expect((JSON.parse(readFileSync(spoolPath, 'utf8')) as { runtimeStateSchemaVersion: number }).runtimeStateSchemaVersion).toBe(4);
    expect((JSON.parse(readFileSync(runtimeSchemaFloorPathForState(statePath), 'utf8')) as { minSchemaVersion: number }).minSchemaVersion).toBe(4);
    expect(existsSync(runtimeMigrationIntentPathForState(statePath))).toBe(false);
    // No schema-4 leftover runtime Event/command state and no schema-5 artifacts.
    const finalState = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>;
    expect(finalState.recentEvents).toEqual([]);
    expect((finalState.sessions as Record<string, Record<string, unknown>>)['sess-1']?.provider).toBe('pi');
  });
});