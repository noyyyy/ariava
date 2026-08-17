import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { isCanonicalTimestamp } from '@ariava/protocol';
import type { BridgeRuntimeHealth, PersistedBridgeState } from '../types';
import {
  pathHasFilesystemEvidence,
  readSecureJson,
  removeSecureFile,
  writeSecureJson,
  writeSecureJsonExclusive,
  type SecureFileRemoveHooks,
  type SecureFileWriteHooks,
} from '../host-manager/secure-files';
import {
  spoolKeyIdForKey,
  spoolPathForState,
  type LocalSpoolFileV2,
  type SpoolKeyStore,
} from '../e2e/local-spool';
import {
  ABSENT_HASH,
  hashOptional,
  isRuntimeHash,
  parseRawJson,
  readOptionalSecureBytes,
  serializeSecureJson,
} from './state-persistence';
import {
  BRIDGE_RUNTIME_STATE_SCHEMA_VERSION,
  LEGACY_RUNTIME_STATE_SCHEMA_VERSION,
  OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION,
  PRIOR_RUNTIME_STATE_SCHEMA_VERSION,
  assertCurrentRuntimeRelationships,
  emptyState,
  hasExactKeys,
  hasResetSourceRelationships,
  hashBytes,
  isNonEmptyString,
  isObsoleteStateRecord,
  isPriorStateRecordV3,
  isRecognizedPriorSpoolRecord,
  isRecognizedPriorStateRecord,
  isRecord,
  isRuntimeEpoch,
  isSpoolRecordForSchema,
  isVerifier,
  migrateSpoolV3ToV4,
  migrateStateV3ToV4,
  parseCurrentSpoolRecord,
  parseCurrentState,
} from './state-codec';

const RESET_INTENT_VERSION = 1 as const;
const MIGRATION_INTENT_VERSION = 1 as const;

interface RuntimeResetIntentV1 {
  version: 1;
  fromSchemaVersion: 1 | 2;
  toSchemaVersion: 2 | 3;
  hostId: string;
  epoch: string;
  keyId: string;
  statePath: string;
  spoolPath: string;
  intentPath: string;
  stateSourceHash: string;
  spoolSourceHash: string;
  stateTargetHash: string;
  spoolTargetHash: string;
  createdAt: string;
}

interface RuntimeSchemaFloorV1 {
  version: 1;
  hostId: string;
  minSchemaVersion: 4;
  statePath: string;
  spoolPath: string;
}

interface RuntimeMigrationIntentV1 {
  version: 1;
  fromSchemaVersion: 3;
  toSchemaVersion: 4;
  hostId: string;
  statePath: string;
  spoolPath: string;
  floorPath: string;
  intentPath: string;
  stateSourceHash: string;
  spoolSourceHash: string;
  floorSourceHash: string;
  stateTargetHash: string;
  spoolTargetHash: string;
  floorTargetHash: string;
  stateTarget: PersistedBridgeState;
  spoolTarget: LocalSpoolFileV2;
  floorTarget: RuntimeSchemaFloorV1;
  createdAt: string;
}

export type RuntimeResetPhase = 'before-intent' | 'after-intent' | 'after-spool' | 'after-state' | 'after-cleanup';

/**
 * Minimal imperative surface the reset/migration workflows need from the
 * lifecycle shell (spec §6.3 pattern). Reset/migration intents are path-bound
 * durable-authority workflows; they never touch in-memory runtime state.
 */
export interface RuntimeResetShell {
  /** Canonical state file path the intents are bound to. */
  readonly filePath: string;
}

export function runtimeResetIntentPathForState(statePath: string): string {
  return `${statePath}.runtime-reset.json`;
}

export function runtimeMigrationIntentPathForState(statePath: string): string {
  return `${statePath}.runtime-migration.json`;
}

export function runtimeSchemaFloorPathForState(statePath: string): string {
  return `${statePath}.schema-floor.json`;
}

export function readCurrentRuntimeHealth(statePath: string): BridgeRuntimeHealth | undefined {
  if (!pathHasFilesystemEvidence(statePath)) return undefined;
  try {
    const state = parseCurrentState(readSecureJson<unknown>(statePath));
    return state.runtimeHealth ? structuredClone(state.runtimeHealth) : { status: 'healthy', drivers: [] };
  } catch { return undefined; }
}

export function assertCurrentRuntimeArtifacts(statePath: string, hostId: string): void {
  const state = parseCurrentState(readSecureJson<unknown>(statePath), hostId);
  const spool = parseCurrentSpoolRecord(
    readSecureJson<Record<string, unknown>>(spoolPathForState(statePath)), hostId, state.runtimeResetEpoch,
  );
  assertCurrentRuntimeRelationships(state, spool, hostId);
}

function parseResetIntent(value: unknown): RuntimeResetIntentV1 {
  if (!isRecord(value) || !hasExactKeys(value, [
    'version', 'fromSchemaVersion', 'toSchemaVersion', 'hostId', 'epoch', 'keyId', 'statePath', 'spoolPath',
    'intentPath', 'stateSourceHash', 'spoolSourceHash', 'stateTargetHash', 'spoolTargetHash', 'createdAt',
  ]) || value.version !== RESET_INTENT_VERSION || !isValidResetTransition(value.fromSchemaVersion, value.toSchemaVersion)
    || !isNonEmptyString(value.hostId)
    || !isRuntimeEpoch(value.epoch) || !isVerifier(value.keyId)
    || !isAbsoluteResolvedPath(value.statePath) || !isAbsoluteResolvedPath(value.spoolPath)
    || !isAbsoluteResolvedPath(value.intentPath)
    || !isRuntimeHash(value.stateSourceHash) || !isRuntimeHash(value.spoolSourceHash)
    || !isRuntimeHash(value.stateTargetHash) || !isRuntimeHash(value.spoolTargetHash)
    || !isNonEmptyString(value.createdAt) || !Number.isFinite(Date.parse(value.createdAt))) {
    throw new Error('Bridge runtime reset intent is invalid');
  }
  return value as unknown as RuntimeResetIntentV1;
}

function isValidResetTransition(from: unknown, to: unknown): boolean {
  return (from === LEGACY_RUNTIME_STATE_SCHEMA_VERSION && to === OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION)
    || (from === OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION && to === PRIOR_RUNTIME_STATE_SCHEMA_VERSION);
}

function emptyStateForSchema(schemaVersion: 2 | 3, epoch: string): Record<string, unknown> {
  const { commandExecutions: _commandExecutions, ...state } = emptyState(epoch);
  return { ...state, schemaVersion, commandResults: {}, seenCommands: {} };
}

function spoolFileForSchema(schemaVersion: 2 | 3, hostId: string, epoch: string, keyId: string): LocalSpoolFileV2 {
  return { version: 2, runtimeStateSchemaVersion: schemaVersion, runtimeResetEpoch: epoch, hostId, keyId, items: [] };
}

function assertResetIntentPaths(intent: RuntimeResetIntentV1, statePath: string): void {
  const expectedStatePath = resolve(statePath);
  if (intent.statePath !== expectedStatePath || intent.spoolPath !== resolve(spoolPathForState(expectedStatePath))
    || intent.intentPath !== resolve(runtimeResetIntentPathForState(expectedStatePath))) {
    throw new Error('Bridge runtime reset intent path binding is invalid');
  }
}

function assertRuntimeResetTargets(
  intent: RuntimeResetIntentV1, stateTarget: Record<string, unknown>, spoolTarget: LocalSpoolFileV2,
 ): void {
  if (hashBytes(serializeSecureJson(stateTarget)) !== intent.stateTargetHash
    || hashBytes(serializeSecureJson(spoolTarget)) !== intent.spoolTargetHash) {
    throw new Error('Bridge runtime reset intent target hash is invalid');
  }
  if (intent.toSchemaVersion === PRIOR_RUNTIME_STATE_SCHEMA_VERSION) {
    if (!isPriorStateRecordV3(stateTarget, intent.hostId) || !isSpoolRecordForSchema(
      spoolTarget as unknown as Record<string, unknown>, PRIOR_RUNTIME_STATE_SCHEMA_VERSION, intent.hostId, intent.epoch, 'current',
    )) throw new Error('Bridge runtime reset intent prior target is invalid');
  } else if (!isObsoleteStateRecord(stateTarget, intent.hostId) || !isSpoolRecordForSchema(
    spoolTarget as unknown as Record<string, unknown>, OBSOLETE_RUNTIME_STATE_SCHEMA_VERSION, intent.hostId, intent.epoch, 'current',
  )) {
    throw new Error('Bridge runtime reset intent obsolete target is invalid');
  }
}

function assertResetStateMember(
  bytes: Buffer | undefined, intent: RuntimeResetIntentV1, hostId: string, target: Record<string, unknown>,
): void {
  const actual = hashOptional(bytes);
  assertResetMemberHash('state', actual, intent.stateSourceHash, intent.stateTargetHash);
  if (actual === intent.stateTargetHash) {
    const parsed = parseRawJson(bytes, 'Bridge runtime reset state target');
    const valid = intent.toSchemaVersion === PRIOR_RUNTIME_STATE_SCHEMA_VERSION
      ? !!parsed && isPriorStateRecordV3(parsed, hostId)
      : !!parsed && isObsoleteStateRecord(parsed, hostId);
    if (!valid || JSON.stringify(parsed) !== JSON.stringify(target)) {
      throw new Error('Bridge runtime reset state target is invalid');
    }
  } else if (bytes) {
    const state = parseRawJson(bytes, 'Bridge runtime reset state source');
    const valid = intent.fromSchemaVersion === LEGACY_RUNTIME_STATE_SCHEMA_VERSION
      ? isRecognizedPriorStateRecord(state, hostId)
      : !!state && isObsoleteStateRecord(state, hostId);
    if (!valid) throw new Error('Bridge runtime reset state source schema is invalid');
  }
}

function assertResetSpoolMember(
  bytes: Buffer | undefined, intent: RuntimeResetIntentV1, hostId: string, target: LocalSpoolFileV2,
): void {
  const actual = hashOptional(bytes);
  assertResetMemberHash('spool', actual, intent.spoolSourceHash, intent.spoolTargetHash);
  if (actual === intent.spoolTargetHash) {
    const spool = parseRawJson(bytes, 'Bridge runtime reset spool target');
    if (!spool || !isSpoolRecordForSchema(spool, intent.toSchemaVersion, hostId, intent.epoch, 'current')
      || JSON.stringify(spool) !== JSON.stringify(target)) {
      throw new Error('Bridge runtime reset spool target is invalid');
    }
  } else if (bytes) {
    const spool = parseRawJson(bytes, 'Bridge runtime reset spool source');
    const valid = intent.fromSchemaVersion === LEGACY_RUNTIME_STATE_SCHEMA_VERSION
      ? !!spool && isRecognizedPriorSpoolRecord(spool, hostId)
      : !!spool && isSpoolRecordForSchema(spool, intent.fromSchemaVersion, hostId,
        (spool.runtimeResetEpoch as string), 'current');
    if (!valid) throw new Error('Bridge runtime reset spool source schema is invalid');
  }
}

export function runtimeSchemaFloor(statePath: string, hostId: string, minSchemaVersion: 4): RuntimeSchemaFloorV1 {
  const resolvedStatePath = resolve(statePath);
  return {
    version: 1, hostId, minSchemaVersion,
    statePath: resolvedStatePath, spoolPath: resolve(spoolPathForState(resolvedStatePath)),
  };
}

export function parseRuntimeSchemaFloor(
  value: Record<string, unknown> | undefined, statePath: string, hostId: string,
 ): RuntimeSchemaFloorV1 {
  if (!value || !hasExactKeys(value, ['version', 'hostId', 'minSchemaVersion', 'statePath', 'spoolPath'])
    || value.version !== 1 || value.hostId !== hostId
    || value.minSchemaVersion !== BRIDGE_RUNTIME_STATE_SCHEMA_VERSION) {
    throw new Error('Bridge runtime schema floor is invalid');
  }
  const expected = runtimeSchemaFloor(statePath, hostId, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION);
  if (value.statePath !== expected.statePath || value.spoolPath !== expected.spoolPath) {
    throw new Error('Bridge runtime schema floor path binding is invalid');
  }
  return value as unknown as RuntimeSchemaFloorV1;
}

function parseMigrationIntent(value: unknown, statePath: string): RuntimeMigrationIntentV1 {
  if (!isRecord(value) || !hasExactKeys(value, [
    'version', 'fromSchemaVersion', 'toSchemaVersion', 'hostId', 'statePath', 'spoolPath', 'floorPath', 'intentPath',
    'stateSourceHash', 'spoolSourceHash', 'floorSourceHash', 'stateTargetHash', 'spoolTargetHash', 'floorTargetHash',
    'stateTarget', 'spoolTarget', 'floorTarget', 'createdAt',
  ]) || value.version !== MIGRATION_INTENT_VERSION || value.fromSchemaVersion !== PRIOR_RUNTIME_STATE_SCHEMA_VERSION
    || value.toSchemaVersion !== BRIDGE_RUNTIME_STATE_SCHEMA_VERSION || !isNonEmptyString(value.hostId)
    || !isAbsoluteResolvedPath(value.statePath) || !isAbsoluteResolvedPath(value.spoolPath)
    || !isAbsoluteResolvedPath(value.floorPath) || !isAbsoluteResolvedPath(value.intentPath)
    || !isRuntimeHash(value.stateSourceHash) || !isRuntimeHash(value.spoolSourceHash) || !isRuntimeHash(value.floorSourceHash)
    || !isRuntimeHash(value.stateTargetHash) || !isRuntimeHash(value.spoolTargetHash) || !isRuntimeHash(value.floorTargetHash)
    || !isNonEmptyString(value.createdAt) || !isCanonicalTimestamp(value.createdAt)) {
    throw new Error('Bridge runtime migration intent is invalid');
  }
  const intent = value as unknown as RuntimeMigrationIntentV1;
  const expectedStatePath = resolve(statePath);
  if (intent.statePath !== expectedStatePath || intent.spoolPath !== resolve(spoolPathForState(expectedStatePath))
    || intent.floorPath !== resolve(runtimeSchemaFloorPathForState(expectedStatePath))
    || intent.intentPath !== resolve(runtimeMigrationIntentPathForState(expectedStatePath))) {
    throw new Error('Bridge runtime migration intent path binding is invalid');
  }
  assertMigrationIntentTargets(intent);
  return intent;
}

function assertMigrationIntentTargets(intent: RuntimeMigrationIntentV1): void {
  parseCurrentState(intent.stateTarget, intent.hostId);
  const spool = parseCurrentSpoolRecord(
    intent.spoolTarget as unknown as Record<string, unknown>, intent.hostId, intent.stateTarget.runtimeResetEpoch,
  );
  const floor = parseRuntimeSchemaFloor(intent.floorTarget as unknown as Record<string, unknown>, intent.statePath, intent.hostId);
  if (floor.minSchemaVersion !== BRIDGE_RUNTIME_STATE_SCHEMA_VERSION) throw new Error('Bridge runtime migration intent target is invalid');
  assertCurrentRuntimeRelationships(intent.stateTarget as unknown as PersistedBridgeState, spool, intent.hostId);
  if (hashBytes(serializeSecureJson(intent.stateTarget)) !== intent.stateTargetHash
    || hashBytes(serializeSecureJson(intent.spoolTarget)) !== intent.spoolTargetHash
    || hashBytes(serializeSecureJson(floor)) !== intent.floorTargetHash || intent.floorSourceHash !== ABSENT_HASH) {
    throw new Error('Bridge runtime migration intent target hash is invalid');
  }
}

function assertMigrationMemberHash(name: string, bytes: Buffer | undefined, source: string, target: string): void {
  const actual = hashOptional(bytes);
  if (actual !== source && actual !== target) {
    throw new Error(`Bridge runtime migration ${name} changed outside the migration journal`);
  }
}

function assertResetMemberHash(name: string, actual: string, source: string, target: string): void {
  if (actual !== source && actual !== target) throw new Error(`Bridge runtime reset ${name} changed outside the reset journal`);
}

function isAbsoluteResolvedPath(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith('/') && resolve(value) === value;
}

export function beginRuntimeReset(
  shell: RuntimeResetShell, hostId: string, keyStore: SpoolKeyStore, stateSource: Buffer | undefined, spoolSource: Buffer | undefined,
  fromSchemaVersion: 1 | 2, toSchemaVersion: 2 | 3,
  resetStep?: (phase: RuntimeResetPhase) => void,
  resetWriteHooks?: SecureFileWriteHooks,
  resetRemoveHooks?: SecureFileRemoveHooks,
): Record<string, unknown> {
  resetStep?.('before-intent');
  const key = keyStore.loadOrCreate(hostId, { allowCreate: spoolSource === undefined });
  let keyId: string;
  try { keyId = spoolKeyIdForKey(key); } finally { key.fill(0); }
  const priorSpool = parseRawJson(spoolSource, 'Bridge runtime spool');
  if (priorSpool && priorSpool.version === 2 && priorSpool.keyId !== keyId) {
    throw new Error('Bridge runtime spool key mismatch');
  }
  const epoch = randomUUID();
  const stateTarget = emptyStateForSchema(toSchemaVersion, epoch);
  const spoolTarget = spoolFileForSchema(toSchemaVersion, hostId, epoch, keyId);
  const statePath = resolve(shell.filePath);
  const spoolPath = resolve(spoolPathForState(shell.filePath));
  const intentPath = resolve(runtimeResetIntentPathForState(shell.filePath));
  const intent: RuntimeResetIntentV1 = {
    version: RESET_INTENT_VERSION, fromSchemaVersion, toSchemaVersion, hostId, epoch, keyId,
    statePath, spoolPath, intentPath,
    stateSourceHash: hashOptional(stateSource), spoolSourceHash: hashOptional(spoolSource),
    stateTargetHash: hashBytes(serializeSecureJson(stateTarget)), spoolTargetHash: hashBytes(serializeSecureJson(spoolTarget)),
    createdAt: new Date().toISOString(),
  };
  writeSecureJsonExclusive(intentPath, intent, undefined, resetWriteHooks);
  resetStep?.('after-intent');
  return finishRuntimeReset(shell, intent, stateTarget, spoolTarget, resetStep, resetWriteHooks, resetRemoveHooks);
}

export function resumeRuntimeReset(
  shell: RuntimeResetShell, hostId: string, keyStore: SpoolKeyStore, resetStep?: (phase: RuntimeResetPhase) => void,
  resetWriteHooks?: SecureFileWriteHooks,
  resetRemoveHooks?: SecureFileRemoveHooks,
): Record<string, unknown> {
  const intent = parseResetIntent(readSecureJson<unknown>(runtimeResetIntentPathForState(shell.filePath)));
  if (intent.hostId !== hostId) throw new Error('Bridge runtime reset intent Host mismatch');
  assertResetIntentPaths(intent, shell.filePath);
  const stateTarget = emptyStateForSchema(intent.toSchemaVersion, intent.epoch);
  const spoolTarget = spoolFileForSchema(intent.toSchemaVersion, hostId, intent.epoch, intent.keyId);
  assertRuntimeResetTargets(intent, stateTarget, spoolTarget);
  assertRuntimeResetMembers(shell, intent, hostId, stateTarget, spoolTarget);
  const key = keyStore.loadOrCreate(hostId, { allowCreate: false });
  try {
    if (spoolKeyIdForKey(key) !== intent.keyId) throw new Error('Bridge runtime reset intent key mismatch');
  } finally { key.fill(0); }
  return finishRuntimeReset(shell, intent, stateTarget, spoolTarget, resetStep, resetWriteHooks, resetRemoveHooks);
}

function assertRuntimeResetMembers(
  shell: RuntimeResetShell,
  intent: RuntimeResetIntentV1, hostId: string, stateTarget: Record<string, unknown>, spoolTarget: LocalSpoolFileV2,
): { stateBytes: Buffer | undefined; spoolBytes: Buffer | undefined } {
  const stateBytes = readOptionalSecureBytes(shell.filePath);
  const spoolBytes = readOptionalSecureBytes(spoolPathForState(shell.filePath));
  assertResetStateMember(stateBytes, intent, hostId, stateTarget);
  assertResetSpoolMember(spoolBytes, intent, hostId, spoolTarget);
  if (hashOptional(stateBytes) === intent.stateSourceHash && hashOptional(spoolBytes) === intent.spoolSourceHash
    && stateBytes && spoolBytes) {
    const state = parseRawJson(stateBytes, 'Bridge runtime reset state source');
    const spool = parseRawJson(spoolBytes, 'Bridge runtime reset spool source');
    if (!state || !spool || !hasResetSourceRelationships(intent.fromSchemaVersion, state, spool, hostId)) {
      throw new Error('Bridge runtime reset source relationships are invalid');
    }
  }
  return { stateBytes, spoolBytes };
}

function finishRuntimeReset(
  shell: RuntimeResetShell,
  intent: RuntimeResetIntentV1, stateTarget: Record<string, unknown>, spoolTarget: LocalSpoolFileV2,
  resetStep?: (phase: RuntimeResetPhase) => void,
  resetWriteHooks?: SecureFileWriteHooks,
  resetRemoveHooks?: SecureFileRemoveHooks,
): Record<string, unknown> {
  assertRuntimeResetTargets(intent, stateTarget, spoolTarget);
  const { stateBytes, spoolBytes } = assertRuntimeResetMembers(shell, intent, intent.hostId, stateTarget, spoolTarget);
  if (hashOptional(spoolBytes) !== intent.spoolTargetHash) {
    writeSecureJson(spoolPathForState(shell.filePath), spoolTarget, undefined, resetWriteHooks);
  }
  resetStep?.('after-spool');
  if (hashOptional(stateBytes) !== intent.stateTargetHash) writeSecureJson(shell.filePath, stateTarget, undefined, resetWriteHooks);
  resetStep?.('after-state');
  removeSecureFile(runtimeResetIntentPathForState(shell.filePath), undefined, resetRemoveHooks);
  resetStep?.('after-cleanup');
  return stateTarget;
}

export function beginRuntimeMigration(
  shell: RuntimeResetShell, hostId: string, stateSource: Record<string, unknown>, spoolSource: Record<string, unknown>,
  stateSourceBytes: Buffer, spoolSourceBytes: Buffer, resetStep?: (phase: RuntimeResetPhase) => void,
  writeHooks?: SecureFileWriteHooks, removeHooks?: SecureFileRemoveHooks,
): PersistedBridgeState {
  const stateTarget = migrateStateV3ToV4(stateSource, hostId);
  const spoolTarget = migrateSpoolV3ToV4(spoolSource, hostId, stateTarget.runtimeResetEpoch);
  const floorTarget = runtimeSchemaFloor(shell.filePath, hostId, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION);
  const intent: RuntimeMigrationIntentV1 = {
    version: MIGRATION_INTENT_VERSION, fromSchemaVersion: PRIOR_RUNTIME_STATE_SCHEMA_VERSION,
    toSchemaVersion: BRIDGE_RUNTIME_STATE_SCHEMA_VERSION, hostId,
    statePath: resolve(shell.filePath), spoolPath: resolve(spoolPathForState(shell.filePath)),
    floorPath: resolve(runtimeSchemaFloorPathForState(shell.filePath)),
    intentPath: resolve(runtimeMigrationIntentPathForState(shell.filePath)),
    stateSourceHash: hashBytes(stateSourceBytes), spoolSourceHash: hashBytes(spoolSourceBytes), floorSourceHash: ABSENT_HASH,
    stateTargetHash: hashBytes(serializeSecureJson(stateTarget)), spoolTargetHash: hashBytes(serializeSecureJson(spoolTarget)),
    floorTargetHash: hashBytes(serializeSecureJson(floorTarget)), stateTarget, spoolTarget, floorTarget,
    createdAt: new Date().toISOString(),
  };
  resetStep?.('before-intent');
  writeSecureJsonExclusive(intent.intentPath, intent, undefined, writeHooks);
  resetStep?.('after-intent');
  return finishRuntimeMigration(shell, intent, resetStep, writeHooks, removeHooks);
}

export function resumeRuntimeMigration(
  shell: RuntimeResetShell, hostId: string, resetStep?: (phase: RuntimeResetPhase) => void,
  writeHooks?: SecureFileWriteHooks, removeHooks?: SecureFileRemoveHooks,
): Record<string, unknown> {
  const value = readSecureJson<unknown>(runtimeMigrationIntentPathForState(shell.filePath));
  if (!isRecord(value)) throw new Error('Bridge runtime migration intent is invalid');
  if (value.version === MIGRATION_INTENT_VERSION) {
    const intent = parseMigrationIntent(value, shell.filePath);
    if (intent.hostId !== hostId) throw new Error('Bridge runtime migration intent Host mismatch');
    return finishRuntimeMigration(shell, intent, resetStep, writeHooks, removeHooks);
  }
  throw new Error('Bridge runtime migration intent version is unknown');
}

function finishRuntimeMigration(
  shell: RuntimeResetShell,
  intent: RuntimeMigrationIntentV1, resetStep?: (phase: RuntimeResetPhase) => void,
  writeHooks?: SecureFileWriteHooks, removeHooks?: SecureFileRemoveHooks,
): PersistedBridgeState {
  assertMigrationIntentTargets(intent);
  const stateBytes = readOptionalSecureBytes(shell.filePath);
  const spoolBytes = readOptionalSecureBytes(spoolPathForState(shell.filePath));
  const floorBytes = readOptionalSecureBytes(runtimeSchemaFloorPathForState(shell.filePath));
  assertMigrationMemberHash('state', stateBytes, intent.stateSourceHash, intent.stateTargetHash);
  assertMigrationMemberHash('spool', spoolBytes, intent.spoolSourceHash, intent.spoolTargetHash);
  assertMigrationMemberHash('schema floor', floorBytes, intent.floorSourceHash, intent.floorTargetHash);
  if (hashOptional(spoolBytes) !== intent.spoolTargetHash) {
    writeSecureJson(spoolPathForState(shell.filePath), intent.spoolTarget, undefined, writeHooks);
  }
  resetStep?.('after-spool');
  if (hashOptional(stateBytes) !== intent.stateTargetHash) {
    writeSecureJson(shell.filePath, intent.stateTarget, undefined, writeHooks);
  }
  resetStep?.('after-state');
  if (hashOptional(floorBytes) !== intent.floorTargetHash) {
    writeSecureJson(runtimeSchemaFloorPathForState(shell.filePath), intent.floorTarget, undefined, writeHooks);
  }
  removeSecureFile(runtimeMigrationIntentPathForState(shell.filePath), undefined, removeHooks);
  resetStep?.('after-cleanup');
  return intent.stateTarget;
}
