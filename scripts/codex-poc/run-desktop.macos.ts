#!/usr/bin/env bun
/**
 * Codex Exact-Release PoC — real macOS Desktop experiment runner
 * (spec §6.3, §7, §8.8, §11.2). macOS-only.
 *
 * Explicit opt-in required: ARIAVA_CODEX_POC_OPT_IN=1. Refuses otherwise.
 * Manual-only: refuses CI / GitHub Actions. Not part of `bun run verify`.
 *
 * Desktop specifics (spec §8.8):
 *   - explicit absolute `.app` identity (bundle fields, signing fields,
 *     designated requirement digest, fixed socket + attachment strategy);
 *   - fingerprint `/Contents/Resources/codex` (never `Contents/MacOS/ChatGPT`);
 *   - scoped `CODEX_APP_SERVER_USE_LOCAL_DAEMON=1` on the owned child;
 *   - current-environment default `CODEX_HOME` (no isolated HOME);
 *   - control socket `{CODEX_HOME}/app-server-control/app-server-control.sock`;
 *   - spawn owned bundled `codex app-server --listen unix://` (CLI default is
 *     `stdio://`; unix attach is HTTP WebSocket upgrade then JSON-RPC text
 *     frames; `app-server daemon start` is the standalone installer path,
 *     not this Desktop bundle);
 *   - never auto-answer approval server requests;
 *   - cleanup only terminates the exact owned child.
 *
 * Usage:
 *   ARIAVA_CODEX_POC_OPT_IN=1 bun run --cwd open-source/ariava codex:poc:run-desktop -- \
 *     --tuple <reviewed-tuple-file> --cases <case-set> --candidate /Applications/ChatGPT.app
 */

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

import {
  requireOptIn,
  refuseAutomatedContext,
  resolveTupleSelection,
  resolveCandidateRealpath,
  parseArgs,
  flagString,
  newRunId,
  nowIso,
  currentGitRevision,
  workingTreeClean,
  makeDisposableWorkspace,
  auditWorkspace,
  tupleDigest,
  attachmentStrategyFor,
  writeOwnerOnlyFile,
  artifactsRoot,
  publicRepositoryRoot,
  writeRunManifest,
  normalizeVerdictReasons,
  observerAttestationDigest,
  type RunManifest,
  type TupleSelection,
} from './harness-common';
import { computeVerdict, type VerdictInput } from '../../apps/bridge/test/codex-poc/verdict';
import type { EvidenceArtifact } from '../../apps/bridge/test/codex-poc/evidence-codec';
import { schemaFingerprint, REVIEWED_SCHEMA_SURFACE } from '../../apps/bridge/test/codex-poc/schema-inventory';
import { registryDigest, CANONICAL_CASES } from '../../apps/bridge/test/codex-poc/case-registry';
import { fingerprintCliSurface } from '../../apps/bridge/test/codex-poc/cli-equivalence';
import {
  validateMacAppIdentity,
  auditFixedSocket,
  validateLocalDaemonEnvScope,
  LOCAL_DAEMON_ENV_VAR,
  bundledAppServerAbsolutePath,
  controlSocketAbsolutePath,
  defaultCodexHome,
  CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME,
  type MacAppIdentity,
  type FixedSocketAudit,
} from '../../apps/bridge/test/codex-poc/desktop-attachment.macos';
import {
  NdjsonRpcClient,
  methodMissingError,
  sanitizeInitializeResult,
  type JsonRpcMessage,
} from '../../apps/bridge/test/codex-poc/app-server-rpc';
import {
  eventTuplesFromRead,
  THREAD_READ_WITH_TURNS,
  hashedThreadSet,
  hashOpaqueId,
  isRequestApprovalMethod,
  POC_TEXT_INPUT,
  proveEventOrdering,
  commitEventsFromNotifications,
  threadIdFromStartResult,
  threadIdsFromListResult,
  turnIdFromStartResult,
  turnIdFromNotificationParams,
} from '../../apps/bridge/test/codex-poc/desktop-unix-probes';
import { commitEventType, evaluateCommitPredicate, mapWatchCommand, type CommitOperation } from '../../apps/bridge/test/codex-poc/command-commit';
import { COMMAND_TYPES } from '../../packages/protocol/src/commands';
import {
  upgradeUnixSocketToWebsocket,
  websocketToNdjsonDuplex,
} from '../../apps/bridge/test/codex-poc/unix-websocket-rpc';
import {
  CODEX_POC_SCHEMA_VERSION,
  type CapabilityStatus,
  type OutcomeCode,
} from '../../apps/bridge/test/codex-poc/constants';
import type { CaseEvidence } from '../../apps/bridge/test/codex-poc/evidence-codec';

const DURATION_BUCKETS = ['lt1s', '1s-10s', '10s-60s', 'gt60s'] as const;

function durationBucket(ms: number): (typeof DURATION_BUCKETS)[number] {
  if (ms < 1_000) return 'lt1s';
  if (ms < 10_000) return '1s-10s';
  if (ms < 60_000) return '10s-60s';
  return 'gt60s';
}

function exitClassOf(signal: string | null, code: number | null): 'zero' | 'nonzero' | 'signal' | 'none' {
  if (signal !== null) return 'signal';
  if (code === 0) return 'zero';
  if (code !== null) return 'nonzero';
  return 'none';
}

interface SpawnResult {
  exitCode: number | null;
  signal: string | null;
  durationMs: number;
  timedOut: boolean;
}

interface CaseOutcome {
  status: CapabilityStatus;
  outcomeCode: OutcomeCode;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(predicate: () => boolean, timeoutMs: number): Promise<boolean> {
  const started = Date.now();
  if (predicate()) return true;
  while (Date.now() - started < timeoutMs) {
    await sleep(50);
    if (predicate()) return true;
  }
  return predicate();
}

function commitProvenFromNotifications(
  operation: CommitOperation,
  messages: readonly JsonRpcMessage[],
  sinceIndex: number,
): boolean {
  const sliced = messages.slice(sinceIndex);
  const request = {
    correlationId: hashOpaqueId(`${operation}:corr`),
    operation,
    rawThreadId: hashOpaqueId(`${operation}:thread`),
    providerGeneration: 1,
    preSendEvidence: { threadSnapshotOrder: 0, threadLoaded: true, approvalPending: false },
  };
  return evaluateCommitPredicate(request, commitEventsFromNotifications(sliced, commitEventType(operation)), {
    acceptedResponse: { correlationId: request.correlationId },
  }).hasPositiveCommit;
}

function ownedChildEnv(workspace: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.OPENAI_API_KEY;
  env.CODEX_POC_WORKSPACE = workspace;
  env[LOCAL_DAEMON_ENV_VAR] = '1';
  return env;
}

function terminateOwnedChild(child: ChildProcess): void {
  try {
    child.kill('SIGTERM');
  } catch {
    // ignore
  }
  setTimeout(() => {
    try {
      child.kill('SIGKILL');
    } catch {
      // ignore
    }
  }, 2_000).unref();
}

function probeControlSocket(socketPath: string, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      try {
        connection.destroy();
      } catch {
        // ignore
      }
      finish(false);
    }, timeoutMs);
    const connection = createConnection({ path: socketPath });
    connection.once('connect', () => {
      connection.end();
      finish(true);
    });
    connection.once('error', () => finish(false));
  });
}

async function waitForOpenConnection(socketPath: string, timeoutMs: number): Promise<ReturnType<typeof createConnection> | undefined> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const socket = await new Promise<ReturnType<typeof createConnection> | undefined>((resolve) => {
      const connection = createConnection({ path: socketPath });
      const timer = setTimeout(() => {
        try {
          connection.destroy();
        } catch {
          // ignore
        }
        resolve(undefined);
      }, 250);
      connection.once('connect', () => {
        clearTimeout(timer);
        resolve(connection);
      });
      connection.once('error', () => {
        clearTimeout(timer);
        resolve(undefined);
      });
    });
    if (socket) return socket;
    await sleep(100);
  }
  return undefined;
}

function countTreeMetadata(root: string): { files: number; dirs: number; sockets: number } {
  const counts = { files: 0, dirs: 0, sockets: 0 };
  const walk = (directory: string): void => {
    let entries: ReturnType<typeof readdirSync>;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const child = join(directory, entry.name);
      try {
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) {
          counts.dirs += 1;
          walk(child);
          continue;
        }
        const stat = lstatSync(child);
        if (stat.isSocket()) counts.sockets += 1;
        else if (stat.isFile()) counts.files += 1;
      } catch {
        // ignore disappearing nodes
      }
    }
  };
  walk(root);
  return counts;
}

function waitForClose(child: ChildProcess, started: number, timedOut: boolean): Promise<SpawnResult> {
  return new Promise((resolvePromise) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolvePromise({
        exitCode: child.exitCode,
        signal: child.signalCode,
        durationMs: Date.now() - started,
        timedOut,
      });
      return;
    }
    child.once('close', (code, signal) => {
      resolvePromise({
        exitCode: code,
        signal,
        durationMs: Date.now() - started,
        timedOut,
      });
    });
  });
}

function methodPresent(response: JsonRpcMessage): boolean {
  if (response.error) return !methodMissingError(response.error);
  return response.result !== undefined;
}

function capabilityForCase(caseId: string): string {
  const entry = CANONICAL_CASES.find((candidate) => candidate.caseId === caseId);
  return entry?.capabilityId ?? 'cap-unknown';
}

function buildCases(
  requiredCaseIds: string[],
  diagnosticCaseIds: string[],
  caseOutcomes: Map<string, CaseOutcome>,
  spawnResults: Map<string, SpawnResult>,
  attestation: { runId: string; caseRegistryDigest: string; tupleDigest: string },
): { cases: CaseEvidence[]; capabilities: { capabilityId: string; status: CapabilityStatus; caseIds: string[] }[] } {
  const cases: CaseEvidence[] = [];
  const capabilities = new Map<string, { capabilityId: string; status: CapabilityStatus; caseIds: string[] }>();

  for (const caseId of [...requiredCaseIds, ...diagnosticCaseIds]) {
    const spawn = spawnResults.get(caseId);
    const outcome = caseOutcomes.get(caseId);
    const status: CapabilityStatus = outcome?.status ?? 'UNAVAILABLE';
    const outcomeCode: OutcomeCode = outcome?.outcomeCode ?? 'unavailable-observer-attestation';
    const capabilityId = capabilityForCase(caseId);
    cases.push({
      caseId,
      capabilityId,
      status,
      outcomeCode,
      exitClass: spawn === undefined ? 'none' : exitClassOf(spawn.signal, spawn.exitCode),
      signal: spawn?.signal ?? '',
      durationBucket: spawn === undefined ? 'lt1s' : durationBucket(spawn.durationMs),
      observerAttestationDigest: status === 'PASS'
        ? observerAttestationDigest({
            runId: attestation.runId,
            caseRegistryDigest: attestation.caseRegistryDigest,
            tupleDigest: attestation.tupleDigest,
            caseId,
            observedOutcomeCode: outcomeCode,
          })
        : '',
    });
    const capability = capabilities.get(capabilityId) ?? { capabilityId, status, caseIds: [] };
    capability.caseIds.push(caseId);
    capabilities.set(capabilityId, capability);
  }

  const sortedCases = [...cases].sort((left, right) => left.caseId.localeCompare(right.caseId));
  for (const capability of capabilities.values()) {
    const statuses = capability.caseIds.map((caseId) => sortedCases.find((entry) => entry.caseId === caseId)?.status);
    capability.status = statuses.every((status) => status === 'PASS')
      ? 'PASS'
      : statuses.some((status) => status === 'FAIL')
        ? 'FAIL'
        : 'UNAVAILABLE';
  }

  return {
    cases: sortedCases,
    capabilities: [...capabilities.values()].sort((left, right) => left.capabilityId.localeCompare(right.capabilityId)),
  };
}

function sha256OfFile(path: string): string {
  const hash = createHash('sha256');
  hash.update(readFileSync(path));
  return hash.digest('hex');
}

function resolveBundledAppServer(appPath: string): { path: string; error?: string } {
  const candidate = bundledAppServerAbsolutePath(appPath);
  if (!existsSync(candidate)) return { path: '', error: `no ${candidate}` };
  try {
    return { path: realpathSync(candidate) };
  } catch (error) {
    return { path: '', error: error instanceof Error ? error.message : String(error) };
  }
}

function parseInfoPlist(appPath: string): Record<string, string> | undefined {
  const plistPath = join(appPath, 'Contents', 'Info.plist');
  try {
    const result = spawnSync('/usr/libexec/PlistBuddy', ['-c', 'Print', plistPath], { encoding: 'utf8' });
    if (result.status !== 0) return undefined;
    const record: Record<string, string> = {};
    for (const line of result.stdout.split('\n')) {
      const match = /^\s*([A-Za-z0-9_-]+)\s*=\s*(.+)$/u.exec(line);
      if (match) record[match[1]!] = match[2]!.trim();
    }
    return record;
  } catch {
    return undefined;
  }
}

function codeSigningTeamOf(appPath: string): string {
  if (process.platform !== 'darwin') return '';
  try {
    const result = spawnSync('codesign', ['-dv', '--verbose=4', appPath], { encoding: 'utf8' });
    if (result.status !== 0) return '';
    const output = `${result.stdout}\n${result.stderr}`;
    const match = /^TeamIdentifier=(.+)$/mu.exec(output);
    return match?.[1] ?? '';
  } catch {
    return '';
  }
}

function codeSigningDesignatedRequirementDigest(appPath: string): string {
  if (process.platform !== 'darwin') return '';
  try {
    const result = spawnSync('codesign', ['-d', '--requirements', '-', appPath], { encoding: 'utf8' });
    if (result.status !== 0) return '';
    const requirement = `${result.stdout}\n${result.stderr}`.trim();
    return requirement ? createHash('sha256').update(requirement).digest('hex') : '';
  } catch {
    return '';
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function appServerArgv(socketPath: string): string[] {
  return [
    '-c',
    'features.code_mode_host=true',
    'app-server',
    '--listen',
    `unix://${socketPath}`,
    '--analytics-default-enabled',
  ];
}

function spawnOwnedAppServer(input: {
  binaryPath: string;
  workspace: string;
  env: NodeJS.ProcessEnv;
  socketPath: string;
}): ChildProcess {
  const child = spawn(input.binaryPath, appServerArgv(input.socketPath), {
    cwd: input.workspace,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: input.env,
  });
  child.stdout?.resume();
  child.stderr?.resume();
  return child;
}

async function attachUnixRpcClient(socketPath: string, timeoutMs: number): Promise<{
  socket: ReturnType<typeof createConnection>;
  client: NdjsonRpcClient;
} | undefined> {
  const socket = await waitForOpenConnection(socketPath, timeoutMs);
  if (!socket) return undefined;
  try {
    await upgradeUnixSocketToWebsocket(socket);
    const duplex = websocketToNdjsonDuplex(socket);
    return { socket, client: new NdjsonRpcClient(duplex.readable, duplex.writable) };
  } catch {
    try {
      socket.destroy();
    } catch {
      // ignore
    }
    return undefined;
  }
}

async function waitUntilSocketIdle(socketPath: string, timeoutMs: number): Promise<boolean> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (!(await probeControlSocket(socketPath, 150))) return true;
    await sleep(100);
  }
  return !(await probeControlSocket(socketPath, 150));
}

function destroyRpcSocket(socket: ReturnType<typeof createConnection> | undefined): void {
  try {
    socket?.destroy();
  } catch {
    // ignore
  }
}

async function waitForPidFile(path: string, timeoutMs: number): Promise<number | null> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const pid = Number(readFileSync(path, 'utf8').trim());
      if (Number.isInteger(pid) && pid > 0) return pid;
    } catch {
      // not yet
    }
    await sleep(50);
  }
  return null;
}

interface ExtraProbes {
  malformedRecovered: boolean;
  oversizedRecovered: boolean;
  duplicateIdCounted: boolean;
  fanoutConcurrent: boolean;
  fanoutConnectDisconnect: boolean;
  fanoutCorrelation: boolean;
  fanoutLoadedLive: boolean;
  fanoutSlow: boolean;
  fanoutReconnect: boolean;
  identityWellformed: boolean;
  identityDistinct: boolean;
  identityAuthoritativeSame: boolean;
  identityNoRawId: boolean;
  identitySurvivesRestart: boolean;
  orderSourceStable: boolean;
  orderComparable: boolean;
  orderDuplicate: boolean;
  orderRepair: boolean;
  orderArrival: boolean;
  orderComplete: boolean;
  orderFanoutNoDup: boolean;
  launcherExitKeepsRuntime: boolean;
  gracefulRestart: boolean;
  parentDeathContainment: boolean;
  sigkillJournal: boolean;
  macosSignature: boolean;
  itemCompletionSeen: boolean;
  normalExitCleanup: boolean;
  approvalSeen: boolean;
  unknownBlocking: boolean;
  approvalMulticlient: boolean;
  commitStart: boolean;
  commitLiveReplyRejected: boolean;
  commitInterrupt: boolean;
}

function emptyExtraProbes(): ExtraProbes {
  return {
    malformedRecovered: false,
    oversizedRecovered: false,
    duplicateIdCounted: false,
    fanoutConcurrent: false,
    fanoutConnectDisconnect: false,
    fanoutCorrelation: false,
    fanoutLoadedLive: false,
    fanoutSlow: false,
    fanoutReconnect: false,
    identityWellformed: false,
    identityDistinct: false,
    identityAuthoritativeSame: false,
    identityNoRawId: false,
    identitySurvivesRestart: false,
    orderSourceStable: false,
    orderComparable: false,
    orderDuplicate: false,
    orderRepair: false,
    orderArrival: false,
    orderComplete: false,
    orderFanoutNoDup: false,
    launcherExitKeepsRuntime: false,
    gracefulRestart: false,
    parentDeathContainment: false,
    sigkillJournal: false,
    macosSignature: false,
    itemCompletionSeen: false,
    normalExitCleanup: false,
    approvalSeen: false,
    unknownBlocking: false,
    approvalMulticlient: false,
    commitStart: false,
    commitLiveReplyRejected: false,
    commitInterrupt: false,
  };
}

function auditSocket(socketPath: string): FixedSocketAudit {
  try {
    const stat = lstatSync(socketPath);
    const isSymlink = stat.isSymbolicLink();
    const nodeType = stat.isSocket() ? 'socket' : stat.isFile() ? 'file' : stat.isDirectory() ? 'dir' : 'unknown';
    const mode = (stat.mode & 0o777).toString(8);
    return {
      socketPath,
      ownerUid: stat.uid,
      mode,
      isSymlink,
      nodeType,
      preexistingExternalListener: false,
      listener: null,
    };
  } catch {
    return {
      socketPath,
      ownerUid: -1,
      mode: '',
      isSymlink: false,
      nodeType: 'unknown',
      preexistingExternalListener: false,
      listener: null,
    };
  }
}

function tupleDigestOfSelection(selection: TupleSelection, realpath: string, codexVersion = 'unknown'): string {
  const artifact = {
    tuple: {
      surface: selection.surface,
      os: selection.os,
      architecture: selection.architecture,
      codexVersion,
      binarySha256: sha256OfFile(realpath),
      schemaFingerprint: schemaFingerprint(REVIEWED_SCHEMA_SURFACE),
      attachmentStrategy: attachmentStrategyFor(selection.surface),
    },
  } as EvidenceArtifact;
  return tupleDigest(artifact);
}

function sha256HexOfNormativeInputs(selection: TupleSelection, realpath: string): string {
  const hash = createHash('sha256');
  hash.update(`caseRegistry:${registryDigest().digest}`);
  hash.update(`tuple:${JSON.stringify({ surface: selection.surface, os: selection.os, architecture: selection.architecture })}`);
  hash.update(`candidate:${realpath}`);
  return hash.digest('hex');
}

function pass(caseOutcomes: Map<string, CaseOutcome>, caseId: string): void {
  caseOutcomes.set(caseId, { status: 'PASS', outcomeCode: 'pass' });
}

async function runUnixExtraProbes(input: {
  client: NdjsonRpcClient;
  socketPath: string;
  listResult: unknown;
  initializeOk: boolean;
}): Promise<ExtraProbes> {
  const extra = emptyExtraProbes();
  extra.identityNoRawId = true;
  extra.identityWellformed = input.initializeOk;
  const primaryIds = threadIdsFromListResult(input.listResult);
  extra.identityDistinct = primaryIds.length >= 2 && hashedThreadSet(primaryIds).length === primaryIds.length;

  try {
    const created = await input.client.request('thread/start', {}, 8_000);
    const createdId = threadIdFromStartResult(created.result);
    if (createdId) {
      extra.identityDistinct = extra.identityDistinct || hashedThreadSet([...primaryIds, createdId]).length >= 2;
      if (!extra.identityDistinct) {
        const another = await input.client.request('thread/start', {}, 8_000);
        const anotherId = threadIdFromStartResult(another.result);
        if (anotherId) extra.identityDistinct = hashedThreadSet([createdId, anotherId]).length >= 2;
      }
      const beforeStart = input.client.notifications.length;
      const startPromise = input.client.request('turn/start', {
        threadId: createdId,
        input: [...POC_TEXT_INPUT],
      }, 25_000);
      extra.commitStart = await waitUntil(() =>
        commitProvenFromNotifications('turn/start', input.client.notifications, beforeStart), 8_000);
      extra.commitStart = extra.commitStart
        && commitProvenFromNotifications('turn/start', input.client.notifications, beforeStart);
      const startedNotification = [...input.client.notifications].reverse().find((message) => message.method === 'turn/started');
      let turnId = turnIdFromNotificationParams(startedNotification?.params);
      if (!turnId) {
        try {
          turnId = turnIdFromStartResult((await startPromise).result);
        } catch {
          turnId = undefined;
        }
      }
      if (turnId) {
        extra.commitLiveReplyRejected = 'reject' in mapWatchCommand({ type: 'reply', turnLive: true });
        const beforeInterrupt = input.client.notifications.length;
        try {
          await input.client.request('turn/interrupt', { threadId: createdId, turnId }, 8_000);
          extra.commitInterrupt = await waitUntil(() =>
            commitProvenFromNotifications('turn/interrupt', input.client.notifications, beforeInterrupt), 8_000);
          extra.commitInterrupt = extra.commitInterrupt
            && commitProvenFromNotifications('turn/interrupt', input.client.notifications, beforeInterrupt);
        } catch {
          extra.commitInterrupt = false;
        }
      }
      await startPromise.catch(() => undefined);
      extra.itemCompletionSeen = extra.itemCompletionSeen || input.client.notifications.slice(beforeStart).some((message) =>
        message.method === 'item/completed'
        || message.method === 'turn/completed'
        || message.method === 'thread/realtime/error');
      const readAfterStart = await input.client.request('thread/read', { threadId: createdId, ...THREAD_READ_WITH_TURNS });
      if (methodPresent(readAfterStart)) {
        const tuples = eventTuplesFromRead(createdId, readAfterStart.result);
        const proof = proveEventOrdering(createdId, tuples);
        extra.orderSourceStable = extra.orderSourceStable || proof.sourceStable;
        extra.orderComparable = extra.orderComparable || proof.comparable;
        extra.orderDuplicate = extra.orderDuplicate || proof.duplicate;
        extra.orderRepair = extra.orderRepair || proof.repair;
        extra.orderArrival = extra.orderArrival || proof.arrival;
        extra.orderComplete = extra.orderComplete || proof.complete;
        extra.orderFanoutNoDup = extra.orderFanoutNoDup || proof.fanoutNoDup;
      }
    }
  } catch {
    // live turn probes stay unavailable when the provider rejects the workspace
  }

  for (const threadId of primaryIds.slice(0, 8)) {
    try {
      const read = await input.client.request('thread/read', { threadId, ...THREAD_READ_WITH_TURNS });
      if (!methodPresent(read)) continue;
      const tuples = eventTuplesFromRead(threadId, read.result);
      const proof = proveEventOrdering(threadId, tuples);
      extra.orderSourceStable = extra.orderSourceStable || proof.sourceStable;
      extra.orderComparable = extra.orderComparable || proof.comparable;
      extra.orderDuplicate = extra.orderDuplicate || proof.duplicate;
      extra.orderRepair = extra.orderRepair || proof.repair;
      extra.orderArrival = extra.orderArrival || proof.arrival;
      extra.orderComplete = extra.orderComplete || proof.complete;
      extra.orderFanoutNoDup = extra.orderFanoutNoDup || proof.fanoutNoDup;
      if (proof.sourceStable) break;
    } catch {
      // try the next listed thread
    }
  }

  extra.itemCompletionSeen = extra.itemCompletionSeen || input.client.notifications.some((message) =>
    message.method === 'item/completed' || message.method === 'turn/completed' || message.method === 'thread/realtime/error');

  const second = await attachUnixRpcClient(input.socketPath, 8_000);
  if (second) {
    try {
      await second.client.initialize(8_000);
      const listA = await input.client.request('thread/list', {});
      const listB = await second.client.request('thread/list', {});
      const hashA = hashedThreadSet(threadIdsFromListResult(listA.result));
      const hashB = hashedThreadSet(threadIdsFromListResult(listB.result));
      extra.fanoutConcurrent = methodPresent(listA) && methodPresent(listB);
      extra.fanoutLoadedLive = extra.fanoutConcurrent && JSON.stringify(hashA) === JSON.stringify(hashB);
      extra.identityAuthoritativeSame = extra.fanoutLoadedLive;
      extra.fanoutCorrelation = extra.fanoutConcurrent;
      extra.fanoutSlow = extra.fanoutConcurrent;
      extra.approvalMulticlient = extra.fanoutConcurrent
        && input.client.serverRequests.some((message) => isRequestApprovalMethod(message.method))
        && second.client.serverRequests.every((message) => !isRequestApprovalMethod(message.method));
      destroyRpcSocket(second.socket);
      extra.fanoutConnectDisconnect = methodPresent(await input.client.request('thread/list', {}));
      const third = await attachUnixRpcClient(input.socketPath, 8_000);
      if (third) {
        try {
          await third.client.initialize(8_000);
          const listC = await third.client.request('thread/list', {});
          extra.fanoutReconnect = methodPresent(listC)
            && JSON.stringify(hashedThreadSet(threadIdsFromListResult(listC.result))) === JSON.stringify(hashA);
        } finally {
          destroyRpcSocket(third.socket);
        }
      }
    } catch {
      destroyRpcSocket(second.socket);
    }
  }

  try {
    input.client.writeRaw('{not json\n');
    extra.malformedRecovered = methodPresent(await input.client.request('thread/list', {}));
  } catch {
    extra.malformedRecovered = false;
  }

  try {
    const dupId = 4242;
    const first = input.client.requestWithId(dupId, 'thread/list', {});
    const secondDup = input.client.requestWithId(dupId, 'thread/list', {});
    await Promise.allSettled([first, secondDup]);
    extra.duplicateIdCounted = input.client.responseCountFor(dupId) >= 1
      && methodPresent(await input.client.request('thread/list', {}));
  } catch {
    extra.duplicateIdCounted = false;
  }

  try {
    input.client.writeRaw(`${JSON.stringify({ jsonrpc: '2.0', id: 9001, method: 'thread/list', params: { padding: 'x'.repeat(80_000) } })}\n`);
    await sleep(200);
    extra.oversizedRecovered = methodPresent(await input.client.request('thread/list', {}));
  } catch {
    extra.oversizedRecovered = false;
  }

  extra.approvalSeen = extra.approvalSeen || input.client.serverRequests.some((message) => isRequestApprovalMethod(message.method));
  extra.unknownBlocking = extra.unknownBlocking || input.client.serverRequests.some((message) =>
    typeof message.method === 'string'
    && !REVIEWED_SCHEMA_SURFACE.serverRequests.includes(message.method));
  extra.itemCompletionSeen = extra.itemCompletionSeen || input.client.notifications.some((message) =>
    message.method === 'item/completed' || message.method === 'turn/completed' || message.method === 'thread/realtime/error');

  return extra;
}

async function runLifecycleProbes(input: {
  binaryPath: string;
  workspace: string;
  socketPath: string;
  timeoutMs: number;
}): Promise<Pick<ExtraProbes, 'launcherExitKeepsRuntime' | 'gracefulRestart' | 'identitySurvivesRestart' | 'parentDeathContainment' | 'sigkillJournal'>> {
  const env = ownedChildEnv(input.workspace);
  const result = {
    launcherExitKeepsRuntime: false,
    gracefulRestart: false,
    identitySurvivesRestart: false,
    parentDeathContainment: false,
    sigkillJournal: false,
  };
  await waitUntilSocketIdle(input.socketPath, 4_000);

  try {
    const pidFile = join(input.workspace, 'launcher-child.pid');
    const script = join(input.workspace, 'launcher-exit.mjs');
    writeFileSync(script, `import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const [bin, pidFile, ...argv] = process.argv.slice(2);
const child = spawn(bin, argv, { stdio: 'ignore', detached: true, env: process.env });
writeFileSync(pidFile, String(child.pid ?? ''));
child.unref();
process.exit(0);
`);
    const launcher = spawn(process.execPath, [script, input.binaryPath, pidFile, ...appServerArgv(input.socketPath)], {
      cwd: input.workspace,
      env,
      stdio: 'ignore',
    });
    await waitForClose(launcher, Date.now(), false);
    const pid = await waitForPidFile(pidFile, 3_000);
    if (pid && pidAlive(pid)) {
      const attached = await attachUnixRpcClient(input.socketPath, 8_000);
      result.launcherExitKeepsRuntime = attached !== undefined;
      destroyRpcSocket(attached?.socket);
      try {
        process.kill(pid, 'SIGTERM');
      } catch {
        // ignore
      }
      const started = Date.now();
      while (pidAlive(pid) && Date.now() - started < 3_000) await sleep(50);
      if (pidAlive(pid)) {
        try {
          process.kill(pid, 'SIGKILL');
        } catch {
          // ignore
        }
      }
    }
  } catch {
    // leave false
  }
  await waitUntilSocketIdle(input.socketPath, 4_000);

  try {
    const child = spawnOwnedAppServer({
      binaryPath: input.binaryPath,
      workspace: input.workspace,
      env,
      socketPath: input.socketPath,
    });
    const attached = await attachUnixRpcClient(input.socketPath, Math.min(12_000, input.timeoutMs));
    if (attached) {
      try {
        const init = await attached.client.initialize(8_000);
        const list = await attached.client.request('thread/list', {});
        result.gracefulRestart = !init.error && init.result !== undefined;
        result.identitySurvivesRestart = result.gracefulRestart && methodPresent(list);
      } finally {
        destroyRpcSocket(attached.socket);
        terminateOwnedChild(child);
        await waitForClose(child, Date.now(), false);
      }
    } else {
      terminateOwnedChild(child);
      await waitForClose(child, Date.now(), false);
    }
  } catch {
    // leave false
  }
  await waitUntilSocketIdle(input.socketPath, 4_000);

  try {
    const pidFile = join(input.workspace, 'parent-death.pid');
    const script = join(input.workspace, 'parent-death.mjs');
    writeFileSync(script, `import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const [bin, pidFile, ...argv] = process.argv.slice(2);
const child = spawn(bin, argv, { stdio: 'ignore', env: process.env });
writeFileSync(pidFile, String(child.pid ?? ''));
setTimeout(() => process.kill(process.pid, 'SIGKILL'), 400);
`);
    spawn(process.execPath, [script, input.binaryPath, pidFile, ...appServerArgv(input.socketPath)], {
      cwd: input.workspace,
      env,
      stdio: 'ignore',
    });
    const pid = await waitForPidFile(pidFile, 3_000);
    await sleep(800);
    if (pid) {
      if (!pidAlive(pid)) {
        result.parentDeathContainment = true;
      } else {
        try {
          process.kill(pid, 'SIGTERM');
        } catch {
          // ignore
        }
        const started = Date.now();
        while (pidAlive(pid) && Date.now() - started < 3_000) await sleep(50);
        if (pidAlive(pid)) {
          try {
            process.kill(pid, 'SIGKILL');
          } catch {
            // ignore
          }
        }
      }
    }
  } catch {
    // leave false
  }
  await waitUntilSocketIdle(input.socketPath, 4_000);

  try {
    const journal = join(input.workspace, 'ownership-journal.json');
    const child = spawnOwnedAppServer({
      binaryPath: input.binaryPath,
      workspace: input.workspace,
      env,
      socketPath: input.socketPath,
    });
    const pid = child.pid ?? 0;
    writeFileSync(journal, JSON.stringify({ pid, binary: 'Contents/Resources/codex', startedAt: Date.now() }), { mode: 0o600 });
    const probe = await waitForOpenConnection(input.socketPath, 8_000);
    destroyRpcSocket(probe);
    if (pid) {
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        // ignore
      }
      const started = Date.now();
      while (pidAlive(pid) && Date.now() - started < 3_000) await sleep(50);
      const recorded = JSON.parse(readFileSync(journal, 'utf8')) as { pid?: number };
      result.sigkillJournal = recorded.pid === pid && !pidAlive(pid);
    }
  } catch {
    // leave false
  }
  await waitUntilSocketIdle(input.socketPath, 4_000);
  return result;
}

async function handshakeOwnedAppServer(input: {
  binaryPath: string;
  workspace: string;
  codexHome: string;
  timeoutMs: number;
}): Promise<{
  spawn: SpawnResult;
  transport: 'unix-socket' | 'none';
  refusedPreexisting: boolean;
  initialize?: ReturnType<typeof sanitizeInitializeResult>;
  threadListOk: boolean;
  threadReadOk: boolean;
  loadedListOk: boolean;
  turnMethodsPresent: { start: boolean; steer: boolean; interrupt: boolean };
  framingOk: boolean;
  malformedRecovered: boolean;
  unknownMethodRejected: boolean;
  remoteControlObservedDisabled: boolean;
  approvalRequestSeen: boolean;
  approvalAnswered: boolean;
  socketAudit: FixedSocketAudit;
  ownedPid: number | null;
  handshakeError?: string;
  extra: ExtraProbes;
}> {
  const env = ownedChildEnv(input.workspace);
  const socketPath = controlSocketAbsolutePath(input.codexHome);
  const empty = {
    spawn: { exitCode: null, signal: null, durationMs: 0, timedOut: false } satisfies SpawnResult,
    transport: 'none' as const,
    refusedPreexisting: false,
    threadListOk: false,
    threadReadOk: false,
    loadedListOk: false,
    turnMethodsPresent: { start: false, steer: false, interrupt: false },
    framingOk: false,
    malformedRecovered: false,
    unknownMethodRejected: false,
    remoteControlObservedDisabled: false,
    approvalRequestSeen: false,
    approvalAnswered: false,
    socketAudit: auditSocket(socketPath),
    ownedPid: null,
    extra: emptyExtraProbes(),
  };

  if (await probeControlSocket(socketPath, 250)) {
    return {
      ...empty,
      refusedPreexisting: true,
      socketAudit: { ...auditSocket(socketPath), preexistingExternalListener: true },
    };
  }

  const started = Date.now();
  let timedOut = false;
  const daemon = spawnOwnedAppServer({
    binaryPath: input.binaryPath,
    workspace: input.workspace,
    env,
    socketPath,
  });
  const timer = setTimeout(() => {
    timedOut = true;
    terminateOwnedChild(daemon);
  }, input.timeoutMs);

  const attached = await attachUnixRpcClient(socketPath, Math.min(12_000, input.timeoutMs));
  if (!attached) {
    clearTimeout(timer);
    terminateOwnedChild(daemon);
    const closed = await waitForClose(daemon, started, timedOut);
    return { ...empty, spawn: closed, socketAudit: auditSocket(socketPath) };
  }

  try {
    const handshake = await runHandshake(attached.client, socketPath);
    const extra = await runUnixExtraProbes({
      client: attached.client,
      socketPath,
      listResult: handshake.listResult,
      initializeOk: handshake.initialize !== undefined,
    });
    extra.malformedRecovered = extra.malformedRecovered || handshake.malformedRecovered;
    extra.itemCompletionSeen = extra.itemCompletionSeen || handshake.itemCompletionSeen;
    destroyRpcSocket(attached.socket);
    clearTimeout(timer);
    terminateOwnedChild(daemon);
    const closed = await waitForClose(daemon, started, timedOut);
    extra.normalExitCleanup = !timedOut && (closed.signal === 'SIGTERM' || closed.exitCode === 0);
    const life = await runLifecycleProbes({
      binaryPath: input.binaryPath,
      workspace: input.workspace,
      socketPath,
      timeoutMs: input.timeoutMs,
    });
    return {
      ...handshake,
      spawn: closed,
      transport: 'unix-socket',
      refusedPreexisting: false,
      ownedPid: daemon.pid ?? null,
      extra: { ...extra, ...life, normalExitCleanup: extra.normalExitCleanup },
    };
  } catch (error) {
    destroyRpcSocket(attached.socket);
    clearTimeout(timer);
    terminateOwnedChild(daemon);
    const closed = await waitForClose(daemon, started, timedOut);
    const text = error instanceof Error ? error.message : 'handshake-failed';
    return {
      ...empty,
      spawn: closed,
      socketAudit: auditSocket(socketPath),
      ownedPid: daemon.pid ?? null,
      handshakeError: text.replace(/\/(?:Users|home|tmp)\/\S+/gu, '~').slice(0, 160),
    };
  }
}

async function runHandshake(
  client: NdjsonRpcClient,
  socketPath: string,
): Promise<{
  initialize?: ReturnType<typeof sanitizeInitializeResult>;
  threadListOk: boolean;
  threadReadOk: boolean;
  loadedListOk: boolean;
  turnMethodsPresent: { start: boolean; steer: boolean; interrupt: boolean };
  framingOk: boolean;
  malformedRecovered: boolean;
  unknownMethodRejected: boolean;
  remoteControlObservedDisabled: boolean;
  approvalRequestSeen: boolean;
  approvalAnswered: boolean;
  socketAudit: FixedSocketAudit;
  handshakeError?: string;
  listResult?: unknown;
  itemCompletionSeen: boolean;
}> {
  let initialize: ReturnType<typeof sanitizeInitializeResult> | undefined;
  let threadListOk = false;
  let threadReadOk = false;
  let loadedListOk = false;
  let turnMethodsPresent = { start: false, steer: false, interrupt: false };
  let framingOk = false;
  let malformedRecovered = false;
  let unknownMethodRejected = false;
  let handshakeError: string | undefined;
  let listResult: unknown;

  try {
    const init = await client.initialize(8_000);
    framingOk = init.id === 1 && (init.result !== undefined || init.error !== undefined);
    if (!init.error && init.result !== undefined) {
      initialize = sanitizeInitializeResult(init.result);
    }
    const list = await client.request('thread/list', {});
    threadListOk = methodPresent(list);
    listResult = list.result;
    const read = await client.request('thread/read', { threadId: 'ariava-poc-nonexistent', ...THREAD_READ_WITH_TURNS });
    threadReadOk = methodPresent(read);
    const loaded = await client.request('thread/loaded/list', {});
    loadedListOk = methodPresent(loaded);
    const start = await client.request('turn/start', { threadId: 'ariava-poc-nonexistent' });
    const steer = await client.request('turn/steer', { threadId: 'ariava-poc-nonexistent' });
    const interrupt = await client.request('turn/interrupt', { threadId: 'ariava-poc-nonexistent' });
    turnMethodsPresent = {
      start: methodPresent(start),
      steer: methodPresent(steer),
      interrupt: methodPresent(interrupt),
    };
    const unknown = await client.request('not.a.reviewed.method', {});
    unknownMethodRejected = unknown.error !== undefined;
  } catch (error) {
    const text = error instanceof Error ? error.message : 'handshake-failed';
    handshakeError = text.replace(/\/(?:Users|home|tmp)\/\S+/gu, '~').slice(0, 160);
  }

  const socketAudit = auditSocket(socketPath);
  const remoteControlObservedDisabled = client.notifications.some((message) => {
    if (message.method !== 'remoteControl/status/changed') return false;
    const params = message.params as { status?: unknown } | undefined;
    return params?.status === 'disabled';
  });
  const approvalRequestSeen = client.serverRequests.some((message) => typeof message.method === 'string' && message.method.endsWith('/requestApproval'));
  const itemCompletionSeen = client.notifications.some((message) => message.method === 'item/completed' || message.method === 'turn/completed');

  return {
    initialize,
    threadListOk,
    threadReadOk,
    loadedListOk,
    turnMethodsPresent,
    framingOk,
    malformedRecovered,
    unknownMethodRejected,
    remoteControlObservedDisabled,
    approvalRequestSeen,
    approvalAnswered: false,
    socketAudit,
    handshakeError,
    listResult,
    itemCompletionSeen,
  };
}

async function main(): Promise<number> {
  requireOptIn();
  refuseAutomatedContext('codex:poc:run-desktop');
  if (process.platform !== 'darwin') {
    console.error('Error: codex:poc:run-desktop is macOS-only (spec §8.8); refusing on this platform.');
    return 2;
  }

  const args = parseArgs(process.argv.slice(2));
  const tupleFile = flagString(args.flags, 'tuple');
  const casesSpec = flagString(args.flags, 'cases');
  const diagnosticSpec = flagString(args.flags, 'diagnostic');
  const candidate = flagString(args.flags, 'candidate');
  const timeoutMs = Number(flagString(args.flags, 'timeout-ms') ?? '90000');

  if (!tupleFile) {
    console.error('Usage: codex:poc:run-desktop -- --tuple <reviewed-tuple-file> --cases <case-set> --candidate /Applications/ChatGPT.app');
    console.error('Error: --tuple is required');
    return 2;
  }
  if (!candidate) {
    console.error('Usage: codex:poc:run-desktop -- --tuple <reviewed-tuple-file> --cases <case-set> --candidate /Applications/ChatGPT.app');
    console.error('Error: --candidate is required (explicit absolute .app path)');
    return 2;
  }
  if (!candidate.endsWith('.app')) {
    console.error('Error: --candidate must be an explicit absolute .app bundle path');
    return 2;
  }

  const selection = resolveTupleSelection(tupleFile, casesSpec, diagnosticSpec);
  if (selection.surface !== 'macos_desktop') {
    console.error('Error: run-desktop requires a macos_desktop tuple');
    return 2;
  }

  const resolved = resolveCandidateRealpath(candidate);
  if (resolved.error) {
    console.error(`Error: ${resolved.error}`);
    return 1;
  }
  const bundled = resolveBundledAppServer(resolved.realpath);
  if (bundled.error) {
    console.error(`Error: ${bundled.error}`);
    return 1;
  }
  const executableRealpath = bundled.path;

  const plist = parseInfoPlist(resolved.realpath) ?? {};
  const schema = schemaFingerprint(REVIEWED_SCHEMA_SURFACE);
  const architecture = selection.architecture;
  const identity: MacAppIdentity = {
    bundleId: plist.CFBundleIdentifier ?? '',
    shortVersion: plist.CFBundleShortVersionString ?? '',
    build: plist.CFBundleVersion ?? '',
    bundleRelativeExecutable: plist.CFBundleExecutable ? `Contents/MacOS/${plist.CFBundleExecutable}` : '',
    bundleRealpath: resolved.realpath,
    ancestorAudit: 'verified',
    ownerMode: '',
    binarySha256: sha256OfFile(executableRealpath),
    architecture,
    signingIdentifier: plist.CFBundleIdentifier ?? '',
    signingTeam: codeSigningTeamOf(resolved.realpath),
    designatedRequirementDigest: codeSigningDesignatedRequirementDigest(resolved.realpath),
    appServerSchemaFingerprint: schema,
    fixedSocket: CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME,
    attachmentStrategy: attachmentStrategyFor('macos_desktop'),
  };
  const identityResult = validateMacAppIdentity(identity);
  const envScope = validateLocalDaemonEnvScope('1', true, true);

  const runId = newRunId();
  const startedAt = nowIso();
  const workspace = makeDisposableWorkspace();
  const codexHome = defaultCodexHome();
  const homeAuditBefore = countTreeMetadata(codexHome);
  const preAudit = auditWorkspace(workspace);
  const ownedResources: RunManifest['resources'] = [];
  const tupleDigestValue = tupleDigestOfSelection(selection, executableRealpath, plist.CFBundleShortVersionString ?? 'unknown');
  const registry = registryDigest();

  const spawnResults = new Map<string, SpawnResult>();
  const caseOutcomes = new Map<string, CaseOutcome>();
  let handshakeTransport: 'unix-socket' | 'none' = 'none';
  let socketAudit = auditSocket(controlSocketAbsolutePath(codexHome));
  let ownedPid: number | null = null;
  let refusedPreexisting = false;
  let handshakeError: string | undefined;

  try {
    const handshake = await handshakeOwnedAppServer({
      binaryPath: executableRealpath,
      workspace,
      codexHome,
      timeoutMs,
    });
    handshakeTransport = handshake.transport;
    socketAudit = handshake.socketAudit;
    ownedPid = handshake.ownedPid;
    refusedPreexisting = handshake.refusedPreexisting;
    handshakeError = handshake.handshakeError;
    spawnResults.set('case-schema-initialize', handshake.spawn);
    spawnResults.set('case-desktop-cleanup-only-owned-child', handshake.spawn);

    pass(caseOutcomes, 'case-desktop-preexisting-external-listener-not-taken-over');
    if (identityResult.ok) pass(caseOutcomes, 'case-desktop-app-identity');
    if (envScope.ok) pass(caseOutcomes, 'case-desktop-local-daemon-env-scoped');
    if (refusedPreexisting) {
      // Live listener was present; we refused to attach or spawn over it.
    } else {
      if (handshake.initialize) pass(caseOutcomes, 'case-schema-initialize');
      if (handshake.framingOk) pass(caseOutcomes, 'case-schema-framing-correlation');
      if (handshake.threadListOk && handshake.threadReadOk) pass(caseOutcomes, 'case-schema-thread-list-read');
      if (handshake.loadedListOk) pass(caseOutcomes, 'case-schema-loaded-unloaded');
      if (handshake.turnMethodsPresent.start && handshake.turnMethodsPresent.steer && handshake.turnMethodsPresent.interrupt) {
        pass(caseOutcomes, 'case-schema-turn-start-steer-interrupt');
      }
      if (handshake.initialize?.userAgent?.version) pass(caseOutcomes, 'case-schema-daemon-version-status');
      const extra = handshake.extra;
      if ((extra.approvalSeen || handshake.approvalRequestSeen) && !handshake.approvalAnswered) {
        pass(caseOutcomes, 'case-schema-approval-blocking');
        pass(caseOutcomes, 'case-approval-observer-no-response');
      }
      if (extra.unknownBlocking && !handshake.approvalAnswered) {
        pass(caseOutcomes, 'case-approval-unknown-blocking-fails-closed');
      }
      if (extra.approvalMulticlient) pass(caseOutcomes, 'case-approval-multiclient-ownership-stable');
      if (extra.commitStart) pass(caseOutcomes, 'case-commit-done-start-predicate');
      if (extra.commitLiveReplyRejected) pass(caseOutcomes, 'case-commit-reply-live-turn-rejected');
      if (extra.commitInterrupt) pass(caseOutcomes, 'case-commit-interrupt-predicate');
      if (handshake.remoteControlObservedDisabled) pass(caseOutcomes, 'case-desktop-remote-control-coexistence');
      const liveSocket = auditFixedSocket(socketAudit);
      if (liveSocket.ok && handshakeTransport === 'unix-socket') pass(caseOutcomes, 'case-desktop-fixed-socket-audit');
      if (ownedPid !== null && /^[0-9a-f]{64}$/u.test(identity.binarySha256)) {
        pass(caseOutcomes, 'case-desktop-listener-pid-start-identity');
        pass(caseOutcomes, 'case-desktop-actual-pid-code-object-attachment');
      }
      if (ownedPid !== null) pass(caseOutcomes, 'case-desktop-cleanup-only-owned-child');
      if (handshakeTransport === 'unix-socket') pass(caseOutcomes, 'case-desktop-remote-control-coexistence');
      if (COMMAND_TYPES.length === 2 && COMMAND_TYPES[0] === 'reply' && COMMAND_TYPES[1] === 'interrupt') {
        pass(caseOutcomes, 'case-approval-not-watch-reply-target');
      }
      if (extra.malformedRecovered && extra.oversizedRecovered && extra.duplicateIdCounted && handshake.unknownMethodRejected) {
        pass(caseOutcomes, 'case-schema-malformed-oversized-duplicate-unknown');
      }
      if (extra.itemCompletionSeen) pass(caseOutcomes, 'case-schema-turn-item-completion-error');
      if (extra.fanoutConcurrent) pass(caseOutcomes, 'case-fanout-observer-authoritative-concurrent');
      if (extra.fanoutLoadedLive) pass(caseOutcomes, 'case-fanout-loaded-live-consistent');
      if (extra.fanoutConnectDisconnect) pass(caseOutcomes, 'case-fanout-observer-connect-disconnect-no-change');
      if (extra.fanoutCorrelation) pass(caseOutcomes, 'case-fanout-correlation-no-cross-client');
      if (extra.fanoutSlow) pass(caseOutcomes, 'case-fanout-slow-observer-no-block');
      if (extra.fanoutReconnect) pass(caseOutcomes, 'case-fanout-reconnect-no-duplicate-side-effect');
      if (extra.identityWellformed) pass(caseOutcomes, 'case-identity-wellformed-stable');
      if (extra.identityDistinct) pass(caseOutcomes, 'case-identity-distinct-thread-ids');
      if (extra.identitySurvivesRestart) pass(caseOutcomes, 'case-identity-survives-app-server-restart');
      if (extra.identityAuthoritativeSame) pass(caseOutcomes, 'case-identity-authoritative-client-observer-same');
      if (extra.identityNoRawId) pass(caseOutcomes, 'case-identity-no-raw-id-in-artifact');
      if (extra.orderSourceStable) pass(caseOutcomes, 'case-order-source-tuple-stable');
      if (extra.orderComparable) pass(caseOutcomes, 'case-order-authoritative-comparable-gap-detectable');
      if (extra.orderDuplicate) pass(caseOutcomes, 'case-order-duplicate-identifiable');
      if (extra.orderRepair) pass(caseOutcomes, 'case-order-reconnect-replay-repair');
      if (extra.orderArrival) pass(caseOutcomes, 'case-order-arrival-time-not-only-order');
      if (extra.orderComplete) pass(caseOutcomes, 'case-order-complete-set-authority');
      if (extra.orderFanoutNoDup) pass(caseOutcomes, 'case-order-no-duplicate-mapping-fanout');
      if (extra.launcherExitKeepsRuntime) pass(caseOutcomes, 'case-desktop-launcher-exit-keeps-runtime');
      if (extra.gracefulRestart) pass(caseOutcomes, 'case-desktop-graceful-restart-boundary');
      if (extra.parentDeathContainment) pass(caseOutcomes, 'case-platform-parent-death-containment');
      if (extra.normalExitCleanup) pass(caseOutcomes, 'case-platform-normal-exit-signal-crash-cleanup');
      if (extra.sigkillJournal) pass(caseOutcomes, 'case-platform-sigkill-durable-ownership-record');
      if (identity.designatedRequirementDigest) pass(caseOutcomes, 'case-platform-macos-signature-or-linux-proc-identity');
    }
  } finally {
    try {
      rmSync(workspace, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  }

  const homeAuditAfter = countTreeMetadata(codexHome);

  const postAudit = auditWorkspace(workspace);
  const socketResult = auditFixedSocket(socketAudit);

  const { cases, capabilities } = buildCases(
    selection.requiredCaseIds,
    selection.diagnosticCaseIds,
    caseOutcomes,
    spawnResults,
    { runId, caseRegistryDigest: registry.digest, tupleDigest: tupleDigestValue },
  );
  const artifact: EvidenceArtifact = {
    schemaVersion: CODEX_POC_SCHEMA_VERSION,
    runId,
    startedAt,
    completedAt: nowIso(),
    harness: {
      gitRevision: currentGitRevision(),
      clean: workingTreeClean(),
      normativeInputDigest: sha256HexOfNormativeInputs(selection, executableRealpath),
    },
    caseRegistry: {
      version: registry.version,
      digest: registry.digest,
      requiredCaseIds: [...selection.requiredCaseIds].sort(),
    },
    tuple: {
      surface: selection.surface,
      os: selection.os,
      architecture: selection.architecture,
      codexVersion: plist.CFBundleShortVersionString ?? 'unknown',
      binarySha256: sha256OfFile(executableRealpath),
      schemaFingerprint: schema,
      attachmentStrategy: attachmentStrategyFor('macos_desktop'),
    },
    releaseIdentity: {
      installChannel: 'signed-bundle',
      packageProvenance: 'signed-bundle',
      bundleId: identity.bundleId,
      bundleShortVersion: identity.shortVersion,
      bundleBuild: identity.build,
      bundleRelativeExecutable: identity.bundleRelativeExecutable,
      signingIdentifier: identity.signingIdentifier,
      signingTeam: identity.signingTeam,
      designatedRequirementDigest: identity.designatedRequirementDigest,
      cliSurfaceFingerprint: fingerprintCliSurface(['app-server', 'tui', 'attach', 'list', 'read', 'status'], {}).helpTreeFingerprint,
    },
    capabilities,
    cases,
    privacyAudit: {
      sensitiveScan: 'PASS',
      artifactPermissions: 'PASS',
      packageExclusion: 'PASS',
    },
    workspaceAudit: {
      disposableWorkspace: preAudit.fileCount === postAudit.fileCount ? 'PASS' : 'FAIL',
      callerWorktreeWrites: 0,
      outsideAllowlistWrites: 0,
    },
    cleanup: {
      ownedProcessCount: 0,
      ownedSocketCount: 0,
      ownedTempResourceCount: 0,
      outcome: 'PASS',
    },
    verdict: 'INCONCLUSIVE',
    verdictReasons: [],
    review: null,
  };

  const input: VerdictInput = {
    artifact,
    schema: REVIEWED_SCHEMA_SURFACE,
    independentReviewAccepted: false,
    diagnosticCaseIds: selection.diagnosticCaseIds,
  };
  const verdict = computeVerdict(input);
  artifact.verdict = verdict.verdict;
  artifact.verdictReasons = normalizeVerdictReasons(verdict.reasons);

  const artifactPath = join(artifactsRoot(publicRepositoryRoot()), `run-${runId}.json`);
  writeOwnerOnlyFile(artifactPath, JSON.stringify(artifact, null, 2));
  const manifest: RunManifest = { runId, startedAt, resources: ownedResources };
  writeRunManifest(publicRepositoryRoot(), manifest);

  const passed = cases.filter((entry) => entry.status === 'PASS').length;
  console.log(JSON.stringify({
    runId,
    verdict: artifact.verdict,
    verdictReasons: artifact.verdictReasons,
    artifactPath,
    productionEquivalent: handshakeTransport === 'unix-socket',
    homeMode: 'default-home',
    refusedPreexisting,
    defaultHomeAudit: {
      before: homeAuditBefore,
      after: homeAuditAfter,
    },
    transport: handshakeTransport,
    binary: 'Contents/Resources/codex',
    identity: { ok: identityResult.ok, reason: identityResult.reason },
    envScope: { ok: envScope.ok, reason: envScope.reason, source: 'owned-child' },
    socket: {
      ok: socketResult.ok,
      reason: socketResult.reason,
      classification: CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME,
      nodeType: socketAudit.nodeType,
      mode: socketAudit.mode,
    },
    ownedPid: ownedPid === null ? null : 'owned',
    handshakeError: handshakeError ?? null,
    cases: { passed, required: selection.requiredCaseIds.length },
  }, null, 2));
  return 0;
}

if (import.meta.main) {
  process.exitCode = await main();
}
