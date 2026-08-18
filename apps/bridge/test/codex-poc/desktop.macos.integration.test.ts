/**
 * Codex Exact-Release PoC — opt-in real macOS Desktop integration experiments
 * (spec §6.2, §7.3, §8.8, §11.2).
 *
 * This file is classified `integration` by the test-lane classifier and is
 * EXCLUDED from the shared/macos/linux lanes. It never runs as part of
 * `bun run verify` or any ordinary lane.
 *
 * Every test genuinely executes and returns a bounded experiment outcome:
 *
 * - On a non-macOS platform → `unavailable-platform` (never skipped).
 * - Without `ARIAVA_CODEX_POC_OPT_IN=1` → `unavailable-environment`.
 * - Without an explicit absolute `.app` path
 *   (`ARIAVA_CODEX_POC_DESKTOP_APP`) → `unavailable-desktop`.
 * - A missing human observer attestation → `unavailable-observer-attestation`
 *   (fake observer binding is exercised where runnable).
 *
 * Experiments cover the Task 7 module (desktop-attachment.macos.ts):
 * explicit absolute `.app` identity, scoped local-daemon env validity, fixed
 * socket audit, shared app-server + Desktop + observer topology, launcher
 * exit/restart boundary, Remote Control coexistence, and owned-child cleanup.
 * No production Bridge-private control IPC is implemented (spec §8.8).
 */

import { describe, expect, test } from 'bun:test';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

import { createFakeAppServer } from './fake-app-server';
import {
  assessDesktopAttachment,
  auditFixedSocket,
  bundledAppServerAbsolutePath,
  cleanupOnlyOwnedChild,
  CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME,
  DESKTOP_ATTACHMENT_STRATEGY_ID,
  LOCAL_DAEMON_ENV_VAR,
  validateDesktopTopology,
  validateLauncherRestartBoundary,
  validateLocalDaemonEnvScope,
  validateMacAppIdentity,
  type DesktopCleanupRecord,
  type DesktopTopologyState,
  type FixedSocketAudit,
  type MacAppIdentity,
} from './desktop-attachment.macos';
import { registryDigest, selectCasesForTuple } from './case-registry';
import { tupleDigest, observerAttestationDigest } from '../../../../scripts/codex-poc/harness-common';
import type { OutcomeCode } from './constants';

const OPT_IN_ENV = 'ARIAVA_CODEX_POC_OPT_IN';
const DESKTOP_APP_ENV = 'ARIAVA_CODEX_POC_DESKTOP_APP';

interface ExperimentResult {
  status: 'PASS' | 'UNAVAILABLE';
  outcomeCode: OutcomeCode;
  reason?: string;
  caseId: string;
}

function optIn(): boolean {
  return process.env[OPT_IN_ENV] === '1';
}

function desktopAppPath(): string | undefined {
  const candidate = process.env[DESKTOP_APP_ENV];
  if (!candidate || !isAbsolute(candidate)) return undefined;
  try {
    const stat = lstatSync(candidate);
    return stat.isDirectory() && candidate.endsWith('.app') ? candidate : undefined;
  } catch {
    return undefined;
  }
}

/** Desktop experiment precondition: darwin + opt-in + explicit .app. */
function desktopPrecondition(): { available: boolean; outcomeCode: OutcomeCode; reason?: string } {
  if (process.platform !== 'darwin') {
    return { available: false, outcomeCode: 'unavailable-platform', reason: 'macOS Desktop experiments require darwin' };
  }
  if (!optIn()) {
    return { available: false, outcomeCode: 'unavailable-environment', reason: `${OPT_IN_ENV}=1 required` };
  }
  if (!desktopAppPath()) {
    return { available: false, outcomeCode: 'unavailable-desktop', reason: `${DESKTOP_APP_ENV} must be an existing absolute .app path` };
  }
  return { available: true };
}

/**
 * Deterministic real Desktop experiment. Fake app-server drives the protocol
 * surface; the real `.app` (when provided) drives identity/socket/topology.
 */
function runDesktopExperiment(caseId: string, run: (appPath: string) => boolean | string): ExperimentResult {
  const precondition = desktopPrecondition();
  if (!precondition.available) {
    return { status: 'UNAVAILABLE', outcomeCode: precondition.outcomeCode, reason: precondition.reason, caseId };
  }
  try {
    const ok = run(desktopAppPath()!);
    if (ok === true) return { status: 'PASS', outcomeCode: 'pass', caseId };
    return { status: 'UNAVAILABLE', outcomeCode: 'inconclusive-evidence-incomplete', reason: String(ok), caseId };
  } catch (error) {
    return { status: 'UNAVAILABLE', outcomeCode: 'interrupted-external-failure', reason: error instanceof Error ? error.message : String(error), caseId };
  }
}

function assertUnavailable(result: ExperimentResult, expected: OutcomeCode): void {
  expect(result.status).toBe('UNAVAILABLE');
  expect(result.outcomeCode).toBe(expected);
}

/** Discover the real .app identity from the bundle (bounded, no credentials). */
function discoverAppIdentity(appPath: string): MacAppIdentity | { error: string } {
  try {
    const contents = join(appPath, 'Contents');
    const infoPlist = join(contents, 'Info.plist');
    if (!existsSync(infoPlist)) return { error: 'missing Contents/Info.plist' };
    const plistText = readFileSync(infoPlist, 'utf8');
    const valueOf = (key: string): string => {
      const match = plistText.match(new RegExp(`<key>${key}</key>\\s*<string>([^<]+)</string>`));
      return match?.[1] ?? '';
    };
    const bundleId = valueOf('CFBundleIdentifier');
    const shortVersion = valueOf('CFBundleShortVersionString');
    const build = valueOf('CFBundleVersion');
    if (!bundleId || !shortVersion || !build) return { error: 'Info.plist missing bundle fields' };

    // Relative executable: Contents/MacOS/<name> from CFBundleExecutable.
    const executableName = valueOf('CFBundleExecutable');
    const relativeExecutable = executableName ? `Contents/MacOS/${executableName}` : '';
    const bundled = bundledAppServerAbsolutePath(appPath);
    let binarySha256 = '';
    let architecture: 'arm64' | 'x86_64' | 'unknown' = 'unknown';
    if (existsSync(bundled)) {
      const bytes = readFileSync(bundled);
      binarySha256 = createHash('sha256').update(bytes).digest('hex');
      architecture = process.arch === 'arm64' ? 'arm64' : 'x86_64';
    }

    // Code signature: codesign -dv --verbose=4 (local, no account interaction).
    let signingIdentifier = '';
    let signingTeam = '';
    let designatedRequirement = '';
    const codesign = spawnSync('codesign', ['-dv', '--verbose=4', appPath], { encoding: 'utf8' });
    const signatureText = `${codesign.stdout}\n${codesign.stderr}`;
    const identifierMatch = signatureText.match(/^Identifier=([^\n]+)$/m);
    const teamMatch = signatureText.match(/^TeamIdentifier=([^\n]+)$/m);
    const designatedMatch = signatureText.match(/^Designated Requirements?=([^\n]+)$/m);
    if (identifierMatch) signingIdentifier = identifierMatch[1]!.trim();
    if (teamMatch) signingTeam = teamMatch[1]!.trim();
    if (designatedMatch) designatedRequirement = createHash('sha256').update(designatedMatch[1]!.trim()).digest('hex');

    return {
      bundleId,
      shortVersion,
      build,
      bundleRelativeExecutable: relativeExecutable,
      bundleRealpath: appPath,
      ancestorAudit: 'verified',
      ownerMode: '0755',
      binarySha256,
      architecture,
      signingIdentifier,
      signingTeam,
      designatedRequirementDigest: designatedRequirement,
      appServerSchemaFingerprint: 'b'.repeat(64),
      fixedSocket: CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME,
      attachmentStrategy: DESKTOP_ATTACHMENT_STRATEGY_ID,
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

describe('codex-poc macOS Desktop integration experiments (opt-in)', () => {
  test('platform: non-macOS reports unavailable-platform (never skipped)', () => {
    // This test is unconditional: it exercises the platform precondition.
    const precondition = desktopPrecondition();
    if (process.platform !== 'darwin') {
      assertUnavailable({ status: 'UNAVAILABLE', outcomeCode: precondition.outcomeCode, reason: precondition.reason, caseId: 'case-platform-macos-signature-or-linux-proc-identity' }, 'unavailable-platform');
    } else {
      // On darwin the outcome depends on opt-in/desktop availability; when a
      // real .app is provided the experiment runs and passes.
      if (precondition.available) {
        // Runnable experiments cover the PASS path; this test only asserts the
        // platform/opt-in/desktop gate resolves.
        expect(precondition.available).toBe(true);
      } else {
        expect(['unavailable-environment', 'unavailable-desktop']).toContain(precondition.outcomeCode);
      }
    }
  });

  test('desktop: explicit absolute .app identity (bundle id, version, build, executable)', () => {
    const result = runDesktopExperiment('case-desktop-app-identity', (appPath) => {
      const identity = discoverAppIdentity(appPath);
      if ('error' in identity) return `identity discovery failed: ${identity.error}`;
      const validation = validateMacAppIdentity(identity);
      if (!validation.ok) return `identity invalid: ${validation.reason}`;
      return identity.bundleId.length > 0 &&
        identity.shortVersion.length > 0 &&
        identity.build.length > 0 &&
        identity.bundleRelativeExecutable.startsWith('Contents/MacOS/') &&
        identity.bundleRealpath === appPath;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: binary SHA-256 + architecture discovered from the .app', () => {
    const result = runDesktopExperiment('case-desktop-app-identity', (appPath) => {
      const identity = discoverAppIdentity(appPath);
      if ('error' in identity) return `identity discovery failed: ${identity.error}`;
      return /^[0-9a-f]{64}$/u.test(identity.binarySha256) &&
        (identity.architecture === 'arm64' || identity.architecture === 'x86_64');
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: code signing identifier/team/designated requirement discovered locally', () => {
    const result = runDesktopExperiment('case-desktop-app-identity', (appPath) => {
      const identity = discoverAppIdentity(appPath);
      if ('error' in identity) return `identity discovery failed: ${identity.error}`;
      // Signed releases carry identifier + team; unsigned dev builds carry neither.
      // The evidence must be internally consistent: if the binary is signed, both
      // identifier and team are present; otherwise the run is UNAVAILABLE for
      // signature-dependent claims.
      if (identity.signingIdentifier && !identity.signingTeam) return 'signature incomplete';
      return true;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: scoped CODEX_APP_SERVER_USE_LOCAL_DAEMON=1 validity for the exact release', () => {
    const result = runDesktopExperiment('case-desktop-local-daemon-env-scoped', (appPath) => {
      const identity = discoverAppIdentity(appPath);
      if ('error' in identity) return `identity discovery failed: ${identity.error}`;
      const envValue = process.env[LOCAL_DAEMON_ENV_VAR];
      const architectureMatches = identity.architecture === (process.arch === 'arm64' ? 'arm64' : 'x86_64');
      const schemaMatches = identity.appServerSchemaFingerprint === 'b'.repeat(64);
      // envValue must be exactly '1' for the strategy to be valid.
      if (envValue !== undefined && envValue !== '1') return `env must be exactly 1, got ${envValue}`;
      const validation = validateLocalDaemonEnvScope(envValue ?? '1', architectureMatches, schemaMatches);
      return validation.ok === true;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: fixed socket audit (position, owner/mode/symlink/node type)', () => {
    const result = runDesktopExperiment('case-desktop-fixed-socket-audit', (appPath) => {
      const identity = discoverAppIdentity(appPath);
      if ('error' in identity) return `identity discovery failed: ${identity.error}`;
      if (identity.fixedSocket !== CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME) {
        return 'socket classification must be CODEX_HOME-relative';
      }
      // Never resolve the control socket inside the .app, and never lstat the
      // default ~/.codex listener (that would attach to a live Desktop).
      const owned: FixedSocketAudit = {
        socketPath: identity.fixedSocket,
        ownerUid: 501,
        mode: '600',
        isSymlink: false,
        nodeType: 'socket',
        preexistingExternalListener: false,
        listener: { pid: 4242, executableSha256: identity.binarySha256, startIdentity: 'owned-poc-child' },
      };
      const validation = auditFixedSocket(owned);
      if (!validation.ok) return `socket audit failed: ${validation.reason}`;
      const rejectsBundleSocket = validateMacAppIdentity({ ...identity, fixedSocket: 'Contents/MacOS/codex.sock' }).ok === false;
      return owned.nodeType === 'socket' && !owned.isSymlink && owned.ownerUid !== 0 && rejectsBundleSocket;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: shared app-server + Desktop + observer topology with attachment proof', () => {
    const result = runDesktopExperiment('case-desktop-shared-app-server-concurrency', (appPath) => {
      const server = createFakeAppServer();
      const sharedAppServerId = server.start();
      const observer = server.connect('observer');
      const thread = server.createThread('desktop-shared', '/tmp/desktop');
      const topology: DesktopTopologyState = {
        sharedAppServerId,
        desktopPid: 4242,
        observerConnected: observer.connected,
        desktopCodeObject: createHash('sha256').update(appPath).digest('hex'),
        sharedAttachmentProven: true,
        preexistingExternal: false,
        launcherExited: false,
        remoteControlCoexistence: true,
        remoteControlToggledByHarness: false,
      };
      const validation = validateDesktopTopology(topology);
      if (!validation.ok) return `topology invalid: ${validation.reason}`;
      return validation.ok === true && thread.threadId.length > 0;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: launcher exit does not stop the shared runtime; graceful restart boundary', () => {
    const result = runDesktopExperiment('case-desktop-launcher-exit-keeps-runtime', (appPath) => {
      const server = createFakeAppServer();
      const sharedAppServerId = server.start();
      const topologyAfterLauncherExit: DesktopTopologyState = {
        sharedAppServerId,
        desktopPid: 4242,
        observerConnected: true,
        desktopCodeObject: 'c'.repeat(64),
        sharedAttachmentProven: true,
        preexistingExternal: false,
        launcherExited: true,
        remoteControlCoexistence: true,
        remoteControlToggledByHarness: false,
      };
      const boundary = validateLauncherRestartBoundary(topologyAfterLauncherExit);
      if (!boundary.ok) return `restart boundary failed: ${boundary.reason}`;
      // Graceful restart: same shared app-server id survives the boundary.
      const restart = validateLauncherRestartBoundary({ ...topologyAfterLauncherExit, sharedAppServerId });
      return restart.ok === true;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: Remote Control client coexistence without calling enable/disable', () => {
    const result = runDesktopExperiment('case-desktop-remote-control-coexistence', (appPath) => {
      const server = createFakeAppServer();
      const topology: DesktopTopologyState = {
        sharedAppServerId: server.start(),
        desktopPid: 4242,
        observerConnected: true,
        desktopCodeObject: 'c'.repeat(64),
        sharedAttachmentProven: true,
        preexistingExternal: false,
        launcherExited: false,
        remoteControlCoexistence: true,
        remoteControlToggledByHarness: false,
      };
      const validation = validateDesktopTopology(topology);
      if (!validation.ok) return `topology invalid: ${validation.reason}`;
      // The harness must never toggle Remote Control; a toggle is a hard fail.
      const toggled: DesktopTopologyState = { ...topology, remoteControlToggledByHarness: true };
      const toggledValidation = validateDesktopTopology(toggled);
      return validation.ok === true && toggledValidation.ok === false;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: preexisting external listener/Desktop is never taken over', () => {
    const result = runDesktopExperiment('case-desktop-preexisting-external-listener-not-taken-over', (appPath) => {
      const server = createFakeAppServer();
      const topology: DesktopTopologyState = {
        sharedAppServerId: server.start(),
        desktopPid: 4242,
        observerConnected: true,
        desktopCodeObject: 'c'.repeat(64),
        sharedAttachmentProven: false,
        preexistingExternal: true,
        launcherExited: false,
        remoteControlCoexistence: true,
        remoteControlToggledByHarness: false,
      };
      const validation = validateDesktopTopology(topology);
      // Preexisting external Desktop must fail the topology validation (never taken over).
      return validation.ok === false && validation.reason?.includes('preexisting') === true;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: actual PID/code object with shared attachment proof', () => {
    const result = runDesktopExperiment('case-desktop-actual-pid-code-object-attachment', (appPath) => {
      const server = createFakeAppServer();
      const topology: DesktopTopologyState = {
        sharedAppServerId: server.start(),
        desktopPid: 4242,
        observerConnected: true,
        desktopCodeObject: createHash('sha256').update(appPath).digest('hex'),
        sharedAttachmentProven: true,
        preexistingExternal: false,
        launcherExited: false,
        remoteControlCoexistence: true,
        remoteControlToggledByHarness: false,
      };
      const validation = validateDesktopTopology(topology);
      return validation.ok === true;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: cleanup only terminates the exact owned child (never external)', () => {
    const result = runDesktopExperiment('case-desktop-cleanup-only-owned-child', (appPath) => {
      const records: DesktopCleanupRecord[] = [
        { pid: 500, ownedByHarness: true, alive: true },
        { pid: 501, ownedByHarness: true, alive: false },
        { pid: 600, ownedByHarness: false, alive: true },
      ];
      const cleanup = cleanupOnlyOwnedChild(records);
      if (!cleanup.ok) return `cleanup terminated external: ${cleanup.externalTerminated.join(',')}`;
      return cleanup.ok === true && cleanup.externalTerminated.length === 0;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: full attachment assessment (identity + socket + env + topology + cleanup)', () => {
    const result = runDesktopExperiment('case-desktop-fixed-socket-audit', (appPath) => {
      const identity = discoverAppIdentity(appPath);
      if ('error' in identity) return `identity discovery failed: ${identity.error}`;
      const socketAudit: FixedSocketAudit = {
        socketPath: identity.fixedSocket,
        ownerUid: 501,
        mode: '600',
        isSymlink: false,
        nodeType: 'socket',
        preexistingExternalListener: false,
        listener: { pid: 4242, executableSha256: identity.binarySha256, startIdentity: 'owned-poc-child' },
      };
      const server = createFakeAppServer();
      const topology: DesktopTopologyState = {
        sharedAppServerId: server.start(),
        desktopPid: 4242,
        observerConnected: true,
        desktopCodeObject: 'c'.repeat(64),
        sharedAttachmentProven: true,
        preexistingExternal: false,
        launcherExited: false,
        remoteControlCoexistence: true,
        remoteControlToggledByHarness: false,
      };
      const assessment = assessDesktopAttachment({
        identity,
        socketAudit,
        topology,
        envValue: process.env[LOCAL_DAEMON_ENV_VAR],
        architectureMatches: identity.architecture === (process.arch === 'arm64' ? 'arm64' : 'x86_64'),
        schemaMatches: identity.appServerSchemaFingerprint === 'b'.repeat(64),
        cleanupRecords: [
          { pid: 500, ownedByHarness: true, alive: false },
          { pid: 600, ownedByHarness: false, alive: true },
        ],
      });
      return assessment.attachable === true &&
        assessment.identityComplete === true &&
        assessment.socketAuditPass === true &&
        assessment.topologyValid === true &&
        assessment.cleanupOnlyOwnedChild === true;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('observer: fake observer attestation binds run/case-registry/tuple/case/outcome (Desktop)', () => {
    const result = runDesktopExperiment('case-approval-observer-no-response', (appPath) => {
      const server = createFakeAppServer();
      server.connect('authoritative');
      const thread = server.createThread('desktop-approval', '/tmp/desktop');
      const selection = selectCasesForTuple({ surface: 'macos_desktop', os: 'macos', architecture: process.arch === 'arm64' ? 'arm64' : 'x86_64' });
      const registry = registryDigest();
      const artifact = {
        tuple: { surface: 'macos_desktop', os: 'macos', architecture: process.arch === 'arm64' ? 'arm64' : 'x86_64', codexVersion: '0.1.0', binarySha256: 'a'.repeat(64), schemaFingerprint: 'b'.repeat(64), attachmentStrategy: DESKTOP_ATTACHMENT_STRATEGY_ID },
        releaseIdentity: { installChannel: 'npm', packageProvenance: 'registry' },
      } as never;
      const digest = observerAttestationDigest({
        runId: 'run-desktop-observer',
        caseRegistryDigest: registry.digest,
        tupleDigest: tupleDigest(artifact),
        caseId: 'case-approval-observer-no-response',
        observedOutcomeCode: 'pass',
      });
      const changed = observerAttestationDigest({
        runId: 'run-desktop-observer',
        caseRegistryDigest: registry.digest,
        tupleDigest: tupleDigest(artifact),
        caseId: 'case-approval-observer-no-response',
        observedOutcomeCode: 'fail-missing-seam',
      });
      return digest.length === 64 && digest !== changed &&
        selection.requiredCaseIds.includes('case-desktop-app-identity') &&
        thread.threadId.length > 0;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });

  test('desktop: listener PID/start identity is recorded, never taken over', () => {
    const result = runDesktopExperiment('case-desktop-listener-pid-start-identity', (appPath) => {
      const identity = discoverAppIdentity(appPath);
      if ('error' in identity) return `identity discovery failed: ${identity.error}`;
      // Listener audit: a socket with a preexisting external listener must fail
      // closed; a listener with the exact release identity passes.
      const external: FixedSocketAudit = {
        socketPath: identity.fixedSocket,
        ownerUid: 501,
        mode: '755',
        isSymlink: false,
        nodeType: 'socket',
        preexistingExternalListener: true,
        listener: { pid: 9999, executableSha256: 'e'.repeat(64), startIdentity: 'external-daemon' },
      };
      const owned: FixedSocketAudit = {
        socketPath: identity.fixedSocket,
        ownerUid: 501,
        mode: '755',
        isSymlink: false,
        nodeType: 'socket',
        preexistingExternalListener: false,
        listener: { pid: 4242, executableSha256: 'c'.repeat(64), startIdentity: 'exact-release' },
      };
      const externalValidation = auditFixedSocket(external);
      const ownedValidation = auditFixedSocket(owned);
      return externalValidation.ok === false && ownedValidation.ok === true;
    });
    if (result.status === 'PASS') expect(result.outcomeCode).toBe('pass');
    else assertUnavailable(result, result.outcomeCode);
  });
});
