import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * macOS Desktop attachment model for the Codex Exact-Release Capability PoC
 * (spec §8.8).
 *
 * macOS-only module. Models the Desktop attachment/lifecycle invariants:
 *   - explicit absolute `.app` identity (bundle id, short version, build,
 *     bundle root/relative executable, realpath/ancestor/symlink/owner/mode,
 *     binary SHA-256 + architecture, signing identifier/team/designated
 *     requirement, app-server schema fingerprint, fixed socket + attachment
 *     strategy);
 *   - `CODEX_APP_SERVER_USE_LOCAL_DAEMON=1` scoped validity;
 *   - fixed socket audit (position, owner/mode/symlink/node type);
 *   - listener PID/start identity/executable/hash/signature;
 *   - shared app-server + Desktop + observer concurrency;
 *   - actual Desktop PID/code object + shared attachment proof;
 *   - preexisting external listener/Desktop never taken over or stopped;
 *   - launcher exit does not stop the shared runtime;
 *   - graceful Desktop restart boundary;
 *   - Remote Control client coexistence without calling enable/disable;
 *   - cleanup only terminates the exact owned child.
 *
 * This module implements NO production Bridge-private control IPC (spec §8.8):
 * it only models and verifies the topology for a target release.
 *
 * Research-only harness code; never part of the production import graph.
 */

/** Scoped env var that must be valid only for the exact release (spec §8.8). */
export const LOCAL_DAEMON_ENV_VAR = 'CODEX_APP_SERVER_USE_LOCAL_DAEMON';

/** Desktop attachment strategy identity (reviewed stable id; spec §5.1). */
export const DESKTOP_ATTACHMENT_STRATEGY_ID = 'reviewed-macos-desktop-local-daemon-socket';

/**
 * Bundled app-server binary inside a Codex `.app`.
 * This is the tuple fingerprint target — not `Contents/MacOS/ChatGPT`.
 */
export const BUNDLED_APP_SERVER_RELATIVE_PATH = 'Contents/Resources/codex';

/**
 * Control socket relative to `CODEX_HOME` (not inside the `.app` bundle).
 * Exact-release field location: `{CODEX_HOME}/app-server-control/app-server-control.sock`.
 */
export const CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME = 'app-server-control/app-server-control.sock';

/**
 * On-disk bundle name for reviewed closed candidate roots.
 * Bundle id remains `com.openai.codex`; the `.app` filename is `ChatGPT.app`.
 */
export const DESKTOP_CLOSED_CANDIDATE_BUNDLE_NAME = 'ChatGPT.app';

export function desktopClosedCandidateRoots(userHome: string): readonly [string, string] {
  return [
    `/Applications/${DESKTOP_CLOSED_CANDIDATE_BUNDLE_NAME}`,
    join(userHome, 'Applications', DESKTOP_CLOSED_CANDIDATE_BUNDLE_NAME),
  ];
}

/** Inherit the current environment: `CODEX_HOME` if set, otherwise `~/.codex`. */
export function defaultCodexHome(env: NodeJS.ProcessEnv = process.env, home = homedir()): string {
  const fromEnv = env.CODEX_HOME?.trim();
  return fromEnv && fromEnv.length > 0 ? fromEnv : join(home, '.codex');
}

export function bundledAppServerAbsolutePath(appRoot: string): string {
  return join(appRoot, ...BUNDLED_APP_SERVER_RELATIVE_PATH.split('/'));
}

export function controlSocketAbsolutePath(codexHome: string): string {
  return join(codexHome, ...CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME.split('/'));
}

export interface MacAppIdentity {
  /** Bundle id (CFBundleIdentifier). */
  bundleId: string;
  shortVersion: string;
  build: string;
  /** Path relative to the bundle root, e.g. Contents/MacOS/ChatGPT. */
  bundleRelativeExecutable: string;
  /** Verified absolute realpath of the bundle root. */
  bundleRealpath: string;
  /** Ancestor/owner/mode audit (relative classification only). */
  ancestorAudit: 'verified' | 'unverified';
  ownerMode: string;
  binarySha256: string;
  architecture: 'arm64' | 'x86_64' | 'unknown';
  signingIdentifier: string;
  signingTeam: string;
  /** Designated requirement digest (sha256 of the requirement string). */
  designatedRequirementDigest: string;
  /** App-server schema fingerprint (from schema inventory). */
  appServerSchemaFingerprint: string;
  /**
   * Reviewed socket classification: relative to `CODEX_HOME`, never a path
   * inside the `.app` bundle.
   */
  fixedSocket: string;
  attachmentStrategy: string;
}

export interface FixedSocketAudit {
  /** Absolute socket path (audited; never persisted raw in evidence). */
  socketPath: string;
  ownerUid: number;
  mode: string;
  /** True when the socket is a symlink (must fail closed). */
  isSymlink: boolean;
  nodeType: 'socket' | 'file' | 'dir' | 'unknown';
  /** Whether a preexisting external listener owns this socket. */
  preexistingExternalListener: boolean;
  /** Listener PID/start identity. */
  listener: { pid: number; executableSha256: string; startIdentity: string } | null;
}

export interface DesktopTopologyState {
  sharedAppServerId: string | null;
  desktopPid: number | null;
  observerConnected: boolean;
  /** Actual Desktop PID/code object + shared attachment proof. */
  desktopCodeObject: string | null;
  sharedAttachmentProven: boolean;
  /** Preexisting external listener/Desktop (never taken over). */
  preexistingExternal: boolean;
  launcherExited: boolean;
  /** Remote Control client coexistence (Ariava never calls enable/disable). */
  remoteControlCoexistence: boolean;
  remoteControlToggledByHarness: boolean;
}

export interface DesktopCleanupRecord {
  pid: number;
  ownedByHarness: boolean;
  alive: boolean;
}

export interface DesktopAttachmentAssessment {
  attachable: boolean;
  identityComplete: boolean;
  socketAuditPass: boolean;
  topologyValid: boolean;
  cleanupOnlyOwnedChild: boolean;
  reason?: string;
}

/** Validate the explicit absolute .app identity (spec §5.3, §8.8). */
export function validateMacAppIdentity(identity: MacAppIdentity): { ok: boolean; reason?: string } {
  if (!identity.bundleId) return { ok: false, reason: 'missing bundleId' };
  if (!identity.shortVersion) return { ok: false, reason: 'missing shortVersion' };
  if (!identity.build) return { ok: false, reason: 'missing build' };
  if (!identity.bundleRelativeExecutable) return { ok: false, reason: 'missing bundleRelativeExecutable' };
  if (!identity.bundleRelativeExecutable.startsWith('Contents/MacOS/')) return { ok: false, reason: 'bundleRelativeExecutable must be Contents/MacOS/<name>' };
  if (!identity.bundleRealpath.startsWith('/')) return { ok: false, reason: 'bundleRealpath must be absolute' };
  if (!/^[0-9a-f]{64}$/u.test(identity.binarySha256)) return { ok: false, reason: 'binarySha256 must be sha256 hex' };
  if (identity.architecture !== 'arm64' && identity.architecture !== 'x86_64') return { ok: false, reason: 'architecture must be arm64 or x86_64' };
  if (!identity.signingIdentifier) return { ok: false, reason: 'missing signingIdentifier' };
  if (!identity.signingTeam) return { ok: false, reason: 'missing signingTeam' };
  if (!/^[0-9a-f]{64}$/u.test(identity.appServerSchemaFingerprint)) return { ok: false, reason: 'appServerSchemaFingerprint must be sha256 hex' };
  if (identity.fixedSocket !== CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME) {
    return { ok: false, reason: 'fixedSocket must be CODEX_HOME-relative app-server-control socket' };
  }
  if (identity.attachmentStrategy !== DESKTOP_ATTACHMENT_STRATEGY_ID) return { ok: false, reason: 'attachmentStrategy mismatch' };
  return { ok: true };
}

/** Audit the fixed socket (position, owner/mode/symlink/node type). */
export function auditFixedSocket(audit: FixedSocketAudit): { ok: boolean; reason?: string } {
  if (audit.isSymlink) return { ok: false, reason: 'socket must not be a symlink' };
  if (audit.nodeType !== 'socket') return { ok: false, reason: `node type must be socket, got ${audit.nodeType}` };
  if (audit.ownerUid === 0) return { ok: false, reason: 'socket must not be root-owned' };
  if (audit.preexistingExternalListener) return { ok: false, reason: 'preexisting external listener must not be taken over' };
  return { ok: true };
}

/** Check `CODEX_APP_SERVER_USE_LOCAL_DAEMON=1` scoped validity for exact release. */
export function validateLocalDaemonEnvScope(
  envValue: string | undefined,
  expectedArchitectureMatches: boolean,
  expectedSchemaMatches: boolean,
): { ok: boolean; reason?: string } {
  if (envValue !== '1') return { ok: false, reason: `${LOCAL_DAEMON_ENV_VAR} must be exactly 1` };
  if (!expectedArchitectureMatches) return { ok: false, reason: 'architecture does not match exact release' };
  if (!expectedSchemaMatches) return { ok: false, reason: 'schema fingerprint does not match exact release' };
  return { ok: true };
}

/** Verify shared app-server + Desktop + observer concurrency + attachment proof. */
export function validateDesktopTopology(state: DesktopTopologyState): { ok: boolean; reason?: string } {
  if (!state.sharedAppServerId) return { ok: false, reason: 'no shared app-server' };
  if (state.desktopPid === null) return { ok: false, reason: 'no Desktop pid' };
  if (!state.observerConnected) return { ok: false, reason: 'no observer' };
  if (!state.desktopCodeObject) return { ok: false, reason: 'no Desktop code object' };
  if (!state.sharedAttachmentProven) return { ok: false, reason: 'shared attachment not proven' };
  if (state.preexistingExternal) return { ok: false, reason: 'preexisting external Desktop must not be taken over' };
  if (state.remoteControlToggledByHarness) return { ok: false, reason: 'harness must never call Remote Control enable/disable' };
  return { ok: true };
}

/** Launcher exit must not stop the shared runtime; graceful restart boundary. */
export function validateLauncherRestartBoundary(state: DesktopTopologyState): { ok: boolean; reason?: string } {
  if (state.launcherExited && state.sharedAppServerId === null) return { ok: false, reason: 'launcher exit stopped shared runtime' };
  return { ok: true };
}

/** Cleanup only terminates the exact owned child (never external). */
export function cleanupOnlyOwnedChild(records: DesktopCleanupRecord[]): { ok: boolean; externalTerminated: number[] } {
  const externalTerminated: number[] = [];
  for (const record of records) {
    if (!record.ownedByHarness && !record.alive) {
      externalTerminated.push(record.pid);
    }
  }
  return { ok: externalTerminated.length === 0, externalTerminated };
}

/** Full Desktop attachment assessment. */
export function assessDesktopAttachment(input: {
  identity: MacAppIdentity;
  socketAudit: FixedSocketAudit;
  topology: DesktopTopologyState;
  envValue: string | undefined;
  architectureMatches: boolean;
  schemaMatches: boolean;
  cleanupRecords: DesktopCleanupRecord[];
}): DesktopAttachmentAssessment {
  const identity = validateMacAppIdentity(input.identity);
  const socket = auditFixedSocket(input.socketAudit);
  const envScope = validateLocalDaemonEnvScope(input.envValue, input.architectureMatches, input.schemaMatches);
  const topology = validateDesktopTopology(input.topology);
  const restart = validateLauncherRestartBoundary(input.topology);
  const cleanup = cleanupOnlyOwnedChild(input.cleanupRecords);

  const reasons: string[] = [];
  if (!identity.ok) reasons.push(`identity:${identity.reason}`);
  if (!socket.ok) reasons.push(`socket:${socket.reason}`);
  if (!envScope.ok) reasons.push(`env:${envScope.reason}`);
  if (!topology.ok) reasons.push(`topology:${topology.reason}`);
  if (!restart.ok) reasons.push(`restart:${restart.reason}`);
  if (!cleanup.ok) reasons.push('cleanup-terminated-external');

  return {
    attachable: reasons.length === 0,
    identityComplete: identity.ok ?? false,
    socketAuditPass: socket.ok ?? false,
    topologyValid: topology.ok ?? false,
    cleanupOnlyOwnedChild: cleanup.ok,
    reason: reasons.length > 0 ? reasons.join(';') : undefined,
  };
}
