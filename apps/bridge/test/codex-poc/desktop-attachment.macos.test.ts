import { describe, expect, test } from 'bun:test';
import {
  assessDesktopAttachment,
  auditFixedSocket,
  cleanupOnlyOwnedChild,
  DESKTOP_ATTACHMENT_STRATEGY_ID,
  LOCAL_DAEMON_ENV_VAR,
  CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME,
  BUNDLED_APP_SERVER_RELATIVE_PATH,
  DESKTOP_CLOSED_CANDIDATE_BUNDLE_NAME,
  defaultCodexHome,
  desktopClosedCandidateRoots,
  validateLocalDaemonEnvScope,
  validateMacAppIdentity,
  validateDesktopTopology,
  validateLauncherRestartBoundary,
  type DesktopTopologyState,
  type FixedSocketAudit,
  type MacAppIdentity,
} from './desktop-attachment.macos';

function makeIdentity(overrides: Partial<MacAppIdentity> = {}): MacAppIdentity {
  return {
    bundleId: 'io.noyx.codex',
    shortVersion: '1.2.3',
    build: '42',
    bundleRelativeExecutable: 'Contents/MacOS/ChatGPT',
    bundleRealpath: '/Applications/ChatGPT.app',
    ancestorAudit: 'verified',
    ownerMode: '0755',
    binarySha256: 'a'.repeat(64),
    architecture: 'arm64',
    signingIdentifier: 'Developer ID Application: X',
    signingTeam: 'ABC123',
    designatedRequirementDigest: 'b'.repeat(64),
    appServerSchemaFingerprint: 'c'.repeat(64),
    fixedSocket: CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME,
    attachmentStrategy: DESKTOP_ATTACHMENT_STRATEGY_ID,
    ...overrides,
  };
}

function makeSocketAudit(overrides: Partial<FixedSocketAudit> = {}): FixedSocketAudit {
  return {
    socketPath: '/tmp/codex-home/app-server-control/app-server-control.sock',
    ownerUid: 501,
    mode: '0600',
    isSymlink: false,
    nodeType: 'socket',
    preexistingExternalListener: false,
    listener: { pid: 1234, executableSha256: 'a'.repeat(64), startIdentity: 'start-1' },
    ...overrides,
  };
}

function makeTopology(overrides: Partial<DesktopTopologyState> = {}): DesktopTopologyState {
  return {
    sharedAppServerId: 'server-1',
    desktopPid: 5678,
    observerConnected: true,
    desktopCodeObject: 'code-object-1',
    sharedAttachmentProven: true,
    preexistingExternal: false,
    launcherExited: false,
    remoteControlCoexistence: true,
    remoteControlToggledByHarness: false,
    ...overrides,
  };
}

describe('macOS Desktop identity (spec §5.3, §8.8)', () => {
  test('validates a complete explicit .app identity', () => {
    expect(validateMacAppIdentity(makeIdentity()).ok).toBe(true);
  });

  test('rejects missing bundle/signing fields', () => {
    expect(validateMacAppIdentity(makeIdentity({ bundleId: '' })).ok).toBe(false);
    expect(validateMacAppIdentity(makeIdentity({ signingIdentifier: '' })).ok).toBe(false);
    expect(validateMacAppIdentity(makeIdentity({ signingTeam: '' })).ok).toBe(false);
  });

  test('rejects non-absolute bundle realpath', () => {
    expect(validateMacAppIdentity(makeIdentity({ bundleRealpath: 'Applications/ChatGPT.app' })).ok).toBe(false);
  });

  test('rejects wrong architecture or attachment strategy', () => {
    expect(validateMacAppIdentity(makeIdentity({ architecture: 'x86_64' as const })).ok).toBe(true);
    expect(validateMacAppIdentity(makeIdentity({ architecture: 'unknown' as const })).ok).toBe(false);
    expect(validateMacAppIdentity(makeIdentity({ attachmentStrategy: 'reviewed-tui-app-server-argv' })).ok).toBe(false);
  });

  test('strategy id is the reviewed stable desktop id', () => {
    expect(DESKTOP_ATTACHMENT_STRATEGY_ID).toBe('reviewed-macos-desktop-local-daemon-socket');
  });

  test('fingerprints the bundled app-server binary and CODEX_HOME control socket', () => {
    expect(BUNDLED_APP_SERVER_RELATIVE_PATH).toBe('Contents/Resources/codex');
    expect(CONTROL_SOCKET_RELATIVE_TO_CODEX_HOME).toBe('app-server-control/app-server-control.sock');
    expect(DESKTOP_CLOSED_CANDIDATE_BUNDLE_NAME).toBe('ChatGPT.app');
    expect(desktopClosedCandidateRoots('/Users/owner')).toEqual([
      '/Applications/ChatGPT.app',
      '/Users/owner/Applications/ChatGPT.app',
    ]);
  });

  test('default Codex home inherits CODEX_HOME or ~/.codex', () => {
    expect(defaultCodexHome({}, '/Users/owner')).toBe('/Users/owner/.codex');
    expect(defaultCodexHome({ CODEX_HOME: '/tmp/explicit-codex-home' }, '/Users/owner')).toBe('/tmp/explicit-codex-home');
  });

  test('rejects a bundle-relative socket or a GUI-stub executable path', () => {
    expect(validateMacAppIdentity(makeIdentity({ fixedSocket: 'Contents/MacOS/codex.sock' })).ok).toBe(false);
    expect(validateMacAppIdentity(makeIdentity({ fixedSocket: 'Contents/Resources/codex.sock' })).ok).toBe(false);
    expect(validateMacAppIdentity(makeIdentity({ bundleRelativeExecutable: 'ChatGPT' })).ok).toBe(false);
  });
});

describe('fixed socket audit (spec §8.8)', () => {
  test('passes on a normal user-owned socket', () => {
    expect(auditFixedSocket(makeSocketAudit()).ok).toBe(true);
  });

  test('fails closed on symlink socket', () => {
    expect(auditFixedSocket(makeSocketAudit({ isSymlink: true })).ok).toBe(false);
  });

  test('fails closed on non-socket node type', () => {
    expect(auditFixedSocket(makeSocketAudit({ nodeType: 'file' })).ok).toBe(false);
  });

  test('fails closed on root-owned socket', () => {
    expect(auditFixedSocket(makeSocketAudit({ ownerUid: 0 })).ok).toBe(false);
  });

  test('fails closed when a preexisting external listener owns the socket', () => {
    expect(auditFixedSocket(makeSocketAudit({ preexistingExternalListener: true })).ok).toBe(false);
  });
});

describe('local daemon env scope (spec §8.8)', () => {
  test('valid only when env=1 and exact release matches', () => {
    expect(validateLocalDaemonEnvScope('1', true, true).ok).toBe(true);
    expect(validateLocalDaemonEnvScope('0', true, true).ok).toBe(false);
    expect(validateLocalDaemonEnvScope('1', false, true).ok).toBe(false);
    expect(validateLocalDaemonEnvScope('1', true, false).ok).toBe(false);
    expect(validateLocalDaemonEnvScope(undefined, true, true).ok).toBe(false);
  });

  test('env var name is the reviewed constant', () => {
    expect(LOCAL_DAEMON_ENV_VAR).toBe('CODEX_APP_SERVER_USE_LOCAL_DAEMON');
  });
});

describe('desktop topology and lifecycle (spec §8.8)', () => {
  test('shared app-server + Desktop + observer concurrency with attachment proof', () => {
    expect(validateDesktopTopology(makeTopology()).ok).toBe(true);
  });

  test('fails without shared attachment proof', () => {
    expect(validateDesktopTopology(makeTopology({ sharedAttachmentProven: false })).ok).toBe(false);
  });

  test('fails when a preexisting external Desktop would be taken over', () => {
    expect(validateDesktopTopology(makeTopology({ preexistingExternal: true })).ok).toBe(false);
  });

  test('harness never calls Remote Control enable/disable', () => {
    expect(validateDesktopTopology(makeTopology({ remoteControlToggledByHarness: true })).ok).toBe(false);
  });

  test('launcher exit does not stop shared runtime', () => {
    expect(validateLauncherRestartBoundary(makeTopology({ launcherExited: true })).ok).toBe(true);
    expect(validateLauncherRestartBoundary(makeTopology({ launcherExited: true, sharedAppServerId: null })).ok).toBe(false);
  });

  test('cleanup only terminates exact owned child', () => {
    const records = [
      { pid: 1, ownedByHarness: true, alive: false },
      { pid: 2, ownedByHarness: false, alive: true },
    ];
    expect(cleanupOnlyOwnedChild(records).ok).toBe(true);
  });

  test('cleanup never terminates external processes', () => {
    const records = [
      { pid: 1, ownedByHarness: true, alive: false },
      { pid: 2, ownedByHarness: false, alive: false },
    ];
    const result = cleanupOnlyOwnedChild(records);
    expect(result.ok).toBe(false);
    expect(result.externalTerminated).toEqual([2]);
  });
});

describe('full desktop attachment assessment (spec §8.8)', () => {
  test('attachable when all invariants hold', () => {
    const result = assessDesktopAttachment({
      identity: makeIdentity(),
      socketAudit: makeSocketAudit(),
      topology: makeTopology(),
      envValue: '1',
      architectureMatches: true,
      schemaMatches: true,
      cleanupRecords: [{ pid: 1, ownedByHarness: true, alive: false }],
    });
    expect(result.attachable).toBe(true);
    expect(result.identityComplete).toBe(true);
    expect(result.socketAuditPass).toBe(true);
    expect(result.topologyValid).toBe(true);
    expect(result.cleanupOnlyOwnedChild).toBe(true);
  });

  test('not attachable when any invariant fails with bounded reason', () => {
    const result = assessDesktopAttachment({
      identity: makeIdentity({ bundleId: '' }),
      socketAudit: makeSocketAudit({ isSymlink: true }),
      topology: makeTopology({ remoteControlToggledByHarness: true }),
      envValue: '0',
      architectureMatches: false,
      schemaMatches: false,
      cleanupRecords: [{ pid: 9, ownedByHarness: false, alive: false }],
    });
    expect(result.attachable).toBe(false);
    expect(result.reason).toContain('identity:');
    expect(result.reason).toContain('socket:');
    expect(result.reason).toContain('env:');
    expect(result.reason).toContain('topology:');
    expect(result.reason).toContain('cleanup-terminated-external');
  });
});
