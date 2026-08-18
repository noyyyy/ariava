import { describe, expect, test } from 'bun:test';
import {
  assertReviewedTopology,
  checkInternalArgCollision,
  classifyAttachability,
  compareSpawnEquivalence,
  detectOwnedOrphans,
  fingerprintCliSurface,
  reservedInternalArgs,
  REVIEWED_SUBCOMMANDS,
  streamOrderFingerprint,
  validateChildExecutableIdentity,
} from './cli-equivalence';

describe('CLI surface fingerprint (spec §8.7)', () => {
  test('help/subcommand tree fingerprint is deterministic', () => {
    const first = fingerprintCliSurface([...REVIEWED_SUBCOMMANDS], { '--thread': 1, '--json': 0 });
    const second = fingerprintCliSurface([...REVIEWED_SUBCOMMANDS], { '--thread': 1, '--json': 0 });
    expect(first.helpTreeFingerprint).toBe(second.helpTreeFingerprint);
    expect(first.helpTreeFingerprint).toMatch(/^[0-9a-f]{64}$/u);
    expect(first.optionArity['--thread']).toBe(1);
    expect(first.optionArity['--json']).toBe(0);
  });

  test('fingerprint changes when option arity changes (stale trigger)', () => {
    const a = fingerprintCliSurface([...REVIEWED_SUBCOMMANDS], { '--thread': 1 });
    const b = fingerprintCliSurface([...REVIEWED_SUBCOMMANDS], { '--thread': 2 });
    expect(a.helpTreeFingerprint).not.toBe(b.helpTreeFingerprint);
  });
});

describe('attachability classification (spec §8.7)', () => {
  test('classifies tui_attachable when app-server + attachment flags exist', () => {
    expect(classifyAttachability({ hasAppServerFlag: true, hasAttachmentFlag: true, isReservedInternal: false })).toBe('tui_attachable');
  });

  test('classifies provider_utility when only app-server flag exists', () => {
    expect(classifyAttachability({ hasAppServerFlag: true, hasAttachmentFlag: false, isReservedInternal: false })).toBe('provider_utility');
  });

  test('classifies reserved_internal otherwise', () => {
    expect(classifyAttachability({ hasAppServerFlag: false, hasAttachmentFlag: false, isReservedInternal: true })).toBe('reserved_internal');
    expect(classifyAttachability({ hasAppServerFlag: false, hasAttachmentFlag: false, isReservedInternal: false })).toBe('reserved_internal');
  });
});

describe('internal argv collision (spec §8.7)', () => {
  test('internal app-server/attachment params never collide with user argv', () => {
    const userArgv = ['codex', 'tui', '--thread', 'abc'];
    const internal = reservedInternalArgs();
    const result = checkInternalArgCollision(userArgv, internal);
    expect(result.collision).toBe(false);
  });

  test('collision is detected when user argv includes an internal param', () => {
    const userArgv = ['codex', '--app-server', 'tui'];
    const result = checkInternalArgCollision(userArgv, reservedInternalArgs());
    expect(result.collision).toBe(true);
    expect(result.collidingArgs).toContain('--app-server');
  });
});

describe('direct vs wrapper equivalence (spec §8.7)', () => {
  test('equivalent spawns when argv/cwd/tty/stream/exit/signal match', () => {
    const direct = { argv: ['codex', 'tui'], cwd: '/tmp/work', tty: true, streamOrderFingerprint: 'a'.repeat(64), exitCode: 0, signal: null };
    const wrapper = { ...direct };
    const result = compareSpawnEquivalence(direct, wrapper);
    expect(result.equivalent).toBe(true);
    expect(result.differences).toEqual([]);
  });

  test('differences are reported when stream ordering or exit differ', () => {
    const direct = { argv: ['codex', 'tui'], cwd: '/tmp/work', tty: true, streamOrderFingerprint: 'a'.repeat(64), exitCode: 0, signal: null };
    const wrapper = { ...direct, streamOrderFingerprint: 'b'.repeat(64), exitCode: 1 };
    const result = compareSpawnEquivalence(direct, wrapper);
    expect(result.equivalent).toBe(false);
    expect(result.differences).toContain('stream-order');
    expect(result.differences).toContain('exit-code');
  });

  test('stream order fingerprint is deterministic', () => {
    const bytes = new TextEncoder().encode('hello world');
    expect(streamOrderFingerprint(bytes)).toBe(streamOrderFingerprint(bytes));
    expect(streamOrderFingerprint(bytes)).toMatch(/^[0-9a-f]{64}$/u);
  });
});

describe('child executable identity (spec §8.7)', () => {
  test('validates direct binary realpath + sha256', () => {
    const identity = { realpath: '/opt/codex/bin/codex', sha256: 'a'.repeat(64), architecture: 'arm64' as const, isDirectBinary: true };
    expect(validateChildExecutableIdentity(identity, '/opt/codex/bin/codex', 'a'.repeat(64)).ok).toBe(true);
  });

  test('rejects realpath mismatch', () => {
    const identity = { realpath: '/opt/other/codex', sha256: 'a'.repeat(64), architecture: 'arm64' as const, isDirectBinary: true };
    expect(validateChildExecutableIdentity(identity, '/opt/codex/bin/codex', 'a'.repeat(64)).ok).toBe(false);
  });

  test('rejects a shell/shim child', () => {
    const identity = { realpath: '/opt/codex/bin/codex', sha256: 'a'.repeat(64), architecture: 'arm64' as const, isDirectBinary: false };
    expect(validateChildExecutableIdentity(identity, '/opt/codex/bin/codex', 'a'.repeat(64)).ok).toBe(false);
  });
});

describe('topology and owned orphans (spec §8.7)', () => {
  test('reviewed app-server + TUI + observer topology is complete', () => {
    const state = { appServerId: 'server-1', tuiPid: 1234, observerConnected: true };
    expect(assertReviewedTopology(state).ok).toBe(true);
  });

  test('topology is incomplete without app-server, TUI, or observer', () => {
    expect(assertReviewedTopology({ appServerId: null, tuiPid: 1, observerConnected: true }).ok).toBe(false);
    expect(assertReviewedTopology({ appServerId: 's', tuiPid: null, observerConnected: true }).ok).toBe(false);
    expect(assertReviewedTopology({ appServerId: 's', tuiPid: 1, observerConnected: false }).ok).toBe(false);
  });

  test('no owned orphan after normal exit/signals/crash/termination', () => {
    const records = [
      { pid: 1, ownershipId: 'o1', ownedByHarness: true, alive: false },
      { pid: 2, ownershipId: 'o2', ownedByHarness: true, alive: false },
      { pid: 3, ownershipId: 'ext', ownedByHarness: false, alive: true },
    ];
    const result = detectOwnedOrphans(records);
    expect(result.clean).toBe(true);
    expect(result.orphanPids).toEqual([]);
  });

  test('detects owned orphans distinctly from external processes', () => {
    const records = [
      { pid: 1, ownershipId: 'o1', ownedByHarness: true, alive: true },
      { pid: 2, ownershipId: 'ext', ownedByHarness: false, alive: true },
    ];
    const result = detectOwnedOrphans(records);
    expect(result.clean).toBe(false);
    expect(result.orphanPids).toEqual([1]);
  });
});
