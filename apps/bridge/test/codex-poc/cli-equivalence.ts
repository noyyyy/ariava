/**
 * CLI surface equivalence for the Codex Exact-Release Capability PoC
 * (spec §8.7).
 *
 * Models the TUI CLI surface the harness must fingerprint and verify:
 *   - public help/subcommand tree and option arity;
 *   - `tui_attachable | provider_utility | reserved_internal` classification;
 *   - internal app-server/attachment params never collide with user argv;
 *   - direct exact binary vs candidate wrapper equivalence for argv, cwd,
 *     TTY, stdin/stdout/stderr ordering, signals, and exit;
 *   - actual TUI child executable identity;
 *   - one reviewed app-server + real TUI + observer topology;
 *   - no owned orphan after normal exit/signals/crash/harness termination.
 *
 * Deterministic public-fixture logic only. Real interactive streams are saved
 * as pass/fail + non-sensitive process results, never raw content.
 *
 * Research-only harness code; never part of the production import graph.
 */

import { createHash } from 'node:crypto';
import { jcs } from './jcs';

/** Internal app-server/attachment parameter prefixes (never user argv). */
export const INTERNAL_ARG_PREFIXES = ['--app-server', '--attachment', '--daemon-socket', '--control'] as const;

/** Reviewed subcommand tree (public CLI surface). */
export const REVIEWED_SUBCOMMANDS = ['app-server', 'tui', 'attach', 'list', 'read', 'status'] as const;

export type AttachabilityClass = 'tui_attachable' | 'provider_utility' | 'reserved_internal';

export interface CliSurfaceFingerprintResult {
  /** Public help/subcommand tree fingerprint (sha256 of JCS canonical tree). */
  helpTreeFingerprint: string;
  /** Option arity map (option -> number of required arguments). */
  optionArity: Record<string, number>;
  /** Subcommand tree as discovered. */
  subcommands: string[];
}

/** Fingerprint the public help/subcommand tree deterministically. */
export function fingerprintCliSurface(subcommands: string[], optionArity: Record<string, number>): CliSurfaceFingerprintResult {
  const canonical = jcs({
    subcommands: [...subcommands].sort(),
    optionArity: Object.fromEntries(Object.entries(optionArity).sort(([left], [right]) => left.localeCompare(right))),
  } as Parameters<typeof jcs>[0]);
  return {
    helpTreeFingerprint: createHash('sha256').update(canonical).digest('hex'),
    optionArity,
    subcommands,
  };
}

/** Classify the attachability of the TUI surface. */
export function classifyAttachability(
  surface: { hasAppServerFlag: boolean; hasAttachmentFlag: boolean; isReservedInternal: boolean },
): AttachabilityClass {
  if (surface.isReservedInternal) return 'reserved_internal';
  if (surface.hasAppServerFlag && surface.hasAttachmentFlag) return 'tui_attachable';
  if (surface.hasAppServerFlag) return 'provider_utility';
  return 'reserved_internal';
}

/** Check internal app-server/attachment params do not collide with user argv. */
export function checkInternalArgCollision(userArgv: string[], internalArgs: string[]): { collision: boolean; collidingArgs: string[] } {
  const userSet = new Set(userArgv);
  const colliding = internalArgs.filter((arg) => userSet.has(arg));
  return { collision: colliding.length > 0, collidingArgs: colliding };
}

export interface SpawnEquivalenceResult {
  direct: ProcessResult;
  wrapper: ProcessResult;
  equivalent: boolean;
  differences: string[];
}

export interface ProcessResult {
  argv: string[];
  cwd: string;
  tty: boolean;
  /** stdin/stdout/stderr ordering fingerprint (byte order, not content). */
  streamOrderFingerprint: string;
  exitCode: number;
  signal: string | null;
}

/** Compare direct exact binary vs candidate wrapper process results. */
export function compareSpawnEquivalence(direct: ProcessResult, wrapper: ProcessResult): SpawnEquivalenceResult {
  const differences: string[] = [];
  if (direct.argv.join(' ') !== wrapper.argv.join(' ')) differences.push('argv');
  if (direct.cwd !== wrapper.cwd) differences.push('cwd');
  if (direct.tty !== wrapper.tty) differences.push('tty');
  if (direct.streamOrderFingerprint !== wrapper.streamOrderFingerprint) differences.push('stream-order');
  if (direct.exitCode !== wrapper.exitCode) differences.push('exit-code');
  if (direct.signal !== wrapper.signal) differences.push('signal');
  return {
    direct,
    wrapper,
    equivalent: differences.length === 0,
    differences,
  };
}

/** Build a deterministic stream-order fingerprint from a byte sequence. */
export function streamOrderFingerprint(streamBytes: ArrayBuffer | Uint8Array): string {
  const bytes = streamBytes instanceof Uint8Array ? streamBytes : new Uint8Array(streamBytes);
  return createHash('sha256').update(bytes).digest('hex');
}

export interface ChildExecutableIdentity {
  realpath: string;
  sha256: string;
  architecture: 'arm64' | 'x86_64' | 'unknown';
  /** Whether the child is the direct reviewed binary (not a shell/shim). */
  isDirectBinary: boolean;
}

/** Validate the actual TUI child executable identity. */
export function validateChildExecutableIdentity(
  identity: ChildExecutableIdentity,
  expectedRealpath: string,
  expectedSha256: string,
): { ok: boolean; reason?: string } {
  if (identity.realpath !== expectedRealpath) {
    return { ok: false, reason: `realpath mismatch ${identity.realpath} != ${expectedRealpath}` };
  }
  if (identity.sha256 !== expectedSha256) {
    return { ok: false, reason: `sha256 mismatch ${identity.sha256} != ${expectedSha256}` };
  }
  if (!identity.isDirectBinary) {
    return { ok: false, reason: 'child is not the direct reviewed binary' };
  }
  return { ok: true };
}

/** Topology: one reviewed app-server + real TUI + observer. */
export interface TopologyState {
  appServerId: string | null;
  tuiPid: number | null;
  observerConnected: boolean;
}

/** Assert the reviewed topology is complete. */
export function assertReviewedTopology(state: TopologyState): { ok: boolean; reason?: string } {
  if (!state.appServerId) return { ok: false, reason: 'no app-server' };
  if (state.tuiPid === null) return { ok: false, reason: 'no TUI' };
  if (!state.observerConnected) return { ok: false, reason: 'no observer' };
  return { ok: true };
}

export interface OwnedProcessRecord {
  pid: number;
  /** Durable ownership record identity (distinguishes owned vs external). */
  ownershipId: string;
  /** Whether this process was created by the harness (owned). */
  ownedByHarness: boolean;
  alive: boolean;
}

/** Detect owned orphans after exit/signal/crash/harness termination. */
export function detectOwnedOrphans(records: OwnedProcessRecord[]): { orphanPids: number[]; clean: boolean } {
  const orphans = records.filter((record) => record.ownedByHarness && record.alive).map((record) => record.pid);
  return { orphanPids: orphans, clean: orphans.length === 0 };
}

/** Internal arg prefixes that must never appear in user argv. */
export function reservedInternalArgs(): string[] {
  return [...INTERNAL_ARG_PREFIXES];
}
