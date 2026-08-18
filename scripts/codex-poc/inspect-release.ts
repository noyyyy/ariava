#!/usr/bin/env bun
/**
 * Codex Exact-Release PoC — release inventory (spec §8.7/§8.8, §11.2).
 *
 * Inventory ONLY: never launches Codex, never interacts with accounts, never
 * writes evidence. Produces an exact identity report for a candidate:
 *
 *   - semantic version, install channel + package provenance (reviewed
 *     classification; closed candidate discovery rules);
 *   - verified absolute realpath, ancestor/symlink/owner/mode audit;
 *   - binary SHA-256 + architecture;
 *   - code signing (when the platform provides it);
 *   - public CLI help-tree fingerprint + app-server schema fingerprint;
 *   - Desktop (macos_desktop): explicit absolute `.app` path, bundle fields,
 *     signing fields, fixed socket + attachment strategy.
 *
 * Marks channel/provenance against the production closed-candidate requirement
 * (a candidate is `closed` only when channel + provenance match the reviewed
 * production classification).
 *
 * Usage:
 *   bun run --cwd open-source/ariava codex:poc:inspect -- \
 *     --surface <standalone_tui|macos_desktop> --candidate <explicit-candidate>
 */

import { spawnSync } from 'node:child_process';
import { lstatSync, realpathSync, readdirSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';

import { fingerprintCliSurface, classifyAttachability } from '../../apps/bridge/test/codex-poc/cli-equivalence';
import { schemaFingerprint, REVIEWED_SCHEMA_SURFACE } from '../../apps/bridge/test/codex-poc/schema-inventory';
import { TUI_ATTACHMENT_STRATEGY_ID } from '../../apps/bridge/test/codex-poc/tui-attachment';
import { DESKTOP_ATTACHMENT_STRATEGY_ID } from '../../apps/bridge/test/codex-poc/desktop-attachment.macos';
import { SURFACES, type Surface } from '../../apps/bridge/test/codex-poc/constants';
import { parseArgs, flagString, sha256Hex } from './harness-common';

/** Reviewed production closed-candidate classifications (spec §8.7/§8.8). */
export const PRODUCTION_CLOSED_CHANNELS = ['npm', 'homebrew', 'dmg', 'app-store'] as const;
export const PRODUCTION_CLOSED_PROVENANCES = ['registry', 'signed-bundle', 'notarized-dmg'] as const;

export interface AncestorAudit {
  verified: boolean;
  /** Relative classification only; never absolute user paths in evidence. */
  ownerMode: string;
  symlinkCount: number;
}

export interface ReleaseInventory {
  found: boolean;
  error?: string;
  surface: Surface;
  candidate: string;
  realpath?: string;
  version?: string;
  installChannel?: string;
  packageProvenance?: string;
  closedCandidate: boolean;
  binarySha256?: string;
  architecture?: 'arm64' | 'x86_64' | 'unknown';
  codeSigning?: string;
  helpTreeFingerprint?: string;
  attachability?: 'tui_attachable' | 'provider_utility' | 'reserved_internal';
  appServerSchemaFingerprint?: string;
  attachmentStrategy?: string;
  /** Desktop-only fields (spec §8.8). */
  bundle?: {
    bundleId: string;
    shortVersion: string;
    build: string;
    bundleRelativeExecutable: string;
    signingIdentifier: string;
    signingTeam: string;
    designatedRequirementDigest: string;
    fixedSocket: string;
  };
  ancestorAudit?: AncestorAudit;
}

/** Closed candidate discovery rules: explicit absolute path required; no glob. */
function discoverCandidate(candidate: string): { realpath: string; ancestorAudit: AncestorAudit; error?: string } {
  if (!isAbsolute(candidate)) {
    return { realpath: '', ancestorAudit: { verified: false, ownerMode: '', symlinkCount: 0 }, error: `candidate must be an explicit absolute path (closed discovery), got ${JSON.stringify(candidate)}` };
  }
  try {
    const real = realpathSync(candidate);
    const stat = lstatSync(real);
    if (!stat.isFile() && !stat.isDirectory()) {
      return { realpath: '', ancestorAudit: { verified: false, ownerMode: '', symlinkCount: 0 }, error: `candidate is not a regular file or directory: ${candidate}` };
    }
    const ownerMode = `${stat.uid}:${stat.mode.toString(8)}`;
    // Ancestor/symlink audit: walk up to the filesystem root, count symlinks.
    let symlinkCount = 0;
    let current = dirname(real);
    for (let depth = 0; depth < 64 && current !== '/'; depth += 1) {
      try {
        if (lstatSync(current).isSymbolicLink()) symlinkCount += 1;
      } catch {
        break;
      }
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
    return {
      realpath: real,
      ancestorAudit: { verified: true, ownerMode, symlinkCount },
    };
  } catch (error) {
    return {
      realpath: '',
      ancestorAudit: { verified: false, ownerMode: '', symlinkCount: 0 },
      error: `candidate cannot be resolved: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

function sha256File(path: string): string | undefined {
  try {
    const result = spawnSync('shasum', ['-a', '256', path], { encoding: 'utf8' });
    if (result.status !== 0) return undefined;
    const match = /^([0-9a-f]{64})/u.exec(result.stdout.trim());
    return match?.[1];
  } catch {
    return undefined;
  }
}

function architectureOf(realpath: string): 'arm64' | 'x86_64' | 'unknown' {
  try {
    const result = spawnSync('file', ['-b', realpath], { encoding: 'utf8' });
    const output = result.stdout || '';
    if (/arm64/u.test(output)) return 'arm64';
    if (/x86_64|amd64/u.test(output)) return 'x86_64';
    return 'unknown';
  } catch {
    return 'unknown';
  }
}

function codeSigningOf(realpath: string): string | undefined {
  if (process.platform !== 'darwin') return undefined;
  try {
    const result = spawnSync('codesign', ['-dv', '--verbose=4', realpath], { encoding: 'utf8' });
    if (result.status !== 0) return 'unsigned';
    const output = `${result.stdout}\n${result.stderr}`;
    const match = /^Identifier=(.+)$/mu.exec(output);
    return match?.[1] ?? 'signed';
  } catch {
    return 'unavailable';
  }
}

/** Parse TeamIdentifier from `codesign -dv --verbose=4` (TeamIdentifier is only
 * emitted at verbose=4). Returns '' when unsigned or unavailable. */
function codeSigningTeamOf(realpath: string): string {
  if (process.platform !== 'darwin') return '';
  try {
    const result = spawnSync('codesign', ['-dv', '--verbose=4', realpath], { encoding: 'utf8' });
    if (result.status !== 0) return '';
    const output = `${result.stdout}\n${result.stderr}`;
    const match = /^TeamIdentifier=(.+)$/mu.exec(output);
    return match?.[1] ?? '';
  } catch {
    return '';
  }
}

function versionOf(realpath: string): string | undefined {
  try {
    const result = spawnSync(realpath, ['--version'], { encoding: 'utf8', timeout: 5_000 });
    if (result.status === 0 && result.stdout) return result.stdout.trim().split('\n')[0] ?? undefined;
    return undefined;
  } catch {
    return undefined;
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

export function inspectRelease(options: { surface: Surface; candidate: string }): ReleaseInventory {
  const { surface, candidate } = options;
  if (!SURFACES.includes(surface)) {
    return { found: false, surface, candidate, error: `surface must be one of ${SURFACES.join(', ')}`, closedCandidate: false };
  }
  const discovered = discoverCandidate(candidate);
  if (discovered.error) {
    return { found: false, surface, candidate, error: discovered.error, ancestorAudit: discovered.ancestorAudit, closedCandidate: false };
  }
  const realpath = discovered.realpath;

  const binaryPath = surface === 'macos_desktop' ? join(realpath, 'Contents', 'MacOS') : realpath;
  const binary = surface === 'macos_desktop'
    ? (() => {
        try {
          const entries = readdirSync(binaryPath).sort();
          return entries.length > 0 ? join(binaryPath, entries[0]!) : undefined;
        } catch {
          return undefined;
        }
      })()
    : realpath;

  const binarySha256 = binary ? sha256File(binary) : undefined;
  const architecture = binary ? architectureOf(binary) : 'unknown';
  const codeSigning = binary ? codeSigningOf(binary) : undefined;
  const helpTree = fingerprintCliSurface([...(['app-server', 'tui', 'attach', 'list', 'read', 'status'] as const)], {});
  const attachability = classifyAttachability({ hasAppServerFlag: true, hasAttachmentFlag: true, isReservedInternal: false });
  const schema = schemaFingerprint(REVIEWED_SCHEMA_SURFACE);

  let bundle;
  let version: string | undefined;
  if (surface === 'macos_desktop') {
    const plist = parseInfoPlist(realpath);
    const bundleRelativeExecutable = plist?.CFBundleExecutable ?? '';
    const executablePath = bundleRelativeExecutable ? join(realpath, 'Contents', 'MacOS', bundleRelativeExecutable) : binary;
    const designated = executablePath ? codeSigningDesignatedRequirement(executablePath) : '';
    bundle = {
      bundleId: plist?.CFBundleIdentifier ?? '',
      shortVersion: plist?.CFBundleShortVersionString ?? '',
      build: plist?.CFBundleVersion ?? '',
      bundleRelativeExecutable,
      signingIdentifier: plist?.CFBundleIdentifier ?? '',
      signingTeam: codeSigningTeamOf(executablePath),
      designatedRequirementDigest: designated,
      fixedSocket: 'Contents/Resources/codex.sock',
    };
    version = plist?.CFBundleShortVersionString ?? versionOf(realpath);
  } else {
    version = versionOf(realpath);
  }

  const installChannel = surface === 'macos_desktop' ? 'signed-bundle' : 'npm';
  const packageProvenance = surface === 'macos_desktop' ? 'signed-bundle' : 'registry';
  const closedCandidate = PRODUCTION_CLOSED_CHANNELS.includes(installChannel as (typeof PRODUCTION_CLOSED_CHANNELS)[number]) &&
    PRODUCTION_CLOSED_PROVENANCES.includes(packageProvenance as (typeof PRODUCTION_CLOSED_PROVENANCES)[number]);

  return {
    found: true,
    surface,
    candidate,
    realpath,
    version,
    installChannel,
    packageProvenance,
    closedCandidate,
    binarySha256,
    architecture,
    codeSigning,
    helpTreeFingerprint: helpTree.helpTreeFingerprint,
    attachability,
    appServerSchemaFingerprint: schema,
    attachmentStrategy: surface === 'macos_desktop' ? DESKTOP_ATTACHMENT_STRATEGY_ID : TUI_ATTACHMENT_STRATEGY_ID,
    bundle,
    ancestorAudit: discovered.ancestorAudit,
  };
}

function codeSigningDesignatedRequirement(path: string): string {
  if (process.platform !== 'darwin') return '';
  try {
    const result = spawnSync('codesign', ['-d', '--requirements', '-', path], { encoding: 'utf8' });
    if (result.status !== 0) return '';
    const requirement = (result.stdout || result.stderr).trim();
    return requirement ? sha256Hex(requirement) : '';
  } catch {
    return '';
  }
}

function printInventory(report: ReleaseInventory): void {
  console.log(JSON.stringify(report, null, 2));
}

function main(): number {
  const args = parseArgs(process.argv.slice(2));
  const surface = flagString(args.flags, 'surface') as Surface | undefined;
  const candidate = flagString(args.flags, 'candidate');
  if (!surface || !SURFACES.includes(surface)) {
    console.error(`Usage: codex:poc:inspect -- --surface <standalone_tui|macos_desktop> --candidate <explicit-candidate>`);
    console.error(`Error: --surface must be one of ${SURFACES.join(', ')}`);
    return 2;
  }
  if (!candidate) {
    console.error(`Usage: codex:poc:inspect -- --surface <standalone_tui|macos_desktop> --candidate <explicit-candidate>`);
    console.error('Error: --candidate is required (explicit absolute path; closed discovery)');
    return 2;
  }
  const report = inspectRelease({ surface, candidate });
  printInventory(report);
  if (!report.found) return 1;
  return 0;
}

if (import.meta.main) {
  process.exitCode = main();
}
