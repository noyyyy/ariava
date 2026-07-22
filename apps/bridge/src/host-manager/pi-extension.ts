import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { isoNow } from '@ariava/shared-utils';
import type { AriavaAssetSource, AriavaPiInstallRecord } from './config';
import { AriavaCliError, sanitizeCommandDetail } from './service/errors';
import { SpawnSyncCommandRunner } from './service/command-runner';
import type { CommandRunner } from './service/types';
import { ARIAVA_PI_EXTENSION_DIR, ARIAVA_PI_MANAGED_METADATA_PATH } from './paths';

export const ARIAVA_PI_PACKAGE_NAME = '@ariava/pi-extension';
export const ARIAVA_PI_PACKAGE_SOURCE = `npm:${ARIAVA_PI_PACKAGE_NAME}`;

export type PiPackageOwnership = 'absent' | 'managed-exact' | 'managed-upgrade' | 'unmanaged' | 'ambiguous';

export interface PiPackageLifecycleDependencies {
  runner: CommandRunner;
  settingsPath: string;
  packagePath: string;
  readText(path: string): string | undefined;
  pathExists(path: string): boolean;
  now(): string;
}

export interface PiExtensionInstallOptions {
  sourcePath: string;
  sourceKind: AriavaAssetSource['kind'];
  version: string;
  force?: boolean;
  installDependencies?: boolean;
  installPath?: string;
  managedMetadataPath?: string;
}

export interface PiExtensionStatus {
  installed: boolean;
  installPath: string;
  expectedManagedPath: string;
  managed: boolean;
  managedMetadataPath: string;
  registeredSource?: string;
  expectedSource: string;
  manifestName?: string;
  manifestVersion?: string;
  sourceOwnership: PiPackageOwnership;
  mismatchReasons: string[];
  installedVersion?: string;
  bundledVersion?: string;
  source?: AriavaAssetSource;
  needsUpgrade?: boolean;
  lastInstalledAt?: string;
}

export interface PiPackageLifecycleResult {
  action: 'reused' | 'installed' | 'upgraded';
  record: AriavaPiInstallRecord;
  status: PiExtensionStatus;
}

export function buildExactPiPackageSource(cliVersion: string): string {
  const version = cliVersion.trim();
  if (!version) throw new TypeError('A nonempty CLI version is required for Pi package installation.');
  return `${ARIAVA_PI_PACKAGE_SOURCE}@${version}`;
}

/** Install or converge the production extension through Pi without editing Pi settings directly. */
export function ensureExactPiPackage(
  cliVersion: string,
  overrides: Partial<PiPackageLifecycleDependencies> = {},
): PiPackageLifecycleResult {
  const deps = piPackageDependencies(overrides);
  const before = inspectPiPackage(cliVersion, deps);
  if (before.sourceOwnership === 'managed-exact' && before.mismatchReasons.length === 0) {
    return { action: 'reused', record: createPiPackageRecord(before, deps.now()), status: before };
  }
  if (before.sourceOwnership === 'unmanaged' || before.sourceOwnership === 'ambiguous') {
    throw unmanagedPiError(before);
  }
  if (before.sourceOwnership === 'managed-exact') {
    throw mismatchError(before);
  }

  const exactSource = buildExactPiPackageSource(cliVersion);
  runPiPackageCommand(['install', exactSource], deps.runner);
  const after = inspectPiPackage(cliVersion, deps);
  if (after.sourceOwnership !== 'managed-exact' || after.mismatchReasons.length > 0) {
    throw mismatchError(after, 'Pi exited successfully but exact Ariava package verification failed.');
  }
  return {
    action: before.sourceOwnership === 'managed-upgrade' ? 'upgraded' : 'installed',
    record: createPiPackageRecord(after, deps.now()),
    status: after,
  };
}

/** Install the production extension at exactly the executing CLI version. */
export function installPiPackage(cliVersion: string, overrides: Partial<PiPackageLifecycleDependencies> = {}): AriavaPiInstallRecord {
  return ensureExactPiPackage(cliVersion, overrides).record;
}

/** Converge an older official package registration to exactly the executing CLI version. */
export function upgradePiPackage(cliVersion: string, overrides: Partial<PiPackageLifecycleDependencies> = {}): AriavaPiInstallRecord {
  return ensureExactPiPackage(cliVersion, overrides).record;
}

/** Remove both the Pi-managed npm package and an older Ariava-managed copy. */
export function removePiPackage(): void {
  if (isPiPackageRegistered()) runPiPackageCommand(['remove', ARIAVA_PI_PACKAGE_SOURCE], defaultPiRunner);
  removePiExtension();
}

/** Legacy/local installer retained only for `ariava dev install pi`. */
export function installPiExtension(options: PiExtensionInstallOptions): AriavaPiInstallRecord {
  const installPath = options.installPath ?? ARIAVA_PI_EXTENSION_DIR;
  const managedMetadataPath = options.managedMetadataPath ?? (options.installPath ? join(installPath, '.ariava-managed.json') : ARIAVA_PI_MANAGED_METADATA_PATH);
  const managedMetadata = readManagedPiMetadata(managedMetadataPath);
  const targetExists = existsSync(installPath);

  if (targetExists && !options.force && !managedMetadata) {
    throw new Error('The target pi extension directory already exists and is not managed by Ariava. Re-run with --force to replace it.');
  }

  rmSync(installPath, { recursive: true, force: true });
  mkdirSync(dirname(installPath), { recursive: true });
  cpSync(options.sourcePath, installPath, {
    recursive: true,
    force: true,
    filter(source) {
      const name = basename(source);
      return name !== 'node_modules' && name !== 'dist' && name !== '.DS_Store';
    },
  });

  if (options.installDependencies !== false && needsDependencyInstall(installPath)) installExtensionDependencies(installPath);

  const installedAt = isoNow();
  const record: AriavaPiInstallRecord = {
    installedAt,
    version: options.version,
    managedPath: installPath,
    source: { kind: options.sourceKind, path: resolve(options.sourcePath), updatedAt: installedAt },
  };
  writeFileSync(managedMetadataPath, `${JSON.stringify(record, null, 2)}\n`);
  return record;
}

/** Remove only the older copied extension. Production callers should use removePiPackage(). */
export function removePiExtension(installPath = ARIAVA_PI_EXTENSION_DIR): void {
  rmSync(installPath, { recursive: true, force: true });
}

export function readManagedPiMetadata(metadataPath = ARIAVA_PI_MANAGED_METADATA_PATH): AriavaPiInstallRecord | null {
  if (!existsSync(metadataPath)) return null;
  try {
    return JSON.parse(readFileSync(metadataPath, 'utf8')) as AriavaPiInstallRecord;
  } catch {
    return null;
  }
}

export function getPiExtensionStatus(
  bundledVersion: string,
  overrides: Partial<PiPackageLifecycleDependencies> = {},
): PiExtensionStatus {
  const packageStatus = inspectPiPackage(bundledVersion, overrides);
  if (packageStatus.registeredSource !== undefined || packageStatus.installed || packageStatus.sourceOwnership !== 'absent') return packageStatus;

  const legacyMetadataPath = ARIAVA_PI_MANAGED_METADATA_PATH;
  const legacyInstallPath = ARIAVA_PI_EXTENSION_DIR;
  const legacy = readManagedPiMetadata(legacyMetadataPath);
  return {
    ...packageStatus,
    installed: existsSync(legacyInstallPath),
    installPath: legacyInstallPath,
    managed: legacy !== null,
    managedMetadataPath: legacyMetadataPath,
    installedVersion: legacy?.version,
    source: legacy?.source,
    needsUpgrade: legacy ? legacy.version !== bundledVersion : undefined,
    lastInstalledAt: legacy?.installedAt,
  };
}

export function inspectPiPackage(
  cliVersion: string,
  overrides: Partial<PiPackageLifecycleDependencies> = {},
): PiExtensionStatus {
  const deps = piPackageDependencies(overrides);
  const expectedSource = buildExactPiPackageSource(cliVersion);
  const settings = readPiSettings(deps);
  const sources = settings.sources;
  const officialSources = sources.filter(isOfficialAriavaSource);
  const suspiciousSources = sources.filter((source) => !isOfficialAriavaSource(source) && source.includes(ARIAVA_PI_PACKAGE_NAME));
  const manifest = readPackageManifest(deps);
  const packageExists = deps.pathExists(deps.packagePath);
  const mismatchReasons: string[] = [];
  let sourceOwnership: PiPackageOwnership;

  if (settings.invalid) {
    sourceOwnership = 'unmanaged';
    mismatchReasons.push('settings-invalid');
  } else if (officialSources.length > 1) {
    sourceOwnership = 'ambiguous';
    mismatchReasons.push('duplicate-official-sources');
  } else if (suspiciousSources.length > 0) {
    sourceOwnership = 'unmanaged';
    mismatchReasons.push('foreign-source');
  } else if (officialSources.length === 0) {
    sourceOwnership = 'absent';
  } else {
    sourceOwnership = officialSources[0] === expectedSource ? 'managed-exact' : 'managed-upgrade';
  }

  if (officialSources.length === 1) {
    if (!packageExists) mismatchReasons.push('managed-path-missing');
    if (!manifest) mismatchReasons.push('manifest-missing');
    else {
      if (manifest.name !== ARIAVA_PI_PACKAGE_NAME) mismatchReasons.push('manifest-name-mismatch');
      if (manifest.version !== cliVersion) mismatchReasons.push('manifest-version-mismatch');
    }
  }

  const registeredSource = officialSources[0] ?? suspiciousSources[0];
  return {
    installed: officialSources.length === 1 && packageExists && manifest?.name === ARIAVA_PI_PACKAGE_NAME,
    installPath: deps.packagePath,
    expectedManagedPath: deps.packagePath,
    managed: sourceOwnership === 'managed-exact' || sourceOwnership === 'managed-upgrade',
    managedMetadataPath: deps.settingsPath,
    registeredSource,
    expectedSource,
    manifestName: manifest?.name,
    manifestVersion: manifest?.version,
    sourceOwnership,
    mismatchReasons,
    installedVersion: manifest?.version,
    bundledVersion: cliVersion,
    source: registeredSource ? { kind: 'npm-package', package: registeredSource, updatedAt: deps.now() } : undefined,
    needsUpgrade: sourceOwnership === 'managed-upgrade' || manifest?.version !== cliVersion,
  };
}

export function resolveReleasePiSource(repoRoot = process.cwd()): string {
  return join(repoRoot, 'extensions', 'pi', 'bundle');
}

export function resolveDevPiSource(explicitPath?: string, cwd = process.cwd()): string {
  return explicitPath ? resolve(explicitPath) : join(cwd, 'extensions', 'pi', 'bundle');
}

function createPiPackageRecord(status: PiExtensionStatus, installedAt: string): AriavaPiInstallRecord {
  if (!status.registeredSource || !status.manifestVersion || status.mismatchReasons.length > 0) throw mismatchError(status);
  return {
    installedAt,
    version: status.manifestVersion,
    managedPath: status.expectedManagedPath,
    source: { kind: 'npm-package', package: status.registeredSource, updatedAt: installedAt },
  };
}

function mismatchError(status: PiExtensionStatus, message = 'Ariava Pi package evidence does not match the required CLI version.'): AriavaCliError {
  let code: AriavaCliError['code'] = 'ERR_EXTENSION_INSTALL';
  if (status.mismatchReasons.includes('manifest-version-mismatch')) {
    code = 'ERR_EXTENSION_VERSION_MISMATCH';
  } else if (status.mismatchReasons.some((reason) =>
    reason === 'manifest-name-mismatch' || reason === 'foreign-source' || reason === 'duplicate-official-sources')) {
    code = 'ERR_EXTENSION_UNMANAGED';
  }
  return new AriavaCliError(code, message, {
    expectedSource: status.expectedSource,
    registeredSource: status.registeredSource,
    expectedManagedPath: status.expectedManagedPath,
    manifestName: status.manifestName,
    manifestVersion: status.manifestVersion,
    mismatchReasons: status.mismatchReasons,
  });
}

function unmanagedPiError(status: PiExtensionStatus): AriavaCliError {
  return new AriavaCliError('ERR_EXTENSION_UNMANAGED', 'The existing Pi package registration is ambiguous or is not managed by the official Ariava npm source.', {
    expectedSource: status.expectedSource,
    registeredSource: status.registeredSource,
    expectedManagedPath: status.expectedManagedPath,
    mismatchReasons: status.mismatchReasons,
  });
}

function runPiPackageCommand(args: string[], runner: CommandRunner): void {
  const result = runner.run('pi', args);
  if (result.status === 0) return;
  if (result.error?.code === 'ENOENT') {
    throw new AriavaCliError('ERR_AGENT_RUNTIME_NOT_FOUND', 'pi CLI is required. Install pi, then retry the Ariava pi package command.');
  }
  const rawDetail = (result.stderr || result.stdout || result.error?.message || `pi ${args.join(' ')} failed.`).trim();
  throw new AriavaCliError('ERR_EXTENSION_INSTALL', 'Pi package command failed.', {
    command: 'pi', args, exitCode: result.status, detail: sanitizeCommandDetail(rawDetail),
  });
}

const defaultPiRunner: CommandRunner = new SpawnSyncCommandRunner();

function piPackageDependencies(overrides: Partial<PiPackageLifecycleDependencies>): PiPackageLifecycleDependencies {
  const agentDir = piAgentDir();
  return {
    runner: overrides.runner ?? defaultPiRunner,
    settingsPath: overrides.settingsPath ?? join(agentDir, 'settings.json'),
    packagePath: overrides.packagePath ?? join(agentDir, 'npm', 'node_modules', ...ARIAVA_PI_PACKAGE_NAME.split('/')),
    readText: overrides.readText ?? ((path) => {
      try { return readFileSync(path, 'utf8'); } catch { return undefined; }
    }),
    pathExists: overrides.pathExists ?? existsSync,
    now: overrides.now ?? isoNow,
  };
}

function piAgentDir(): string {
  const configured = process.env.PI_CODING_AGENT_DIR?.trim();
  return configured ? resolve(configured) : join(homedir(), '.pi', 'agent');
}

function readPiSettings(deps: PiPackageLifecycleDependencies): { sources: string[]; invalid: boolean } {
  const text = deps.readText(deps.settingsPath);
  if (text === undefined) return { sources: [], invalid: false };
  try {
    const value = JSON.parse(text) as { packages?: unknown };
    if (value.packages === undefined) return { sources: [], invalid: false };
    if (!Array.isArray(value.packages)) return { sources: [], invalid: true };
    const sources: string[] = [];
    for (const entry of value.packages) {
      if (typeof entry === 'string') sources.push(entry);
      else if (entry && typeof entry === 'object' && typeof (entry as { source?: unknown }).source === 'string') sources.push((entry as { source: string }).source);
    }
    return { sources, invalid: false };
  } catch {
    return { sources: [], invalid: true };
  }
}

function readPackageManifest(deps: PiPackageLifecycleDependencies): { name?: string; version?: string } | undefined {
  const text = deps.readText(join(deps.packagePath, 'package.json'));
  if (text === undefined) return undefined;
  try {
    const value = JSON.parse(text) as { name?: unknown; version?: unknown };
    return {
      name: typeof value.name === 'string' ? value.name : undefined,
      version: typeof value.version === 'string' ? value.version : undefined,
    };
  } catch {
    return undefined;
  }
}

function isOfficialAriavaSource(source: string): boolean {
  if (source === ARIAVA_PI_PACKAGE_SOURCE) return true;
  if (!source.startsWith(`${ARIAVA_PI_PACKAGE_SOURCE}@`)) return false;
  return source.slice(ARIAVA_PI_PACKAGE_SOURCE.length + 1).length > 0;
}

function isPiPackageRegistered(): boolean {
  return readPiSettings(piPackageDependencies({})).sources.some(isOfficialAriavaSource);
}

function needsDependencyInstall(installPath: string): boolean {
  return existsSync(join(installPath, 'package.json')) && !existsSync(join(installPath, '.ariava-release-bundle.json'));
}

function installExtensionDependencies(installPath: string): void {
  const bun = spawnSync('bun', ['install'], { cwd: installPath, encoding: 'utf8', shell: false });
  if (bun.status === 0) return;
  const npm = spawnSync('npm', ['install'], { cwd: installPath, encoding: 'utf8', shell: false });
  if (npm.status === 0) return;
  throw new Error((npm.stderr || bun.stderr || 'Failed to install pi extension dependencies.').trim());
}
