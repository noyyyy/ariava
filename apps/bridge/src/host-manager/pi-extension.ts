import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { isoNow } from '@ariava/shared-utils';
import type { AriavaAssetSource, AriavaPiInstallRecord } from './config';
import { ARIAVA_PI_EXTENSION_DIR, ARIAVA_PI_MANAGED_METADATA_PATH } from './paths';

export const ARIAVA_PI_PACKAGE_SOURCE = 'npm:@ariava/pi-extension';
const ARIAVA_PI_PACKAGE_NAME = '@ariava/pi-extension';

export interface PiExtensionInstallOptions {
  sourcePath: string;
  sourceKind: AriavaAssetSource['kind'];
  version: string;
  force?: boolean;
  installDependencies?: boolean;
}

export interface PiExtensionStatus {
  installed: boolean;
  installPath: string;
  managed: boolean;
  managedMetadataPath: string;
  installedVersion?: string;
  bundledVersion?: string;
  source?: AriavaAssetSource;
  needsUpgrade?: boolean;
  lastInstalledAt?: string;
}

/** Install the production extension through Pi so it persists in settings.json. */
export function installPiPackage(): AriavaPiInstallRecord {
  runPiPackageCommand(['install', ARIAVA_PI_PACKAGE_SOURCE]);
  removeLegacyManagedPiExtension();
  return createPiPackageRecord();
}

/** Ask Pi to update the package, installing it first if it is not registered. */
export function upgradePiPackage(): AriavaPiInstallRecord {
  if (isPiPackageRegistered()) runPiPackageCommand(['update', ARIAVA_PI_PACKAGE_SOURCE]);
  else runPiPackageCommand(['install', ARIAVA_PI_PACKAGE_SOURCE]);
  removeLegacyManagedPiExtension();
  return createPiPackageRecord();
}

/** Remove both the Pi-managed npm package and an older Ariava-managed copy. */
export function removePiPackage(): void {
  if (isPiPackageRegistered()) runPiPackageCommand(['remove', ARIAVA_PI_PACKAGE_SOURCE]);
  removePiExtension();
}

/** Legacy/local installer retained only for `ariava dev install pi`. */
export function installPiExtension(options: PiExtensionInstallOptions): AriavaPiInstallRecord {
  const installPath = ARIAVA_PI_EXTENSION_DIR;
  const managedMetadata = readManagedPiMetadata();
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

  if (options.installDependencies !== false && needsDependencyInstall(installPath)) {
    installExtensionDependencies(installPath);
  }

  const record: AriavaPiInstallRecord = {
    installedAt: isoNow(),
    version: options.version,
    managedPath: installPath,
    source: {
      kind: options.sourceKind,
      path: resolve(options.sourcePath),
      updatedAt: isoNow(),
    },
  };

  writeFileSync(ARIAVA_PI_MANAGED_METADATA_PATH, `${JSON.stringify(record, null, 2)}\n`);
  return record;
}

/** Remove only the older copied extension. Production callers should use removePiPackage(). */
export function removePiExtension(): void {
  rmSync(ARIAVA_PI_EXTENSION_DIR, { recursive: true, force: true });
}

export function readManagedPiMetadata(): AriavaPiInstallRecord | null {
  if (!existsSync(ARIAVA_PI_MANAGED_METADATA_PATH)) return null;
  try {
    return JSON.parse(readFileSync(ARIAVA_PI_MANAGED_METADATA_PATH, 'utf8')) as AriavaPiInstallRecord;
  } catch {
    return null;
  }
}

export function getPiExtensionStatus(bundledVersion: string): PiExtensionStatus {
  const packageRegistered = isPiPackageRegistered();
  const packagePath = piPackageInstallPath();
  const packageVersion = readPackageVersion(packagePath);
  const legacy = readManagedPiMetadata();
  const packageSource: AriavaAssetSource = { kind: 'npm-package', package: ARIAVA_PI_PACKAGE_SOURCE, updatedAt: legacy?.installedAt ?? isoNow() };
  const installed = packageRegistered && existsSync(packagePath);

  if (packageRegistered || installed) {
    return {
      installed,
      installPath: packagePath,
      managed: packageRegistered,
      managedMetadataPath: piSettingsPath(),
      installedVersion: packageVersion,
      bundledVersion,
      source: packageSource,
      needsUpgrade: packageVersion ? packageVersion !== bundledVersion : undefined,
    };
  }

  return {
    installed: existsSync(ARIAVA_PI_EXTENSION_DIR),
    installPath: ARIAVA_PI_EXTENSION_DIR,
    managed: legacy !== null,
    managedMetadataPath: ARIAVA_PI_MANAGED_METADATA_PATH,
    installedVersion: legacy?.version,
    bundledVersion,
    source: legacy?.source,
    needsUpgrade: legacy ? legacy.version !== bundledVersion : undefined,
    lastInstalledAt: legacy?.installedAt,
  };
}

export function resolveReleasePiSource(repoRoot = process.cwd()): string {
  return join(repoRoot, 'extensions', 'pi', 'bundle');
}

export function resolveDevPiSource(explicitPath?: string, cwd = process.cwd()): string {
  return explicitPath ? resolve(explicitPath) : join(cwd, 'extensions', 'pi', 'bundle');
}

function createPiPackageRecord(): AriavaPiInstallRecord {
  const managedPath = piPackageInstallPath();
  const version = readPackageVersion(managedPath);
  if (!isPiPackageRegistered() || !existsSync(managedPath) || !version) {
    throw new Error(`Pi did not register ${ARIAVA_PI_PACKAGE_SOURCE} correctly. Run \`pi list\` for details.`);
  }
  const installedAt = isoNow();
  return {
    installedAt,
    version,
    managedPath,
    source: { kind: 'npm-package', package: ARIAVA_PI_PACKAGE_SOURCE, updatedAt: installedAt },
  };
}

function runPiPackageCommand(args: string[]): void {
  const result = spawnSync('pi', args, { encoding: 'utf8' });
  if (result.status === 0) return;
  if (result.error && (result.error as NodeJS.ErrnoException).code === 'ENOENT') {
    throw new Error('pi CLI is required. Install pi, then retry the Ariava pi package command.');
  }
  throw new Error((result.stderr || result.stdout || result.error?.message || `pi ${args.join(' ')} failed.`).trim());
}

function piAgentDir(): string {
  const configured = process.env.PI_CODING_AGENT_DIR?.trim();
  return configured ? resolve(configured) : join(homedir(), '.pi', 'agent');
}

function piSettingsPath(): string {
  return join(piAgentDir(), 'settings.json');
}

function piPackageInstallPath(): string {
  return join(piAgentDir(), 'npm', 'node_modules', ...ARIAVA_PI_PACKAGE_NAME.split('/'));
}

function isPiPackageRegistered(): boolean {
  try {
    const settings = JSON.parse(readFileSync(piSettingsPath(), 'utf8')) as { packages?: Array<string | { source?: string }> };
    return (settings.packages ?? []).some((entry) => {
      const source = typeof entry === 'string' ? entry : entry.source;
      return source === ARIAVA_PI_PACKAGE_SOURCE || source?.startsWith(`${ARIAVA_PI_PACKAGE_SOURCE}@`) === true;
    });
  } catch {
    return false;
  }
}

function readPackageVersion(packagePath: string): string | undefined {
  try {
    const manifest = JSON.parse(readFileSync(join(packagePath, 'package.json'), 'utf8')) as { version?: string };
    return manifest.version;
  } catch {
    return undefined;
  }
}

function removeLegacyManagedPiExtension(): void {
  if (readManagedPiMetadata()) removePiExtension();
}

function needsDependencyInstall(installPath: string): boolean {
  return existsSync(join(installPath, 'package.json')) && !existsSync(join(installPath, '.ariava-release-bundle.json'));
}

function installExtensionDependencies(installPath: string): void {
  const bun = spawnSync('bun', ['install'], { cwd: installPath, encoding: 'utf8' });
  if (bun.status === 0) return;

  const npm = spawnSync('npm', ['install'], { cwd: installPath, encoding: 'utf8' });
  if (npm.status === 0) return;

  throw new Error((npm.stderr || bun.stderr || 'Failed to install pi extension dependencies.').trim());
}
