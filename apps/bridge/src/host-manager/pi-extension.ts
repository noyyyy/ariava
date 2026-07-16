import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { isoNow } from '@ariava/shared-utils';
import type { AriavaAssetSource, AriavaPiInstallRecord } from './config';
import { ARIAVA_PI_EXTENSION_DIR, ARIAVA_PI_MANAGED_METADATA_PATH } from './paths';

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
  const managed = readManagedPiMetadata();
  return {
    installed: existsSync(ARIAVA_PI_EXTENSION_DIR),
    installPath: ARIAVA_PI_EXTENSION_DIR,
    managed: managed !== null,
    managedMetadataPath: ARIAVA_PI_MANAGED_METADATA_PATH,
    installedVersion: managed?.version,
    bundledVersion,
    source: managed?.source,
    needsUpgrade: managed ? managed.version !== bundledVersion : undefined,
    lastInstalledAt: managed?.installedAt,
  };
}

export function resolveReleasePiSource(repoRoot = process.cwd()): string {
  return join(repoRoot, 'extensions', 'pi', 'bundle');
}

export function resolveDevPiSource(explicitPath?: string, cwd = process.cwd()): string {
  return explicitPath ? resolve(explicitPath) : join(cwd, 'extensions', 'pi', 'bundle');
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
