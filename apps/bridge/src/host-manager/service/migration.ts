import { isAbsolute, resolve } from 'node:path';
import { isCanonicalTimestamp } from '@ariava/protocol/validation';
import { ARIAVA_LAUNCHD_LABEL, ARIAVA_SYSTEMD_SERVICE_ID } from '../paths';
import type { AriavaInstallMetadata, AriavaInstallerMetadata } from '../config';
import type { AriavaServiceInstallRecord, ServiceBackend } from './types';

export interface InstallMetadataDiagnostics {
  serviceMetadataValid: boolean;
  installerMetadataValid?: boolean;
  serviceMetadataIssue?: 'invalid-service-record';
  installerMetadataIssue?: 'invalid-installer-record';
  documentMetadataValid?: boolean;
  documentMetadataIssue?: 'invalid-root' | 'invalid-identity-path' | 'invalid-source-record';
}

export interface InstallMetadataLoadResult {
  metadata: AriavaInstallMetadata;
  diagnostics: InstallMetadataDiagnostics;
}

type UnknownRecord = Record<string, unknown>;

export function normalizeInstallMetadata(value: unknown): InstallMetadataLoadResult {
  if (!isRecord(value)) return invalidDocumentResult('invalid-root');

  const metadata: AriavaInstallMetadata = {};
  let documentIssue: InstallMetadataDiagnostics['documentMetadataIssue'];
  if ('bridgeSource' in value && value.bridgeSource !== undefined) {
    if (isAssetSource(value.bridgeSource)) metadata.bridgeSource = value.bridgeSource;
    else documentIssue = 'invalid-source-record';
  }
  if ('piSource' in value && value.piSource !== undefined) {
    if (isAssetSource(value.piSource)) metadata.piSource = value.piSource;
    else documentIssue = 'invalid-source-record';
  }
  if ('piExtension' in value && value.piExtension !== undefined) {
    if (isPiExtensionRecord(value.piExtension)) metadata.piExtension = value.piExtension;
    else documentIssue = 'invalid-source-record';
  }
  if ('identityPath' in value && value.identityPath !== undefined) {
    if (safeAbsolutePath(value.identityPath)) metadata.identityPath = resolve(value.identityPath);
    else documentIssue = 'invalid-identity-path';
  }
  const hasInstaller = 'installer' in value && value.installer !== undefined;
  const installerValid = isInstallerMetadata(value.installer);
  if (installerValid) metadata.installer = value.installer;
  if (!('service' in value) || value.service === undefined) {
    return validResult(metadata, hasInstaller && !installerValid, documentIssue);
  }

  const service = normalizeServiceInstallRecord(value.service);
  if (!service) {
    return {
      metadata,
      diagnostics: {
        serviceMetadataValid: false,
        ...(hasInstaller ? { installerMetadataValid: installerValid } : {}),
        serviceMetadataIssue: 'invalid-service-record',
        ...(hasInstaller && !installerValid ? { installerMetadataIssue: 'invalid-installer-record' as const } : {}),
      },
    };
  }

  metadata.service = service;
  return validResult(metadata, hasInstaller && !installerValid, documentIssue);
}

export function normalizeServiceInstallRecord(value: unknown): AriavaServiceInstallRecord | undefined {
  if (!isRecord(value)) return undefined;

  if ('backend' in value) {
    if (!isServiceBackend(value.backend)) return undefined;
    if (!hasNonEmptyStrings(value, [
      'installedAt',
      'runtimePath',
      'ariavaBinPath',
      'definitionPath',
      'serviceId',
    ])) return undefined;
    const hasConfigPath = typeof value.configPath === 'string' && safeAbsolutePath(value.configPath);
    const hasIdentityReference = isPublicIdentityReference(value.identityReference);
    if (hasConfigPath !== hasIdentityReference) return undefined;
    if (!isValidServiceRecordPaths(value, value.backend)) return undefined;
    return {
      backend: value.backend,
      installedAt: value.installedAt as string,
      runtimePath: value.runtimePath as string,
      ariavaBinPath: value.ariavaBinPath as string,
      definitionPath: value.definitionPath as string,
      serviceId: value.serviceId as string,
      ...(hasConfigPath ? {
        configPath: value.configPath as string,
        identityReference: value.identityReference as NonNullable<AriavaServiceInstallRecord['identityReference']>,
      } : {}),
    };
  }

  if (!hasNonEmptyStrings(value, ['installedAt', 'nodePath', 'ariavaBinPath', 'plistPath', 'label'])
    || !isValidLegacyLaunchdRecord(value)) {
    return undefined;
  }
  return {
    backend: 'launchd',
    installedAt: value.installedAt as string,
    runtimePath: value.nodePath as string,
    ariavaBinPath: value.ariavaBinPath as string,
    definitionPath: value.plistPath as string,
    serviceId: value.label as string,
    ...(typeof value.configPath === 'string' && isPublicIdentityReference(value.identityReference)
      ? { configPath: value.configPath, identityReference: value.identityReference }
      : {}),
  };
}

function validResult(
  metadata: AriavaInstallMetadata,
  installerInvalid = false,
  documentIssue?: InstallMetadataDiagnostics['documentMetadataIssue'],
): InstallMetadataLoadResult {
  return {
    metadata,
    diagnostics: {
      serviceMetadataValid: true,
      ...(installerInvalid ? {
        installerMetadataValid: false,
        installerMetadataIssue: 'invalid-installer-record' as const,
      } : {}),
      ...(documentIssue ? { documentMetadataValid: false, documentMetadataIssue: documentIssue } : {}),
    },
  };
}

function invalidDocumentResult(issue: NonNullable<InstallMetadataDiagnostics['documentMetadataIssue']>): InstallMetadataLoadResult {
  return {
    metadata: {},
    diagnostics: { serviceMetadataValid: true, documentMetadataValid: false, documentMetadataIssue: issue },
  };
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isServiceBackend(value: unknown): value is ServiceBackend {
  return value === 'launchd' || value === 'systemd-user';
}

function isInstallerMetadata(value: unknown): value is AriavaInstallerMetadata {
  return isRecord(value)
    && (value.manager === 'npm' || value.manager === 'pnpm' || value.manager === 'bun' || value.manager === 'homebrew')
    && typeof value.ariavaBinRealPath === 'string'
    && safeAbsolutePath(value.ariavaBinRealPath)
    && typeof value.recordedAt === 'string'
    && isCanonicalTimestamp(value.recordedAt);
}

function isPublicIdentityReference(value: unknown): value is AriavaServiceInstallRecord['identityReference'] {
  if (!isRecord(value)) return false;
  if (value.type === 'linux-json') return typeof value.path === 'string' && safeAbsolutePath(value.path);
  return value.type === 'macos-keychain'
    && value.service === 'io.noyx.ariava.host-identity'
    && typeof value.account === 'string'
    && value.account.length > 0;
}

function isValidServiceRecordPaths(value: UnknownRecord, backend: ServiceBackend): boolean {
  return safeAbsolutePath(value.runtimePath)
    && safeAbsolutePath(value.ariavaBinPath)
    && safeAbsolutePath(value.definitionPath)
    && value.serviceId === (backend === 'launchd' ? ARIAVA_LAUNCHD_LABEL : ARIAVA_SYSTEMD_SERVICE_ID);
}

function isValidLegacyLaunchdRecord(value: UnknownRecord): boolean {
  return safeAbsolutePath(value.nodePath)
    && safeAbsolutePath(value.ariavaBinPath)
    && safeAbsolutePath(value.plistPath)
    && value.label === ARIAVA_LAUNCHD_LABEL;
}

function safeAbsolutePath(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && isAbsolute(value)
    && resolve(value) === value
    && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
}

function isAssetSource(value: unknown): value is NonNullable<AriavaInstallMetadata['bridgeSource']> {
  if (!isRecord(value)
    || (value.kind !== 'release-bundle' && value.kind !== 'npm-package' && value.kind !== 'dev-repo' && value.kind !== 'explicit-path')
    || typeof value.updatedAt !== 'string' || value.updatedAt.length === 0) return false;
  if (value.path !== undefined && !safeAbsolutePath(value.path)) return false;
  if (value.package !== undefined && (typeof value.package !== 'string' || value.package.length === 0)) return false;
  if (value.kind === 'npm-package') return typeof value.package === 'string';
  return value.kind === 'release-bundle' || typeof value.path === 'string';
}

function isPiExtensionRecord(value: unknown): value is NonNullable<AriavaInstallMetadata['piExtension']> {
  return isRecord(value)
    && typeof value.installedAt === 'string' && value.installedAt.length > 0
    && typeof value.version === 'string' && value.version.length > 0
    && safeAbsolutePath(value.managedPath)
    && isAssetSource(value.source);
}

function hasNonEmptyStrings(value: UnknownRecord, keys: string[]): boolean {
  return keys.every((key) => typeof value[key] === 'string' && value[key].trim().length > 0);
}
