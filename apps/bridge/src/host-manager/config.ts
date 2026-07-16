import { dirname, isAbsolute, resolve } from 'node:path';
import type { HostIdentityMetadata } from '../identity/types';
import {
  ensureSecureDirectory,
  pathHasFilesystemEvidence,
  readSecureJson,
  writeSecureJson,
} from './secure-files';
import type { AriavaServiceInstallRecord } from './service/types';
import {
  normalizeInstallMetadata,
  type InstallMetadataLoadResult,
} from './service/migration';
import { AriavaCliError } from './service/errors';
import {
  ARIAVA_AGENT_ADAPTER_CONFIG_PATH,
  ARIAVA_CONFIG_PATH,
  ARIAVA_INSTALL_PATH,
  ARIAVA_LOG_DIR,
  ARIAVA_HOST_IDENTITY_PATH,
  ARIAVA_STATE_PATH,
  ARIAVA_STDERR_LOG_PATH,
  ARIAVA_STDOUT_LOG_PATH,
  ARIAVA_TMP_DIR,
} from './paths';

export interface AriavaUserConfig {
  relayBaseUrl?: string;
  hostName?: string;
  agentAdapterPort?: number;
  agentAdapterConfigPath?: string;
  agentAdapterSecret?: string;
  statePath?: string;
  identity?: HostIdentityMetadata;
  identityPath?: string;
  pollIntervalMs?: number;
}

export type AssetSourceKind = 'release-bundle' | 'npm-package' | 'dev-repo' | 'explicit-path';

export interface AriavaAssetSource {
  kind: AssetSourceKind;
  path?: string;
  package?: string;
  updatedAt: string;
}

export type AriavaInstallerManager = 'npm' | 'pnpm' | 'bun' | 'homebrew';

export interface AriavaInstallerMetadata {
  manager: AriavaInstallerManager;
  ariavaBinRealPath: string;
  recordedAt: string;
}

export type { AriavaServiceInstallRecord } from './service/types';

export interface AriavaPiInstallRecord {
  installedAt: string;
  version: string;
  managedPath: string;
  source: AriavaAssetSource;
}

export interface AriavaInstallMetadata {
  bridgeSource?: AriavaAssetSource;
  piSource?: AriavaAssetSource;
  service?: AriavaServiceInstallRecord;
  piExtension?: AriavaPiInstallRecord;
  identityPath?: string;
  installer?: AriavaInstallerMetadata;
}

export interface ResolvedAriavaConfig extends AriavaUserConfig {
  relayBaseUrl: string;
  hostName: string;
  agentAdapterPort: number;
  agentAdapterConfigPath: string;
  statePath: string;
  identityPath: string;
  configPath: string;
  installPath: string;
  logDir: string;
  stdoutLogPath: string;
  stderrLogPath: string;
  tmpDir: string;
  environmentOverrides: string[];
}

export function loadUserConfig(configPath = ARIAVA_CONFIG_PATH): AriavaUserConfig {
  return readJsonFile<AriavaUserConfig>(configPath, {});
}

export function saveUserConfig(config: AriavaUserConfig, configPath = ARIAVA_CONFIG_PATH): void {
  writeJsonFile(configPath, config);
}

export function loadInstallMetadataDetailed(installPath = ARIAVA_INSTALL_PATH): InstallMetadataLoadResult {
  if (!pathHasFilesystemEvidence(installPath)) return normalizeInstallMetadata({});
  return normalizeInstallMetadata(readSecureJson<unknown>(installPath));
}

export function loadInstallMetadata(installPath = ARIAVA_INSTALL_PATH): AriavaInstallMetadata {
  const result = loadInstallMetadataDetailed(installPath);
  assertValidInstallMetadata(result);
  return result.metadata;
}

export function saveInstallMetadata(metadata: AriavaInstallMetadata, installPath = ARIAVA_INSTALL_PATH): void {
  const result = normalizeInstallMetadata(metadata);
  assertValidInstallMetadata(result);
  writeJsonFile(installPath, result.metadata);
}

export function mergeInstallMetadata(
  patch: Partial<AriavaInstallMetadata>,
  installPath = ARIAVA_INSTALL_PATH,
): AriavaInstallMetadata {
  const next = normalizeInstallMetadata({ ...loadInstallMetadata(installPath), ...patch }).metadata;
  saveInstallMetadata(next, installPath);
  return next;
}

function assertValidInstallMetadata(result: InstallMetadataLoadResult): void {
  if (result.diagnostics.serviceMetadataValid
    && result.diagnostics.installerMetadataValid !== false
    && result.diagnostics.documentMetadataValid !== false) return;
  throw new AriavaCliError(
    'ERR_SERVICE_METADATA',
    'Ariava install metadata is invalid. Repair or remove the corrupt install metadata before retrying.',
    {
      serviceMetadataIssue: result.diagnostics.serviceMetadataIssue,
      installerMetadataIssue: result.diagnostics.installerMetadataIssue,
      documentMetadataIssue: result.diagnostics.documentMetadataIssue,
    },
  );
}

export function resolveAriavaConfig(
  overrides: Partial<AriavaUserConfig> = {},
  configPath = ARIAVA_CONFIG_PATH,
  useEnvironment = true,
): ResolvedAriavaConfig {
  const resolvedConfigPath = resolveRequiredPersistedPath(configPath, 'Ariava config path');
  const fileConfig = loadUserConfig(resolvedConfigPath);
  const environmentOverrides: string[] = [];
  const env = (name: string): string | undefined => useEnvironment ? readEnv(name, environmentOverrides) : undefined;

  const relayBaseUrl = env('ARIAVA_RELAY_BASE_URL') ?? overrides.relayBaseUrl ?? fileConfig.relayBaseUrl ?? 'http://127.0.0.1:8787';
  const hostName = env('ARIAVA_HOST_NAME') ?? overrides.hostName ?? fileConfig.hostName ?? '';
  const agentAdapterPort = Number.parseInt(
    env('ARIAVA_AGENT_ADAPTER_PORT') ?? String(overrides.agentAdapterPort ?? fileConfig.agentAdapterPort ?? 7272),
    10,
  );
  const agentAdapterConfigPath =
    env('ARIAVA_AGENT_ADAPTER_CONFIG_PATH')
    ?? overrides.agentAdapterConfigPath
    ?? fileConfig.agentAdapterConfigPath
    ?? ARIAVA_AGENT_ADAPTER_CONFIG_PATH;
  const statePath = env('ARIAVA_STATE_PATH') ?? overrides.statePath ?? fileConfig.statePath ?? ARIAVA_STATE_PATH;
  const agentAdapterSecret = env('ARIAVA_AGENT_ADAPTER_SECRET') ?? overrides.agentAdapterSecret ?? fileConfig.agentAdapterSecret;
  const identityPath = resolveIdentityPath(overrides, fileConfig, environmentOverrides, useEnvironment);
  const resolvedAgentAdapterPath = resolveRequiredPersistedPath(agentAdapterConfigPath, 'Agent Adapter config path');
  const resolvedStatePath = resolveRequiredPersistedPath(statePath, 'Bridge state path');

  return {
    relayBaseUrl,
    ...fileConfig,
    ...overrides,
    hostName,
    agentAdapterPort: Number.isFinite(agentAdapterPort) ? agentAdapterPort : 7272,
    agentAdapterConfigPath: resolvedAgentAdapterPath,
    statePath: resolvedStatePath,
    identityPath,
    agentAdapterSecret,
    configPath: resolvedConfigPath,
    installPath: ARIAVA_INSTALL_PATH,
    logDir: ARIAVA_LOG_DIR,
    stdoutLogPath: ARIAVA_STDOUT_LOG_PATH,
    stderrLogPath: ARIAVA_STDERR_LOG_PATH,
    tmpDir: ARIAVA_TMP_DIR,
    environmentOverrides,
  };
}

export function resolvePersistedAriavaConfig(configPath: string): ResolvedAriavaConfig {
  return resolveAriavaConfig({}, configPath, false);
}

export function ensureParentDir(path: string): void {
  const parent = dirname(path);
  if (!isAbsolute(parent)) throw new TypeError('Ariava persisted paths must be absolute');
  ensureSecureDirectory(resolve(parent));
}

function resolveRequiredPersistedPath(path: string, label: string): string {
  if (!isAbsolute(path)) throw new TypeError(`${label} must be absolute`);
  return resolve(path);
}

function resolveIdentityPath(
  overrides: Partial<AriavaUserConfig>,
  fileConfig: AriavaUserConfig,
  environmentOverrides: string[],
  useEnvironment: boolean,
): string {
  const persisted = overrides.identityPath ?? fileConfig.identityPath;
  if (persisted !== undefined) return resolveRequiredPersistedPath(persisted, 'Host identity path');
  const environmentPath = useEnvironment ? readEnv('ARIAVA_HOST_IDENTITY_PATH', environmentOverrides) : undefined;
  return environmentPath === undefined
    ? ARIAVA_HOST_IDENTITY_PATH
    : resolveRequiredPersistedPath(environmentPath, 'Host identity path');
}

function readEnv(name: string, sink: string[]): string | undefined {
  const value = process.env[name]?.trim();
  if (!value) return undefined;
  sink.push(name);
  return value;
}

function readJsonFile<T>(path: string, fallback: T): T {
  if (!pathHasFilesystemEvidence(path)) return structuredClone(fallback);
  return { ...structuredClone(fallback), ...readSecureJson<Record<string, unknown>>(path) } as T;
}

function writeJsonFile(path: string, value: unknown): void {
  ensureParentDir(path);
  writeSecureJson(path, value);
}
