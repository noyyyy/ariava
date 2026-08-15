import type { HostReplacementSpoolKeyStore } from '../../e2e/local-spool';
import { removeSecureFileIfPresent } from '../../host-manager/secure-files';
import {
  assertRuntimeCoordinatorPaths,
  assertRuntimeWriterAllowed,
  type RuntimeCoordinator,
} from '../../runtime-lock';
import type { ResolvedProfileResources } from '../context';
import { HOST_DOMAIN_RESET_BINDING_INPUTS } from './host-domain-reset-journal-binding';

/**
 * Fixed Host-domain reset artifact cleanup plan (primary spec §3.3,
 * journal-boundary spec §7.1).
 *
 * The generic destructive cleanup helper may delete EXACTLY these resources
 * and nothing else:
 *   - link keyring (`linkKeyringPath`);
 *   - runtime state (`statePath`);
 *   - encrypted spool (`encryptedSpoolPath`);
 *   - runtime reset intent (`runtimeResetIntentPath`);
 *   - exact spool-key evidence via `HostReplacementSpoolKeyStore`.
 *
 * Agent Adapter config, Pi log, profile root, install metadata, and
 * non-identity config are preserved. Signing/X25519 stores keep their own
 * exact old-key/account cleanup and are never delegated to this helper.
 */
export const HOST_DOMAIN_RESET_CLEANUP_TARGETS = [
  'linkKeyringPath',
  'statePath',
  'encryptedSpoolPath',
  'runtimeResetIntentPath',
] as const;

export type HostDomainResetCleanupTarget = (typeof HOST_DOMAIN_RESET_CLEANUP_TARGETS)[number];

/**
 * Resources explicitly preserved by the generic artifact helper (primary spec
 * §3.3). None of these may be a generic cleanup target.
 */
export const HOST_DOMAIN_RESET_PRESERVED_RESOURCES = [
  'root',
  'configPath',
  'agentAdapterConfigPath',
  'piExtensionLogPath',
  'installMetadataPath',
] as const;

export type HostDomainResetPreservedResource = (typeof HOST_DOMAIN_RESET_PRESERVED_RESOURCES)[number];

/**
 * Pure boundary assertion: every generic cleanup target must be a journal
 * binding input, and no preserved resource may be a generic cleanup target.
 * This documents the fixed resource cleanup contract; the coordinator invokes
 * it before any destructive effect.
 */
export function assertArtifactCleanupBoundary(): void {
  const bindingInputs = new Set<string>(HOST_DOMAIN_RESET_BINDING_INPUTS);
  for (const target of HOST_DOMAIN_RESET_CLEANUP_TARGETS) {
    if (!bindingInputs.has(target)) {
      throw new TypeError(`Host-domain reset cleanup target ${target} is not a journal binding input`);
    }
  }
  const cleanupTargets = new Set<string>(HOST_DOMAIN_RESET_CLEANUP_TARGETS);
  for (const preserved of HOST_DOMAIN_RESET_PRESERVED_RESOURCES) {
    if (cleanupTargets.has(preserved)) {
      throw new TypeError(`Host-domain reset preserved resource ${preserved} must not be a cleanup target`);
    }
  }
}

export function clearHostDomainArtifacts(
  resources: ResolvedProfileResources,
  coordinator: RuntimeCoordinator,
  spoolKeyStore: HostReplacementSpoolKeyStore,
  expectedOldHostId?: string,
): void {
  assertRuntimeCoordinatorPaths(coordinator, resources.statePath, resources.encryptedSpoolPath);
  assertRuntimeWriterAllowed(coordinator);
  for (const path of [
    resources.linkKeyringPath,
    resources.statePath,
    resources.encryptedSpoolPath,
    resources.runtimeResetIntentPath,
  ]) {
    assertRuntimeWriterAllowed(coordinator);
    removeSecureFileIfPresent(path);
  }
  assertRuntimeWriterAllowed(coordinator);
  spoolKeyStore.removeForHostReplacement(expectedOldHostId);
}
