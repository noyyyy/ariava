import type { HostIdentity, HostIdentityInspection } from '../../identity/types';
import {
  ARIAVA_PRODUCTION_RELAY_BASE_URL,
  type AriavaInstallMetadata,
  type AriavaUserConfig,
  type ResolvedAriavaConfig,
} from '../config';
import type { StableBootstrapResult } from './bootstrap';

export interface OnboardingHostState {
  config: ResolvedAriavaConfig;
  identityInspection: HostIdentityInspection;
  identity: HostIdentity;
}

export interface HostIdentityReadinessFailure {
  reason: string;
  identityStatus: HostIdentityInspection['status'];
  pendingRotation: boolean;
}

export type ReusableHostState =
  | { reusable: true }
  | { reusable: false; identityFailure?: HostIdentityReadinessFailure };

export type ReadyHostState =
  | { ready: true }
  | { ready: false; identityFailure?: HostIdentityReadinessFailure };

export interface RelaySelectionProposal {
  value: string;
  changed: boolean;
  config: AriavaUserConfig;
}

export interface StableInstallerMetadataProposal {
  metadata: AriavaInstallMetadata;
  changed: boolean;
}

export function proposeRelaySelection(
  config: AriavaUserConfig,
  requested: string | undefined,
): RelaySelectionProposal {
  const persisted = config.relayBaseUrl?.trim();
  const value = persisted || requested?.trim() || ARIAVA_PRODUCTION_RELAY_BASE_URL;
  if (persisted) return { value, changed: false, config };
  return { value, changed: true, config: { ...config, relayBaseUrl: value } };
}

export function evaluateReusableHostState(state: OnboardingHostState): ReusableHostState {
  if (state.identityInspection.status === 'not-initialized') return { reusable: false };
  const identityFailure = inspectIdentityReadiness(state.identityInspection, state.identity);
  if (identityFailure) return { reusable: false, identityFailure };
  return { reusable: completeHostConfiguration(state) };
}

export function evaluateReadyHostState(state: OnboardingHostState): ReadyHostState {
  const identityFailure = inspectIdentityReadiness(state.identityInspection, state.identity);
  if (identityFailure) return { ready: false, identityFailure };
  return { ready: completeHostConfiguration(state) };
}

export function proposeStableInstallerMetadata(
  metadata: AriavaInstallMetadata,
  bootstrap: StableBootstrapResult,
  cliVersion: string,
  recordedAt: string,
): StableInstallerMetadataProposal {
  const installer = {
    manager: 'npm' as const,
    ariavaBinRealPath: bootstrap.evidence.executablePath,
    recordedAt,
  };
  const bridgeSource = metadata.bridgeSource ?? {
    kind: 'npm-package' as const,
    package: `ariava@${cliVersion}`,
    updatedAt: recordedAt,
  };
  if (metadata.installer?.manager === installer.manager
    && metadata.installer.ariavaBinRealPath === installer.ariavaBinRealPath
    && metadata.bridgeSource) {
    return { metadata, changed: false };
  }
  return { metadata: { ...metadata, installer, bridgeSource }, changed: true };
}

function completeHostConfiguration(state: OnboardingHostState): boolean {
  const config = state.config;
  return Boolean(config.relayBaseUrl && config.hostName && config.agentAdapterSecret && config.identity
    && config.identity.hostId === state.identity.hostId);
}

function inspectIdentityReadiness(
  inspection: HostIdentityInspection,
  identity: HostIdentity,
): HostIdentityReadinessFailure | undefined {
  if (inspection.status === 'ready' && !inspection.pendingRotation && inspection.ownerIntegrity
    && inspection.permissionIntegrity && inspection.metadataIntegrity
    && inspection.hostId === identity.hostId && inspection.keyId === identity.keyId) {
    return undefined;
  }
  return {
    reason: identityNotReadyReason(inspection, identity),
    identityStatus: inspection.status,
    pendingRotation: inspection.pendingRotation,
  };
}

function identityNotReadyReason(inspection: HostIdentityInspection, identity: HostIdentity): string {
  if (inspection.status === 'rotation-pending' || inspection.pendingRotation) {
    return 'Host identity key rotation is pending and must be completed or explicitly reset before onboarding can continue.';
  }
  if (inspection.status === 'invalid') {
    return 'Host identity evidence exists but is invalid or unreadable (for example a locked or inaccessible Keychain private key). Explicit reset is required.';
  }
  if (inspection.status === 'not-initialized') {
    return 'Host identity is not initialized.';
  }
  if (!inspection.ownerIntegrity || !inspection.permissionIntegrity || !inspection.metadataIntegrity) {
    return 'Host identity integrity checks failed; the persisted identity is not safe to reuse.';
  }
  if (inspection.hostId !== identity.hostId || inspection.keyId !== identity.keyId) {
    return 'Persisted Host identity metadata does not match the loaded Host key material.';
  }
  return 'Existing Host identity state is not safe to reuse.';
}
