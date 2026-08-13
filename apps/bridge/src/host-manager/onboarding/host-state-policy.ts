import type { HostIdentity, HostIdentityInspection } from '../../identity/types';
import {
  ARIAVA_PRODUCTION_RELAY_BASE_URL,
  type AriavaInstallMetadata,
  type AriavaUserConfig,
  type ResolvedAriavaConfig,
} from '../config';

type LoadedHostIdentityInspection = HostIdentityInspection & {
  status: Exclude<HostIdentityInspection['status'], 'not-initialized'>;
};

export interface OnboardingHostState {
  config: ResolvedAriavaConfig;
  identityInspection: LoadedHostIdentityInspection;
  identity: HostIdentity;
}

export type HostIdentityReadiness =
  | { ready: true }
  | {
    ready: false;
    reason: string;
    identityStatus: HostIdentityInspection['status'];
    pendingRotation: boolean;
  };

export type OnboardingHostStateDecision =
  | { kind: 'reuse' }
  | { kind: 'initialize'; reason: 'missing-state' | 'incomplete-config' }
  | {
    kind: 'reject';
    reason: string;
    identityStatus: HostIdentityInspection['status'];
    pendingRotation: boolean;
  };

export interface RelaySelectionProposal {
  value: string;
  changed: boolean;
}

export interface StableInstallerMetadataProposal {
  metadata: AriavaInstallMetadata;
  changed: boolean;
}

export function evaluateHostIdentityReadiness(
  inspection: HostIdentityInspection,
  identity: Pick<HostIdentity, 'hostId' | 'keyId'>,
): HostIdentityReadiness {
  const ready = inspection.status === 'ready'
    && !inspection.pendingRotation
    && inspection.ownerIntegrity
    && inspection.permissionIntegrity
    && inspection.metadataIntegrity
    && inspection.hostId === identity.hostId
    && inspection.keyId === identity.keyId;
  if (ready) return { ready: true };

  return {
    ready: false,
    reason: identityNotReadyReason(inspection, identity),
    identityStatus: inspection.status,
    pendingRotation: inspection.pendingRotation,
  };
}

export function decideOnboardingHostState(
  state: OnboardingHostState | undefined,
): OnboardingHostStateDecision {
  if (!state) return { kind: 'initialize', reason: 'missing-state' };

  const identityReadiness = evaluateHostIdentityReadiness(state.identityInspection, state.identity);
  if (!identityReadiness.ready) {
    return {
      kind: 'reject',
      reason: identityReadiness.reason,
      identityStatus: identityReadiness.identityStatus,
      pendingRotation: identityReadiness.pendingRotation,
    };
  }

  const config = state.config;
  if (config.relayBaseUrl && config.hostName && config.agentAdapterSecret && config.identity
    && config.identity.hostId === state.identity.hostId) {
    return { kind: 'reuse' };
  }
  return { kind: 'initialize', reason: 'incomplete-config' };
}

export function proposeRelaySelection(
  config: Pick<AriavaUserConfig, 'relayBaseUrl'>,
  requested: string | undefined,
): RelaySelectionProposal {
  const persisted = config.relayBaseUrl?.trim();
  const value = persisted || requested?.trim() || ARIAVA_PRODUCTION_RELAY_BASE_URL;
  return { value, changed: !persisted };
}

export function proposeStableInstallerMetadata(
  metadata: AriavaInstallMetadata,
  ariavaBinRealPath: string,
  cliVersion: string,
  recordedAt: string,
): StableInstallerMetadataProposal {
  const installer = { manager: 'npm' as const, ariavaBinRealPath, recordedAt };
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

function identityNotReadyReason(
  inspection: HostIdentityInspection,
  identity: Pick<HostIdentity, 'hostId' | 'keyId'>,
): string {
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
