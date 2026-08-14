import type { MacOSIdentityProfile } from './macos-keychain-store';

export const RESET_ONLY_IDENTITY_EVIDENCE_SOURCE: unique symbol = Symbol('ariava.reset-only-identity-evidence-source');
export const PREPARE_RESET_ONLY_IDENTITY_CLEANUP: unique symbol = Symbol('ariava.prepare-reset-only-identity-cleanup');

export type ResetOnlyIdentityEvidenceSource =
  | { kind: 'linux-json'; identityPath: string }
  | {
    kind: 'macos-keychain';
    metadataPath: string;
    evidenceAccount: string;
    profile: MacOSIdentityProfile;
    itemExists(account: string): boolean;
  };

export interface ResetOnlyIdentityCleanupPlan {
  previousAccount: string | null;
  previousPendingAccount: string | null;
  interruptedCreationAccount: string | null;
}
