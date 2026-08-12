import {
  enrollCurrentIdentity,
  inspectPublicIdentity,
  publicIdentityMetadata,
  replaceHostIdentityAfterRevoke,
  revokeHostIdentityForReset,
  rotateHostIdentity,
  HostIdentityError,
  type HostEncryptionIdentity,
  type HostIdentity,
  type HostIdentityInspection,
  type HostIdentityStore,
} from '../../identity';
import type { HostPlatform, KeyRotationResponse } from '@ariava/protocol';
import { buildProfileInitializedConfig } from './initialize';
import { loadResolvedProfileConfig, type AriavaProfileCliContext } from '../context';
import { resetHostDomain, type HostDomainResetPrimitive, type HostDomainResetResult } from './host-domain-reset';
import { AriavaCliError } from '../../host-manager/service/errors';
import { loadHostDomainResetJournal } from './host-domain-reset-journal';

export async function inspectProfileIdentity(
  context: AriavaProfileCliContext,
): Promise<HostIdentityInspection> {
  context.validation.descriptor();
  const { resources } = loadResolvedProfileConfig(context);
  return inspectPublicIdentity(context.identity.create(resources, context.platform));
}

export interface ProfileIdentityRotationDependencies {
  rotate(store: HostIdentityStore, relayBaseUrl: string): Promise<KeyRotationResponse>;
}

const defaultRotationDependencies: ProfileIdentityRotationDependencies = {
  rotate: rotateHostIdentity,
};

export async function rotateProfileIdentity(
  context: AriavaProfileCliContext,
  dependencies: ProfileIdentityRotationDependencies = defaultRotationDependencies,
): Promise<KeyRotationResponse> {
  context.validation.descriptor();
  const loaded = loadResolvedProfileConfig(context);
  return context.hostIdentityOperationLock.run(loaded.resources, async () => {
    const { fileConfig, resolved, resources } = loaded;
    const journal = loadHostDomainResetJournal(resources);
    if (journal) {
      throw new AriavaCliError(
        'ERR_HOST_RESET_IN_PROGRESS',
        `Host reset recovery is pending at phase ${journal.phase}; key rotation is blocked.`,
        {
          phase: journal.phase, operationId: journal.operationId, retryable: true,
          remediation: { message: 'Resume the pending Host reset before rotating the Host key.' },
        },
      );
    }
    const store = context.identity.create(resources, context.platform);
    const result = await dependencies.rotate(store, resolved.relayBaseUrl);
    const identity = await store.load();
    if (!identity) throw new HostIdentityError('ERR_IDENTITY_MISSING', 'Rotated identity could not be loaded');
    saveProfileConfig(context, { ...fileConfig, identity: publicIdentityMetadata(identity) });
    return result;
  });
}

export interface ProfileIdentityResetDependencies {
  bridgeVersion: string;
  enroll: HostDomainResetPrimitive['enroll'];
  revoke?: HostDomainResetPrimitive['revoke'];
  replace?: HostDomainResetPrimitive['replace'];
  reset?(store: HostIdentityStore, relayBaseUrl: string): Promise<{
    identity: HostIdentity; revokedOldIdentity: boolean; warning?: string;
  }>;
}

export type ProfileIdentityResetResult = HostDomainResetResult;

export async function resetProfileIdentity(
  context: AriavaProfileCliContext,
  dependencies: ProfileIdentityResetDependencies,
): Promise<ProfileIdentityResetResult> {
  if (dependencies.revoke && dependencies.replace) return resetHostDomain(context, dependencies as HostDomainResetPrimitive);
  let legacyReplacement: HostIdentity | undefined;
  const legacyReset = dependencies.reset;
  if (!legacyReset) throw new TypeError('Host reset dependencies are incomplete');
  return resetHostDomain(context, {
    bridgeVersion: dependencies.bridgeVersion,
    enroll: dependencies.enroll,
    async revoke(identity, relayBaseUrl) {
      const { resources } = loadResolvedProfileConfig(context);
      const store = context.identity.create(resources, context.platform);
      const result = await legacyReset(store, relayBaseUrl);
      legacyReplacement = result.identity;
      return result.revokedOldIdentity ? 'revoked' : 'identity-already-revoked';
    },
    async replace() {
      if (!legacyReplacement) throw new TypeError('Legacy Host reset did not produce a replacement identity');
      return legacyReplacement;
    },
  });
}

export function createDefaultProfileIdentityResetDependencies(
  bridgeVersion: string,
): ProfileIdentityResetDependencies {
  return {
    bridgeVersion,
    revoke: revokeHostIdentityForReset,
    replace: replaceHostIdentityAfterRevoke,
    enroll: enrollCurrentIdentity,
  };
}

function saveProfileConfig(context: AriavaProfileCliContext, config: Parameters<AriavaProfileCliContext['config']['save']>[0]): void {
  context.access?.('filesystemWrites', context.profile.resources.configPath);
  context.config.save(config, context.profile.resources.configPath);
}
