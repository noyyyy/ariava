import {
  enrollCurrentIdentity,
  inspectPublicIdentity,
  publicIdentityMetadata,
  replaceHostIdentityAfterRevoke,
  revokeHostIdentityForReset,
  type HostEncryptionIdentity,
  type HostIdentity,
  type HostIdentityInspection,
  type HostIdentityStore,
} from '../../identity';
import { loadResolvedProfileConfig, type AriavaProfileCliContext } from '../context';
import { resetHostDomain, type HostDomainResetPrimitive, type HostDomainResetResult } from './host-domain-reset';

export async function inspectProfileIdentity(
  context: AriavaProfileCliContext,
): Promise<HostIdentityInspection> {
  context.validation.descriptor();
  const { resources } = loadResolvedProfileConfig(context);
  return inspectPublicIdentity(context.identity.create(resources, context.platform));
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
