import {
  enrollCurrentIdentity,
  inspectPublicIdentity,
  publicIdentityMetadata,
  replaceHostIdentityAfterRevoke,
  revokeHostIdentityForReset,
  type HostEncryptionIdentity,
  type HostIdentity,
  type HostIdentityInspection,
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
  revoke: HostDomainResetPrimitive['revoke'];
  replace: HostDomainResetPrimitive['replace'];
}

export type ProfileIdentityResetResult = HostDomainResetResult;

export async function resetProfileIdentity(
  context: AriavaProfileCliContext,
  dependencies: ProfileIdentityResetDependencies,
): Promise<ProfileIdentityResetResult> {
  return resetHostDomain(context, dependencies);
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
