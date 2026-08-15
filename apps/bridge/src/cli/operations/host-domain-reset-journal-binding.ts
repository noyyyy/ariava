import { createHash } from 'node:crypto';

export const HOST_DOMAIN_RESET_BINDING_INPUTS = [
  'root',
  'configPath',
  'identityMetadataPath',
  'encryptionIdentityPath',
  'linkKeyringPath',
  'statePath',
  'agentAdapterConfigPath',
  'piExtensionLogPath',
  'installMetadataPath',
  'encryptedSpoolPath',
  'runtimeResetIntentPath',
  'runtimeLockPath',
  'runtimeTakeoverMutexPath',
  'macosSpoolEvidencePath',
  'linuxSpoolKeyPath',
  'hostDomainResetJournalPath',
] as const;

export type HostDomainResetBindingInput = (typeof HOST_DOMAIN_RESET_BINDING_INPUTS)[number];
export type HostDomainResetProfileId = 'default' | 'dev';
export type HostDomainResetResourceSet = {
  identityProfile: HostDomainResetProfileId;
} & Record<HostDomainResetBindingInput, string>;

export function identityResourceDigest(path: string): string {
  return createHash('sha256').update(path).digest('hex');
}

export function hostDomainResourceDigest(resources: HostDomainResetResourceSet): string {
  const paths = hostDomainResourcePaths(resources);
  const canonical = JSON.stringify(Object.fromEntries(
    Object.entries(paths).sort(([left], [right]) => left.localeCompare(right)),
  ));
  return createHash('sha256').update(canonical).digest('hex');
}

function hostDomainResourcePaths(resources: HostDomainResetResourceSet): Record<HostDomainResetBindingInput, string> {
  const paths: Record<HostDomainResetBindingInput, string> = {
    root: resources.root,
    configPath: resources.configPath,
    identityMetadataPath: resources.identityMetadataPath,
    encryptionIdentityPath: resources.encryptionIdentityPath,
    linkKeyringPath: resources.linkKeyringPath,
    statePath: resources.statePath,
    agentAdapterConfigPath: resources.agentAdapterConfigPath,
    piExtensionLogPath: resources.piExtensionLogPath,
    installMetadataPath: resources.installMetadataPath,
    encryptedSpoolPath: resources.encryptedSpoolPath,
    runtimeResetIntentPath: resources.runtimeResetIntentPath,
    runtimeLockPath: resources.runtimeLockPath,
    runtimeTakeoverMutexPath: resources.runtimeTakeoverMutexPath,
    macosSpoolEvidencePath: resources.macosSpoolEvidencePath,
    linuxSpoolKeyPath: resources.linuxSpoolKeyPath,
    hostDomainResetJournalPath: resources.hostDomainResetJournalPath,
  };
  for (const key of HOST_DOMAIN_RESET_BINDING_INPUTS) {
    if (!(key in paths)) throw new TypeError(`Host-domain reset binding input ${key} is missing from the resource inventory`);
  }
  return paths;
}
