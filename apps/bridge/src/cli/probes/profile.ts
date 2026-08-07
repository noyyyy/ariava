import { dirname } from 'node:path';
import { readAgentAdapterConfig, type AgentAdapterDiscoveryFile } from '../../agent-adapter/config';
import { isConfigComplete } from '../../host-manager/status';
import type { HostIdentityInspection } from '../../identity';
import {
  loadResolvedProfileConfig,
  type AriavaProfileCliContext,
  type ResolvedProfileResources,
} from '../context';

export interface ProfileRuntimeProbe {
  nodeFound: boolean;
  runtimeNameIsNode: boolean;
  runtimeVersionSupported: boolean;
  runtimeCryptoSelfTestPassed: boolean;
}

export interface ProfileProbeDependencies {
  context(): AriavaProfileCliContext;
  pathExists(path: string): boolean;
  runtime(): ProfileRuntimeProbe;
  readAdapter?(path: string, expectedPort?: number): AgentAdapterDiscoveryFile | null;
}

export interface ProfileProbeEvidence {
  profile: AriavaProfileCliContext['profile']['id'];
  config: ReturnType<typeof loadResolvedProfileConfig>['resolved'];
  resources: ResolvedProfileResources;
  configComplete: boolean;
  identity: HostIdentityInspection;
  relay: {
    configured: boolean;
    baseUrl: string;
  };
  adapter: {
    configPath: string;
    present: boolean;
    valid: boolean;
    url: string | null;
    port: number;
  };
  paths: {
    configPath: string;
    identityPath: string;
    statePath: string;
    statePresent: boolean;
    statePathParentExists: boolean;
    discoveryPath: string;
    piLogPath: string;
  };
  runtime: ProfileRuntimeProbe;
}

export async function probeProfile(
  dependencies: ProfileProbeDependencies,
): Promise<ProfileProbeEvidence> {
  const context = dependencies.context();
  context.validation.descriptor();
  const loaded = loadResolvedProfileConfig(context);
  const resolved = context.resolveForDisplay?.(loaded.fileConfig) ?? loaded.resolved;
  const resources = context.validation.resolved(resolved);
  const identity = await inspectIdentity(context, resources);
  const adapterPresent = pathExists(context, dependencies, resources.agentAdapterConfigPath);
  let adapter: AgentAdapterDiscoveryFile | null = null;
  let adapterValid = false;
  if (adapterPresent) {
    context.access?.('filesystemReads', resources.agentAdapterConfigPath);
    try {
      adapter = (dependencies.readAdapter ?? readAgentAdapterConfig)(
        resources.agentAdapterConfigPath,
        resources.agentAdapterPort,
      );
      adapterValid = adapter !== null;
    } catch {
      adapterValid = false;
    }
  }
  const statePresent = pathExists(context, dependencies, resources.statePath);
  const statePathParentExists = pathExists(context, dependencies, dirname(resources.statePath));

  return {
    profile: context.profile.id,
    config: resolved,
    resources,
    configComplete: isConfigComplete(resolved),
    identity,
    relay: {
      configured: Boolean(resolved.relayBaseUrl),
      baseUrl: resolved.relayBaseUrl,
    },
    adapter: {
      configPath: resources.agentAdapterConfigPath,
      present: adapterPresent,
      valid: adapterValid,
      url: adapter?.url ?? null,
      port: resources.agentAdapterPort,
    },
    paths: {
      configPath: resources.configPath,
      identityPath: resources.identityMetadataPath,
      statePath: resources.statePath,
      statePresent,
      statePathParentExists,
      discoveryPath: resources.agentAdapterConfigPath,
      piLogPath: resources.piExtensionLogPath,
    },
    runtime: dependencies.runtime(),
  };
}

async function inspectIdentity(
  context: AriavaProfileCliContext,
  resources: ResolvedProfileResources,
): Promise<HostIdentityInspection> {
  if (context.platform === 'darwin' || context.platform === 'linux') {
    return context.identity.create(resources, context.platform).inspect();
  }
  return {
    status: 'not-initialized',
    storageType: 'linux-json',
    storageReference: { type: 'linux-json', path: resources.identityMetadataPath },
    path: resources.identityMetadataPath,
    ownerIntegrity: false,
    permissionIntegrity: false,
    metadataIntegrity: false,
    pendingRotation: false,
  };
}

function pathExists(
  context: AriavaProfileCliContext,
  dependencies: ProfileProbeDependencies,
  path: string,
): boolean {
  context.access?.('filesystemReads', path);
  return dependencies.pathExists(path);
}
