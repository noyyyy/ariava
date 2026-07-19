import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

export const ARIAVA_DEV_AGENT_ADAPTER_PORT = 7273 as const;

export interface AriavaDevProfilePaths {
  root: string;
  configPath: string;
  identityPath: string;
  agentAdapterConfigPath: string;
  statePath: string;
  piExtensionLogPath: string;
  agentAdapterPort: typeof ARIAVA_DEV_AGENT_ADAPTER_PORT;
}

export function resolveAriavaDevProfilePaths(homeDirectory: string = homedir()): AriavaDevProfilePaths {
  if (!isAbsolute(homeDirectory)) throw new Error('Ariava dev profile home directory must be absolute');
  const root = resolve(homeDirectory, '.config', 'ariava-dev');
  return {
    root,
    configPath: join(root, 'config.json'),
    identityPath: join(root, 'host-identity.json'),
    agentAdapterConfigPath: join(root, 'agent-adapter.json'),
    statePath: join(root, 'state', 'bridge-state.json'),
    piExtensionLogPath: join(root, 'pi-extension.log'),
    agentAdapterPort: ARIAVA_DEV_AGENT_ADAPTER_PORT,
  };
}
