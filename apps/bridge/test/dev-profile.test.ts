import { describe, expect, test } from 'bun:test';
import { isAbsolute, relative, resolve } from 'node:path';
import {
  ARIAVA_DEV_AGENT_ADAPTER_PORT,
  resolveAriavaDevProfilePaths,
} from '../src/host-manager/dev-profile';

describe('dev profile paths', () => {
  test('derives fixed absolute paths under the isolated ariava-dev root', () => {
    const home = resolve('/tmp', 'ariava-dev-profile-home');
    const paths = resolveAriavaDevProfilePaths(home);
    const expectedRoot = resolve(home, '.config', 'ariava-dev');

    expect(paths).toEqual({
      root: expectedRoot,
      configPath: resolve(expectedRoot, 'config.json'),
      identityPath: resolve(expectedRoot, 'host-identity.json'),
      agentAdapterConfigPath: resolve(expectedRoot, 'agent-adapter.json'),
      statePath: resolve(expectedRoot, 'state', 'bridge-state.json'),
      piExtensionLogPath: resolve(expectedRoot, 'pi-extension.log'),
      agentAdapterPort: ARIAVA_DEV_AGENT_ADAPTER_PORT,
    });

    for (const path of [
      paths.root,
      paths.configPath,
      paths.identityPath,
      paths.agentAdapterConfigPath,
      paths.statePath,
      paths.piExtensionLogPath,
    ]) {
      expect(isAbsolute(path)).toBe(true);
      const withinDevRoot = relative(expectedRoot, path);
      expect(withinDevRoot === '' || (!withinDevRoot.startsWith('..') && !isAbsolute(withinDevRoot))).toBe(true);
      const withinDefaultRoot = relative(resolve(home, '.config', 'ariava'), path);
      expect(withinDefaultRoot === '' || (!withinDefaultRoot.startsWith('..') && !isAbsolute(withinDefaultRoot))).toBe(false);
    }
  });

  test('rejects relative home overrides', () => {
    expect(() => resolveAriavaDevProfilePaths('relative-home')).toThrow('must be absolute');
  });
});
