import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ARIAVA_TEST_PATH_ENVIRONMENT_KEYS = [
  'ARIAVA_AGENT_ADAPTER_CONFIG_PATH',
  'ARIAVA_HOST_IDENTITY_PATH',
  'ARIAVA_STATE_PATH',
];

export function createIsolatedTestHome() {
  return mkdtempSync(join(tmpdir(), 'ariava-test-lane-'));
}

export function createIsolatedTestEnvironment(environment, homeDirectory) {
  const isolated = {
    ...environment,
    HOME: homeDirectory,
    XDG_CONFIG_HOME: join(homeDirectory, '.config'),
    PI_CODING_AGENT_DIR: join(homeDirectory, '.pi', 'agent'),
  };
  for (const key of ARIAVA_TEST_PATH_ENVIRONMENT_KEYS) delete isolated[key];
  mkdirSync(isolated.XDG_CONFIG_HOME, { recursive: true, mode: 0o700 });
  return isolated;
}

export function applyIsolatedTestEnvironment(environment, homeDirectory) {
  const isolated = createIsolatedTestEnvironment(environment, homeDirectory);
  environment.HOME = isolated.HOME;
  environment.XDG_CONFIG_HOME = isolated.XDG_CONFIG_HOME;
  environment.PI_CODING_AGENT_DIR = isolated.PI_CODING_AGENT_DIR;
  for (const key of ARIAVA_TEST_PATH_ENVIRONMENT_KEYS) delete environment[key];
  return isolated;
}
