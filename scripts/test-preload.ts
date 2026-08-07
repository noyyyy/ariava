import { rmSync } from 'node:fs';
import { afterAll } from 'bun:test';
import {
  applyIsolatedTestEnvironment,
  createIsolatedTestHome,
} from './test-environment.mjs';

const testHome = createIsolatedTestHome();
applyIsolatedTestEnvironment(process.env, testHome);

afterAll(() => {
  rmSync(testHome, { recursive: true, force: true });
});
