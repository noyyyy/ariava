import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { logExtensionError, resolveExtensionLogPath } from '../src/logger';

const originalLogPath = process.env.ARIAVA_PI_LOG_PATH;
const temporaryDirectories: string[] = [];

afterEach(() => {
  if (originalLogPath === undefined) {
    delete process.env.ARIAVA_PI_LOG_PATH;
  } else {
    process.env.ARIAVA_PI_LOG_PATH = originalLogPath;
  }
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe('pi extension logging', () => {
  test('explicit log path takes precedence over the process environment', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'pi-logger-'));
    temporaryDirectories.push(directory);
    const explicitPath = join(directory, 'explicit.log');
    const environmentPath = join(directory, 'environment.log');
    process.env.ARIAVA_PI_LOG_PATH = environmentPath;

    expect(resolveExtensionLogPath(explicitPath)).toBe(explicitPath);
    logExtensionError('explicit path', new Error('expected'), explicitPath);
    await waitForFile(explicitPath);

    expect(readFileSync(explicitPath, 'utf8')).toContain('explicit path');
    expect(existsSync(environmentPath)).toBe(false);
  });

  test('uses ARIAVA_PI_LOG_PATH when no explicit path is supplied', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'pi-logger-'));
    temporaryDirectories.push(directory);
    const environmentPath = join(directory, 'environment.log');
    process.env.ARIAVA_PI_LOG_PATH = environmentPath;

    expect(resolveExtensionLogPath()).toBe(environmentPath);
    logExtensionError('environment path', new Error('expected'));
    await waitForFile(environmentPath);

    expect(readFileSync(environmentPath, 'utf8')).toContain('environment path');
  });

  test('keeps the production default when the environment value is absent or empty', () => {
    delete process.env.ARIAVA_PI_LOG_PATH;
    const defaultPath = join(homedir(), '.config', 'ariava', 'pi-extension.log');
    expect(resolveExtensionLogPath()).toBe(defaultPath);

    process.env.ARIAVA_PI_LOG_PATH = '   ';
    expect(resolveExtensionLogPath()).toBe(defaultPath);
  });
});

async function waitForFile(path: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (existsSync(path)) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for log file: ${path}`);
}
