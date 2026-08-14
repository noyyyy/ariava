import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { logExtensionEvent, resolveExtensionLogPath } from '../src/logger';

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
  test('explicit log path takes precedence and writes only fixed fields', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'pi-logger-'));
    temporaryDirectories.push(directory);
    const explicitPath = join(directory, 'explicit.log');
    const environmentPath = join(directory, 'environment.log');
    process.env.ARIAVA_PI_LOG_PATH = environmentPath;

    expect(resolveExtensionLogPath(explicitPath)).toBe(explicitPath);
    logExtensionEvent('command_result_submit_failed', { commandId: 'opaque-command-1' }, explicitPath);
    await waitForFile(explicitPath);

    const entry = JSON.parse(readFileSync(explicitPath, 'utf8')) as Record<string, unknown>;
    expect(entry).toEqual({
      event: 'command_result_submit_failed',
      commandId: 'opaque-command-1',
    });
    expect(Object.keys(entry).sort()).toEqual(['commandId', 'event']);
    expect(existsSync(environmentPath)).toBe(false);
  });

  test('capture excludes plaintext, exception text, ciphertext, key wrap, and private material', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'pi-logger-'));
    temporaryDirectories.push(directory);
    const environmentPath = join(directory, 'environment.log');
    process.env.ARIAVA_PI_LOG_PATH = environmentPath;
    const forbidden = [
      'continue with secret instructions',
      'private driver failure',
      'ciphertext_private_marker',
      'keywrap_private_marker',
      'private_key_private_marker',
    ];

    logExtensionEvent('command_dispatch_failed', {
      commandId: 'opaque-command-2',
      commandPlaintext: forbidden[0],
      error: forbidden[1],
      ciphertext: forbidden[2],
      keyWrap: forbidden[3],
      privateKey: forbidden[4],
    } as never);
    await waitForFile(environmentPath);

    const capture = readFileSync(environmentPath, 'utf8');
    expect(JSON.parse(capture)).toEqual({
      event: 'command_dispatch_failed',
      commandId: 'opaque-command-2',
    });
    for (const value of forbidden) expect(capture).not.toContain(value);
    expect(capture).not.toMatch(/error|message|reason|detail|stack|ciphertext|keywrap|private[_-]?key/iu);
  });

  test('uses ARIAVA_PI_LOG_PATH when no explicit path is supplied', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'pi-logger-'));
    temporaryDirectories.push(directory);
    const environmentPath = join(directory, 'environment.log');
    process.env.ARIAVA_PI_LOG_PATH = environmentPath;

    expect(resolveExtensionLogPath()).toBe(environmentPath);
    logExtensionEvent('command_poll_failed');
    await waitForFile(environmentPath);

    expect(JSON.parse(readFileSync(environmentPath, 'utf8'))).toEqual({
      event: 'command_poll_failed',
    });
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
