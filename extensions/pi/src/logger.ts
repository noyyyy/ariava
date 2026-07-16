import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

const DEFAULT_LOG_PATH = join(homedir(), '.config', 'ariava', 'pi-extension.log');

const lastThrottledLogAt = new Map<string, number>();

export function logExtensionError(label: string, error: unknown, logPath = DEFAULT_LOG_PATH): void {
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    label,
    error: serializeError(error),
  });

  void mkdir(dirname(logPath), { recursive: true })
    .then(() => appendFile(logPath, `${entry}\n`, 'utf8'))
    .catch(() => {
      // Logging must never affect pi interaction.
    });
}

export function logExtensionErrorThrottled(label: string, error: unknown, intervalMs = 60_000): void {
  const now = Date.now();
  const lastLoggedAt = lastThrottledLogAt.get(label) ?? 0;
  if (now - lastLoggedAt < intervalMs) return;
  lastThrottledLogAt.set(label, now);
  logExtensionError(label, error);
}

function serializeError(error: unknown): { name?: string; message: string; stack?: string } {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }
  return { message: String(error) };
}
