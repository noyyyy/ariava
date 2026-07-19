import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

const DEFAULT_LOG_PATH = join(homedir(), '.config', 'ariava', 'pi-extension.log');

const lastThrottledLogAt = new Map<string, number>();

export function resolveExtensionLogPath(explicitLogPath?: string): string {
  if (explicitLogPath !== undefined) return explicitLogPath;
  const environmentLogPath = process.env.ARIAVA_PI_LOG_PATH;
  return environmentLogPath?.trim() ? environmentLogPath : DEFAULT_LOG_PATH;
}

export function logExtensionError(label: string, error: unknown, logPath?: string): void {
  const resolvedLogPath = resolveExtensionLogPath(logPath);
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    label,
    error: serializeError(error),
  });

  void mkdir(dirname(resolvedLogPath), { recursive: true })
    .then(() => appendFile(resolvedLogPath, `${entry}\n`, 'utf8'))
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
