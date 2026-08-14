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

export type ExtensionLogEventCode =
  | 'adapter_task_failed'
  | 'command_dispatch_failed'
  | 'command_dispatch_canceled'
  | 'command_poll_failed'
  | 'command_result_invalid'
  | 'command_result_submit_failed'
  | 'heartbeat_failed'
  | 'session_register_failed'
  | 'terminal_event_push_failed';

export interface ExtensionLogContext {
  commandId?: string;
}

export function logExtensionEvent(
  event: ExtensionLogEventCode,
  context: ExtensionLogContext = {},
  logPath?: string,
 ): void {
  const resolvedLogPath = resolveExtensionLogPath(logPath);
  const entry = JSON.stringify({
    event,
    ...(context.commandId ? { commandId: context.commandId } : {}),
  });

  void mkdir(dirname(resolvedLogPath), { recursive: true })
    .then(() => appendFile(resolvedLogPath, `${entry}\n`, 'utf8'))
    .catch(() => {
      // Logging must never affect pi interaction.
    });
}

export function logExtensionEventThrottled(
  event: ExtensionLogEventCode,
  context: ExtensionLogContext = {},
  intervalMs = 60_000,
): void {
  const key = `${event}:${context.commandId ?? ''}`;
  const now = Date.now();
  const lastLoggedAt = lastThrottledLogAt.get(key) ?? 0;
  if (now - lastLoggedAt < intervalMs) return;
  lastThrottledLogAt.set(key, now);
  logExtensionEvent(event, context);
}
