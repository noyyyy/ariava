import type { CommandEnvelope } from '@ariava/protocol';
import type { AgentAdapter } from './adapter-interface';
import type { PiSessionInfo } from './session';
import { logExtensionErrorThrottled } from './logger';

const DEFAULT_POLL_INTERVAL_MS = 5_000;
const IMMEDIATE_POLL_TIMEOUT_MS = 0;
const POLL_ERROR_BACKOFF_MS = 1_000;

export interface CommandPollerContext {
  sessionId: string;
  client: AgentAdapter;
  onCommand: (command: CommandEnvelope) => Promise<void>;
  getSession?: () => PiSessionInfo | null;
}

export interface CommandPollerHandle {
  stop(): void;
}

export function startCommandPoller(
  ctx: CommandPollerContext,
  pollIntervalMs = DEFAULT_POLL_INTERVAL_MS,
): CommandPollerHandle {
  const abort = new AbortController();
  let stopped = false;

  const run = async () => {
    while (!stopped && !abort.signal.aborted) {
      try {
        const command = await ctx.client.pollCommands(ctx.sessionId, IMMEDIATE_POLL_TIMEOUT_MS, ctx.getSession?.() ?? undefined);
        if (command) {
          await ctx.onCommand(command);
          continue;
        }
        await sleep(pollIntervalMs, abort.signal);
      } catch (error) {
        logExtensionErrorThrottled('poll commands', error);
        await sleep(POLL_ERROR_BACKOFF_MS, abort.signal);
      }
    }
  };

  void run();

  return {
    stop() {
      stopped = true;
      abort.abort();
    },
  };
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
  });
}
