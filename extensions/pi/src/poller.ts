import type { CommandEnvelope } from '@ariava/protocol';
import {
  validateAgentAdapterCommand,
  validateAgentAdapterCommandResult,
  type AgentAdapter,
  type CommandExecutionOutcome,
} from './adapter-interface';
import { logExtensionEvent, logExtensionEventThrottled } from './logger';

const DEFAULT_POLL_INTERVAL_MS = 5_000;
const IMMEDIATE_POLL_TIMEOUT_MS = 0;
const POLL_ERROR_BACKOFF_MS = 1_000;

export interface CommandPollerContext {
  sessionId: string;
  client: AgentAdapter;
  onCommand: (command: CommandEnvelope) => Promise<CommandExecutionOutcome>;
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
  let generation = 0;

  const canceled = (commandGeneration: number) =>
    stopped || abort.signal.aborted || commandGeneration !== generation;

  const run = async () => {
    while (!stopped && !abort.signal.aborted) {
      try {
        const command = await ctx.client.pollCommands(ctx.sessionId, IMMEDIATE_POLL_TIMEOUT_MS);
        if (stopped || abort.signal.aborted) return;
        if (command) {
          if (!validateAgentAdapterCommand(command) || command.sessionId !== ctx.sessionId) {
            logExtensionEvent('command_dispatch_failed');
            await sleep(POLL_ERROR_BACKOFF_MS, abort.signal);
            continue;
          }
          const commandGeneration = generation;
          try {
            const outcome = await ctx.onCommand(structuredClone(command));
            if (canceled(commandGeneration)) {
              ctx.client.abandonCommand?.(command.commandId);
              logExtensionEvent('command_dispatch_canceled', { commandId: command.commandId });
              return;
            }
            if (outcome.kind === 'outcome_unknown') {
              ctx.client.abandonCommand?.(command.commandId);
              continue;
            }
            const result = outcome.result;
            if (!validateAgentAdapterCommandResult(result)
              || result.commandId !== command.commandId
              || result.hostId !== command.hostId
              || result.sessionId !== command.sessionId) {
              ctx.client.abandonCommand?.(command.commandId);
              logExtensionEvent('command_result_invalid', { commandId: command.commandId });
              continue;
            }
            try {
              await ctx.client.submitResult(command.commandId, result);
            } catch {
              logExtensionEvent('command_result_submit_failed', { commandId: command.commandId });
            }
          } catch {
            ctx.client.abandonCommand?.(command.commandId);
            if (canceled(commandGeneration)) {
              logExtensionEvent('command_dispatch_canceled', { commandId: command.commandId });
              return;
            }
            logExtensionEvent('command_dispatch_failed', { commandId: command.commandId });
          }
          continue;
        }
        await sleep(pollIntervalMs, abort.signal);
      } catch {
        logExtensionEventThrottled('command_poll_failed');
        await sleep(POLL_ERROR_BACKOFF_MS, abort.signal);
      }
    }
  };

  void run();

  return {
    stop() {
      if (stopped) return;
      stopped = true;
      generation += 1;
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
