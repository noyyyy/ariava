import type { AgentAdapter } from './adapter-interface';
import type { SessionStatus } from '@ariava/protocol';
import { logExtensionErrorThrottled } from './logger';

const DEFAULT_HEARTBEAT_INTERVAL_MS = 10_000;

export interface HeartbeatContext {
  sessionId: string;
  client: AgentAdapter;
  status: SessionStatus;
  latestActivityText?: string;
}

let activeTimer: ReturnType<typeof setInterval> | null = null;

export function startHeartbeat(ctx: HeartbeatContext, intervalMs = DEFAULT_HEARTBEAT_INTERVAL_MS): void {
  stopHeartbeat();
  activeTimer = setInterval(async () => {
    try {
      await ctx.client.heartbeat(ctx.sessionId, ctx.status, ctx.latestActivityText);
    } catch (error) {
      logExtensionErrorThrottled('heartbeat', error);
    }
  }, intervalMs);
}

export function stopHeartbeat(): void {
  if (activeTimer) {
    clearInterval(activeTimer);
    activeTimer = null;
  }
}
