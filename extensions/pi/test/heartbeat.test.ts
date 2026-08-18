import { describe, expect, test } from 'bun:test';
import { startHeartbeat, stopHeartbeat } from '../src/heartbeat';
import type { AgentAdapter } from '../src/adapter-interface';

describe('startHeartbeat default interval', () => {
  test('schedules setInterval at 5000ms', () => {
    const intervals: number[] = [];
    const original = globalThis.setInterval;
    globalThis.setInterval = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => {
      intervals.push(timeout ?? -1);
      return original(handler, timeout, ...args);
    }) as typeof setInterval;
    try {
      const client = { heartbeat: async () => undefined } as Pick<AgentAdapter, 'heartbeat'> as AgentAdapter;
      startHeartbeat({ sessionId: 'sess-1', client, status: 'idle' });
      expect(intervals).toEqual([5_000]);
    } finally {
      stopHeartbeat();
      globalThis.setInterval = original;
    }
  });
});
