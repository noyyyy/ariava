import { describe, expect, test } from 'bun:test';
import type { CommandEnvelope } from '@ariava/protocol';
import type { AgentAdapter } from '../src/adapter-interface';
import { startCommandPoller } from '../src/poller';

function makeCommand(): CommandEnvelope {
  return {
    commandId: 'cmd-1',
    hostId: 'host-1',
    sessionId: 'session-1',
    type: 'reply',
    payload: { text: 'Continue' },
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    nonce: 'n',
    watchDeviceId: 'watch-1',
  };
}

describe('startCommandPoller', () => {
  test('dispatches polled command to onCommand', async () => {
    const command = makeCommand();

    let callCount = 0;
    const adapter = {
      pollCommands: async (_sessionId: string, _timeoutMs: number) => {
        callCount += 1;
        if (callCount === 1) return command;
        return null;
      },
    } as unknown as AgentAdapter;

    const dispatched: CommandEnvelope[] = [];
    const poller = startCommandPoller(
      {
        sessionId: 'session-1',
        client: adapter,
        onCommand: async (cmd) => {
          dispatched.push(cmd);
          poller.stop();
        },
      },
      10,
    );

    await new Promise<void>((resolve) => {
      const check = () => {
        if (dispatched.length >= 1) {
          resolve();
        } else {
          setTimeout(check, 5);
        }
      };
      check();
    });

    poller.stop();
    expect(dispatched).toHaveLength(1);
    expect(dispatched[0].commandId).toBe('cmd-1');
  });

  test('waits for the configured interval after an empty poll and uses immediate server checks', async () => {
    const command = makeCommand();
    const intervals: number[] = [];
    const timeouts: number[] = [];
    let callCount = 0;

    const adapter = {
      pollCommands: async (_sessionId: string, timeoutMs: number) => {
        timeouts.push(timeoutMs);
        intervals.push(Date.now());
        callCount += 1;
        if (callCount === 1) return null;
        return command;
      },
    } as unknown as AgentAdapter;

    const dispatched: CommandEnvelope[] = [];
    const poller = startCommandPoller(
      {
        sessionId: 'session-1',
        client: adapter,
        onCommand: async (cmd) => {
          dispatched.push(cmd);
          poller.stop();
        },
      },
      20,
    );

    await new Promise<void>((resolve) => {
      const check = () => {
        if (dispatched.length >= 1) {
          resolve();
        } else {
          setTimeout(check, 5);
        }
      };
      check();
    });

    poller.stop();
    expect(dispatched).toHaveLength(1);
    expect(timeouts).toEqual([0, 0]);
    expect(intervals).toHaveLength(2);
    expect(intervals[1] - intervals[0]).toBeGreaterThanOrEqual(15);
  });
});
