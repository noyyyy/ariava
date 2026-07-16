import { afterEach, describe, expect, test } from 'bun:test';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CanonicalSessionState, CommandResult } from '@ariava/protocol';
import { BridgeStateStore } from '../src/state-store';
import { CommandRouter } from '../src/command-router';
import type { AgentDriver, DriverCommandContext } from '../src/types';

const paths: string[] = [];

afterEach(() => {
  for (const path of paths.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

class FakeDriver implements AgentDriver {
  readonly name = 'pi';

  async listSessions(): Promise<CanonicalSessionState[]> {
    return [];
  }

  async executeCommand(context: DriverCommandContext): Promise<CommandResult> {
    return {
      commandId: context.command.commandId,
      hostId: context.command.hostId,
      sessionId: context.command.sessionId,
      accepted: true,
      status: 'executed',
      message: `ran ${context.command.type}`,
      updatedAt: '2026-06-28T12:00:00Z',
    };
  }
}

describe('CommandRouter', () => {
  test('routes reply to the driver', async () => {
    const root = join(tmpdir(), `bridge-router-${Date.now()}`);
    paths.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    store.replaceDriverSessions('pi', [
      {
        sessionId: 'pane-1',
        hostId: 'host-1',
        provider: 'pi',
        projectName: 'proj',
        nameText: 'Task',
        status: 'blocked',
        latestActivityText: 'Needs help',
        stateLabel: 'Needs attention',
        updatedAt: '2026-06-28T10:00:00Z',
      },
    ]);

    const router = new CommandRouter(store, new Map([['pi', new FakeDriver()]]), 'host-1');
    const outcome = await router.handle({
      commandId: 'cmd-1',
      hostId: 'host-1',
      sessionId: 'pane-1',
      type: 'reply',
      payload: { text: 'Continue with option B.' },
      issuedAt: '2099-06-28T10:00:00Z',
      expiresAt: '2099-06-28T10:10:00Z',
      nonce: 'n-1',
      watchDeviceId: 'watch-1',
    });

    expect(outcome.result.accepted).toBe(true);
    expect(outcome.result.message).toBe('ran reply');
    expect(outcome.followUpEvents).toEqual([]);
  });

  test('returns no follow-up events for interrupt', async () => {
    const root = join(tmpdir(), `bridge-router-${Date.now()}`);
    paths.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    store.replaceDriverSessions('pi', [
      {
        sessionId: 'pane-1',
        hostId: 'host-1',
        provider: 'pi',
        projectName: 'proj',
        nameText: 'Task',
        status: 'working',
        latestActivityText: 'Still running',
        stateLabel: 'In progress',
        updatedAt: '2026-06-28T10:00:00Z',
      },
    ]);

    const router = new CommandRouter(store, new Map([['pi', new FakeDriver()]]), 'host-1');
    const outcome = await router.handle({
      commandId: 'cmd-2',
      hostId: 'host-1',
      sessionId: 'pane-1',
      type: 'interrupt',
      payload: {},
      issuedAt: '2099-06-28T10:00:00Z',
      expiresAt: '2099-06-28T10:10:00Z',
      nonce: 'n-2',
      watchDeviceId: 'watch-1',
    });

    expect(outcome.result.accepted).toBe(true);
    expect(outcome.followUpEvents).toEqual([]);
  });
});
