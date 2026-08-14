import { afterEach, describe, expect, test } from 'bun:test';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CanonicalSessionState, CommandResult } from '@ariava/protocol';
import { BridgeStateStore } from '../src/state-store';
import { CommandRouter } from '../src/command-router';
import { AgentAdapterClient } from '../src/agent-adapter/client';
import { AgentAdapterRegistry } from '../src/agent-adapter/registry';
import { PaiDriver } from '../src/drivers/pi';
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
      updatedAt: '2026-06-28T12:00:00.000Z',
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
        status: 'idle',
        latestActivityText: 'Completed work',
        lastEventId: 'event-done',
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

    expect(outcome.result).toMatchObject({ accepted: true, status: 'executed' });
    expect(outcome.result).not.toHaveProperty('message');
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

  test('foreign Host rejection persists only the startup Host identity', async () => {
    const root = join(tmpdir(), `bridge-router-${Date.now()}`); paths.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    const router = new CommandRouter(store, new Map(), 'host-1');
    const outcome = await router.handle({
      commandId: 'cmd-foreign', hostId: 'host-foreign', sessionId: 'missing', type: 'interrupt', payload: {},
      issuedAt: '2099-06-28T10:00:00Z', expiresAt: '2099-06-28T10:10:00Z', nonce: 'n', watchDeviceId: 'watch-1',
    });
    expect(outcome.result).toMatchObject({ commandId: 'cmd-foreign', hostId: 'host-1', accepted: false, status: 'rejected' });
    expect(store.listCommandExecutions()).toEqual([]);
  });

  test('runs pure preflight before the durable marker and releases only after it succeeds', async () => {
    const root = join(tmpdir(), `bridge-router-order-${Date.now()}`); paths.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    store.replaceDriverSessions('pi', [{
      sessionId: 'pane-1', hostId: 'host-1', provider: 'pi', projectName: 'proj', nameText: 'Task',
      status: 'idle', updatedAt: '2026-06-28T10:00:00Z',
    }]);
    const order: string[] = [];
    const driver: AgentDriver = {
      name: 'pi',
      listSessions: async () => [],
      preflightCommandDispatch: () => { order.push('preflight'); },
      releaseCommandDispatch: () => { order.push('release'); },
      executeCommand: async (context) => {
        order.push('execute');
        return { commandId: context.command.commandId, hostId: context.command.hostId, sessionId: context.command.sessionId,
          accepted: true, status: 'executed', updatedAt: '2026-06-28T12:00:00.000Z' };
      },
    };
    const router = new CommandRouter(store, new Map([['pi', driver]]), 'host-1');
    const command = {
      commandId: 'cmd-order', hostId: 'host-1', sessionId: 'pane-1', type: 'interrupt' as const, payload: {},
      issuedAt: '2099-06-28T10:00:00Z', expiresAt: '2099-06-28T10:10:00Z', nonce: 'n-order', watchDeviceId: 'watch-1',
    };

    await router.handle(command, { beforeDispatch: () => { order.push('durable'); } });
    expect(order).toEqual(['preflight', 'durable', 'release', 'execute']);

    order.length = 0;
    await expect(router.handle(command, { beforeDispatch: () => { order.push('durable-failed'); throw new Error('write failed'); } }))
      .rejects.toThrow('write failed');
    expect(order).toEqual(['preflight', 'durable-failed']);
  });

  test('does not release an already-waiting Pi poll until the durable marker succeeds', async () => {
    const root = join(tmpdir(), `bridge-router-poll-order-${Date.now()}`); paths.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    store.replaceDriverSessions('pi', [{
      sessionId: 'pane-1', hostId: 'host-1', provider: 'pi', projectName: 'proj', nameText: 'Task',
      status: 'idle', updatedAt: '2026-06-28T10:00:00Z',
    }]);
    const registry = new AgentAdapterRegistry('host-1', store);
    registry.register({ sessionId: 'pane-1', provider: 'pi', projectName: 'proj', nameText: 'Task', cwd: '/' });
    const router = new CommandRouter(
      store, new Map([['pi', new PaiDriver(new AgentAdapterClient(registry), 'host-1')]]), 'host-1',
    );
    const command = {
      commandId: 'cmd-poll-order', hostId: 'host-1', sessionId: 'pane-1', type: 'interrupt' as const, payload: {},
      issuedAt: '2099-06-28T10:00:00Z', expiresAt: '2099-06-28T10:10:00Z', nonce: 'n-poll-order', watchDeviceId: 'watch-1',
    };
    let pollResolved = false;
    const poll = registry.dequeueCommand(command.sessionId, 500).then((value) => { pollResolved = true; return value; });

    await expect(router.handle(command, { beforeDispatch: () => { throw new Error('marker write failed'); } }))
      .rejects.toThrow('marker write failed');
    await Bun.sleep(10);
    expect(pollResolved).toBe(false);
    registry.cancelCommandPolls();
    expect(await poll).toBeNull();

    let durableState = false;
    const successfulPoll = registry.dequeueCommand(command.sessionId, 500).then((value) => ({ value, durableState }));
    const handling = router.handle(command, { beforeDispatch: () => { durableState = true; } });
    expect(await successfulPoll).toEqual({ value: command, durableState: true });
    registry.resolveCommand(command.commandId, {
      commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
      accepted: true, status: 'executed', updatedAt: '2026-06-28T12:00:00.000Z',
    });
    expect((await handling).result.status).toBe('executed');
    registry.dispose();
  });

});
