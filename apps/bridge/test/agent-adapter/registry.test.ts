import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentAdapterRegistry } from '../../src/agent-adapter/registry';
import { BridgeStateStore } from '../../src/state-store';
import type { CommandEnvelope, CommandResult } from '@ariava/protocol';

function makeStore(): { store: BridgeStateStore; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-'));
  const store = new BridgeStateStore(join(dir, 'state.json'));
  return {
    store,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function makeCommand(sessionId: string, type: CommandEnvelope['type'] = 'reply'): CommandEnvelope {
  return {
    commandId: `cmd-${sessionId}-${type}`,
    hostId: 'host-1',
    sessionId,
    type,
    payload: {},
    issuedAt: '2026-06-30T10:00:00Z',
    expiresAt: '2026-06-30T10:05:00Z',
    nonce: 'n-1',
    watchDeviceId: 'watch-1',
  };
}

describe('AgentAdapterRegistry', () => {
  test('registers a session and lists it', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({
        sessionId: 'sess-1',
        provider: 'pi',
        projectName: 'deploy-tools',
        cwd: '/Users/demo/deploy-tools',
        nameText: 'Fix deploy',
        pid: 1234,
      });

      const sessions = registry.listSessions();
      expect(sessions).toHaveLength(1);
      expect(sessions[0]?.sessionId).toBe('sess-1');
      expect(sessions[0]?.hostId).toBe('host-1');
      expect(sessions[0]?.provider).toBe('pi');
      expect(sessions[0]?.projectName).toBe('deploy-tools');
      expect(sessions[0]?.nameText).toBe('Fix deploy');
      expect(sessions[0]?.status).toBe('idle');
    } finally {
      cleanup();
    }
  });

  test('heartbeat updates status and latest activity', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/' });
      registry.heartbeat('sess-1', 'working', 'Running tests');

      const session = registry.listSessions()[0];
      expect(session?.status).toBe('working');
      expect(session?.latestActivityText).toBe('Running tests');
    } finally {
      cleanup();
    }
  });

  test('heartbeat distinguishes omitted semantic text from explicit null clear', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({
        sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/',
        openingText: 'Original task', latestActivityText: 'Original activity',
      });

      registry.heartbeat('sess-1', 'idle');
      expect(registry.listSessions()[0]).toMatchObject({
        openingText: 'Original task', latestActivityText: 'Original activity',
      });

      registry.heartbeat('sess-1', 'idle', null, { openingText: null });
      expect(registry.listSessions()[0]?.openingText).toBeUndefined();
      expect(registry.listSessions()[0]?.latestActivityText).toBeUndefined();
    } finally {
      cleanup();
    }
  });

  test('notifies only for semantic changes and TTL/unregister live-set removals', () => {
    const { store, cleanup } = makeStore();
    try {
      let now = new Date('2026-07-20T00:00:00.000Z');
      const reasons: string[] = [];
      const registry = new AgentAdapterRegistry('host-1', store, (reason) => reasons.push(reason), () => now);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/' });
      expect(reasons).toEqual(['register']);
      const firstUpdatedAt = registry.listSessions()[0]?.updatedAt;
      now = new Date('2026-07-20T00:00:10.000Z');
      registry.heartbeat('sess-1', 'idle');
      expect(reasons).toEqual(['register']);
      expect(registry.listSessions()[0]?.updatedAt).toBe(firstUpdatedAt);
      registry.heartbeat('sess-1', 'working', 'Running');
      expect(reasons).toEqual(['register', 'semantic']);
      registry.unregister('sess-1');
      expect(reasons).toEqual(['register', 'semantic', 'unregister']);

      registry.register({ sessionId: 'sess-ttl', provider: 'pi', projectName: 'p', cwd: '/' });
      now = new Date('2026-07-20T00:01:00.001Z');
      expect(registry.listSessions()).toHaveLength(0);
      expect(reasons.at(-1)).toBe('ttl');
    } finally {
      cleanup();
    }
  });

  test('restart authority waits for persisted Pi sessions to re-register but expires at normal TTL', () => {
    const { store, cleanup } = makeStore();
    try {
      let now = new Date('2026-07-20T00:00:00.000Z');
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => now);
      const persisted = [{
        sessionId: 'sess-live', hostId: 'host-1', provider: 'pi', projectName: 'p', nameText: 'live',
        stateLabel: 'In progress', status: 'working' as const, updatedAt: now.toISOString(),
      }];
      expect(registry.isAuthoritativeSetReady(persisted)).toBe(false);
      registry.register({ sessionId: 'sess-live', provider: 'pi', projectName: 'p', cwd: '/', status: 'working' });
      expect(registry.isAuthoritativeSetReady(persisted)).toBe(true);

      const anotherRestart = new AgentAdapterRegistry('host-1', store, () => {}, () => now);
      now = new Date('2026-07-20T00:00:45.001Z');
      expect(anotherRestart.isAuthoritativeSetReady(persisted)).toBe(true);
    } finally {
      cleanup();
    }
  });

  test('pushEvent updates status and meaningful latest activity in the same semantic mutation', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({
        sessionId: 'sess-activity', provider: 'pi', projectName: 'p', cwd: '/',
        status: 'idle', latestActivityText: 'Old activity',
      });
      registry.pushEvent('sess-activity', {
        type: 'working', status: 'working', assistantText: 'Running the integration suite',
      });
      expect(registry.listSessions()[0]).toMatchObject({
        status: 'working', latestActivityText: 'Running the integration suite',
      });
    } finally {
      cleanup();
    }
  });

  test('pushEvent queues a canonical event to the state store', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/' });
      const eventId = registry.pushEvent('sess-1', {
        type: 'working',
        status: 'working',
        assistantText: 'Agent is running',
      });

      expect(typeof eventId).toBe('string');
      const pending = store.peekPendingEvents();
      expect(pending).toHaveLength(1);
      expect(pending[0]?.hostId).toBe('host-1');
      expect(pending[0]?.sessionId).toBe('sess-1');
      expect(pending[0]?.provider).toBe('pi');
      expect(pending[0]?.type).toBe('working');
      expect(pending[0]?.assistantText).toBe('Agent is running');
    } finally {
      cleanup();
    }
  });

  test('pushEvent preserves assistant reply and user message fields', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/' });
      registry.pushEvent('sess-1', {
        type: 'question_requested',
        status: 'blocked',
        assistantText: 'Which environment should I target?',
        assistantText: 'Which environment should I target?',
        userMessageText: 'Deploy the latest build.',
      });

      const pending = store.peekPendingEvents();
      expect(pending[0]?.assistantText).toBe('Which environment should I target?');
      expect(pending[0]?.userMessageText).toBe('Deploy the latest build.');
    } finally {
      cleanup();
    }
  });

  test('pushEvent preserves assistant text line breaks and spacing', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/' });
      const assistantText = "First line\n\n  - indented item\n    code-ish spacing";

      registry.pushEvent('sess-1', {
        type: 'done',
        status: 'done',
        assistantText,
      });

      expect(store.peekPendingEvents()[0]?.assistantText).toBe(assistantText);
    } finally {
      cleanup();
    }
  });

  test('pushEvent falls back for empty previews', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'Task' });
      registry.pushEvent('sess-1', { type: 'done', status: 'done', assistantText: '' });
      registry.pushEvent('sess-1', { type: 'blocked', status: 'blocked', assistantText: '   ' });
      registry.pushEvent('sess-1', { type: 'question_requested', status: 'blocked' });

      const pending = store.peekPendingEvents();
      expect(pending[0]?.assistantText).toBe('Task complete');
      expect(pending[1]?.assistantText).toBe('Review needed on desktop');
      expect(pending[2]?.assistantText).toBe('Agent has a question');
    } finally {
      cleanup();
    }
  });

  test('pushEvent prefers session latest activity when event preview is blank', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({
        sessionId: 'sess-1',
        provider: 'pi',
        projectName: 'p',
        cwd: '/',
        latestActivityText: 'Latest useful activity',
      });
      registry.pushEvent('sess-1', { type: 'blocked', status: 'blocked', assistantText: '   ' });

      expect(store.peekPendingEvents()[0]?.assistantText).toBe('Latest useful activity');
    } finally {
      cleanup();
    }
  });

  test('pushEvent throws for unregistered session', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      expect(() => registry.pushEvent('missing', { type: 'done', status: 'done', assistantText: '' })).toThrow(
        /not registered/,
      );
    } finally {
      cleanup();
    }
  });

  test('queues session handles and bounds the legacy read alias to trusted Bridge sources', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/' });
      expect(registry.handleSession('sess-1', {
        handledThroughEventId: 'evt-1',
        handledThroughEventCreatedAt: '2026-07-16T00:00:01Z',
        action: 'pi_input',
      })).toMatchObject({
        ok: true, hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-1',
      });
      expect(store.peekPendingSessionHandles()[0]).toMatchObject({
        handledThroughEventId: 'evt-1',
        handledThroughEventCreatedAt: '2026-07-16T00:00:01Z',
        action: 'pi_input',
      });
      expect(() => registry.handleSessionReadAlias('sess-1', { latestReadEventId: 'evt-2', source: 'watch_view' })).toThrow(/requires/);
    } finally {
      cleanup();
    }
  });

  test('commands are queued when no waiter exists', async () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/' });
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);

      const resolved = await registry.dequeueCommand('sess-1', 50);
      expect(resolved?.commandId).toBe(command.commandId);
    } finally {
      cleanup();
    }
  });

  test('waitForResult resolves when command result is submitted', async () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      const result: CommandResult = {
        commandId: 'cmd-1',
        hostId: 'host-1',
        sessionId: 'sess-1',
        accepted: true,
        status: 'executed',
        message: 'done',
        updatedAt: '2026-06-30T10:00:00Z',
      };

      const promise = registry.waitForResult('cmd-1', { timeoutMs: 500 });
      registry.resolveCommand('cmd-1', result);

      expect(await promise).toEqual(result);
    } finally {
      cleanup();
    }
  });
});

describe('AgentAdapterRegistry terminal alert guard', () => {
  test('delays terminal events while command work is pending and flushes latest after result', async () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/' });
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);

      registry.pushEvent('sess-1', { type: 'done', status: 'done', assistantText: 'First done' });
      registry.pushEvent('sess-1', { type: 'blocked', status: 'blocked', assistantText: 'Latest blocker' });
      expect(store.peekPendingEvents()).toHaveLength(0);

      await registry.dequeueCommand('sess-1', 0);
      registry.resolveCommand(command.commandId, {
        commandId: command.commandId,
        hostId: command.hostId,
        sessionId: command.sessionId,
        accepted: true,
        status: 'executed',
        message: 'ok',
        updatedAt: '2026-06-30T10:00:00Z',
      });

      const pending = store.peekPendingEvents();
      expect(pending).toHaveLength(1);
      expect(pending[0]?.type).toBe('blocked');
      expect(pending[0]?.assistantText).toBe('Latest blocker');
    } finally {
      cleanup();
    }
  });

  test('does not delay non-terminal events while commands are pending', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/' });
      registry.enqueueCommand(makeCommand('sess-1'));
      registry.pushEvent('sess-1', { type: 'working', status: 'working', assistantText: 'Still running' });
      expect(store.peekPendingEvents()).toHaveLength(1);
      expect(store.peekPendingEvents()[0]?.type).toBe('working');
    } finally {
      cleanup();
    }
  });
});
