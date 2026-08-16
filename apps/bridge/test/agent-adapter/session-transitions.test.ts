import { describe, expect, test } from 'bun:test';
import type { CanonicalSessionState } from '@ariava/protocol';
import type { RegisteredSession, RegisterSessionInput } from '../../src/agent-adapter/registry-types';
import {
  authorizeRegistration,
  reduceHeartbeat,
  reduceRegistration,
  type RegistrationEvidence,
} from '../../src/agent-adapter/session-transitions';

const NOW = '2026-08-15T10:00:00.000Z';
const HOST_ID = 'host-1';

function registeredSession(overrides: Partial<RegisteredSession> = {}): RegisteredSession {
  return {
    sessionId: 'sess-1', provider: 'adapter', harnessProvider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
    hostId: HOST_ID, registeredAt: '2026-08-15T09:00:00.000Z', lastHeartbeatAt: '2026-08-15T09:30:00.000Z',
    status: 'working', semanticUpdatedAt: '2026-08-15T09:00:00.000Z', latestActivityText: 'Running', lastEventId: 'evt-1',
    ...overrides,
  };
}

function input(overrides: Partial<RegisterSessionInput> = {}): RegisterSessionInput {
  return {
    sessionId: 'sess-1', provider: 'adapter', harnessProvider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
    status: 'working', latestActivityText: 'Running', ...overrides,
  };
}

function canonicalSession(overrides: Partial<CanonicalSessionState> = {}): CanonicalSessionState {
  return {
    sessionId: 'sess-1', hostId: HOST_ID, provider: 'adapter', harnessProvider: 'pi', projectName: 'project', nameText: 'Task',
    workingDirectory: '/project', status: 'working', updatedAt: '2026-08-15T09:00:00.000Z', lastEventId: 'evt-1', ...overrides,
  };
}

function evidence(overrides: Partial<RegistrationEvidence> = {}): RegistrationEvidence {
  return { previousLive: undefined, persistedSession: undefined, terminalCancellation: undefined, ...overrides };
}

describe('authorizeRegistration', () => {
  test('authorizes first registration and the same normalized owner', () => {
    expect(authorizeRegistration(evidence(), input())).toEqual({ kind: 'authorized' });
    expect(authorizeRegistration({ previousLive: registeredSession(), persistedSession: canonicalSession() }, input()))
      .toEqual({ kind: 'authorized' });
  });

  test('rejects a different live owner', () => {
    expect(authorizeRegistration({ previousLive: registeredSession(), persistedSession: undefined }, input({ harnessProvider: 'codex' })))
      .toEqual({ kind: 'collision', sessionId: 'sess-1' });
  });

  test('rejects a different persisted owner even when live evidence matches', () => {
    expect(authorizeRegistration({
      previousLive: registeredSession(),
      persistedSession: canonicalSession({ harnessProvider: 'codex' }),
    }, input())).toEqual({ kind: 'collision', sessionId: 'sess-1' });
  });
});

describe('reduceRegistration', () => {
  test('builds a first canonical session with default status', () => {
    const transition = reduceRegistration(evidence(), input({ status: undefined }), HOST_ID, NOW);
    expect(transition.nextSession).toMatchObject({
      sessionId: 'sess-1', provider: 'adapter', harnessProvider: 'pi', hostId: HOST_ID,
      registeredAt: NOW, lastHeartbeatAt: NOW, status: 'idle', semanticUpdatedAt: NOW,
    });
    expect(transition.semanticChanged).toBe(true);
    expect(transition.contextChanged).toBe(false);
    expect(transition.persistence).toEqual({ kind: 'durable-set-session-driver' });
  });

  test('keeps idempotent registration freshness and persists the driver', () => {
    const previous = registeredSession();
    const transition = reduceRegistration(evidence({ previousLive: previous }), input(), HOST_ID, NOW);
    expect(transition.semanticChanged).toBe(false);
    expect(transition.contextChanged).toBe(false);
    expect(transition.persistence).toEqual({ kind: 'durable-set-session-driver' });
    expect(transition.nextSession.registeredAt).toBe(previous.registeredAt);
    expect(transition.nextSession.semanticUpdatedAt).toBe(previous.semanticUpdatedAt);
    expect(transition.nextSession.lastHeartbeatAt).toBe(NOW);
  });

  test('bumps semantic freshness for a non-context semantic change', () => {
    const transition = reduceRegistration(
      evidence({ previousLive: registeredSession() }), input({ status: 'idle' }), HOST_ID, NOW,
    );
    expect(transition.semanticChanged).toBe(true);
    expect(transition.contextChanged).toBe(false);
    expect(transition.nextSession.semanticUpdatedAt).toBe(NOW);
    expect(transition.persistence).toEqual({ kind: 'durable-set-session-driver' });
  });

  test('routes a same-owner context change without terminal evidence through live cancellation only', () => {
    const transition = reduceRegistration(
      evidence({ previousLive: registeredSession() }), input({ projectName: 'other-project' }), HOST_ID, NOW,
    );
    expect(transition.contextChanged).toBe(true);
    expect(transition.persistence).toEqual({ kind: 'no-op', nextDriverName: 'adapter', persistedCancellation: undefined });
  });

  test('durably cancels terminal evidence for a same-owner context change', () => {
    const terminalCancellation = { eventId: 'evt-9', fingerprint: 'fp-9' };
    const transition = reduceRegistration(
      evidence({ previousLive: registeredSession(), terminalCancellation }),
      input({ projectName: 'other-project' }), HOST_ID, NOW,
    );
    expect(transition.persistence).toEqual({
      kind: 'durable-cancel-terminal', nextDriverName: 'adapter', persistedCancellation: terminalCancellation,
    });
  });

  test('restart context change with cancellation uses durable cancellation', () => {
    const terminalCancellation = { eventId: 'evt-5', fingerprint: 'fp-5' };
    const transition = reduceRegistration(
      evidence({ persistedSession: canonicalSession(), terminalCancellation }),
      input({ projectName: 'other-project' }), HOST_ID, NOW,
    );
    expect(transition.persistence).toEqual({
      kind: 'durable-cancel-terminal', nextDriverName: 'adapter', persistedCancellation: terminalCancellation,
    });
  });

  test('restart context change without cancellation durably replaces the same-owner snapshot', () => {
    const transition = reduceRegistration(
      evidence({ persistedSession: canonicalSession() }), input({ projectName: 'other-project' }), HOST_ID, NOW,
    );
    expect(transition.persistence).toEqual({ kind: 'durable-set-session-driver' });
  });
});

describe('reduceHeartbeat', () => {
  test('no-op heartbeat changes only lastHeartbeatAt', () => {
    const session = registeredSession();
    const transition = reduceHeartbeat(session, { status: session.status }, NOW);
    expect(transition.semanticChanged).toBe(false);
    expect(transition.contextChanged).toBe(false);
    expect(transition.nextSession.lastHeartbeatAt).toBe(NOW);
    expect(transition.nextSession.semanticUpdatedAt).toBe(session.semanticUpdatedAt);
  });

  test('semantic status change bumps semanticUpdatedAt', () => {
    const transition = reduceHeartbeat(registeredSession(), { status: 'idle' }, NOW);
    expect(transition.semanticChanged).toBe(true);
    expect(transition.contextChanged).toBe(false);
    expect(transition.nextSession.semanticUpdatedAt).toBe(NOW);
  });

  test('project metadata change is a context and semantic change', () => {
    const transition = reduceHeartbeat(
      registeredSession(), { status: 'working', metadata: { projectName: 'other-project' } }, NOW,
    );
    expect(transition.contextChanged).toBe(true);
    expect(transition.semanticChanged).toBe(true);
    expect(transition.nextSession.projectName).toBe('other-project');
  });

  test('explicit null clears nullable activity and opening text', () => {
    const transition = reduceHeartbeat(
      registeredSession({ openingText: 'Open', latestActivityText: 'Running' }),
      { status: 'working', latestActivityText: null, metadata: { openingText: null } }, NOW,
    );
    expect(transition.nextSession.latestActivityText).toBeUndefined();
    expect(transition.nextSession.openingText).toBeUndefined();
    expect(transition.semanticChanged).toBe(true);
  });
});
