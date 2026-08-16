import { describe, expect, test } from 'bun:test';
import type { CanonicalEvent, CanonicalSessionState } from '@ariava/protocol';

const {
  PendingUploadBindingError,
  eventSourceDigest,
  preflightEventSource,
  preflightSessionSource,
  sessionSourceDigest,
} = await import('../src/e2e/upload-preflight');
const { assertEventSessionBinding } = await import('../src/e2e/upload-inputs');

function terminalSession(overrides: Partial<CanonicalSessionState> = {}): CanonicalSessionState {
  return {
    sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'secret-project', nameText: 'Session',
    latestActivityText: 'terminal activity', workingDirectory: '/secret/project',
    harnessProvider: 'pi', status: 'idle', updatedAt: '2026-08-07T00:00:01.000Z',
    lastEventId: 'event-test', ...overrides,
  } as CanonicalSessionState;
}

function doneEvent(overrides: Partial<CanonicalEvent> = {}): CanonicalEvent {
  return {
    eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'done', status: 'idle',
    agentText: 'terminal activity', projectName: 'secret-project',
    workingDirectory: '/secret/project', harnessProvider: 'pi',
    createdAt: '2026-08-07T00:00:01.000Z', ...overrides,
  } as CanonicalEvent;
}

describe('LocalUploadPreflight (§4.1)', () => {
  test('legal Session snapshot is ready with a deterministic 43-char base64url source digest', () => {
    const first = preflightSessionSource(terminalSession());
    const second = preflightSessionSource(terminalSession());
    expect(first.type).toBe('ready');
    if (first.type !== 'ready') throw new Error('unreachable');
    expect(first.sourceDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second.type === 'ready' && second.sourceDigest).toBe(first.sourceDigest);
    expect(sessionSourceDigest(terminalSession())).toBe(first.sourceDigest);
  });

  test('legal Event + bundled Session tuple is ready; digest changes with content', () => {
    const first = preflightEventSource(doneEvent(), terminalSession());
    const changed = preflightEventSource(doneEvent({ agentText: 'different terminal activity' }), terminalSession());
    expect(first.type).toBe('ready');
    if (first.type !== 'ready') throw new Error('unreachable');
    expect(first.sourceDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(eventSourceDigest(doneEvent(), terminalSession())).toBe(first.sourceDigest);
    expect(changed.type === 'ready' && changed.sourceDigest).not.toBe(first.sourceDigest);
  });

  test('fixed digest vectors lock namespace + newline + shared length-prefixed canonical bytes', () => {
    expect(sessionSourceDigest(terminalSession())).toBe('APqa24ZZ0Ra__BOOKVjv639H4iXf8CBwYFdM_pjaSf8');
    expect(eventSourceDigest(doneEvent(), terminalSession())).toBe('kJM9NnlRfNX7qbQym7fKYHz66SXqWJ0M-yUhy3R1TEc');
  });

  test('Session digest binds snoozedUntil: a changed snooze is a different immutable source', () => {
    const base = sessionSourceDigest(terminalSession());
    const snoozed = sessionSourceDigest(terminalSession({ snoozedUntil: '2026-08-07T00:10:00.000Z' }));
    expect(snoozed).not.toBe(base);
  });

  test('Event digest binds the bundled Session updatedAt and snoozedUntil metadata', () => {
    const base = eventSourceDigest(doneEvent(), terminalSession());
    const moved = eventSourceDigest(doneEvent(), terminalSession({ updatedAt: '2026-08-07T00:00:02.000Z' }));
    const snoozed = eventSourceDigest(doneEvent(), terminalSession({ snoozedUntil: '2026-08-07T00:10:00.000Z' }));
    expect(moved).not.toBe(base);
    expect(snoozed).not.toBe(base);
    // Identical tuples still produce identical digests.
    expect(eventSourceDigest(doneEvent(), terminalSession())).toBe(base);
  });

  test('oversized Event content is invalid-content with protected-event-invalid', () => {
    const result = preflightEventSource(doneEvent({ agentText: 'a'.repeat(64 * 1024) }), terminalSession());
    expect(result).toEqual({ type: 'invalid-content', code: 'protected-event-invalid' });
  });

  test('oversized Session content is invalid-content with protected-session-invalid on both preflight entry points', () => {
    const oversizedSession = terminalSession({ openingText: 'a'.repeat(64 * 1024) });
    expect(preflightSessionSource(oversizedSession)).toEqual({ type: 'invalid-content', code: 'protected-session-invalid' });
    expect(preflightEventSource(doneEvent(), oversizedSession)).toEqual({ type: 'invalid-content', code: 'protected-session-invalid' });
  });

  test('Event/Session binding mismatch is invalid-source-binding with event-session-binding-invalid', () => {
    const result = preflightEventSource(doneEvent(), terminalSession({ sessionId: 'other-session' }));
    expect(result).toEqual({ type: 'invalid-source-binding', code: 'event-session-binding-invalid' });
    expect(() => assertEventSessionBinding(doneEvent(), terminalSession({ sessionId: 'other-session' })))
      .toThrow(PendingUploadBindingError);
  });

  test('arbitrary internal TypeError at source access propagates and is never classified as invalid-content', () => {
    // A getter fault on a source field simulates an internal (e.g. keyring/IO)
    // failure at source access time. Preflight must propagate it, not return
    // `invalid-content` or `invalid-source-binding`.
    const faultySession = terminalSession();
    Object.defineProperty(faultySession, 'projectName', {
      get() { throw new TypeError('internal source access fault'); },
    });
    expect(() => preflightSessionSource(faultySession)).toThrow(TypeError);
    expect(() => preflightEventSource(doneEvent(), faultySession)).toThrow(TypeError);
  });
});
