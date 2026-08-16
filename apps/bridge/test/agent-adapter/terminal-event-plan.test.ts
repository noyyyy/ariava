import { describe, expect, test } from 'bun:test';
import type { CanonicalEvent, CanonicalSessionState } from '@ariava/protocol';
import { immutableCopy, producerEventFingerprint } from '../../src/agent-adapter/registry-codec';
import { planTerminalEvent, toCanonicalSessionState, type ProducerReservation, type TerminalEventTuple } from '../../src/agent-adapter/terminal-event-plan';
import type { AgentAdapterEventInput, PendingTerminal, RegisteredSession } from '../../src/agent-adapter/registry-types';

function session(overrides: Partial<RegisteredSession> = {}): RegisteredSession {
  return {
    sessionId: 'sess-1', provider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
    hostId: 'host-1', registeredAt: '2026-08-07T00:00:00.000Z', lastHeartbeatAt: '2026-08-07T00:00:00.000Z',
    status: 'working', semanticUpdatedAt: '2026-08-07T00:00:00.000Z',
    ...overrides,
  };
}

function input(overrides: Partial<AgentAdapterEventInput> = {}): AgentAdapterEventInput {
  return {
    sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle', agentText: 'Finished successfully',
    projectName: 'project', workingDirectory: '/project', harnessProvider: 'pi', createdAt: '2026-08-07T00:00:01.000Z',
    ...overrides,
  } as AgentAdapterEventInput;
}

function pendingFor(event: CanonicalEvent, registered: RegisteredSession): PendingTerminal {
  return Object.freeze({ event: immutableCopy(event), session: immutableCopy(toCanonicalSessionState(registered)) });
}

function canonicalEvent(eventId: string, producer: AgentAdapterEventInput, hostId = 'host-1'): CanonicalEvent {
  return immutableCopy({ ...producer, eventId, hostId } as CanonicalEvent);
}

function reservedTuple(event: CanonicalEvent, registered: RegisteredSession): TerminalEventTuple {
  return { event, session: immutableCopy(toCanonicalSessionState(registered)) };
}

function reservationFor(eventId: string, producer: AgentAdapterEventInput): ProducerReservation {
  return { version: 1, eventId, sessionId: producer.sessionId, fingerprint: producerEventFingerprint(producer), createdAt: producer.createdAt };
}

describe('planTerminalEvent leaf coverage', () => {
  test('rejects when the session is missing', () => {
    const plan = planTerminalEvent({
      session: undefined, livePending: undefined, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: false, input: input(), eventId: 'evt_new',
    });
    expect(plan).toEqual({ type: 'reject', error: new Error('Session sess-1 is not registered') });
  });

  test('rejects when the canonical Event sessionId does not match the session', () => {
    const plan = planTerminalEvent({
      session: session(), livePending: undefined, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: false, input: input({ sessionId: 'sess-other' }), eventId: 'evt_new',
    });
    expect(plan).toEqual({ type: 'reject', error: new TypeError('canonical Event sessionId does not match the request path') });
  });

  test('rejects when the canonical Event provider does not match the session', () => {
    const plan = planTerminalEvent({
      session: session(), livePending: undefined, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: false, input: input({ provider: 'codex' }), eventId: 'evt_new',
    });
    expect(plan).toEqual({ type: 'reject', error: new TypeError('canonical Event provider does not match the registered Session') });
  });

  test('rejects when the canonical Event context does not match the session', () => {
    const plan = planTerminalEvent({
      session: session(), livePending: undefined, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: false, input: input({ projectName: 'other-project' }), eventId: 'evt_new',
    });
    expect(plan.type).toBe('reject');
    expect((plan as { error: Error }).error.message).toMatch(/canonical Event projectName does not match the registered Session/u);
  });

  test('reserves a new tuple for the first terminal with no command work (promoteNow)', () => {
    const producer = input();
    const plan = planTerminalEvent({
      session: session(), livePending: undefined, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: false, input: producer, eventId: 'evt_new',
    });
    expect(plan.type).toBe('reserve-new-tuple');
    if (plan.type !== 'reserve-new-tuple') return;
    expect(plan.promoteNow).toBe(true);
    expect(plan.tuple.event).toMatchObject({ eventId: 'evt_new', hostId: 'host-1', ...producer });
    expect(plan.tuple.session).toMatchObject({ sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', status: 'idle', lastEventId: 'evt_new' });
    expect(plan.reservation).toEqual(reservationFor('evt_new', producer));
    expect(Object.isFrozen(plan.tuple)).toBe(true);
    expect(Object.isFrozen(plan.tuple.event)).toBe(true);
    expect(Object.isFrozen(plan.tuple.session)).toBe(true);
  });

  test('reserves a new tuple and defers promotion during command work', () => {
    const plan = planTerminalEvent({
      session: session(), livePending: undefined, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: true, input: input(), eventId: 'evt_new',
    });
    expect(plan).toMatchObject({ type: 'reserve-new-tuple', promoteNow: false });
  });

  test('cancels the older pending terminal and reserves the new tuple (promoteNow)', () => {
    const older = input({ agentText: 'Older terminal', createdAt: '2026-08-07T00:00:00.500Z' });
    const olderEvent = canonicalEvent('evt_older', older);
    const livePending = pendingFor(olderEvent, session({ status: 'working', latestActivityText: 'Older terminal' }));
    const producer = input({ createdAt: '2026-08-07T00:00:01.000Z' });
    const plan = planTerminalEvent({
      session: session(), livePending, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: false, input: producer, eventId: 'evt_new',
    });
    expect(plan.type).toBe('cancel-older-and-reserve');
    if (plan.type !== 'cancel-older-and-reserve') return;
    expect(plan.promoteNow).toBe(true);
    expect(plan.tuple.event).toMatchObject({ eventId: 'evt_new', ...producer });
    expect(plan.reservation).toEqual(reservationFor('evt_new', producer));
  });

  test('cancels the older pending terminal and defers promotion during command work', () => {
    const older = input({ agentText: 'Older terminal', createdAt: '2026-08-07T00:00:00.500Z' });
    const olderEvent = canonicalEvent('evt_older', older);
    const livePending = pendingFor(olderEvent, session({ status: 'working', latestActivityText: 'Older terminal' }));
    const plan = planTerminalEvent({
      session: session(), livePending, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: true, input: input(), eventId: 'evt_new',
    });
    expect(plan).toMatchObject({ type: 'cancel-older-and-reserve', promoteNow: false });
  });

  test('returns the live duplicate when the pending terminal matches (promoteNow)', () => {
    const producer = input();
    const event = canonicalEvent('evt_dupe', producer);
    const livePending = pendingFor(event, session({ status: 'working', latestActivityText: 'Finished successfully' }));
    const plan = planTerminalEvent({
      session: session(), livePending, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: false, input: producer, eventId: 'evt_unused',
    });
    expect(plan).toEqual({ type: 'return-live-duplicate', promoteNow: true });
  });

  test('returns the live duplicate and defers promotion during command work', () => {
    const producer = input();
    const event = canonicalEvent('evt_dupe', producer);
    const livePending = pendingFor(event, session({ status: 'working', latestActivityText: 'Finished successfully' }));
    const plan = planTerminalEvent({
      session: session(), livePending, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: true, input: producer, eventId: 'evt_unused',
    });
    expect(plan).toEqual({ type: 'return-live-duplicate', promoteNow: false });
  });

  test('returns the persisted Event ID when a reservation has no tuple', () => {
    const producer = input({ createdAt: '2026-08-07T00:00:11.000Z' });
    const reservation = reservationFor('evt_persisted', producer);
    const plan = planTerminalEvent({
      session: session(), livePending: undefined, persistedReservation: reservation, persistedTuple: undefined,
      hasPendingCommandWork: false, input: producer, eventId: 'evt_unused',
    });
    expect(plan).toEqual({ type: 'return-reservation-without-tuple', eventId: 'evt_persisted' });
  });

  test('stages the persisted tuple and promotes when no command work', () => {
    const producer = input({ createdAt: '2026-08-07T00:00:12.000Z' });
    const event = canonicalEvent('evt_persisted', producer);
    const tuple = reservedTuple(event, session({ status: 'idle', latestActivityText: 'Finished successfully', lastEventId: 'evt_persisted' }));
    const reservation = reservationFor('evt_persisted', producer);
    const plan = planTerminalEvent({
      session: session(), livePending: undefined, persistedReservation: reservation, persistedTuple: tuple,
      hasPendingCommandWork: false, input: producer, eventId: 'evt_unused',
    });
    expect(plan.type).toBe('stage-reserved-tuple');
    if (plan.type !== 'stage-reserved-tuple') return;
    expect(plan.promoteNow).toBe(true);
    expect(plan.tuple).toBe(tuple);
  });

  test('stages the persisted tuple and defers promotion during command work', () => {
    const producer = input({ createdAt: '2026-08-07T00:00:13.000Z' });
    const event = canonicalEvent('evt_persisted', producer);
    const tuple = reservedTuple(event, session({ status: 'idle', latestActivityText: 'Finished successfully', lastEventId: 'evt_persisted' }));
    const reservation = reservationFor('evt_persisted', producer);
    const plan = planTerminalEvent({
      session: session(), livePending: undefined, persistedReservation: reservation, persistedTuple: tuple,
      hasPendingCommandWork: true, input: producer, eventId: 'evt_unused',
    });
    expect(plan).toEqual({ type: 'stage-reserved-tuple', tuple, promoteNow: false });
  });

  test('prefers the live duplicate over a persisted reservation when both match', () => {
    const producer = input();
    const liveEvent = canonicalEvent('evt_live', producer);
    const livePending = pendingFor(liveEvent, session({ status: 'working', latestActivityText: 'Finished successfully' }));
    const reservation = reservationFor('evt_persisted', producer);
    const plan = planTerminalEvent({
      session: session(), livePending, persistedReservation: reservation, persistedTuple: undefined,
      hasPendingCommandWork: false, input: producer, eventId: 'evt_unused',
    });
    expect(plan).toEqual({ type: 'return-live-duplicate', promoteNow: true });
  });

  test('a live pending with a different fingerprint does not shadow the persisted recovery path', () => {
    const older = input({ agentText: 'Older terminal' });
    const olderEvent = canonicalEvent('evt_older', older);
    const livePending = pendingFor(olderEvent, session({ status: 'working', latestActivityText: 'Older terminal' }));
    const producer = input({ createdAt: '2026-08-07T00:00:12.000Z' });
    const event = canonicalEvent('evt_persisted', producer);
    const tuple = reservedTuple(event, session({ status: 'idle', latestActivityText: 'Finished successfully', lastEventId: 'evt_persisted' }));
    const reservation = reservationFor('evt_persisted', producer);
    const plan = planTerminalEvent({
      session: session(), livePending, persistedReservation: reservation, persistedTuple: tuple,
      hasPendingCommandWork: false, input: producer, eventId: 'evt_unused',
    });
    expect(plan).toEqual({ type: 'stage-reserved-tuple', tuple, promoteNow: true });
  });

  test('the produced tuple session carries the canonical terminal mapping', () => {
    const producer = input({ status: 'need_human' as const, type: 'need_human' as const, agentText: 'Question', needHuman: { reason: 'question' } });
    const plan = planTerminalEvent({
      session: session(), livePending: undefined, persistedReservation: undefined, persistedTuple: undefined,
      hasPendingCommandWork: false, input: producer, eventId: 'evt_new',
    });
    expect(plan.type).toBe('reserve-new-tuple');
    if (plan.type !== 'reserve-new-tuple') return;
    const canonical = plan.tuple.session as CanonicalSessionState;
    expect(canonical).toMatchObject({
      sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', status: 'need_human', workingDirectory: '/project',
      projectName: 'project', nameText: 'Task', latestActivityText: 'Question', lastEventId: 'evt_new',
    });
  });
});
