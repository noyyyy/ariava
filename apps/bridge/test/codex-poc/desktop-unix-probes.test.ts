import { describe, expect, test } from 'bun:test';

import {
  eventTuplesFromRead,
  hashedThreadSet,
  hashOpaqueId,
  isRequestApprovalMethod,
  commitEventsFromNotifications,
  proveEventOrdering,
  threadIdFromStartResult,
  threadIdsFromListResult,
  turnIdFromStartResult,
  turnIdFromNotificationParams,
} from './desktop-unix-probes';

describe('desktop unix probes', () => {
  test('hashes thread ids and never returns the raw id from hashedThreadSet', () => {
    const ids = threadIdsFromListResult({ data: [{ threadId: 'thread-raw-1' }, { id: 'thread-raw-2' }] });
    expect(ids).toEqual(['thread-raw-1', 'thread-raw-2']);
    const hashed = hashedThreadSet(ids);
    expect(hashed).toHaveLength(2);
    expect(hashed.some((value) => value.includes('thread-raw'))).toBe(false);
    expect(hashed).toEqual([hashOpaqueId('thread-raw-1'), hashOpaqueId('thread-raw-2')].sort());
  });

  test('extracts nested thread and turn ids from start results', () => {
    expect(threadIdFromStartResult({ thread: { id: 'thread-nested' } })).toBe('thread-nested');
    expect(turnIdFromStartResult({ turn: { id: 'turn-nested' } })).toBe('turn-nested');
    expect(turnIdFromNotificationParams({ turn: { id: 'turn-from-notification' } })).toBe('turn-from-notification');
    expect(isRequestApprovalMethod('item/commandExecution/requestApproval')).toBe(true);
    expect(isRequestApprovalMethod('thread/list')).toBe(false);
  });

  test('event ordering proofs require a stable source tuple', () => {
    const tuples = eventTuplesFromRead('t1', {
      events: [
        { id: 'e1', type: 'item/completed', generation: 1 },
        { id: 'e2', type: 'turn/completed', generation: 1 },
      ],
    });
    const proof = proveEventOrdering('t1', tuples);
    expect(proof.sourceStable).toBe(true);
    expect(proof.duplicate).toBe(true);
    expect(proof.complete).toBe(true);
  });

  test('flattens thread.turns[].items from includeTurns reads without using content', () => {
    const tuples = eventTuplesFromRead('t1', {
      thread: {
        turns: [
          { id: 'turn-a', items: [{ id: 'item-1', type: 'userMessage', content: 'secret-a' }] },
          { id: 'turn-b', items: [{ id: 'item-2', type: 'agentMessage', content: 'secret-b' }] },
        ],
      },
    });
    expect(tuples).toHaveLength(2);
    expect(tuples[0]?.sourceEventId).toBe(hashOpaqueId('item-1'));
    expect(tuples[1]?.sourceEventId).toBe(hashOpaqueId('item-2'));
    expect(JSON.stringify(tuples).includes('secret')).toBe(false);
    const proof = proveEventOrdering('t1', tuples);
    expect(proof.sourceStable).toBe(true);
    expect(proof.comparable).toBe(true);
  });

  test('commit events come from notification method names, hashed not raw', () => {
    const events = commitEventsFromNotifications([
      { method: 'turn/started', params: { turn: { id: 'raw-turn-1' } } },
      { method: 'item/completed' },
      { method: 'turn/started', id: 2, params: { turn: { id: 'raw-turn-2' } } },
    ], 'turn/started');
    expect(events).toHaveLength(2);
    expect(events.every((event) => event.type === 'turn/started')).toBe(true);
    expect(JSON.stringify(events).includes('raw-turn')).toBe(false);
    expect(new Set(events.map((event) => event.sourceEventId)).size).toBe(2);
  });
});
