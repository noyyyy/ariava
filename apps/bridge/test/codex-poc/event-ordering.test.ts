import { describe, expect, test } from 'bun:test';
import {
  arrivalTimeIsNotOnlyOrder,
  approvalNotDuplicatedByFanout,
  createEventStream,
  detectGaps,
  hasCompleteSetAuthority,
  recordArrival,
  recordEvent,
  repairFromAuthoritative,
  type EventSourceTuple,
} from './event-ordering';

function tuple(partial: Partial<EventSourceTuple> & Pick<EventSourceTuple, 'sourceEventId'>): EventSourceTuple {
  return {
    rawThreadId: 'thread-1',
    providerGeneration: 1,
    authoritativeOrder: 1,
    type: 'turn.item.completed',
    ...partial,
  };
}

describe('event source ordering (spec §8.3)', () => {
  test('source tuple is stable: rawThreadId + generation + order + sourceEventId', () => {
    const stream = createEventStream('thread-1');
    recordEvent(stream, tuple({ sourceEventId: 'evt-1', authoritativeOrder: 1, type: 'loaded' }));
    recordEvent(stream, tuple({ sourceEventId: 'evt-2', authoritativeOrder: 2, type: 'turn.start' }));
    expect(stream.events[0]).toMatchObject({ rawThreadId: 'thread-1', providerGeneration: 1, authoritativeOrder: 1, sourceEventId: 'evt-1', type: 'loaded' });
    expect(stream.events[1]).toMatchObject({ sourceEventId: 'evt-2', type: 'turn.start' });
  });

  test('duplicates are identifiable by sourceEventId', () => {
    const stream = createEventStream('thread-1');
    recordEvent(stream, tuple({ sourceEventId: 'evt-1', authoritativeOrder: 1 }));
    const result = recordEvent(stream, tuple({ sourceEventId: 'evt-1', authoritativeOrder: 2 }));
    expect(result).toBe('duplicate');
    expect(stream.duplicates).toContain('evt-1');
    expect(stream.events).toHaveLength(1);
  });

  test('authoritative order is strict, comparable, and gap-detectable', () => {
    const stream = createEventStream('thread-1');
    recordEvent(stream, tuple({ sourceEventId: 'evt-1', authoritativeOrder: 1 }));
    recordEvent(stream, tuple({ sourceEventId: 'evt-2', authoritativeOrder: 2 }));
    recordEvent(stream, tuple({ sourceEventId: 'evt-4', authoritativeOrder: 4 }));
    const gaps = detectGaps(stream);
    expect(gaps).toContainEqual({ from: 2, to: 4 });
  });

  test('out-of-order authoritative event fails closed', () => {
    const stream = createEventStream('thread-1');
    recordEvent(stream, tuple({ sourceEventId: 'evt-1', authoritativeOrder: 2 }));
    expect(() => recordEvent(stream, tuple({ sourceEventId: 'evt-2', authoritativeOrder: 1 }))).toThrow('out-of-order');
  });

  test('reconnect/replay repair fills gaps from authoritative read', () => {
    const stream = createEventStream('thread-1');
    recordEvent(stream, tuple({ sourceEventId: 'evt-1', authoritativeOrder: 1 }));
    recordEvent(stream, tuple({ sourceEventId: 'evt-3', authoritativeOrder: 3 }));
    // Authoritative read/replay contains the missing event.
    const authoritative: EventSourceTuple[] = [
      tuple({ sourceEventId: 'evt-1', authoritativeOrder: 1 }),
      tuple({ sourceEventId: 'evt-2', authoritativeOrder: 2 }),
      tuple({ sourceEventId: 'evt-3', authoritativeOrder: 3 }),
    ];
    const applied = repairFromAuthoritative(stream, authoritative);
    expect(applied).toBe(1);
    expect(stream.repaired).toBe(true);
    expect(stream.events.map((event) => event.sourceEventId)).toEqual(['evt-1', 'evt-3', 'evt-2']);
  });

  test('loaded-set/read determines complete-set authority', () => {
    const stream = createEventStream('thread-1');
    recordEvent(stream, tuple({ sourceEventId: 'evt-1', authoritativeOrder: 1 }));
    recordEvent(stream, tuple({ sourceEventId: 'evt-2', authoritativeOrder: 2 }));
    const loadedSet: EventSourceTuple[] = [
      tuple({ sourceEventId: 'evt-1', authoritativeOrder: 1 }),
      tuple({ sourceEventId: 'evt-2', authoritativeOrder: 2 }),
    ];
    expect(hasCompleteSetAuthority(stream, loadedSet)).toBe(true);
    const partial: EventSourceTuple[] = [tuple({ sourceEventId: 'evt-1', authoritativeOrder: 1 })];
    expect(hasCompleteSetAuthority(stream, partial)).toBe(false);
  });

  test('notification arrival time is not the only order', () => {
    const stream = createEventStream('thread-1');
    const first = tuple({ sourceEventId: 'evt-1', authoritativeOrder: 1 });
    const second = tuple({ sourceEventId: 'evt-2', authoritativeOrder: 2 });
    recordEvent(stream, first);
    recordEvent(stream, second);
    // Arrival order reversed relative to authoritative order: evt-2 arrives
    // before evt-1, but authoritative order still ranks evt-1 first.
    recordArrival(stream, { sourceEventId: 'evt-2', arrivedAtMs: 100, tuple: second });
    recordArrival(stream, { sourceEventId: 'evt-1', arrivedAtMs: 200, tuple: first });
    expect(arrivalTimeIsNotOnlyOrder(stream)).toBe(true);
  });

  test('approval is not duplicated by fanout mapping', () => {
    expect(approvalNotDuplicatedByFanout(['approval-1', 'approval-2'])).toBe(true);
    expect(approvalNotDuplicatedByFanout(['approval-1', 'approval-1'])).toBe(false);
  });

  test('thread id mismatch fails closed', () => {
    const stream = createEventStream('thread-1');
    expect(() => recordEvent(stream, tuple({ rawThreadId: 'thread-2', sourceEventId: 'evt-x' }))).toThrow('thread id mismatch');
  });
});
