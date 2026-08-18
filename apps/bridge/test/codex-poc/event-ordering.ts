/**
 * Event source ordering model for the Codex Exact-Release Capability PoC
 * (spec §8.3).
 *
 * Every mapped canonical Event must have a provider-native source tuple:
 *   rawThreadId + providerGeneration + authoritativeOrder + sourceEventId/type
 *
 * This module models the invariants the harness must prove:
 *   - source identity stable across reconnect/replay;
 *   - authoritative order strict, comparable, and gap-detectable;
 *   - duplicates identifiable;
 *   - reconnect can repair from authoritative read/replay;
 *   - notification arrival time is not the only order;
 *   - loaded-set/read determines complete-set authority;
 *   - approval and ordinary question/error/completion are not duplicated by
 *     fanout mapping.
 *
 * Research-only harness code; never part of the production import graph.
 */

/** Provider-native event source tuple (spec §8.3). */
export interface EventSourceTuple {
  rawThreadId: string;
  providerGeneration: number;
  authoritativeOrder: number;
  sourceEventId: string;
  type: string;
}

/** A notification as observed by a client (arrival order is not authoritative). */
export interface ObservedNotification {
  sourceEventId: string;
  arrivalOrder: number;
  arrivedAtMs: number;
  tuple?: EventSourceTuple;
}

export interface EventStreamState {
  /** Thread identity (stable across reconnect). */
  rawThreadId: string;
  /** Events in authoritative order (deduplicated by sourceEventId). */
  events: EventSourceTuple[];
  /** Highest authoritative order seen. */
  lastOrder: number;
  /** Arrival-order observations (not authoritative). */
  arrivals: ObservedNotification[];
  /** Duplicates identified by sourceEventId. */
  duplicates: string[];
  /** Gaps detected in authoritative order. */
  gaps: Array<{ from: number; to: number }>;
  /** Whether the stream has been repaired from authoritative read/replay. */
  repaired: boolean;
}

export interface EventOrderingOptions {
  /** Maximum buffered authoritative events (bounded memory). */
  maxBufferedEvents?: number;
}

function compareTuples(left: EventSourceTuple, right: EventSourceTuple): number {
  if (left.providerGeneration !== right.providerGeneration) {
    return left.providerGeneration < right.providerGeneration ? -1 : 1;
  }
  return left.authoritativeOrder < right.authoritativeOrder ? -1 : left.authoritativeOrder > right.authoritativeOrder ? 1 : 0;
}

/** Create an empty event stream for a thread. */
export function createEventStream(rawThreadId: string, options: EventOrderingOptions = {}): EventStreamState {
  return {
    rawThreadId,
    events: [],
    lastOrder: 0,
    arrivals: [],
    duplicates: [],
    gaps: [],
    repaired: false,
  };
}

/**
 * Record a provider-native event into the stream.
 * Returns 'accepted' | 'duplicate' | 'gap-bridged'.
 * A duplicate sourceEventId is identified and rejected (not re-applied).
 */
export function recordEvent(stream: EventStreamState, tuple: EventSourceTuple): 'accepted' | 'duplicate' | 'gap-bridged' {
  if (tuple.rawThreadId !== stream.rawThreadId) {
    throw new Error(`event ordering: thread id mismatch ${tuple.rawThreadId} != ${stream.rawThreadId}`);
  }
  if (stream.events.some((event) => event.sourceEventId === tuple.sourceEventId)) {
    stream.duplicates.push(tuple.sourceEventId);
    return 'duplicate';
  }
  if (stream.events.length > 0) {
    const last = stream.events[stream.events.length - 1]!;
    if (compareTuples(last, tuple) >= 0) {
      // Out-of-order authoritative event: reject (fail closed).
      throw new Error(`event ordering: out-of-order event ${tuple.sourceEventId}`);
    }
    const expectedOrder = last.providerGeneration === tuple.providerGeneration ? last.authoritativeOrder + 1 : 1;
    if (tuple.providerGeneration === last.providerGeneration && tuple.authoritativeOrder !== expectedOrder) {
      stream.gaps.push({ from: last.authoritativeOrder, to: tuple.authoritativeOrder });
    }
  }
  stream.events.push(tuple);
  stream.lastOrder = tuple.authoritativeOrder;
  return stream.gaps.length > 0 ? 'gap-bridged' : 'accepted';
}

/** Record an observed notification arrival (arrival order is NOT authoritative). */
export function recordArrival(stream: EventStreamState, notification: Omit<ObservedNotification, 'arrivalOrder'>): void {
  stream.arrivals.push({
    ...notification,
    arrivalOrder: stream.arrivals.length + 1,
  });
}

/** Detect gaps in the authoritative order sequence (per generation). */
export function detectGaps(stream: EventStreamState): Array<{ from: number; to: number }> {
  const gaps: Array<{ from: number; to: number }> = [];
  const byGeneration = new Map<number, EventSourceTuple[]>();
  for (const event of stream.events) {
    const list = byGeneration.get(event.providerGeneration) ?? [];
    list.push(event);
    byGeneration.set(event.providerGeneration, list);
  }
  for (const [generation, events] of byGeneration) {
    const sorted = [...events].sort((left, right) => left.authoritativeOrder - right.authoritativeOrder);
    for (let index = 1; index < sorted.length; index += 1) {
      const prev = sorted[index - 1]!;
      const current = sorted[index]!;
      if (current.authoritativeOrder !== prev.authoritativeOrder + 1) {
        gaps.push({ from: prev.authoritativeOrder, to: current.authoritativeOrder });
      }
    }
  }
  return gaps;
}

/**
 * Repair the stream from an authoritative read/replay result.
 * Returns the number of new events applied (0 means already complete).
 */
export function repairFromAuthoritative(stream: EventStreamState, authoritative: EventSourceTuple[]): number {
  let applied = 0;
  const sorted = [...authoritative].sort(compareTuples);
  for (const tuple of sorted) {
    if (tuple.rawThreadId !== stream.rawThreadId) {
      throw new Error(`event ordering: authoritative repair thread mismatch ${tuple.rawThreadId}`);
    }
    if (!stream.events.some((event) => event.sourceEventId === tuple.sourceEventId)) {
      stream.events.push(tuple);
      stream.lastOrder = tuple.authoritativeOrder;
      applied += 1;
    }
  }
  stream.repaired = true;
  return applied;
}

/** Complete-set authority: loaded-set/read must cover every authoritative event. */
export function hasCompleteSetAuthority(stream: EventStreamState, loadedSet: EventSourceTuple[]): boolean {
  const loadedIds = new Set(loadedSet.map((event) => event.sourceEventId));
  return stream.events.every((event) => loadedIds.has(event.sourceEventId));
}

/**
 * Prove that notification arrival time is not the only order:
 * two events with reversed arrival order must still compare correctly by
 * authoritative order.
 */
export function arrivalTimeIsNotOnlyOrder(stream: EventStreamState): boolean {
  const pairs: Array<[EventSourceTuple, EventSourceTuple]> = [];
  for (let left = 0; left < stream.events.length; left += 1) {
    for (let right = left + 1; right < stream.events.length; right += 1) {
      pairs.push([stream.events[left]!, stream.events[right]!]);
    }
  }
  for (const [left, right] of pairs) {
    const authoritative = compareTuples(left, right);
    const arrivalLeft = stream.arrivals.find((arrival) => arrival.tuple?.sourceEventId === left.sourceEventId);
    const arrivalRight = stream.arrivals.find((arrival) => arrival.tuple?.sourceEventId === right.sourceEventId);
    if (arrivalLeft && arrivalRight && arrivalLeft.arrivalOrder > arrivalRight.arrivalOrder && authoritative < 0) {
      // Arrival reversed but authoritative order is correct: proves arrival is
      // not the only order.
      return true;
    }
  }
  return false;
}

/** Approval is not duplicated by fanout mapping: same sourceEventId once per client. */
export function approvalNotDuplicatedByFanout(sourceEventIds: string[]): boolean {
  const seen = new Set<string>();
  for (const id of sourceEventIds) {
    if (seen.has(id)) return false;
    seen.add(id);
  }
  return true;
}
