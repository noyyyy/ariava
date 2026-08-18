/**
 * Default-home unix/WebSocket handshake probes for the Desktop PoC.
 * Hashes thread/event ids; never returns raw ids for artifact storage.
 */
import { createHash } from 'node:crypto';

import {
  approvalNotDuplicatedByFanout,
  arrivalTimeIsNotOnlyOrder,
  createEventStream,
  detectGaps,
  hasCompleteSetAuthority,
  recordArrival,
  recordEvent,
  repairFromAuthoritative,
  type EventSourceTuple,
} from './event-ordering';

export function hashOpaqueId(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function threadIdsFromListResult(result: unknown): string[] {
  if (typeof result !== 'object' || result === null) return [];
  const record = result as Record<string, unknown>;
  const list = Array.isArray(record.data)
    ? record.data
    : Array.isArray(record.threads)
      ? record.threads
      : Array.isArray(record.items)
        ? record.items
        : [];
  const ids: string[] = [];
  for (const item of list) {
    if (typeof item === 'string') {
      ids.push(item);
      continue;
    }
    if (!item || typeof item !== 'object') continue;
    const row = item as Record<string, unknown>;
    const id = typeof row.threadId === 'string' ? row.threadId : typeof row.id === 'string' ? row.id : undefined;
    if (id) ids.push(id);
  }
  return ids;
}

export function hashedThreadSet(ids: string[]): string[] {
  return [...new Set(ids.map((id) => hashOpaqueId(id)))].sort();
}

export const POC_TEXT_INPUT = Object.freeze([{ type: 'text' as const, text: 'status' }]);

export function nestedStringId(value: unknown, path: readonly string[]): string | undefined {
  let current: unknown = value;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'string' && current.length > 0 ? current : undefined;
}

export function threadIdFromStartResult(result: unknown): string | undefined {
  return nestedStringId(result, ['thread', 'id'])
    ?? nestedStringId(result, ['thread', 'threadId'])
    ?? nestedStringId(result, ['threadId']);
}

export function turnIdFromStartResult(result: unknown): string | undefined {
  return nestedStringId(result, ['turn', 'id'])
    ?? nestedStringId(result, ['turn', 'turnId'])
    ?? nestedStringId(result, ['turnId']);
}

export function turnIdFromNotificationParams(params: unknown): string | undefined {
  return nestedStringId(params, ['turn', 'id'])
    ?? nestedStringId(params, ['turn', 'turnId'])
    ?? nestedStringId(params, ['turnId']);
}

export function isRequestApprovalMethod(method: string | undefined): boolean {
  return typeof method === 'string' && method.endsWith('/requestApproval');
}

export interface NotificationMessage {
  method?: string;
  id?: string | number | null;
  params?: unknown;
}

function notificationFingerprint(message: NotificationMessage, index: number): string {
  const nested = nestedStringId(message.params, ['turn', 'id'])
    ?? nestedStringId(message.params, ['item', 'id'])
    ?? nestedStringId(message.params, ['id'])
    ?? '';
  return `${message.method ?? ''}:${String(message.id ?? '')}:${nested}:${index}`;
}

/** Map JSON-RPC notifications of one exact-release commit type into hashed events. */
export function commitEventsFromNotifications(
  messages: readonly NotificationMessage[],
  expectedType: string,
  generation = 1,
): Array<{ sourceEventId: string; type: string; generation: number; order: number }> {
  const events: Array<{ sourceEventId: string; type: string; generation: number; order: number }> = [];
  for (let index = 0; index < messages.length; index += 1) {
    const message = messages[index];
    if (!message || message.method !== expectedType) continue;
    events.push({
      sourceEventId: hashOpaqueId(notificationFingerprint(message, index)),
      type: expectedType,
      generation,
      order: index + 1,
    });
  }
  return events;
}

/** Exact-release `thread/read` needs this to populate `turns[].items`. */
export const THREAD_READ_WITH_TURNS = Object.freeze({ includeTurns: true as const });

function threadRecord(result: unknown): Record<string, unknown> | undefined {
  if (!result || typeof result !== 'object') return undefined;
  const record = result as Record<string, unknown>;
  if (record.thread && typeof record.thread === 'object' && !Array.isArray(record.thread)) {
    return record.thread as Record<string, unknown>;
  }
  return record;
}

function itemsFromTurns(result: unknown): Record<string, unknown>[] {
  const thread = threadRecord(result);
  const turns = Array.isArray(thread?.turns) ? thread.turns : [];
  const items: Record<string, unknown>[] = [];
  for (const turn of turns) {
    if (!turn || typeof turn !== 'object' || Array.isArray(turn)) continue;
    const nested = (turn as { items?: unknown }).items;
    if (!Array.isArray(nested)) continue;
    for (const item of nested) {
      if (item && typeof item === 'object' && !Array.isArray(item)) items.push(item as Record<string, unknown>);
    }
  }
  return items;
}

function tupleFromRow(rawThreadId: string, row: Record<string, unknown>, index: number): EventSourceTuple {
  const rawId = typeof row.id === 'string'
    ? row.id
    : typeof row.eventId === 'string'
      ? row.eventId
      : `idx:${index}`;
  const type = typeof row.type === 'string'
    ? row.type
    : typeof row.kind === 'string'
      ? row.kind
      : 'item';
  return {
    rawThreadId,
    sourceEventId: hashOpaqueId(rawId),
    type,
    providerGeneration: typeof row.generation === 'number' ? row.generation : 1,
    authoritativeOrder: index + 1,
  };
}

function collectObjectArrays(value: unknown, key?: string, found: unknown[][] = []): unknown[][] {
  if (Array.isArray(value)) {
    if (
      value.length > 0 &&
      value.every((entry) => entry && typeof entry === 'object' && !Array.isArray(entry)) &&
      (key === 'events' || key === 'items' || key === 'turns' || key === 'messages' || key === 'data' || key === undefined)
    ) {
      found.push(value);
    }
    for (const entry of value) collectObjectArrays(entry, key, found);
    return found;
  }
  if (value && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) {
      collectObjectArrays(child, childKey, found);
    }
  }
  return found;
}

export function eventTuplesFromRead(rawThreadId: string, result: unknown): EventSourceTuple[] {
  const fromTurns = itemsFromTurns(result);
  if (fromTurns.length >= 2) {
    return fromTurns.slice(0, 32).map((row, index) => tupleFromRow(rawThreadId, row, index));
  }
  const arrays = collectObjectArrays(result).sort((left, right) => right.length - left.length);
  const chosen = arrays[0] ?? [];
  return chosen.slice(0, 32).map((item, index) => tupleFromRow(rawThreadId, item as Record<string, unknown>, index));
}

export function proveEventOrdering(rawThreadId: string, tuples: EventSourceTuple[]): {
  sourceStable: boolean;
  comparable: boolean;
  duplicate: boolean;
  repair: boolean;
  arrival: boolean;
  complete: boolean;
  fanoutNoDup: boolean;
} {
  const empty = {
    sourceStable: false,
    comparable: false,
    duplicate: false,
    repair: false,
    arrival: false,
    complete: false,
    fanoutNoDup: false,
  };
  if (tuples.length < 2 || tuples.some((tuple) => tuple.rawThreadId !== rawThreadId)) return empty;
  const stream = createEventStream(rawThreadId);
  for (const tuple of tuples) recordEvent(stream, tuple);
  const duplicate = recordEvent(stream, tuples[0]!) === 'duplicate';
  const comparable = detectGaps(stream).length === 0;
  const partial = createEventStream(rawThreadId);
  recordEvent(partial, tuples[0]!);
  const repair = repairFromAuthoritative(partial, tuples) >= 1 && hasCompleteSetAuthority(partial, tuples);
  const reversed = createEventStream(rawThreadId);
  for (const tuple of tuples) recordEvent(reversed, tuple);
  [...tuples].reverse().forEach((tuple, index) => {
    recordArrival(reversed, { sourceEventId: tuple.sourceEventId, arrivedAtMs: index, tuple });
  });
  return {
    sourceStable: true,
    comparable,
    duplicate,
    repair,
    arrival: arrivalTimeIsNotOnlyOrder(reversed),
    complete: hasCompleteSetAuthority(stream, tuples),
    fanoutNoDup: approvalNotDuplicatedByFanout(tuples.map((tuple) => tuple.sourceEventId)),
  };
}
