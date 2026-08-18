/**
 * Deterministic fake app-server for the Codex Exact-Release Capability PoC
 * (spec §8.1).
 *
 * Implements the bounded JSON-RPC/notification surface the harness needs to
 * exercise client framing/parsing and experiment drivers without a real Codex
 * binary:
 *   - initialize/initialized
 *   - thread list/read (exact-release equivalent)
 *   - loaded/unloaded
 *   - turn start/steer/interrupt
 *   - turn/item completion and error notifications
 *   - approval/blocking server requests
 *   - daemon version/status
 *
 * The fake is deterministic (no randomness), in-memory, and research-only. It
 * is never part of the production import graph. It enforces bounded frame
 * size, message depth, pending-request queue, per-thread buffer, and rate
 * limits, and it fails closed when an unknown authority-changing
 * request/notification would otherwise be accepted (spec §8.1).
 */

import { createHash } from 'node:crypto';
import { jcs } from './jcs';

/** Bounded frame size (bytes of serialized JSON). */
export const MAX_FRAME_BYTES = 64 * 1024;

/** Bounded JSON message depth (nested arrays/objects). */
export const MAX_MESSAGE_DEPTH = 16;

/** Bounded pending-request queue per client. */
export const MAX_PENDING_REQUESTS = 128;

/** Bounded per-thread event buffer (events retained before replay). */
export const MAX_PER_THREAD_BUFFER = 512;

/** Bounded notifications per second per client (rate limit). */
export const MAX_NOTIFICATIONS_PER_SECOND = 256;

/** Bounded threads per app-server instance. */
export const MAX_THREADS = 4096;

/** Reviewed app-server methods (spec §8.1). */
export const FAKE_METHODS = [
  'initialize',
  'thread.list',
  'thread.read',
  'turn.start',
  'turn.steer',
  'turn.interrupt',
  'daemon.version',
  'daemon.status',
] as const;

/** Reviewed notifications (spec §8.1). */
export const FAKE_NOTIFICATIONS = [
  'initialized',
  'loaded',
  'unloaded',
  'turn.item.completed',
  'turn.completed',
  'turn.error',
  'approval.request',
] as const;

/** Reviewed server requests (spec §8.1). */
export const FAKE_SERVER_REQUESTS = [
  'approval.request',
] as const;

export type FakeMethod = (typeof FAKE_METHODS)[number];
export type FakeNotification = (typeof FAKE_NOTIFICATIONS)[number];
export type FakeServerRequest = (typeof FAKE_SERVER_REQUESTS)[number];

/** A request/response or notification frame on the wire. */
export interface WireFrame {
  /** JSON-RPC request id (null for notifications). */
  id: string | number | null;
  method: string;
  params: Record<string, unknown> | unknown[];
  /** True when this frame is a notification (no response expected). */
  isNotification?: boolean;
  /** True when this frame is a server-initiated request (approval). */
  isServerRequest?: boolean;
  /** For responses: correlation to the request id. */
  result?: unknown;
  error?: { code: number; message: string };
}

export interface ParseResult {
  ok: boolean;
  frames: WireFrame[];
  error?: string;
  errorCode?: string;
}

export interface FakeThread {
  threadId: string;
  title: string;
  cwd: string;
  loaded: boolean;
  /** Authoritative generation counter (increments on app-server restart). */
  generation: number;
  /** Monotonic authoritative event order for this thread. */
  eventOrder: number;
  /** Events retained for authoritative replay (bounded). */
  eventBuffer: EventRecord[];
  turnState: 'idle' | 'working' | 'awaiting-approval';
}

export interface EventRecord {
  threadId: string;
  generation: number;
  order: number;
  type: string;
  /** Source event id (stable, unique per event). */
  sourceEventId: string;
  timestampMs: number;
  payload: Record<string, unknown>;
}

export interface FakeClientState {
  clientId: string;
  connected: boolean;
  pendingRequests: Map<string | number, { method: string; sentAtMs: number }>;
  /** Monotonic local notification counter (arrival order, not authoritative). */
  arrivalOrder: number;
  /** Requests observed by this client (for correlation isolation). */
  seenRequestIds: Set<string>;
  /** Notification rate window (timestamps). */
  notificationWindowMs: number[];
}

export interface FakeAppServerOptions {
  /** Maximum threads (default MAX_THREADS). */
  maxThreads?: number;
  /** Maximum pending requests per client. */
  maxPendingRequests?: number;
  /** Maximum per-thread event buffer. */
  maxPerThreadBuffer?: number;
  /** Whether the fake auto-increments generation on restart. */
  autoGeneration?: boolean;
  /** Simulated server latency (ms) before responses. */
  latencyMs?: number;
}

export interface FakeAppServer {
  /** Start the server; returns a client handle (deterministic). */
  start(): string;
  stop(): void;
  /** Client lifecycle. */
  connect(clientId: string): FakeClientState;
  disconnect(clientId: string): void;
  /** Handle a raw wire frame from a client. */
  handleFrame(clientId: string, raw: string): ParseResult;
  /** Encode a frame to a wire string (for framing tests). */
  encodeFrame(frame: WireFrame): string;
  /** Inspect server state. */
  threads(): FakeThread[];
  getThread(threadId: string): FakeThread | undefined;
  getClient(clientId: string): FakeClientState | undefined;
  /** Notifications the server has emitted to a client (arrival order). */
  emittedNotifications(clientId: string): EventRecord[];
  /** Authoritative replay for a thread (read/replay repair). */
  replayThread(threadId: string, clientId: string): EventRecord[];
  /** Simulate app-server restart (generation++). */
  restart(): void;
  /** Create a thread deterministically. */
  createThread(title: string, cwd: string): FakeThread;
  /** Current generation. */
  generation(): number;
}

function jsonDepth(value: unknown, depth = 0): number {
  if (depth > MAX_MESSAGE_DEPTH) return depth;
  if (Array.isArray(value)) {
    let max = depth + 1;
    for (const entry of value) max = Math.max(max, jsonDepth(entry, depth + 1));
    return max;
  }
  if (typeof value === 'object' && value !== null) {
    let max = depth + 1;
    for (const entry of Object.values(value)) max = Math.max(max, jsonDepth(entry, depth + 1));
    return max;
  }
  return depth;
}

function failClosed(error: string): ParseResult {
  return { ok: false, frames: [], error, errorCode: 'fail-closed' };
}

/** Create a deterministic fake app-server instance. */
export function createFakeAppServer(options: FakeAppServerOptions = {}): FakeAppServer {
  const maxThreads = options.maxThreads ?? MAX_THREADS;
  const maxPendingRequests = options.maxPendingRequests ?? MAX_PENDING_REQUESTS;
  const maxPerThreadBuffer = options.maxPerThreadBuffer ?? MAX_PER_THREAD_BUFFER;
  const latencyMs = options.latencyMs ?? 0;
  let generation = 1;
  let serverEventCounter = 0;
  const threads = new Map<string, FakeThread>();
  const clients = new Map<string, FakeClientState>();
  const emittedByClient = new Map<string, EventRecord[]>();
  const disconnectedClients = new Set<string>();

  const nextSourceEventId = (): string => {
    serverEventCounter += 1;
    // Stable, deterministic, opaque source event id (no raw thread content).
    return `evt-${generation}-${serverEventCounter.toString(36)}`;
  };

  const emit = (clientId: string, record: EventRecord): void => {
    const client = clients.get(clientId);
    if (!client || !client.connected) return;
    const list = emittedByClient.get(clientId) ?? [];
    list.push(record);
    emittedByClient.set(clientId, list);
    client.arrivalOrder += 1;
    client.notificationWindowMs.push(record.timestampMs);
    client.notificationWindowMs = client.notificationWindowMs.filter((ts) => record.timestampMs - ts <= 1000);
    if (client.notificationWindowMs.length > MAX_NOTIFICATIONS_PER_SECOND) {
      // Rate limit: drop the oldest notification (bounded behavior).
      client.notificationWindowMs.shift();
    }
  };

  const emitToAll = (record: EventRecord): void => {
    for (const clientId of clients.keys()) emit(clientId, record);
  };

  const pushEvent = (threadId: string, type: string, payload: Record<string, unknown>): EventRecord => {
    const thread = threads.get(threadId);
    if (!thread) throw new Error(`fake app-server: unknown thread ${threadId}`);
    thread.eventOrder += 1;
    const record: EventRecord = {
      threadId,
      generation: thread.generation,
      order: thread.eventOrder,
      type,
      sourceEventId: nextSourceEventId(),
      timestampMs: Date.now(),
      payload,
    };
    thread.eventBuffer.push(record);
    if (thread.eventBuffer.length > maxPerThreadBuffer) {
      thread.eventBuffer.splice(0, thread.eventBuffer.length - maxPerThreadBuffer);
    }
    return record;
  };

  const replay = (threadId: string, clientId: string): EventRecord[] => {
    const thread = threads.get(threadId);
    if (!thread) return [];
    const records = [...thread.eventBuffer];
    for (const record of records) emit(clientId, record);
    return records;
  };

  const handleRequest = (clientId: string, frame: WireFrame): ParseResult => {
    const client = clients.get(clientId);
    if (!client || !client.connected) return failClosed(`client ${clientId} not connected`);

    if (frame.id === null || frame.id === undefined) {
      // Notifications from client: no response expected. Only allow known methods.
      if (!FAKE_METHODS.includes(frame.method as FakeMethod)) {
        return failClosed(`unknown client notification method ${frame.method}`);
      }
      return { ok: true, frames: [] };
    }

    if (client.pendingRequests.size >= maxPendingRequests) {
      return failClosed('pending request queue full');
    }

    // Record pending request for correlation (bounded queue).
    client.pendingRequests.set(frame.id, { method: frame.method, sentAtMs: Date.now() });
    client.seenRequestIds.add(String(frame.id));

    // Dispatch known methods.
    switch (frame.method) {
      case 'initialize': {
        emit(clientId, {
          threadId: '',
          generation,
          order: 0,
          type: 'initialized',
          sourceEventId: nextSourceEventId(),
          timestampMs: Date.now(),
          payload: { protocolVersion: 1 },
        });
        return { ok: true, frames: [{ id: frame.id, method: 'initialize', params: {}, result: { protocolVersion: 1 } }] };
      }
      case 'thread.list': {
        const list = [...threads.values()].map((thread) => ({ threadId: thread.threadId, title: thread.title, cwd: thread.cwd, loaded: thread.loaded, generation: thread.generation }));
        return { ok: true, frames: [{ id: frame.id, method: 'thread.list', params: {}, result: { threads: list } }] };
      }
      case 'thread.read': {
        const params = frame.params as { threadId?: string };
        const threadId = params?.threadId ?? '';
        const thread = threads.get(threadId);
        if (!thread) return failClosed(`unknown thread ${threadId}`);
        return {
          ok: true,
          frames: [{
            id: frame.id,
            method: 'thread.read',
            params: {},
            result: {
              threadId: thread.threadId,
              generation: thread.generation,
              loaded: thread.loaded,
              events: thread.eventBuffer.map((record) => ({ order: record.order, type: record.type, sourceEventId: record.sourceEventId })),
            },
          }],
        };
      }
      case 'turn.start':
      case 'turn.steer':
      case 'turn.interrupt': {
        const params = frame.params as { threadId?: string };
        const threadId = params?.threadId ?? '';
        const thread = threads.get(threadId);
        if (!thread) return failClosed(`unknown thread ${threadId}`);
        if (frame.method === 'turn.interrupt' && thread.turnState === 'idle') {
          return failClosed('cannot interrupt an idle turn');
        }
        if (frame.method === 'turn.start' && thread.turnState !== 'idle') {
          return failClosed('cannot start a turn while working');
        }
        const record = pushEvent(threadId, `turn.${frame.method.slice(5)}`, { requested: true });
        thread.turnState = frame.method === 'turn.interrupt' ? 'idle' : 'working';
        emitToAll(record);
        return { ok: true, frames: [{ id: frame.id, method: frame.method, params: {}, result: { threadId, generation: thread.generation, eventOrder: record.order } }] };
      }
      case 'daemon.version': {
        return { ok: true, frames: [{ id: frame.id, method: 'daemon.version', params: {}, result: { version: '0.0.0-fake' } }] };
      }
      case 'daemon.status': {
        return { ok: true, frames: [{ id: frame.id, method: 'daemon.status', params: {}, result: { running: true, generation } }] };
      }
      default:
        return failClosed(`unknown method ${frame.method}`);
    }
  };

  const handleServerRequest = (clientId: string, frame: WireFrame): ParseResult => {
    // Server requests (approval/blocking) from the server to the client: the
    // authoritative client must not be preempted by an observer (spec §8.5).
    // The fake only emits these to the authoritative client; an observer that
    // tries to respond is rejected (fail closed).
    if (frame.method !== 'approval.request') {
      return failClosed(`unknown server request ${frame.method}`);
    }
    emit(clientId, {
      threadId: String(frame.params?.threadId ?? ''),
      generation,
      order: 0,
      type: 'approval.request',
      sourceEventId: nextSourceEventId(),
      timestampMs: Date.now(),
      payload: { requestId: frame.id },
    });
    return { ok: true, frames: [] };
  };

  const server: FakeAppServer = {
    start(): string {
      // Deterministic server id.
      return `fake-app-server-${generation}`;
    },
    stop(): void {
      threads.clear();
      clients.clear();
      emittedByClient.clear();
    },
    connect(clientId: string): FakeClientState {
      let client = clients.get(clientId);
      if (!client) {
        client = {
          clientId,
          connected: true,
          pendingRequests: new Map(),
          arrivalOrder: 0,
          seenRequestIds: new Set(),
          notificationWindowMs: [],
        };
        clients.set(clientId, client);
      } else {
        client.connected = true;
      }
      disconnectedClients.delete(clientId);
      // Reconnect: no duplicate side effects; a fresh authoritative snapshot is
      // provided via thread.read (spec §8.3 reconnect/replay).
      return client;
    },
    disconnect(clientId: string): void {
      const client = clients.get(clientId);
      if (client) {
        client.connected = false;
        client.pendingRequests.clear();
        disconnectedClients.add(clientId);
      }
    },
    handleFrame(clientId: string, raw: string): ParseResult {
      if (raw.length > MAX_FRAME_BYTES) {
        return failClosed(`frame exceeds ${MAX_FRAME_BYTES} bytes`);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        return failClosed('malformed JSON');
      }
      if (jsonDepth(parsed) > MAX_MESSAGE_DEPTH) {
        return failClosed(`message depth exceeds ${MAX_MESSAGE_DEPTH}`);
      }
      const parsedFrames = Array.isArray(parsed) ? parsed : [parsed];
      const results: ParseResult[] = [];
      for (const candidate of parsedFrames) {
        if (typeof candidate !== 'object' || candidate === null) {
          results.push(failClosed('frame must be an object'));
          continue;
        }
        const frame = candidate as Record<string, unknown>;
        if (typeof frame.method !== 'string' || frame.method.length === 0) {
          results.push(failClosed('frame missing method'));
          continue;
        }
        if (frame.id !== undefined && frame.id !== null && typeof frame.id !== 'string' && typeof frame.id !== 'number') {
          results.push(failClosed('frame id must be string|number|null'));
          continue;
        }
        // Duplicate ID: a response with an unknown/duplicate id must not be
        // accepted as a commit (spec §8.4 correlation).
        if (typeof frame.id === 'string' || typeof frame.id === 'number') {
          const client = clients.get(clientId);
          if (client?.pendingRequests.has(frame.id) && frame.result !== undefined) {
            // Duplicate response for an already-resolved id: fail closed.
            results.push(failClosed(`duplicate response id ${String(frame.id)}`));
            continue;
          }
        }
        const wire: WireFrame = {
          id: (frame.id as string | number | null) ?? null,
          method: frame.method as string,
          params: (frame.params ?? {}) as Record<string, unknown> | unknown[],
          isNotification: frame.id === undefined || frame.id === null,
          isServerRequest: frame.isServerRequest === true || FAKE_SERVER_REQUESTS.includes(frame.method as FakeServerRequest),
          result: frame.result,
          error: frame.error as { code: number; message: string } | undefined,
        };
        if (wire.isServerRequest && !wire.isNotification) {
          results.push(handleServerRequest(clientId, wire));
          continue;
        }
        if (wire.isNotification) {
          results.push({ ok: true, frames: [] });
          continue;
        }
        results.push(handleRequest(clientId, wire));
      }
      const ok = results.every((result) => result.ok);
      const frames = results.flatMap((result) => result.frames);
      const error = results.find((result) => !result.ok)?.error;
      const errorCode = results.find((result) => !result.ok)?.errorCode;
      return ok
        ? { ok, frames }
        : { ok, frames, error, errorCode };
    },
    encodeFrame(frame: WireFrame): string {
      const payload: Record<string, unknown> = {
        id: frame.id,
        method: frame.method,
        params: frame.params,
      };
      if (frame.result !== undefined) payload.result = frame.result;
      if (frame.error !== undefined) payload.error = frame.error;
      return jcs(payload as Parameters<typeof jcs>[0]);
    },
    threads(): FakeThread[] {
      return [...threads.values()];
    },
    getThread(threadId: string): FakeThread | undefined {
      return threads.get(threadId);
    },
    getClient(clientId: string): FakeClientState | undefined {
      return clients.get(clientId);
    },
    emittedNotifications(clientId: string): EventRecord[] {
      return emittedByClient.get(clientId) ?? [];
    },
    replayThread(threadId: string, clientId: string): EventRecord[] {
      return replay(threadId, clientId);
    },
    restart(): void {
      generation += 1;
      // Preserve threads (identity survives restart) but bump their generation.
      for (const thread of threads.values()) {
        thread.generation = generation;
        thread.loaded = false;
        thread.turnState = 'idle';
      }
      // Server-initiated notifications after restart reflect the new generation.
    },
    createThread(title: string, cwd: string): FakeThread {
      if (threads.size >= maxThreads) throw new Error('fake app-server: max threads reached');
      // Stable, well-formed, opaque thread identity (spec §8.2): distinct per
      // title/cwd pair, never derived from user content.
      const threadId = createHash('sha256').update(`fake:${title}:${cwd}:${generation}`).digest('hex').slice(0, 24);
      const thread: FakeThread = {
        threadId,
        title,
        cwd,
        loaded: true,
        generation,
        eventOrder: 0,
        eventBuffer: [],
        turnState: 'idle',
      };
      threads.set(threadId, thread);
      emitToAll({
        threadId,
        generation,
        order: 0,
        type: 'loaded',
        sourceEventId: nextSourceEventId(),
        timestampMs: Date.now(),
        payload: { title },
      });
      return thread;
    },
    generation(): number {
      return generation;
    },
  };

  return server;
}

/** Canonical JSON-RPC framing validation (spec §8.1 negative cases). */
export function validateFrameShape(frame: WireFrame): { ok: boolean; reason?: string } {
  if (frame.method.length === 0) return { ok: false, reason: 'empty method' };
  if (!FAKE_METHODS.includes(frame.method as FakeMethod) && !FAKE_NOTIFICATIONS.includes(frame.method as FakeNotification) && !FAKE_SERVER_REQUESTS.includes(frame.method as FakeServerRequest)) {
    return { ok: false, reason: `unknown method ${frame.method}` };
  }
  return { ok: true };
}
