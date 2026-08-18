/**
 * Bounded NDJSON JSON-RPC client for the Codex Exact-Release PoC.
 *
 * Speaks one JSON object per line (exact-release stdio/unix app-server).
 * Never auto-answers server requests (approval/blocking). Research-only;
 * never part of the production import graph.
 */

import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';

import { REVIEWED_SCHEMA_SURFACE } from './schema-inventory';

export const POC_CLIENT_INFO = Object.freeze({ name: 'ariava-poc', version: '0.0.0' });

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcMessage {
  jsonrpc?: '2.0';
  id?: string | number | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: JsonRpcError;
}

export function encodeNdjson(value: unknown): string {
  return `${JSON.stringify(value)}\n`;
}

/** Real unix-socket JSON-RPC lines may exceed the fake 64KiB NDJSON bound. */
export const MAX_JSONRPC_LINE_BYTES = 1024 * 1024;

export function parseNdjsonLine(line: string): { ok: true; message: JsonRpcMessage } | { ok: false; error: string } {
  if (line.length > MAX_JSONRPC_LINE_BYTES) return { ok: false, error: `frame exceeds ${MAX_JSONRPC_LINE_BYTES} bytes` };
  try {
    const parsed: unknown = JSON.parse(line);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { ok: false, error: 'frame must be an object' };
    }
    return { ok: true, message: parsed as JsonRpcMessage };
  } catch {
    return { ok: false, error: 'malformed JSON' };
  }
}

/** Keep only non-sensitive initialize identity fields. Never persist home/host/id. */
export function sanitizeInitializeResult(result: unknown): { protocolVersion?: unknown; userAgent?: { name?: string; version?: string } } {
  if (typeof result !== 'object' || result === null) return {};
  const record = result as Record<string, unknown>;
  const userAgentRaw = record.userAgent;
  const userAgent = typeof userAgentRaw === 'string'
    ? { version: userAgentRaw }
    : typeof userAgentRaw === 'object' && userAgentRaw !== null
    ? {
        name: typeof (userAgentRaw as { name?: unknown }).name === 'string' ? (userAgentRaw as { name: string }).name : undefined,
        version: typeof (userAgentRaw as { version?: unknown }).version === 'string' ? (userAgentRaw as { version: string }).version : undefined,
      }
    : undefined;
  return {
    protocolVersion: record.protocolVersion,
    userAgent,
  };
}

export function isServerRequestMethod(method: string): boolean {
  return REVIEWED_SCHEMA_SURFACE.serverRequests.includes(method) ||
    method.endsWith('/requestApproval');
}

export function methodMissingError(error: JsonRpcError | undefined): boolean {
  if (!error) return false;
  if (error.code === -32601) return true;
  return /method not found|unknown method/i.test(error.message);
}

export class NdjsonRpcClient {
  private readonly writable: Writable;
  private nextId = 1;
  private readonly pending = new Map<number, { resolve: (message: JsonRpcMessage) => void; reject: (error: Error) => void }>();
  private readonly responseCounts = new Map<number, number>();
  readonly notifications: JsonRpcMessage[] = [];
  readonly serverRequests: JsonRpcMessage[] = [];
  private closed = false;

  constructor(readable: Readable, writable: Writable) {
    this.writable = writable;
    const lines = createInterface({ input: readable, crlfDelay: Infinity });
    lines.on('line', (line) => {
      const trimmed = line.trim();
      if (trimmed.length === 0) return;
      const parsed = parseNdjsonLine(trimmed);
      if (!parsed.ok) return;
      this.dispatch(parsed.message);
    });
    lines.on('close', () => {
      this.closed = true;
      for (const pending of this.pending.values()) pending.reject(new Error('rpc stream closed'));
      this.pending.clear();
    });
  }

  private dispatch(message: JsonRpcMessage): void {
    if (message.id !== undefined && message.id !== null && (message.result !== undefined || message.error !== undefined)) {
      const id = typeof message.id === 'number' ? message.id : Number(message.id);
      if (Number.isFinite(id)) this.responseCounts.set(id, (this.responseCounts.get(id) ?? 0) + 1);
      const pending = this.pending.get(id);
      if (pending) {
        this.pending.delete(id);
        pending.resolve(message);
        return;
      }
    }
    if (typeof message.method === 'string' && message.id !== undefined && message.id !== null && message.result === undefined && message.error === undefined) {
      // Server-initiated request. Never auto-respond (approval must not be preempted).
      this.serverRequests.push(message);
      return;
    }
    if (typeof message.method === 'string') {
      this.notifications.push(message);
    }
  }

  notify(method: string, params: unknown = {}): void {
    this.writable.write(encodeNdjson({ jsonrpc: '2.0', method, params }));
  }

  writeRaw(text: string): void {
    this.writable.write(text.endsWith('\n') ? text : `${text}\n`);
  }

  responseCountFor(id: number): number {
    return this.responseCounts.get(id) ?? 0;
  }

  request(method: string, params: unknown = {}, timeoutMs = 8_000): Promise<JsonRpcMessage> {
    const id = this.nextId;
    this.nextId += 1;
    return this.requestWithId(id, method, params, timeoutMs);
  }

  requestWithId(id: number, method: string, params: unknown = {}, timeoutMs = 8_000): Promise<JsonRpcMessage> {
    if (this.closed) return Promise.reject(new Error('rpc stream closed'));
    if (id >= this.nextId) this.nextId = id + 1;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`rpc timeout for ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (message) => {
          clearTimeout(timer);
          resolve(message);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      this.writable.write(encodeNdjson({ jsonrpc: '2.0', id, method, params }));
    });
  }

  async initialize(timeoutMs = 8_000): Promise<JsonRpcMessage> {
    const response = await this.request('initialize', { clientInfo: POC_CLIENT_INFO }, timeoutMs);
    this.notify('initialized');
    return response;
  }
}
