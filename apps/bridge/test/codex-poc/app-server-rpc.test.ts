import { describe, expect, test } from 'bun:test';
import { PassThrough } from 'node:stream';

import {
  encodeNdjson,
  isServerRequestMethod,
  methodMissingError,
  NdjsonRpcClient,
  parseNdjsonLine,
  POC_CLIENT_INFO,
  MAX_JSONRPC_LINE_BYTES,
  sanitizeInitializeResult,
} from './app-server-rpc';

describe('app-server NDJSON RPC', () => {
  test('encodeNdjson is one JSON object per line', () => {
    expect(encodeNdjson({ jsonrpc: '2.0', id: 1, method: 'thread/list' })).toBe('{"jsonrpc":"2.0","id":1,"method":"thread/list"}\n');
  });

  test('parseNdjsonLine accepts objects and rejects malformed or oversized frames', () => {
    expect(parseNdjsonLine('{"id":1,"method":"initialize"}').ok).toBe(true);
    expect(parseNdjsonLine('{not json').ok).toBe(false);
    expect(parseNdjsonLine(`{"padding":"${'x'.repeat(MAX_JSONRPC_LINE_BYTES)}}`).ok).toBe(false);
  });

  test('sanitizeInitializeResult drops home/host/id fields', () => {
    const sanitized = sanitizeInitializeResult({
      protocolVersion: 1,
      userAgent: { name: 'codex_cli.rs', version: '0.148.0-alpha.9' },
      codexHome: '/secret/home/.codex',
      installationId: 'do-not-persist',
      remoteControl: { hostname: 'secret-host' },
    });
    expect(sanitized.protocolVersion).toBe(1);
    expect(sanitized.userAgent).toEqual({ name: 'codex_cli.rs', version: '0.148.0-alpha.9' });
    expect(JSON.stringify(sanitized)).not.toContain('secret');
    expect(JSON.stringify(sanitized)).not.toContain('installationId');
  });

  test('approval server requests are recognized and never auto-classified as missing methods', () => {
    expect(isServerRequestMethod('item/commandExecution/requestApproval')).toBe(true);
    expect(isServerRequestMethod('thread/list')).toBe(false);
    expect(methodMissingError({ code: -32601, message: 'Method not found' })).toBe(true);
    expect(methodMissingError({ code: -32602, message: 'Invalid params' })).toBe(false);
  });

  test('client correlates responses by id and does not answer server requests', async () => {
    const readable = new PassThrough();
    const writable = new PassThrough();
    const written: string[] = [];
    writable.on('data', (chunk: Buffer) => written.push(chunk.toString('utf8')));
    const client = new NdjsonRpcClient(readable, writable);

    const pending = client.request('thread/list', {});
    await new Promise((resolve) => setTimeout(resolve, 10));
    readable.write(encodeNdjson({ jsonrpc: '2.0', method: 'item/fileChange/requestApproval', id: 'srv-1', params: {} }));
    readable.write(encodeNdjson({ jsonrpc: '2.0', id: 1, result: { data: [], nextCursor: null } }));
    const response = await pending;
    expect(response.result).toEqual({ data: [], nextCursor: null });
    expect(client.serverRequests).toHaveLength(1);
    expect(written.some((chunk) => chunk.includes('item/fileChange/requestApproval') && chunk.includes('"result"'))).toBe(false);
    expect(POC_CLIENT_INFO).toEqual({ name: 'ariava-poc', version: '0.0.0' });
  });

  test('writeRaw and duplicate request ids are countable without auto-answering', async () => {
    const readable = new PassThrough();
    const writable = new PassThrough();
    const written: string[] = [];
    writable.on('data', (chunk: Buffer) => written.push(chunk.toString('utf8')));
    const client = new NdjsonRpcClient(readable, writable);
    client.writeRaw('{not json\n');
    const first = client.requestWithId(9, 'thread/list', {});
    await new Promise((resolve) => setTimeout(resolve, 10));
    readable.write(encodeNdjson({ jsonrpc: '2.0', id: 9, result: { data: [] } }));
    readable.write(encodeNdjson({ jsonrpc: '2.0', id: 9, result: { data: [] } }));
    await first;
    expect(client.responseCountFor(9)).toBe(2);
    expect(written.some((chunk) => chunk.includes('{not json'))).toBe(true);
  });
});
