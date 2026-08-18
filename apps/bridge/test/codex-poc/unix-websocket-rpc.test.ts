import { describe, expect, test } from 'bun:test';
import { PassThrough } from 'node:stream';

import { encodeNdjson, NdjsonRpcClient } from './app-server-rpc';
import {
  encodeMaskedTextFrame,
  WebsocketFrameParser,
} from './unix-websocket-rpc';

function unmaskFrame(frame: Buffer): { opcode: number; payload: Buffer } {
  const opcode = frame[0]! & 0x0f;
  const masked = (frame[1]! & 0x80) !== 0;
  let length = frame[1]! & 0x7f;
  let offset = 2;
  if (length === 126) {
    length = frame.readUInt16BE(offset);
    offset += 2;
  }
  const mask = masked ? frame.subarray(offset, offset + 4) : Buffer.alloc(0);
  if (masked) offset += 4;
  const payload = Buffer.allocUnsafe(length);
  const body = frame.subarray(offset, offset + length);
  if (masked) {
    for (let i = 0; i < length; i += 1) payload[i] = body[i]! ^ mask[i % 4]!;
  } else {
    body.copy(payload);
  }
  return { opcode, payload };
}

describe('unix websocket JSON-RPC framing', () => {
  test('masked text frames decode back to the original JSON payload', () => {
    const payload = '{"jsonrpc":"2.0","id":1,"method":"initialize"}';
    const frame = encodeMaskedTextFrame(payload);
    expect(frame[0]).toBe(0x81);
    expect((frame[1]! & 0x80) !== 0).toBe(true);
    const parsed = unmaskFrame(frame);
    expect(parsed.opcode).toBe(0x1);
    expect(parsed.payload.toString('utf8')).toBe(payload);
  });

  test('parser accepts unmasked server text frames used after upgrade', () => {
    const payload = Buffer.from('{"jsonrpc":"2.0","id":1,"result":{}}', 'utf8');
    const header = Buffer.from([0x81, payload.length]);
    const parser = new WebsocketFrameParser();
    const frames = parser.push(Buffer.concat([header, payload]));
    expect(frames).toHaveLength(1);
    expect(frames[0]?.opcode).toBe(0x1);
    expect(frames[0]?.payload.toString('utf8')).toContain('"result"');
  });

  test('NdjsonRpcClient can speak JSON-RPC after websocket payloads are re-lined', async () => {
    const readable = new PassThrough();
    const writable = new PassThrough();
    const client = new NdjsonRpcClient(readable, writable);
    const pending = client.request('thread/list', {});
    readable.write(encodeNdjson({ jsonrpc: '2.0', id: 1, result: { data: [], nextCursor: null } }));
    const response = await pending;
    expect(response.result).toEqual({ data: [], nextCursor: null });
  });
});
