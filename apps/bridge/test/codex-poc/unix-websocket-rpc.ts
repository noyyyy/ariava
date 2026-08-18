/**
 * Unix-socket WebSocket JSON-RPC transport for the Codex Desktop PoC.
 *
 * Exact-release `codex app-server --listen unix://` accepts an HTTP/1.1
 * WebSocket upgrade on `{CODEX_HOME}/app-server-control/app-server-control.sock`.
 * Each JSON-RPC message is one WebSocket text frame (not raw NDJSON).
 * Research-only; never part of the production import graph.
 */

import { randomBytes } from 'node:crypto';
import type { Socket } from 'node:net';
import { PassThrough, Writable } from 'node:stream';

/** Bounded WebSocket text payload. Larger than fake-app-server NDJSON (64KiB). */
export const MAX_WEBSOCKET_PAYLOAD_BYTES = 1024 * 1024;

export function encodeMaskedTextFrame(payload: Buffer | string): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  return encodeMaskedFrame(0x1, data);
}

export function encodeMaskedPongFrame(payload: Buffer): Buffer {
  return encodeMaskedFrame(0xA, payload);
}

function encodeMaskedFrame(opcode: number, data: Buffer): Buffer {
  const mask = randomBytes(4);
  const masked = Buffer.allocUnsafe(data.length);
  for (let i = 0; i < data.length; i += 1) {
    masked[i] = data[i]! ^ mask[i % 4]!;
  }
  const length = data.length;
  let header: Buffer;
  if (length < 126) {
    header = Buffer.allocUnsafe(2 + 4);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | length;
    mask.copy(header, 2);
  } else if (length < 65536) {
    header = Buffer.allocUnsafe(2 + 2 + 4);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(length, 2);
    mask.copy(header, 4);
  } else {
    header = Buffer.allocUnsafe(2 + 8 + 4);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(length), 2);
    mask.copy(header, 10);
  }
  return Buffer.concat([header, masked]);
}

export interface WebsocketFrame {
  opcode: number;
  payload: Buffer;
  fin: boolean;
}

export class WebsocketFrameParser {
  private buffer = Buffer.alloc(0);

  push(chunk: Buffer): WebsocketFrame[] {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const frames: WebsocketFrame[] = [];
    while (this.buffer.length >= 2) {
      const b1 = this.buffer[0]!;
      const b2 = this.buffer[1]!;
      const fin = (b1 & 0x80) !== 0;
      const opcode = b1 & 0x0f;
      const masked = (b2 & 0x80) !== 0;
      let length = b2 & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (this.buffer.length < offset + 2) break;
        length = this.buffer.readUInt16BE(offset);
        offset += 2;
      } else if (length === 127) {
        if (this.buffer.length < offset + 8) break;
        const big = this.buffer.readBigUInt64BE(offset);
        if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
          throw new Error('websocket frame too large');
        }
        length = Number(big);
        offset += 8;
      }
      if (length > MAX_WEBSOCKET_PAYLOAD_BYTES) {
        throw new Error(`websocket payload exceeds ${MAX_WEBSOCKET_PAYLOAD_BYTES} bytes`);
      }
      if (masked) {
        if (this.buffer.length < offset + 4) break;
      }
      const maskOffset = masked ? offset : -1;
      const payloadOffset = masked ? offset + 4 : offset;
      if (this.buffer.length < payloadOffset + length) break;
      let payload = this.buffer.subarray(payloadOffset, payloadOffset + length);
      if (masked) {
        const mask = this.buffer.subarray(maskOffset, maskOffset + 4);
        const decoded = Buffer.allocUnsafe(length);
        for (let i = 0; i < length; i += 1) {
          decoded[i] = payload[i]! ^ mask[i % 4]!;
        }
        payload = decoded;
      } else {
        payload = Buffer.from(payload);
      }
      this.buffer = this.buffer.subarray(payloadOffset + length);
      frames.push({ opcode, payload, fin });
    }
    return frames;
  }
}

export async function upgradeUnixSocketToWebsocket(socket: Socket): Promise<void> {
  const key = randomBytes(16).toString('base64');
  const request = [
    'GET / HTTP/1.1',
    'Host: localhost',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Key: ${key}`,
    'Sec-WebSocket-Version: 13',
    '',
    '',
  ].join('\r\n');

  await new Promise<void>((resolve, reject) => {
    const chunks: Buffer[] = [];
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      const index = buf.indexOf('\r\n\r\n');
      if (index === -1) return;
      cleanup();
      const header = buf.subarray(0, index).toString('latin1');
      if (!/^HTTP\/1\.1 101\b/u.test(header) || !/upgrade:\s*websocket/iu.test(header)) {
        reject(new Error('unix control socket websocket upgrade failed'));
        return;
      }
      const leftover = buf.subarray(index + 4);
      if (leftover.length > 0) socket.unshift(leftover);
      resolve();
    };
    const cleanup = () => {
      socket.off('data', onData);
      socket.off('error', onError);
    };
    socket.on('data', onData);
    socket.once('error', onError);
    socket.write(request);
  });
}

export function websocketToNdjsonDuplex(socket: Socket): { readable: PassThrough; writable: Writable } {
  const readable = new PassThrough();
  const parser = new WebsocketFrameParser();

  const onData = (chunk: Buffer) => {
    try {
      for (const frame of parser.push(chunk)) {
        if (frame.opcode === 0x9) {
          socket.write(encodeMaskedPongFrame(frame.payload));
          continue;
        }
        if (frame.opcode === 0x8) {
          readable.end();
          return;
        }
        if (frame.opcode === 0x1 || frame.opcode === 0x2) {
          const text = frame.payload.toString('utf8');
          readable.write(text.endsWith('\n') ? text : `${text}\n`);
        }
      }
    } catch (error) {
      readable.destroy(error instanceof Error ? error : new Error(String(error)));
    }
  };
  socket.on('data', onData);
  socket.on('end', () => {
    if (!readable.writableEnded) readable.end();
  });
  socket.on('error', (error) => {
    readable.destroy(error);
  });

  const writable = new Writable({
    write(chunk, _encoding, callback) {
      const text = chunk.toString('utf8');
      const lines = text.split('\n').map((line) => line.trim()).filter((line) => line.length > 0);
      try {
        for (const line of lines) {
          socket.write(encodeMaskedTextFrame(line));
        }
        callback();
      } catch (error) {
        callback(error instanceof Error ? error : new Error(String(error)));
      }
    },
  });
  return { readable, writable };
}
