import { describe, expect, test } from 'bun:test';
import {
  validateAgentAdapterCommand,
  validateAgentAdapterCommandResult,
} from '../src/adapter-interface';

const command = {
  commandId: 'cmd-1',
  hostId: 'host-1',
  sessionId: 'session-1',
  type: 'reply',
  payload: { text: 'continue' },
  targetAlertEventId: 'event-1',
  issuedAt: '2026-08-12T00:00:00.000Z',
  expiresAt: '2026-08-12T00:01:00.000Z',
  nonce: 'nonce-1',
  watchDeviceId: 'watch-1',
} as const;

const result = {
  commandId: command.commandId,
  hostId: command.hostId,
  sessionId: command.sessionId,
  accepted: true,
  status: 'executed',
  updatedAt: '2026-08-12T00:00:01.000Z',
} as const;

describe('Agent Adapter command boundary', () => {
  test('accepts only the closed reply and interrupt command mappings', () => {
    expect(validateAgentAdapterCommand(command)).toBe(true);
    expect(validateAgentAdapterCommand({
      ...command,
      type: 'interrupt',
      payload: {},
      targetAlertEventId: undefined,
    })).toBe(true);

    expect(validateAgentAdapterCommand({ ...command, type: 'shell' })).toBe(false);
    expect(validateAgentAdapterCommand({ ...command, payload: { text: 'continue', raw: 'stdin' } })).toBe(false);
    expect(validateAgentAdapterCommand({ ...command, extra: true })).toBe(false);
    expect(validateAgentAdapterCommand({ ...command, type: 'interrupt', payload: { text: 'stop' } })).toBe(false);
  });

  test('accepts exact legal terminal results without a correlation field', () => {
    expect(validateAgentAdapterCommandResult(result)).toBe(true);
    for (const status of ['failed', 'rejected'] as const) {
      expect(validateAgentAdapterCommandResult({ ...result, accepted: false, status })).toBe(true);
    }
  });

  test.each([
    ['message', { message: 'private text' }],
    ['reason', { reason: 'private reason' }],
    ['detail', { detail: 'private detail' }],
    ['error', { error: 'private error' }],
    ['correlationId', { correlationId: 'correlation-1' }],
    ['queued', { status: 'queued' }],
    ['delivered', { status: 'delivered' }],
    ['unknown', { status: 'unknown' }],
    ['expired', { accepted: false, status: 'expired' }],
    ['illegal accepted pair', { accepted: false }],
  ])('rejects non-exact terminal result: %s', (_label, override) => {
    expect(validateAgentAdapterCommandResult({ ...result, ...override })).toBe(false);
  });

  test('rejects inherited, accessor, symbol, and custom-prototype result fields', () => {
    const inherited = Object.create({ reason: 'hidden' });
    Object.assign(inherited, result);
    expect(validateAgentAdapterCommandResult(inherited)).toBe(false);

    const accessor = { ...result } as Record<string, unknown>;
    Object.defineProperty(accessor, 'status', { enumerable: true, get: () => 'executed' });
    expect(validateAgentAdapterCommandResult(accessor)).toBe(false);

    const symbol = { ...result } as Record<PropertyKey, unknown>;
    symbol[Symbol('private')] = 'private';
    expect(validateAgentAdapterCommandResult(symbol)).toBe(false);

    const custom = { ...result };
    Object.setPrototypeOf(custom, { toJSON: () => result });
    expect(validateAgentAdapterCommandResult(custom)).toBe(false);
  });
});
