import { describe, expect, test } from 'bun:test';
import {
  validateAgentAdapterCommand,
  validateAgentAdapterCommandResult,
} from '../src/adapter-interface';

const command = {
  commandId: 'cmd-1', hostId: 'host-1', sessionId: 'session-1', type: 'reply',
  payload: { text: 'continue' }, targetAlertEventId: 'event-1',
  issuedAt: '2026-08-12T00:00:00.000Z', expiresAt: '2026-08-12T00:01:00.000Z',
  nonce: 'nonce-1', watchDeviceId: 'watch-1',
} as const;

const rejected = {
  commandId: command.commandId,
  hostId: command.hostId,
  sessionId: command.sessionId,
  accepted: false,
  status: 'rejected',
  updatedAt: '2026-08-12T00:00:01.000Z',
} as const;

describe('Agent Adapter command boundary', () => {
  test('accepts only the closed reply and interrupt command mappings', () => {
    expect(validateAgentAdapterCommand(command)).toBe(true);
    expect(validateAgentAdapterCommand({ ...command, type: 'interrupt', payload: {}, targetAlertEventId: undefined })).toBe(true);
    expect(validateAgentAdapterCommand({ ...command, type: 'shell' })).toBe(false);
    expect(validateAgentAdapterCommand({ ...command, payload: { text: 'continue', raw: 'stdin' } })).toBe(false);
    expect(validateAgentAdapterCommand({ ...command, extra: true })).toBe(false);
    expect(validateAgentAdapterCommand({ ...command, type: 'interrupt', payload: { text: 'stop' } })).toBe(false);
  });

  test('Pi wire results allow executed and deterministic rejected only', () => {
    expect(validateAgentAdapterCommandResult(rejected)).toBe(true);
    expect(validateAgentAdapterCommandResult({ ...rejected, accepted: true, status: 'executed' })).toBe(true);
    expect(validateAgentAdapterCommandResult({ ...rejected, accepted: true, status: 'rejected' })).toBe(false);
    expect(validateAgentAdapterCommandResult({ ...rejected, accepted: false, status: 'executed' })).toBe(false);
    expect(validateAgentAdapterCommandResult({ ...rejected, status: 'failed' })).toBe(false);
    expect(validateAgentAdapterCommandResult({ ...rejected, status: 'expired' })).toBe(false);
    expect(validateAgentAdapterCommandResult({ ...rejected, status: 'outcome_unknown' })).toBe(false);
  });

  test.each([
    ['message', { message: 'private text' }],
    ['reason', { reason: 'private reason' }],
    ['detail', { detail: 'private detail' }],
    ['correlationId', { correlationId: 'correlation-1' }],
    ['noncanonical timestamp', { updatedAt: '2026-08-12T00:00:01Z' }],
  ])('rejects non-exact result: %s', (_label, override) => {
    expect(validateAgentAdapterCommandResult({ ...rejected, ...override })).toBe(false);
  });

  test('rejects inherited, accessor, symbol, and custom-prototype result fields', () => {
    const inherited = Object.create({ reason: 'hidden' });
    Object.assign(inherited, rejected);
    expect(validateAgentAdapterCommandResult(inherited)).toBe(false);
    const accessor = { ...rejected } as Record<string, unknown>;
    Object.defineProperty(accessor, 'status', { enumerable: true, get: () => 'rejected' });
    expect(validateAgentAdapterCommandResult(accessor)).toBe(false);
    const symbol = { ...rejected } as Record<PropertyKey, unknown>;
    symbol[Symbol('private')] = 'private';
    expect(validateAgentAdapterCommandResult(symbol)).toBe(false);
    const custom = { ...rejected };
    Object.setPrototypeOf(custom, { toJSON: () => rejected });
    expect(validateAgentAdapterCommandResult(custom)).toBe(false);
  });
});
