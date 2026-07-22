import { describe, expect, test } from 'bun:test';
import {
  COMMAND_TYPES,
  SESSION_HANDLE_ACTIONS,
  SESSION_STATUSES,
  HOST_PLATFORMS,
  LINK_REVOKE_REASONS,
  formatPairingCode,
  isCommandExpired,
  isHostPlatform,
  isUserVisibleActionableAlert,
  normalizeMarkSessionReadRequest,
  normalizePairingCode,
  statusToStateLabel,
  validateCommandType,
  type CanonicalEvent,
  type MarkSessionReadRequest,
  type SessionReadSource,
  type SessionHandleAction,
} from '../src';

const baseEvent: CanonicalEvent = {
  eventId: 'evt_1', hostId: 'host_1', sessionId: 'sess_1', provider: 'pi', type: 'blocked', status: 'blocked',
  typeLabel: 'Session blocked', assistantText: 'Needs help', createdAt: '2026-06-28T10:00:00Z',
};

describe('protocol helpers', () => {
  test('preserves the narrow signed-HTTP command surface', () => {
    expect(COMMAND_TYPES).toEqual(['reply', 'interrupt']);
    expect(validateCommandType('reply')).toBe(true);
    expect(validateCommandType('shell')).toBe(false);
    expect(isCommandExpired({ expiresAt: '2026-06-28T09:59:59Z' }, new Date('2026-06-28T10:00:00Z'))).toBe(true);
  });

  test('exposes v2 Host platforms and link constants', () => {
    expect(HOST_PLATFORMS).toEqual(['macos', 'linux']);
    expect(isHostPlatform('macos')).toBe(true);
    expect(isHostPlatform('linux')).toBe(true);
    expect(isHostPlatform('windows')).toBe(false);
    expect(LINK_REVOKE_REASONS).toContain('device_replaced');
  });

  test('normalizes only the six-symbol continuous Crockford pairing form', () => {
    expect(normalizePairingCode('PEYX7K')).toBe('PEYX7K');
    expect(normalizePairingCode('peyx7k')).toBe('PEYX7K');
    expect(formatPairingCode('PEYX7K')).toBe('PEYX7K');
    expect(() => normalizePairingCode('ABCD-EFGH')).toThrow('exactly 6 Crockford symbols');
    for (const invalid of ['PEYX7', 'PEYX7K0', 'ABCDEFGH', 'PEY-X7K', ' PEYX7K', 'PEYX7K ', 'PEYI7K', 'PEYX7ſ']) {
      expect(() => normalizePairingCode(invalid)).toThrow();
    }
  });

  test('keeps canonical actionable event behavior public', () => {
    expect(isUserVisibleActionableAlert({ ...baseEvent, type: 'blocked' })).toBe(true);
    expect(isUserVisibleActionableAlert({ ...baseEvent, type: 'driver_error' })).toBe(false);
  });

  test('keeps idle additive and maps every status to its compatibility label', () => {
    expect(SESSION_STATUSES).toEqual(['idle', 'working', 'blocked', 'done', 'unknown']);
    expect(SESSION_STATUSES.map((status) => [status, statusToStateLabel(status)])).toEqual([
      ['idle', 'Ready'],
      ['working', 'In progress'],
      ['blocked', 'Needs attention'],
      ['done', 'Done'],
      ['unknown', 'Status unavailable'],
    ]);
  });

  test('normalizes current and transitional session read fields', () => {
    const request: MarkSessionReadRequest = { latestReadEventId: 'evt-2', readAt: '2026-07-13T10:00:00.000Z', source: 'pi_local_interaction' };
    expect(normalizeMarkSessionReadRequest(request)).toEqual(request);
    expect(normalizeMarkSessionReadRequest({ latestSeenEventId: 'evt-old', seenAt: '2026-07-13T09:00:00.000Z' })).toEqual({ latestReadEventId: 'evt-old', readAt: '2026-07-13T09:00:00.000Z', source: undefined });
    const source: SessionReadSource = 'watch_view'; expect(source).toBe('watch_view');
    expect(SESSION_HANDLE_ACTIONS).toEqual(['pi_input', 'watch_reply', 'bridge_recovery']);
    const action: SessionHandleAction = 'watch_reply'; expect(action).toBe('watch_reply');
  });
});
