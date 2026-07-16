import { describe, expect, test } from 'bun:test';
import {
  COMMAND_TYPES,
  SESSION_HANDLE_ACTIONS,
  HOST_PLATFORMS,
  LINK_REVOKE_REASONS,
  formatPairingCode,
  isCommandExpired,
  isHostPlatform,
  isUserVisibleActionableAlert,
  normalizeMarkSessionReadRequest,
  normalizePairingCode,
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

  test('normalizes the approved Crockford pairing form', () => {
    expect(normalizePairingCode('abcd-efgh')).toBe('ABCDEFGH');
    expect(formatPairingCode('ABCDEFGH')).toBe('ABCD-EFGH');
    expect(() => normalizePairingCode('ABCI-EFGH')).toThrow('exactly 8 Crockford symbols');
    for (const invalid of ['AB-CD-EFGH', 'ABCDEFG-H', 'ABCD--EFGH', ' ABCD-EFGH', 'ABCD-EFGH ']) expect(() => normalizePairingCode(invalid)).toThrow();
  });

  test('keeps canonical actionable event behavior public', () => {
    expect(isUserVisibleActionableAlert({ ...baseEvent, type: 'blocked' })).toBe(true);
    expect(isUserVisibleActionableAlert({ ...baseEvent, type: 'driver_error' })).toBe(false);
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
