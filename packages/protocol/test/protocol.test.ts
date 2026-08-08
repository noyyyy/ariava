import { describe, expect, test } from 'bun:test';
import {
  COMMAND_TYPES,
  EVENT_TYPES,
  NEED_HUMAN_ERROR_KINDS,
  NEED_HUMAN_REASONS,
  SESSION_HANDLE_ACTIONS,
  SESSION_STATUSES,
  HOST_PLATFORMS,
  LINK_REVOKE_REASONS,
  formatPairingCode,
  isCommandExpired,
  isHostPlatform,
  isUserVisibleActionableAlert,
  normalizePairingCode,
  validateCanonicalEventInvariant,
  validateEventTypeStatusPair,
  validateCommandType,
  type CanonicalEvent,
  type MarkSessionReadRequest,
  type NeedHumanContext,
  type NeedHumanError,
  type SessionReadSource,
  type SessionHandleAction,
} from '../src';

const baseEvent: CanonicalEvent = {
  eventId: 'evt_1', hostId: 'host_1', sessionId: 'sess_1', provider: 'pi', type: 'need_human', status: 'need_human',
  typeLabel: 'Needs attention', agentText: 'Needs help', needHuman: { reason: 'blocked' }, createdAt: '2026-06-28T10:00:00Z',
};

const validError: NeedHumanError = {
  kind: 'provider_failure',
  message: 'The provider stopped after retries.',
  providerCode: 'rate_limit_exceeded',
  retryExhausted: true,
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

  test('exposes only the canonical event and Session enums', () => {
    expect(EVENT_TYPES).toEqual(['done', 'need_human']);
    expect(SESSION_STATUSES).toEqual(['idle', 'working', 'need_human']);
    expect(NEED_HUMAN_REASONS).toEqual(['question', 'blocked', 'error']);
    expect(NEED_HUMAN_ERROR_KINDS).toEqual([
      'context_overflow', 'provider_failure', 'response_length', 'incomplete_tool_use', 'unknown',
    ]);
    for (const legacy of ['working', 'question_requested', 'blocked', 'driver_error', 'host_unavailable', 'error']) {
      expect((EVENT_TYPES as readonly string[]).includes(legacy)).toBe(false);
    }
    for (const legacy of ['blocked', 'done', 'unknown']) {
      expect((SESSION_STATUSES as readonly string[]).includes(legacy)).toBe(false);
    }
  });

  test('validates exact canonical event type and status pairs at runtime', () => {
    expect(validateEventTypeStatusPair('done', 'idle')).toBe(true);
    expect(validateEventTypeStatusPair('need_human', 'need_human')).toBe(true);
    expect(validateEventTypeStatusPair('done', 'need_human')).toBe(false);
    expect(validateEventTypeStatusPair('need_human', 'idle')).toBe(false);
    expect(validateEventTypeStatusPair('blocked', 'blocked')).toBe(false);
  });

  test('accepts only exact canonical event/status/protected-context combinations', () => {
    const valid: unknown[] = [
      { type: 'done', status: 'idle' },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'question' } },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'blocked' } },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'error', error: validError } },
    ];
    for (const candidate of valid) expect(validateCanonicalEventInvariant(candidate), JSON.stringify(candidate)).toEqual({ success: true, value: candidate, issues: [] });

    const invalid: unknown[] = [
      { type: 'done', status: 'working' },
      { type: 'done', status: 'need_human' },
      { type: 'done', status: 'idle', needHuman: { reason: 'blocked' } },
      { type: 'done', status: 'idle', needHuman: undefined },
      { type: 'need_human', status: 'idle', needHuman: { reason: 'blocked' } },
      { type: 'need_human', status: 'need_human' },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'error' } },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'question', error: validError } },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'blocked', error: validError } },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'blocked', error: undefined } },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'other' } },
      { type: 'working', status: 'working' },
      { type: 'question_requested', status: 'need_human', needHuman: { reason: 'question' } },
      { type: 'blocked', status: 'need_human', needHuman: { reason: 'blocked' } },
      { type: 'driver_error', status: 'need_human', needHuman: { reason: 'error', error: validError } },
      { type: 'host_unavailable', status: 'need_human', needHuman: { reason: 'blocked' } },
      { type: 'error', status: 'need_human', needHuman: { reason: 'error', error: validError } },
      { type: 'done', status: 'idle', extra: true },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'blocked', extra: true } },
      { type: 'need_human', status: 'need_human', needHuman: { reason: 'error', error: { ...validError, extra: true } } },
    ];
    for (const candidate of invalid) expect(validateCanonicalEventInvariant(candidate).success, JSON.stringify(candidate)).toBe(false);
    const symbolCandidate = { type: 'done', status: 'idle', [Symbol('unsupported')]: true };
    expect(validateCanonicalEventInvariant(symbolCandidate).success).toBe(false);
  });

  test('rejects inherited optional invariant fields at every protected level', () => {
    const inheritedNeedHuman = Object.assign(Object.create({ needHuman: { reason: 'blocked' } }), {
      type: 'done', status: 'idle',
    });
    const inheritedContextError = Object.assign(Object.create({ error: validError }), { reason: 'blocked' });
    const inheritedProviderCode = Object.assign(Object.create({ providerCode: '' }), {
      kind: validError.kind, message: validError.message, retryExhausted: validError.retryExhausted,
    });
    const inheritedErrorProviderCode = {
      type: 'need_human', status: 'need_human',
      needHuman: { reason: 'error', error: inheritedProviderCode },
    };

    expect(validateCanonicalEventInvariant(inheritedNeedHuman).success).toBe(false);
    expect(validateCanonicalEventInvariant({
      type: 'need_human', status: 'need_human', needHuman: inheritedContextError,
    }).success).toBe(false);
    expect(validateCanonicalEventInvariant(inheritedErrorProviderCode).success).toBe(false);
  });

  test('strictly validates bounded sanitized protected errors', () => {
    const context: NeedHumanContext = { reason: 'error', error: validError };
    expect(validateCanonicalEventInvariant({ type: 'need_human', status: 'need_human', needHuman: context }).success).toBe(true);
    for (const error of [
      { ...validError, kind: 'network' },
      { ...validError, message: '' },
      { ...validError, message: ' leading whitespace' },
      { ...validError, message: 'trailing whitespace ' },
      { ...validError, message: 'line\nbreak' },
      { ...validError, message: 'double  space' },
      { ...validError, message: '\ud800' },
      { ...validError, message: 'x'.repeat(2_001) },
      { ...validError, message: 'Authorization: Bearer abc123' },
      { ...validError, message: 'token=abc123' },
      { ...validError, message: 'api key=abc123' },
      { ...validError, message: 'API Key =abc123' },
      { ...validError, message: 'Api K_e-y:abc123' },
      { ...validError, message: '-----BEGIN PRIVATE KEY-----' },
      { ...validError, message: 'request body={"prompt":"private"}' },
      { ...validError, providerCode: '' },
      { ...validError, providerCode: 'contains whitespace' },
      { ...validError, providerCode: 'x'.repeat(129) },
      { ...validError, retryExhausted: 'yes' },
      { ...validError, providerCode: 'sk-AAAAAAAAAAAAAAAA' },
      { ...validError, providerCode: 'Bearer.token-value' },
      { ...validError, retryExhausted: false },
    ]) {
      expect(validateCanonicalEventInvariant({ type: 'need_human', status: 'need_human', needHuman: { reason: 'error', error } }).success, JSON.stringify(error)).toBe(false);
    }
  });

  test('keeps every terminal event user-visible and actionable', () => {
    expect(isUserVisibleActionableAlert({ ...baseEvent, type: 'need_human' })).toBe(true);
    expect(isUserVisibleActionableAlert({ ...baseEvent, type: 'done' })).toBe(true);
  });


  test('exposes only canonical session read fields', () => {
    const request: MarkSessionReadRequest = {
      latestReadEventId: 'evt-2',
      readAt: '2026-07-13T10:00:00.000Z',
      source: 'pi_local_interaction',
    };
    expect(request.latestReadEventId).toBe('evt-2');
    const source: SessionReadSource = 'watch_view'; expect(source).toBe('watch_view');
    expect(SESSION_HANDLE_ACTIONS).toEqual(['pi_input', 'watch_reply', 'bridge_recovery']);
    const action: SessionHandleAction = 'watch_reply'; expect(action).toBe('watch_reply');
  });
});
