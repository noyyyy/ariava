import { describe, expect, test } from 'bun:test';
import {
  SESSION_PRESENCES,
  SESSION_SNAPSHOT_ERROR_CODES,
  validateReplaceCurrentSessionsRequest,
  type ActiveSessionSnapshot,
  type ReplaceCurrentSessionsErrorResponse,
  type ReplaceCurrentSessionsRequest,
  type ReplaceCurrentSessionsResponse,
} from '../src';

const activeSession: ActiveSessionSnapshot = {
  sessionId: 'session-1',
  hostId: 'host-1',
  provider: 'pi',
  projectName: 'ariava',
  nameText: 'Lifecycle implementation',
  openingText: 'Implement the session lifecycle',
  latestActivityText: 'Adding the protocol contract',
  stateLabel: 'Ready',
  status: 'idle',
  actionablePrompt: {
    promptId: 'prompt-1',
    type: 'question',
    label: 'Reply',
    options: ['Proceed'],
    expiresAt: '2026-07-20T02:30:00.000Z',
  },
  updatedAt: '2026-07-20T02:15:00.000Z',
  lastEventId: 'event-1',
  snoozedUntil: '2026-07-20T02:20:00.000Z',
  presence: 'active',
};

const request: ReplaceCurrentSessionsRequest = {
  hostId: 'host-1',
  revision: 1,
  observedAt: '2026-07-20T02:15:01.000Z',
  sessions: [activeSession],
};

function cloneRequest(): Record<string, unknown> {
  return structuredClone(request) as unknown as Record<string, unknown>;
}

function expectInvalid(candidate: unknown, issue: string): void {
  const result = validateReplaceCurrentSessionsRequest(candidate);
  expect(result.success).toBe(false);
  expect(result.issues.some((item) => item.includes(issue))).toBe(true);
}


describe('current-session snapshot contract', () => {
  test('accepts an exact active full-set snapshot without normalizing it', () => {
    const result = validateReplaceCurrentSessionsRequest(request);
    expect(result).toEqual({ success: true, value: request, issues: [] });
    expect(SESSION_PRESENCES).toEqual(['active', 'ended']);
  });

  test('accepts an empty authoritative active set and legacy unknown status', () => {
    const empty = { ...request, sessions: [] };
    expect(validateReplaceCurrentSessionsRequest(empty)).toEqual({ success: true, value: empty, issues: [] });

    const legacy = cloneRequest();
    const sessions = legacy.sessions as Array<Record<string, unknown>>;
    sessions[0]!.status = 'unknown';
    sessions[0]!.stateLabel = 'Status unavailable';
    expect(validateReplaceCurrentSessionsRequest(legacy).success).toBe(true);
  });

  test('rejects request and nested extra keys', () => {
    expectInvalid({ ...request, partial: true }, 'body.partial is unsupported');
    const nested = cloneRequest();
    (nested.sessions as Array<Record<string, unknown>>)[0]!.extra = true;
    expectInvalid(nested, 'sessions[0].extra is unsupported');
  });

  test('requires positive safe integer revisions and canonical timestamps', () => {
    expect(validateReplaceCurrentSessionsRequest({ ...request, revision: Number.MAX_SAFE_INTEGER }).success).toBe(true);
    for (const revision of [0, -1, 1.5, Number.NaN, '1', Number.MAX_SAFE_INTEGER + 1, Number.MIN_SAFE_INTEGER - 1]) {
      expectInvalid({ ...request, revision }, 'revision must be a positive integer');
    }
    expectInvalid({ ...request, observedAt: '2026-07-20T02:15:01Z' }, 'observedAt must be a canonical');

    const updated = cloneRequest();
    (updated.sessions as Array<Record<string, unknown>>)[0]!.updatedAt = '2026-07-20 02:15:00Z';
    expectInvalid(updated, 'updatedAt must be a canonical');
  });

  test('rejects duplicate, cross-Host, and ended entries', () => {
    expectInvalid({ ...request, sessions: [activeSession, { ...activeSession }] }, 'duplicates a hostId/sessionId entry');
    expectInvalid({ ...request, sessions: [{ ...activeSession, hostId: 'host-2' }] }, 'hostId must match hostId');
    expectInvalid({ ...request, sessions: [{ ...activeSession, presence: 'ended' }] }, 'presence must be active');
  });

  test('rejects unsupported status, noncanonical stateLabel, and blank identities', () => {
    expectInvalid({ ...request, sessions: [{ ...activeSession, status: 'paused' }] }, 'status is unsupported');
    expectInvalid({ ...request, sessions: [{ ...activeSession, stateLabel: 'Waiting' }] }, 'stateLabel must match status');
    for (const field of ['sessionId', 'hostId', 'provider', 'projectName', 'nameText'] as const) {
      expectInvalid({ ...request, sessions: [{ ...activeSession, [field]: '   ' }] }, `${field} must be a non-blank string`);
    }
    expectInvalid({ ...request, hostId: ' ' }, 'hostId must be a non-blank string');
  });

  test('rejects malformed optional canonical session fields', () => {
    expectInvalid({ ...request, sessions: [{ ...activeSession, openingText: 42 }] }, 'openingText must be a string');
    expectInvalid({ ...request, sessions: [{ ...activeSession, lastEventId: '' }] }, 'lastEventId must be a non-blank string');
    expectInvalid({ ...request, sessions: [{ ...activeSession, snoozedUntil: 'tomorrow' }] }, 'snoozedUntil must be a canonical');
    expectInvalid({ ...request, sessions: [{ ...activeSession, actionablePrompt: { promptId: '', type: 'choice', label: '', options: [''] } }] }, 'actionablePrompt.promptId');
  });

  test('exports stable success and conflict response contracts', () => {
    expect(SESSION_SNAPSHOT_ERROR_CODES).toEqual(['session_snapshot_stale', 'session_snapshot_conflict']);
    const success: ReplaceCurrentSessionsResponse = { ok: true, hostId: 'host-1', revision: 2, activeSessionCount: 1 };
    const stale: ReplaceCurrentSessionsErrorResponse = { ok: false, code: 'session_snapshot_stale', hostId: 'host-1', acceptedRevision: 2 };
    const conflict: ReplaceCurrentSessionsErrorResponse = { ok: false, code: 'session_snapshot_conflict', hostId: 'host-1', acceptedRevision: 2 };
    expect(success).toEqual({ ok: true, hostId: 'host-1', revision: 2, activeSessionCount: 1 });
    expect(stale.acceptedRevision).toBe(2);
    expect(conflict.acceptedRevision).toBe(2);
  });
});
