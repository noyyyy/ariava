import { describe, expect, test } from 'bun:test';
import {
  SESSION_SNAPSHOT_ERROR_CODES,
  canonicalE2ECurrentSessionsDigestV1,
  e2eCurrentSessionsSemanticDigestV1,
  validateReplaceE2ECurrentSessionsRequestV1,
  type ReplaceE2ECurrentSessionsRequestV1,
} from '../src';

const request: ReplaceE2ECurrentSessionsRequestV1 = {
  hostId: 'host-1', revision: 7, observedAt: '2026-07-29T00:00:00.000Z', recipientSetVersion: 3,
  sessions: [{ sessionId: 'session-b', sessionRevision: 11 }, { sessionId: 'session-a', sessionRevision: 2 }],
};

function invalid(value: unknown, issue: string) {
  const result = validateReplaceE2ECurrentSessionsRequestV1(value);
  expect(result.success).toBe(false);
  expect(result.issues.some((item) => item.includes(issue))).toBe(true);
}

describe('E2E current-session lifecycle manifest', () => {
  test('accepts only the metadata-only exact contract', () => {
    expect(validateReplaceE2ECurrentSessionsRequestV1(request)).toEqual({ success: true, value: request, issues: [] });
    invalid({ ...request, projectName: 'secret' }, 'projectName is unsupported');
    invalid({ ...request, sessions: [{ ...request.sessions[0], openingText: 'secret' }] }, 'openingText is unsupported');
  });

  test('rejects duplicates, diagnostics, malformed timestamps and revision domains', () => {
    invalid({ ...request, sessions: [request.sessions[0], request.sessions[0]] }, 'must be unique');
    invalid({ ...request, sessions: [{ sessionId: 'driver:pi', sessionRevision: 1 }] }, 'must not be diagnostic');
    invalid({ ...request, observedAt: '2026-07-29T00:00:00Z' }, 'canonical RFC3339');
    for (const field of ['revision', 'recipientSetVersion'] as const) invalid({ ...request, [field]: 0 }, 'positive safe integer');
    invalid({ ...request, sessions: [{ sessionId: 'session-a', sessionRevision: Number.MAX_SAFE_INTEGER + 1 }] }, 'positive safe integer');
  });

  test('keeps Host and Session revisions independent and canonicalizes set order', async () => {
    expect((await canonicalE2ECurrentSessionsDigestV1(request))).toBe(await canonicalE2ECurrentSessionsDigestV1({ ...request, sessions: [...request.sessions].reverse() }));
    expect(await canonicalE2ECurrentSessionsDigestV1(request)).not.toBe(await canonicalE2ECurrentSessionsDigestV1({ ...request, revision: 8 }));
    expect(await canonicalE2ECurrentSessionsDigestV1(request)).not.toBe(await canonicalE2ECurrentSessionsDigestV1({ ...request, sessions: [{ ...request.sessions[0]!, sessionRevision: 12 }, request.sessions[1]!] }));
    expect(SESSION_SNAPSHOT_ERROR_CODES).toEqual(['session_snapshot_stale', 'session_snapshot_conflict', 'e2e_recipient_set_changed', 'e2e_session_reference_invalid']);
  });

  test('has a fixed locale-independent non-ASCII digest vector', async () => {
    const vector = { ...request, sessions: [
      { sessionId: 'éclair', sessionRevision: 4 },
      { sessionId: '中', sessionRevision: 5 },
      { sessionId: 'zebra', sessionRevision: 6 },
    ] };
    expect(await canonicalE2ECurrentSessionsDigestV1(vector)).toBe('kAu-niMo0JphM1LCLnP1XRYpYwcKyPDW6aJ9svoyyC8');
  });

  test('semantic digest projects only retained canonical Session fields', async () => {
    const session = {
      sessionId: 'session-a', hostId: 'host-1', provider: 'pi', projectName: 'ariava', nameText: 'Task 1',
      openingText: 'Opening', latestActivityText: 'Working', workingDirectory: '/workspace/ariava',
      harnessProvider: 'pi', status: 'working', updatedAt: '2026-07-29T00:00:00.000Z',
      lastEventId: 'event-1', snoozedUntil: '2026-07-29T01:00:00.000Z', presence: 'active', sessionRevision: 7,
    } as const;
    const baseline = await e2eCurrentSessionsSemanticDigestV1('host-1', [session]);
    for (const extra of [
      { unknownRuntimeProperty: 'ignored' },
      { hbaseSessionKey: 'retired-session-key' },
      { actionablePrompt: { promptId: 'retired', type: 'question', label: 'Reply' } },
    ]) expect(await e2eCurrentSessionsSemanticDigestV1(
      'host-1', [{ ...session, ...extra } as typeof session],
    )).toBe(baseline);
    for (const retained of [
      { sessionId: 'session-b' }, { provider: 'codex' }, { projectName: 'other' }, { nameText: 'Other task' },
      { openingText: 'Other opening' }, { latestActivityText: 'Done' }, { workingDirectory: '/workspace/other' },
      { harnessProvider: 'other' }, { status: 'idle' }, { lastEventId: 'event-2' },
      { snoozedUntil: '2026-07-29T02:00:00.000Z' },
    ]) expect(await e2eCurrentSessionsSemanticDigestV1('host-1', [{ ...session, ...retained }])).not.toBe(baseline);
    expect(await e2eCurrentSessionsSemanticDigestV1('host-2', [session])).not.toBe(baseline);
    expect(await e2eCurrentSessionsSemanticDigestV1(
      'host-1', [{ ...session, updatedAt: '2026-07-30T00:00:00.000Z' } as typeof session],
    )).toBe(baseline);
    expect(await e2eCurrentSessionsSemanticDigestV1(
      'host-1', [{ ...session, sessionRevision: 8 } as typeof session],
    )).toBe(baseline);
  });
});
