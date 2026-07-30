import { isCanonicalTimestamp } from './validation.js';
import type { ValidationResult } from './validation.js';
import { contentSha256 } from './request-signing.js';

export const SESSION_SNAPSHOT_ERROR_CODES = [
  'session_snapshot_stale',
  'session_snapshot_conflict',
  'e2e_recipient_set_changed',
  'e2e_session_reference_invalid',
] as const;
export type SessionSnapshotErrorCode = (typeof SESSION_SNAPSHOT_ERROR_CODES)[number];

export interface E2ECurrentSessionReferenceV1 {
  sessionId: string;
  sessionRevision: number;
}

/** Host lifecycle revisions and encrypted Session revisions are independent domains. */
export interface ReplaceE2ECurrentSessionsRequestV1 {
  hostId: string;
  revision: number;
  observedAt: string;
  recipientSetVersion: number;
  sessions: E2ECurrentSessionReferenceV1[];
}

export interface ReplaceE2ECurrentSessionsResponseV1 {
  ok: true;
  hostId: string;
  revision: number;
  activeSessionCount: number;
}

export interface ReplaceE2ECurrentSessionsErrorResponseV1 {
  ok: false;
  code: SessionSnapshotErrorCode;
  hostId: string;
  acceptedRevision?: number;
}

const REQUEST_KEYS = ['hostId', 'revision', 'observedAt', 'recipientSetVersion', 'sessions'] as const;
const SESSION_KEYS = ['sessionId', 'sessionRevision'] as const;
const SEMANTIC_OMITTED_KEYS = new Set(['hostId', 'updatedAt', 'presence', 'sessionRevision']);

export function validateReplaceE2ECurrentSessionsRequestV1(
  value: unknown,
): ValidationResult<ReplaceE2ECurrentSessionsRequestV1> {
  const issues: string[] = [];
  const request = asRecord(value, 'body', issues);
  if (!request) return { success: false, issues };
  exactKeys(request, REQUEST_KEYS, 'body', issues);
  nonBlank(request.hostId, 'hostId', issues);
  positiveRevision(request.revision, 'revision', issues);
  positiveRevision(request.recipientSetVersion, 'recipientSetVersion', issues);
  if (!isCanonicalTimestamp(request.observedAt)) issues.push('observedAt must be a canonical RFC3339 timestamp');
  if (!Array.isArray(request.sessions)) issues.push('sessions must be an array');
  else {
    const seen = new Set<string>();
    request.sessions.forEach((candidate, index) => {
      const path = `sessions[${index}]`;
      const session = asRecord(candidate, path, issues);
      if (!session) return;
      exactKeys(session, SESSION_KEYS, path, issues);
      nonBlank(session.sessionId, `${path}.sessionId`, issues);
      if (typeof session.sessionId === 'string') {
        if (session.sessionId.startsWith('driver:') || session.sessionId.startsWith('host:')) issues.push(`${path}.sessionId must not be diagnostic`);
        if (seen.has(session.sessionId)) issues.push(`${path}.sessionId must be unique`);
        seen.add(session.sessionId);
      }
      positiveRevision(session.sessionRevision, `${path}.sessionRevision`, issues);
    });
  }
  return issues.length ? { success: false, issues } : { success: true, value: value as ReplaceE2ECurrentSessionsRequestV1, issues };
}

/** Canonical digest sorts members by Session ID, so set ordering is not semantic. */
export async function canonicalE2ECurrentSessionsDigestV1(request: ReplaceE2ECurrentSessionsRequestV1): Promise<string> {
  const canonical = {
    hostId: request.hostId,
    observedAt: request.observedAt,
    recipientSetVersion: request.recipientSetVersion,
    revision: request.revision,
    sessions: [...request.sessions].sort((a, b) => compareCanonicalStrings(a.sessionId, b.sessionId))
      .map(({ sessionId, sessionRevision }) => ({ sessionId, sessionRevision })),
  };
  return contentSha256(new TextEncoder().encode(stableJson(canonical)));
}

/** Digest used by Bridge change detection; excludes liveness and allocated revisions. */
export async function e2eCurrentSessionsSemanticDigestV1(
  hostId: string,
  sessions: readonly E2ECurrentSessionReferenceV1[] | readonly { sessionId: string }[],
): Promise<string> {
  const semanticSessions = sessions.map((item) => {
    const value = item as Record<string, unknown>;
    return Object.fromEntries(Object.entries(value)
      .filter(([key]) => !SEMANTIC_OMITTED_KEYS.has(key))
      .sort(([left], [right]) => compareCanonicalStrings(left, right)));
  }).sort((left, right) => compareCanonicalStrings(String(left.sessionId), String(right.sessionId)));
  return contentSha256(new TextEncoder().encode(stableJson({ hostId, sessions: semanticSessions })));
}

function positiveRevision(value: unknown, path: string, issues: string[]): void {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) issues.push(`${path} must be a positive safe integer`);
}
function nonBlank(value: unknown, path: string, issues: string[]): void {
  if (typeof value !== 'string' || !value.trim()) issues.push(`${path} must be a non-blank string`);
}
function exactKeys(value: Record<string, unknown>, keys: readonly string[], path: string, issues: string[]): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) if (!allowed.has(key)) issues.push(`${path}.${key} is unsupported`);
  for (const key of keys) if (!Object.hasOwn(value, key)) issues.push(`${path}.${key} is required`);
}
function asRecord(value: unknown, path: string, issues: string[]): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) { issues.push(`${path} must be an object`); return undefined; }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) if (!('value' in descriptor)) issues.push(`${path}.${key} must be an own data property`);
  return Object.fromEntries(Object.entries(descriptors).filter(([, descriptor]) => 'value' in descriptor).map(([key, descriptor]) => [key, descriptor.value]));
}
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function compareCanonicalStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
