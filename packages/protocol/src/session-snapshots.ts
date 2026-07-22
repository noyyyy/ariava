import { SESSION_STATUSES, statusToStateLabel } from './events.js';
import type { ActiveSessionSnapshot } from './sessions.js';
import { isCanonicalTimestamp } from './validation.js';
import type { ValidationResult } from './validation.js';

export const SESSION_SNAPSHOT_ERROR_CODES = [
  'session_snapshot_stale',
  'session_snapshot_conflict',
] as const;
export type SessionSnapshotErrorCode = (typeof SESSION_SNAPSHOT_ERROR_CODES)[number];

export interface ReplaceCurrentSessionsRequest {
  hostId: string;
  revision: number;
  observedAt: string;
  sessions: ActiveSessionSnapshot[];
}

export interface ReplaceCurrentSessionsResponse {
  ok: true;
  hostId: string;
  revision: number;
  activeSessionCount: number;
}

export interface ReplaceCurrentSessionsErrorResponse {
  ok: false;
  code: SessionSnapshotErrorCode;
  hostId: string;
  acceptedRevision: number;
}

const REQUEST_KEYS = ['hostId', 'revision', 'observedAt', 'sessions'] as const;
const SESSION_KEYS = [
  'sessionId',
  'hostId',
  'provider',
  'projectName',
  'nameText',
  'openingText',
  'latestActivityText',
  'stateLabel',
  'status',
  'actionablePrompt',
  'updatedAt',
  'lastEventId',
  'snoozedUntil',
  'presence',
] as const;
const PROMPT_KEYS = ['promptId', 'type', 'label', 'options', 'expiresAt'] as const;

/**
 * This Host-wide active-set snapshot revision is independent from any future
 * per-session encrypted content revision; the two revision domains must not be reused.
 */

/**
 * Validates an exact authoritative Host current-session snapshot without
 * normalizing free text, labels, timestamps, or Host scope.
 */
export function validateReplaceCurrentSessionsRequest(
  value: unknown,
): ValidationResult<ReplaceCurrentSessionsRequest> {
  const issues: string[] = [];
  const request = asRecord(value, 'body', issues);
  if (!request) return { success: false, issues };

  requireExactKeys(request, REQUEST_KEYS, 'body', issues);
  requireNonBlankString(request.hostId, 'hostId', issues);
  if (typeof request.revision !== 'number' || !Number.isSafeInteger(request.revision) || request.revision <= 0) {
    issues.push('revision must be a positive integer');
  }
  requireCanonicalTimestamp(request.observedAt, 'observedAt', issues);

  if (!Array.isArray(request.sessions)) {
    issues.push('sessions must be an array');
  } else {
    const seen = new Set<string>();
    request.sessions.forEach((candidate, index) => {
      const path = `sessions[${index}]`;
      const session = asRecord(candidate, path, issues);
      if (!session) return;
      validateActiveSession(session, path, issues);

      if (typeof request.hostId === 'string' && typeof session.hostId === 'string' && session.hostId !== request.hostId) {
        issues.push(`${path}.hostId must match hostId`);
      }
      if (typeof session.hostId === 'string' && typeof session.sessionId === 'string') {
        const key = `${session.hostId}\u0000${session.sessionId}`;
        if (seen.has(key)) issues.push(`${path} duplicates a hostId/sessionId entry`);
        seen.add(key);
      }
    });
  }

  return issues.length
    ? { success: false, issues }
    : { success: true, value: value as ReplaceCurrentSessionsRequest, issues };
}

function validateActiveSession(
  session: Record<string, unknown>,
  path: string,
  issues: string[],
): void {
  requireExactKeys(session, SESSION_KEYS, path, issues, [
    'sessionId', 'hostId', 'provider', 'projectName', 'nameText',
    'stateLabel', 'status', 'updatedAt', 'presence',
  ]);
  requireNonBlankString(session.sessionId, `${path}.sessionId`, issues);
  requireNonBlankString(session.hostId, `${path}.hostId`, issues);
  requireNonBlankString(session.provider, `${path}.provider`, issues);
  requireNonBlankString(session.projectName, `${path}.projectName`, issues);
  requireNonBlankString(session.nameText, `${path}.nameText`, issues);
  requireOptionalString(session.openingText, `${path}.openingText`, issues);
  requireOptionalString(session.latestActivityText, `${path}.latestActivityText`, issues);
  requireNonBlankString(session.stateLabel, `${path}.stateLabel`, issues);

  if (typeof session.status !== 'string' || !(SESSION_STATUSES as readonly string[]).includes(session.status)) {
    issues.push(`${path}.status is unsupported`);
  } else if (session.stateLabel !== statusToStateLabel(session.status as ActiveSessionSnapshot['status'])) {
    issues.push(`${path}.stateLabel must match status`);
  }

  if (session.presence !== 'active') issues.push(`${path}.presence must be active`);
  requireCanonicalTimestamp(session.updatedAt, `${path}.updatedAt`, issues);
  requireOptionalNonBlankString(session.lastEventId, `${path}.lastEventId`, issues);
  requireOptionalCanonicalTimestamp(session.snoozedUntil, `${path}.snoozedUntil`, issues);
  if (session.actionablePrompt !== undefined) validateActionablePrompt(session.actionablePrompt, `${path}.actionablePrompt`, issues);
}

function validateActionablePrompt(value: unknown, path: string, issues: string[]): void {
  const prompt = asRecord(value, path, issues);
  if (!prompt) return;
  requireExactKeys(prompt, PROMPT_KEYS, path, issues, ['promptId', 'type', 'label']);
  requireNonBlankString(prompt.promptId, `${path}.promptId`, issues);
  if (prompt.type !== 'question') issues.push(`${path}.type must be question`);
  requireNonBlankString(prompt.label, `${path}.label`, issues);
  if (prompt.options !== undefined) {
    if (!Array.isArray(prompt.options)) {
      issues.push(`${path}.options must be an array`);
    } else {
      prompt.options.forEach((option, index) => requireNonBlankString(option, `${path}.options[${index}]`, issues));
    }
  }
  requireOptionalCanonicalTimestamp(prompt.expiresAt, `${path}.expiresAt`, issues);
}

function asRecord(value: unknown, path: string, issues: string[]): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    issues.push(`${path} must be an object`);
    return undefined;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!('value' in descriptor)) issues.push(`${path}.${key} must be an own data property`);
  }
  return Object.fromEntries(
    Object.entries(descriptors)
      .filter(([, descriptor]) => 'value' in descriptor)
      .map(([key, descriptor]) => [key, descriptor.value]),
  );
}

function requireExactKeys(
  object: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
  issues: string[],
  required: readonly string[] = allowed,
): void {
  const supported = new Set(allowed);
  for (const key of Object.keys(object)) if (!supported.has(key)) issues.push(`${path}.${key} is unsupported`);
  for (const key of required) if (!Object.prototype.hasOwnProperty.call(object, key)) issues.push(`${path}.${key} is required`);
}

function requireNonBlankString(value: unknown, path: string, issues: string[]): void {
  if (typeof value !== 'string' || !value.trim()) issues.push(`${path} must be a non-blank string`);
}

function requireOptionalString(value: unknown, path: string, issues: string[]): void {
  if (value !== undefined && typeof value !== 'string') issues.push(`${path} must be a string`);
}

function requireOptionalNonBlankString(value: unknown, path: string, issues: string[]): void {
  if (value !== undefined) requireNonBlankString(value, path, issues);
}

function requireCanonicalTimestamp(value: unknown, path: string, issues: string[]): void {
  if (!isCanonicalTimestamp(value)) issues.push(`${path} must be a canonical RFC3339 timestamp`);
}

function requireOptionalCanonicalTimestamp(value: unknown, path: string, issues: string[]): void {
  if (value !== undefined) requireCanonicalTimestamp(value, path, issues);
}
