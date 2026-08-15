import { RelayClientError } from '../relay-client';

/**
 * Desensitized failure category shared by the upload decision model and the
 * public event-failure hook surface. Values are stable contract strings; no
 * error text, ciphertext, or secrets ever appear here.
 */
export type UploadFailureCategory = 'network' | 'http' | 'recipient-set' | 'session-revision' | 'event-content';

/** Category alias used by the Event upload decision and failure surfaces. */
export type EncryptedEventFailureCategory = UploadFailureCategory;

/** Exact baseline mapping of permanent 409 event conflict reasons to categories. */
export const PERMANENT_EVENT_CONFLICT_CATEGORIES: ReadonlyMap<string, UploadFailureCategory> = new Map([
  ['session_revision_stale', 'session-revision'],
  ['session_revision_gap', 'session-revision'],
  ['session revision conflict', 'session-revision'],
  ['encrypted event conflict', 'event-content'],
  ['encrypted upload conflict', 'event-content'],
]);

export function isRelayConflict(error: unknown): error is RelayClientError {
  if (error instanceof RelayClientError) return error.status === 409;
  if (!error || typeof error !== 'object') return false;
  const candidate = error as { status?: unknown; reason?: unknown };
  return candidate.status === 409 && typeof candidate.reason === 'string';
}

export function isPermanentEventConflict(error: unknown): error is RelayClientError {
  return isRelayConflict(error) && PERMANENT_EVENT_CONFLICT_CATEGORIES.has(error.reason ?? '');
}

export function relayErrorStatus(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const status = (error as { status?: unknown }).status;
  return typeof status === 'number' ? status : undefined;
}

export function relayErrorReason(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const reason = (error as { reason?: unknown }).reason;
  return typeof reason === 'string' ? reason : undefined;
}

export function relayFailureCategory(error: unknown): UploadFailureCategory {
  const reason = relayErrorReason(error);
  if (reason === 'e2e_recipient_set_changed') return 'recipient-set';
  const permanentCategory = PERMANENT_EVENT_CONFLICT_CATEGORIES.get(reason ?? '');
  if (permanentCategory) return permanentCategory;
  return relayErrorStatus(error) === undefined ? 'network' : 'http';
}
