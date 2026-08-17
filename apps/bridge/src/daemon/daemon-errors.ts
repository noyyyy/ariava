import { RelayClientError } from '../relay-client';

/**
 * Abort recognition for the daemon poll loop (spec §10). Pure: any `Error`
 * whose name is exactly `AbortError` is treated as an intentional stop.
 * Preserves the exact recognition baseline (Error instance + name only).
 */
export function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

export type SnapshotErrorCode =
  | 'session_snapshot_stale'
  | 'session_snapshot_conflict'
  | 'e2e_recipient_not_ready'
  | 'e2e_recipient_set_changed'
  | 'e2e_session_reference_invalid';

export type SnapshotErrorEvidence = { acceptedRevision?: number };

/**
 * Relay 409 conflict/error extraction (spec §7/§10). Pure parser preserving the
 * exact status/reason/body mapping and fail-closed `acceptedRevision` handling:
 *  - non-`RelayClientError`, non-409, non-object body, or reason mismatch => `undefined`;
 *  - `session_snapshot_stale` without a safe-integer `acceptedRevision` => `undefined` (fail closed);
 *  - numeric `acceptedRevision` => `{ acceptedRevision }`;
 *  - otherwise `{}` (recognized error with no revision evidence).
 */
export function snapshotError(
  error: unknown,
  code: SnapshotErrorCode,
): SnapshotErrorEvidence | undefined {
  if (!(error instanceof RelayClientError) || error.status !== 409 || !error.body || typeof error.body !== 'object') return undefined;
  const body = error.body as Record<string, unknown>;
  const reason = typeof body.code === 'string' ? body.code
    : typeof body.error === 'string' ? body.error
      : typeof body.reason === 'string' ? body.reason : error.reason;
  if (reason !== code) return undefined;
  if (code === 'session_snapshot_stale' && (typeof body.acceptedRevision !== 'number' || !Number.isSafeInteger(body.acceptedRevision))) return undefined;
  return typeof body.acceptedRevision === 'number' ? { acceptedRevision: body.acceptedRevision } : {};
}
