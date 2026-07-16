export const SESSION_STATUSES = ['working', 'blocked', 'done', 'unknown'] as const;
export type SessionStatus = (typeof SESSION_STATUSES)[number];

export const EVENT_TYPES = [
  'working',
  'blocked',
  'done',
  'question_requested',
  'driver_error',
  'host_unavailable',
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export interface ActionablePrompt {
  promptId: string;
  type: 'question';
  label: string;
  options?: string[];
  expiresAt?: string;
}

export interface CanonicalEvent {
  eventId: string;
  hostId: string;
  sessionId: string;
  provider: string;
  type: EventType;
  status: SessionStatus;
  typeLabel: string;
  assistantText: string;
  userMessageText?: string;
  contextText?: string;
  actionablePrompt?: ActionablePrompt;
  correlationId?: string;
  createdAt: string;
}

/** Legacy shared read model retained only for compatibility aliases/backfill. */
export type SessionReadSource = 'watch_view' | 'watch_reply' | 'pi_local_interaction' | 'bridge_recovery';

export interface MarkSessionReadRequest {
  latestReadEventId?: string;
  readAt?: string;
  source?: SessionReadSource;
  /** @deprecated Compatibility for older watch clients. */
  latestSeenEventId?: string;
  /** @deprecated Compatibility for older watch clients. */
  seenAt?: string;
}

export interface NormalizedMarkSessionReadRequest {
  latestReadEventId: string;
  readAt?: string;
  source?: SessionReadSource;
}

export interface MarkSessionReadResponse {
  ok: true;
  hostId?: string;
  sessionId: string;
  latestReadEventId: string;
  /** @deprecated Compatibility for older watch clients. */
  latestSeenEventId?: string;
}

export const SESSION_HANDLE_ACTIONS = ['pi_input', 'watch_reply', 'bridge_recovery'] as const;
export type SessionHandleAction = (typeof SESSION_HANDLE_ACTIONS)[number];
export type SessionHandleActorKind = 'bridge' | 'watch' | 'unknown';

export interface HandleSessionRequest {
  handledThroughEventId: string;
  handledThroughEventCreatedAt?: string;
  handledAt?: string;
  action?: Extract<SessionHandleAction, 'pi_input' | 'bridge_recovery'>;
}

export function normalizeMarkSessionReadRequest(request: MarkSessionReadRequest): NormalizedMarkSessionReadRequest {
  return {
    latestReadEventId: request.latestReadEventId ?? request.latestSeenEventId ?? '',
    readAt: request.readAt ?? request.seenAt,
    source: request.source,
  };
}

export interface EventCursor {
  eventId: string;
  createdAt: string;
}

/** Stable canonical event ordering: timestamp first, then lexical event ID. */
export function compareEventCursors(left: EventCursor, right: EventCursor): number {
  const createdAt = left.createdAt.localeCompare(right.createdAt);
  return createdAt === 0 ? left.eventId.localeCompare(right.eventId) : createdAt;
}

export function eventCursorCovers(cursor: EventCursor | undefined, event: EventCursor): boolean {
  return Boolean(cursor && compareEventCursors(cursor, event) >= 0);
}

export function isUserVisibleActionableAlert(event: Pick<CanonicalEvent, 'type'>): boolean {
  return event.type === 'question_requested' || event.type === 'blocked' || event.type === 'done';
}

export function statusToStateLabel(status: SessionStatus): string {
  switch (status) {
    case 'working':
      return 'In progress';
    case 'blocked':
      return 'Needs attention';
    case 'done':
      return 'Done';
    case 'unknown':
      return 'Unknown';
  }
}
