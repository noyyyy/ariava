export const SESSION_STATUSES = ['idle', 'working', 'need_human'] as const;
export type SessionStatus = (typeof SESSION_STATUSES)[number];

export const EVENT_TYPES = ['done', 'need_human'] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export const NEED_HUMAN_REASONS = ['question', 'blocked', 'error'] as const;
export type NeedHumanReason = (typeof NEED_HUMAN_REASONS)[number];

export const NEED_HUMAN_ERROR_KINDS = [
  'context_overflow',
  'provider_failure',
  'response_length',
  'incomplete_tool_use',
  'unknown',
] as const;
export type NeedHumanErrorKind = (typeof NEED_HUMAN_ERROR_KINDS)[number];

export interface NeedHumanError {
  kind: NeedHumanErrorKind;
  message: string;
  providerCode?: string;
  retryExhausted: true;
}

export type NeedHumanContext =
  | { reason: Exclude<NeedHumanReason, 'error'>; error?: never }
  | { reason: 'error'; error: NeedHumanError };

export interface ActionablePrompt {
  promptId: string;
  type: 'question';
  label: string;
  options?: string[];
  expiresAt?: string;
}

interface CanonicalEventBase {
  eventId: string;
  hostId: string;
  sessionId: string;
  provider: string;
  typeLabel: string;
  agentText: string;
  humanText?: string;
  projectName?: string;
  contextText?: string;
  workingDirectory?: string;
  hbaseSessionKey?: string;
  harnessProvider?: string;
  actionablePrompt?: ActionablePrompt;
  correlationId?: string;
  createdAt: string;
}

export type CanonicalEvent = CanonicalEventBase & (
  | { type: 'done'; status: 'idle'; needHuman?: never }
  | { type: 'need_human'; status: 'need_human'; needHuman: NeedHumanContext }
);

/** Host-local plaintext model. It must never be used as a Relay persistence/read projection. */
export type LocalCanonicalEventPlaintext = CanonicalEvent;
export type DecryptedWatchEvent = CanonicalEvent & {
  seen: boolean;
  handled: boolean;
  actionable: boolean;
};

export type SessionReadSource = 'watch_view' | 'watch_reply' | 'pi_local_interaction' | 'bridge_recovery';

export interface MarkSessionReadRequest {
  latestReadEventId: string;
  readAt?: string;
  source?: SessionReadSource;
}

export interface MarkSessionReadResponse {
  ok: true;
  hostId?: string;
  sessionId: string;
  latestReadEventId: string;
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

export function validateEventTypeStatusPair(type: unknown, status: unknown): type is EventType {
  if (type === 'done') return status === 'idle';
  return type === 'need_human' && status === 'need_human';
}

export function isUserVisibleActionableAlert(event: Pick<CanonicalEvent, 'type'>): boolean {
  return EVENT_TYPES.includes(event.type);
}
