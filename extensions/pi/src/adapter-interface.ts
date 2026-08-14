import {
  isCanonicalTimestamp,
  type CanonicalEvent,
  type CommandEnvelope,
  type HandleSessionRequest,
  type SessionStatus,
} from '@ariava/protocol';
import type { PiSessionInfo } from './session';

type WithoutBridgeIdentity<T> = T extends CanonicalEvent ? Omit<T, 'eventId' | 'hostId'> : never;
export type AgentAdapterEvent = WithoutBridgeIdentity<CanonicalEvent>;

export type AgentAdapterCommandResult =
  | {
      commandId: string;
      hostId: string;
      sessionId: string;
      accepted: true;
      status: 'executed';
      updatedAt: string;
    }
  | {
      commandId: string;
      hostId: string;
      sessionId: string;
      accepted: false;
      status: 'failed' | 'rejected';
      updatedAt: string;
    };

export interface AgentAdapter {
  registerSession(session: PiSessionInfo): Promise<{ sessionId: string; registeredAt: string }>;
  unregisterSession(sessionId: string): Promise<void>;
  pushEvent(event: AgentAdapterEvent): Promise<{ eventId: string }>;
  handleSession(sessionId: string, request: HandleSessionRequest): Promise<{ ok: true; hostId: string; sessionId: string; handledThroughEventId: string }>;
  heartbeat(sessionId: string, status: SessionStatus, latestActivityText?: string | null, session?: PiSessionInfo): Promise<void>;
  pollCommands(sessionId: string, timeoutMs: number, session?: PiSessionInfo): Promise<CommandEnvelope | null>;
  submitResult(commandId: string, result: AgentAdapterCommandResult): Promise<void>;
}

export function validateAgentAdapterCommand(value: unknown): value is CommandEnvelope {
  if (!isExactRecord(value,
    ['commandId', 'hostId', 'sessionId', 'type', 'payload', 'targetAlertEventId', 'issuedAt', 'expiresAt', 'nonce', 'watchDeviceId'],
    ['commandId', 'hostId', 'sessionId', 'type', 'payload', 'issuedAt', 'expiresAt', 'nonce', 'watchDeviceId'],
  )) return false;
  if (!isIdentifier(value.commandId) || !isIdentifier(value.hostId) || !isIdentifier(value.sessionId)
    || !isIdentifier(value.nonce) || !isIdentifier(value.watchDeviceId)
    || !isCanonicalTimestamp(value.issuedAt) || !isCanonicalTimestamp(value.expiresAt)
    || Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) return false;
  if (value.type === 'reply') {
    return (value.targetAlertEventId === undefined || isIdentifier(value.targetAlertEventId))
      && isExactRecord(value.payload, ['text'], [])
      && (value.payload.text === undefined || typeof value.payload.text === 'string');
  }
  return value.type === 'interrupt'
    && value.targetAlertEventId === undefined
    && isExactRecord(value.payload, [], []);
}

export function validateAgentAdapterCommandResult(value: unknown): value is AgentAdapterCommandResult {
  return isExactRecord(value,
    ['commandId', 'hostId', 'sessionId', 'accepted', 'status', 'updatedAt'],
    ['commandId', 'hostId', 'sessionId', 'accepted', 'status', 'updatedAt'],
  )
    && isIdentifier(value.commandId)
    && isIdentifier(value.hostId)
    && isIdentifier(value.sessionId)
    && isCanonicalTimestamp(value.updatedAt)
    && ((value.accepted === true && value.status === 'executed')
      || (value.accepted === false && (value.status === 'failed' || value.status === 'rejected')));
}

function isExactRecord(
  value: unknown,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (Object.getPrototypeOf(value) !== Object.prototype) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = new Set(allowedKeys);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.has(key)) return false;
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  for (const key of requiredKeys) if (!Object.hasOwn(value, key)) return false;
  for (const key of allowedKeys) if (!Object.hasOwn(value, key) && key in value) return false;
  return true;
}

function isIdentifier(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && new TextEncoder().encode(value).byteLength <= 256
    && isWellFormedUnicode(value);
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}
