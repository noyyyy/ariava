import { createHash } from 'node:crypto';
import {
  base64UrlEncode,
  buildProtectedEventContentBytes,
  buildProtectedSessionContentBytes,
  encodeLengthPrefixedFields,
  isCanonicalTimestamp,
  validateCanonicalEventInvariant,
  type CanonicalEvent,
  type CanonicalSessionState,
} from '@ariava/protocol';
import { isBoundedAgentAdapterIdentifier, type AgentAdapterEventInput, type RegisteredSession } from './registry-types';

const EVENT_KEYS = [
  'sessionId', 'provider', 'type', 'status', 'agentText', 'humanText', 'projectName',
  'workingDirectory', 'harnessProvider', 'createdAt', 'needHuman',
] as const;
const EVENT_REQUIRED_KEYS = [
  'sessionId', 'provider', 'type', 'status', 'agentText', 'projectName', 'workingDirectory',
  'harnessProvider', 'createdAt',
] as const;

export function parseCanonicalProducerEvent(value: unknown): AgentAdapterEventInput {
  const event = exactRecord(value, EVENT_KEYS, EVENT_REQUIRED_KEYS, 'canonical Event');
  for (const key of ['sessionId', 'provider', 'harnessProvider'] as const) requireIdentifier(event, key);
  for (const key of ['agentText', 'projectName', 'workingDirectory', 'createdAt'] as const) requireString(event, key);
  optionalString(event, 'humanText');
  if (!isCanonicalTimestamp(event.createdAt)) throw new TypeError('canonical Event createdAt is invalid');
  const invariant = validateCanonicalEventInvariant({ type: event.type, status: event.status, ...(Object.hasOwn(event, 'needHuman') ? { needHuman: event.needHuman } : {}) });
  if (!invariant.success) throw new TypeError(`canonical Event invariant is invalid: ${invariant.issues.join(', ')}`);
  buildProtectedEventContentBytes({
    version: 3,
    agentText: event.agentText as string,
    ...(event.humanText !== undefined ? { humanText: event.humanText as string } : {}),
    projectName: event.projectName as string,
    workingDirectory: event.workingDirectory as string,
    harnessProvider: event.harnessProvider as string,
    ...(event.needHuman !== undefined ? { needHuman: event.needHuman as never } : {}),
  });
  return event as unknown as AgentAdapterEventInput;
}

/**
 * Enforce the full canonical `ProtectedSessionContentV3` ≤ 65,536 B boundary for
 * register/heartbeat mappings (§3.4) before any registry mutation. Throws the
 * dedicated `ProtectedContentValidationError` (mapped to a stable 400 by the
 * server); never truncates.
 */
export function assertCanonicalSessionWithinLimit(session: CanonicalSessionState): void {
  buildProtectedSessionContentBytes({
    version: 3,
    projectName: session.projectName,
    nameText: session.nameText,
    ...(session.openingText !== undefined ? { openingText: session.openingText } : {}),
    ...(session.latestActivityText !== undefined ? { latestActivityText: session.latestActivityText } : {}),
    ...(session.workingDirectory !== undefined ? { workingDirectory: session.workingDirectory } : {}),
    ...(session.harnessProvider !== undefined ? { harnessProvider: session.harnessProvider } : {}),
  });
}

function exactRecord(value: unknown, allowedKeys: readonly string[], requiredKeys: readonly string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  const allowed = new Set(allowedKeys);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.has(key)) throw new TypeError(`${label} contains unsupported fields`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!descriptor.enumerable || !('value' in descriptor)) throw new TypeError(`${label}.${key} is invalid`);
  }
  for (const key of requiredKeys) if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
  return value as Record<string, unknown>;
}

export function immutableCopy<Value>(value: Value): Value {
  const copy = structuredClone(value);
  return deepFreeze(copy);
}

function deepFreeze<Value>(value: Value): Value {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function requireIdentifier(value: Record<string, unknown>, key: string): void {
  if (!isBoundedAgentAdapterIdentifier(value[key])) throw new TypeError(`canonical Event.${key} is invalid`);
}
function requireString(value: Record<string, unknown>, key: string): void { if (typeof value[key] !== 'string') throw new TypeError(`canonical Event.${key} is invalid`); }
function optionalString(value: Record<string, unknown>, key: string): void { if (value[key] !== undefined && typeof value[key] !== 'string') throw new TypeError(`canonical Event.${key} is invalid`); }
export function normalizeHandledAt(value: string | undefined, fallback: string): string { if (!value) return fallback; return Number.isFinite(new Date(value).getTime()) ? value : fallback; }

export function assertProducerContextMatchesSession(event: AgentAdapterEventInput, session: RegisteredSession): void {
  const expected = {
    projectName: session.projectName,
    workingDirectory: session.cwd,
    harnessProvider: session.harnessProvider ?? session.provider,
  };
  for (const [key, value] of Object.entries(expected)) {
    if ((event as unknown as Record<string, unknown>)[key] !== value) {
      throw new TypeError(`canonical Event ${key} does not match the registered Session`);
    }
  }
}

export function producerEventFingerprint(event: AgentAdapterEventInput | CanonicalEvent): string {
  const producer = event as CanonicalEvent;
  const protectedContent = buildProtectedEventContentBytes({
    version: 3,
    agentText: producer.agentText,
    ...(producer.humanText === undefined ? {} : { humanText: producer.humanText }),
    ...(producer.projectName === undefined ? {} : { projectName: producer.projectName }),
    ...(producer.workingDirectory === undefined ? {} : { workingDirectory: producer.workingDirectory }),
    ...(producer.harnessProvider === undefined ? {} : { harnessProvider: producer.harnessProvider }),
    ...(producer.needHuman === undefined ? {} : { needHuman: producer.needHuman }),
  });
  const publicMetadata = JSON.stringify({
    sessionId: producer.sessionId,
    provider: producer.provider,
    type: producer.type,
    status: producer.status,
    createdAt: producer.createdAt,
  });
  const canonical = encodeLengthPrefixedFields([
    'ariava-producer-event-fingerprint-v1',
    publicMetadata,
    base64UrlEncode(protectedContent),
  ]);
  return createHash('sha256').update(canonical).digest('base64url');
}

export function producerContextFingerprint(session: Pick<RegisteredSession, 'projectName' | 'cwd' | 'harnessProvider' | 'provider'>): string {
  return JSON.stringify({
    projectName: session.projectName,
    workingDirectory: session.cwd,
    harnessProvider: session.harnessProvider ?? session.provider,
  });
}

export function canonicalProducerContextFingerprint(session: CanonicalSessionState): string {
  return JSON.stringify({
    projectName: session.projectName,
    workingDirectory: session.workingDirectory ?? '',
    harnessProvider: session.harnessProvider ?? session.provider,
  });
}

export function normalizedOwner(session: Pick<RegisteredSession, 'provider' | 'harnessProvider'>): readonly [string, string] {
  return [session.provider, session.harnessProvider ?? session.provider] as const;
}

export function sameOwner(left: readonly [string, string], right: readonly [string, string]): boolean {
  return left[0] === right[0] && left[1] === right[1];
}

export function semanticFingerprint(session: RegisteredSession): string {
  return JSON.stringify({ sessionId: session.sessionId, provider: session.provider, projectName: session.projectName, cwd: session.cwd,
    nameText: session.nameText, openingText: session.openingText, latestActivityText: session.latestActivityText,
    harnessProvider: session.harnessProvider, pid: session.pid,
    hostId: session.hostId, status: session.status, lastEventId: session.lastEventId });
}
