import { isCanonicalTimestamp, type CommandResult } from '@ariava/protocol';

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

const RESULT_KEYS = ['commandId', 'hostId', 'sessionId', 'accepted', 'status', 'updatedAt'] as const;
const encoder = new TextEncoder();

export function validateAgentAdapterCommandResult(value: unknown): value is AgentAdapterCommandResult {
  if (!isExactResultRecord(value)) return false;
  return isIdentifier(value.commandId)
    && isIdentifier(value.hostId)
    && isIdentifier(value.sessionId)
    && isCanonicalTimestamp(value.updatedAt)
    && ((value.accepted === true && value.status === 'executed')
      || (value.accepted === false && (value.status === 'failed' || value.status === 'rejected')));
}

export function parseAgentAdapterCommandResult(value: unknown): AgentAdapterCommandResult {
  if (!validateAgentAdapterCommandResult(value)) {
    throw new TypeError('Agent Adapter command result is invalid');
  }
  return structuredClone(value);
}

export function asCommandResult(value: AgentAdapterCommandResult): CommandResult {
  return value;
}

function isExactResultRecord(value: unknown): value is Record<(typeof RESULT_KEYS)[number], unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== RESULT_KEYS.length) return false;
  for (const key of keys) {
    if (typeof key !== 'string' || !RESULT_KEYS.includes(key as (typeof RESULT_KEYS)[number])) return false;
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return RESULT_KEYS.every((key) => Object.hasOwn(value, key));
}

function isIdentifier(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && encoder.encode(value).byteLength <= 256
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
