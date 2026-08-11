import type {
  ActionablePrompt,
  NeedHumanContext,
  NeedHumanError,
  NeedHumanErrorKind,
} from '@ariava/protocol';
import type { AgentAdapterEvent } from './adapter-interface';
import type { PiSessionInfo } from './session';
import { normalizeAssistantTextForEvent } from './session';

const ERROR_MESSAGE_MAX_BYTES = 2_000;
const PROVIDER_CODE_MAX_BYTES = 128;
const UNKNOWN_STOP_REASON_MAX_CHARACTERS = 80;
const ERROR_EXTRACTION_MAX_DEPTH = 8;
const encoder = new TextEncoder();
const PROTECTED_MARKER_WORDS = [
  'authorization',
  'api',
  'key',
  'private',
  'client',
  'access',
  'refresh',
  'id',
  'auth',
  'basic',
  'bearer',
  'session',
  'token',
  'secret',
  'password',
  'request',
  'response',
  'body',
  'payload',
  'begin',
  'end',
];
const insertedHiddenCharacterPattern = '[\\u0000-\\u001F\\u007F-\\u009F\\p{Cf}]*';
const protectedMarkerPattern = new RegExp(
  PROTECTED_MARKER_WORDS
    .map((word) => [...word].join(insertedHiddenCharacterPattern))
    .join('|'),
  'giu',
);

const CONTEXT_OVERFLOW_SIGNALS = new Set([
  'context_length_exceeded',
  'context_overflow',
  'context_window_exceeded',
  'contextwindowexceedederror',
]);

export interface RuntimeTerminalErrorInput {
  stopReason?: string;
  errorMessage?: unknown;
  error?: unknown;
}

export type NeedHumanEventInput = {
  reason: 'question' | 'blocked';
  agentText: string;
  humanText?: string;
  createdAt?: string;
  correlationId?: string;
} | {
  reason: 'error';
  error: NeedHumanError;
  agentText?: string;
  humanText?: string;
  createdAt?: string;
  correlationId?: string;
};

export function buildDoneEvent(
  session: PiSessionInfo,
  agentText?: string,
  humanText?: string,
  createdAt = new Date().toISOString(),
): AgentAdapterEvent {
  return {
    ...buildEventBase(session, {
      agentText: normalizeAssistantTextForEvent('done', session, agentText),
      humanText,
      createdAt,
    }),
    type: 'done',
    status: 'idle',
  };
}

export function buildNeedHumanEvent(session: PiSessionInfo, input: NeedHumanEventInput): AgentAdapterEvent {
  const createdAt = input.createdAt ?? new Date().toISOString();
  const needHuman: NeedHumanContext = input.reason === 'error'
    ? { reason: 'error', error: input.error }
    : { reason: input.reason };
  const agentText = input.reason === 'error'
    ? input.agentText ?? input.error.message
    : input.agentText;
  const actionablePrompt: ActionablePrompt | undefined = input.reason === 'question'
    ? {
        promptId: `question-${Date.parse(createdAt)}`,
        type: 'question',
        label: 'Reply',
      }
    : undefined;

  return {
    ...buildEventBase(session, {
      agentText: normalizeAssistantTextForEvent('need_human', session, agentText),
      humanText: input.humanText,
      createdAt,
      correlationId: input.correlationId,
      actionablePrompt,
    }),
    type: 'need_human',
    status: 'need_human',
    needHuman,
  };
}

export function extractNeedHumanError(input: RuntimeTerminalErrorInput): NeedHumanError {
  const structuredErrorMessage = extractStructuredError(input.errorMessage);
  const structuredError = extractStructuredError(input.error);
  const explicitCodes = [...structuredError.codes, ...structuredErrorMessage.codes];
  const explicitTypes = [...structuredError.types, ...structuredErrorMessage.types];
  const selectedCode = explicitCodes.find(isContextOverflowSignal) ?? explicitCodes[0];
  const classificationSignal = explicitCodes.find(isContextOverflowSignal)
    ?? explicitTypes.find(isContextOverflowSignal);
  const kind = classifyErrorKind(input.stopReason, classificationSignal);
  const fallback = fallbackErrorMessage(input.stopReason);
  const message = sanitizeProtectedErrorMessage(
    structuredError.message ?? structuredErrorMessage.message ?? extractErrorMessage(input.errorMessage) ?? fallback,
  ) ?? fallback;
  const providerCode = sanitizeProviderCode(selectedCode);

  return {
    kind,
    message,
    ...(providerCode ? { providerCode } : {}),
    retryExhausted: true,
  };
}

export function sanitizeProtectedErrorMessage(value: unknown): string | undefined {
  const extracted = extractErrorMessage(value);
  if (!extracted) return undefined;

  const normalized = normalizeForProtectedDetection(extracted);
  const redacted = redactSerializedPayloads(normalized)
    .replace(/-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/giu, '[redacted credential]')
    .replace(/-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*$/giu, '[redacted credential]')
    .replace(
      /(?<![\p{L}\p{N}_])["']?authorization["']?[ \t]*[:=]\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|(?:[^\s,;}\]]+[ \t]+)?[^\s,;}\]]+)/giu,
      '[redacted credential]',
    )
    .replace(
      /\b(?:basic|bearer)\s+(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)/giu,
      '[redacted credential]',
    )
    .replace(
      /(?<![\p{L}\p{N}_])["']?(?:api[\s_-]*key|private[\s_-]*key|client[\s_-]*secret|(?:access|refresh|id|auth|bearer|session)[\s_-]*token|token|secret|password)["']?\s*[:=]\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)/giu,
      '[redacted credential]',
    )
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/gu, '[redacted credential]')
    .replace(/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu, '[redacted credential]')
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu, '[redacted credential]')
    .replace(
      /(^|[\r\n])[ \t]*at[ \t]+(?:(?:async|new)[ \t]+)?(?:[^\r\n]*?[ \t]+\((?:[^()\r\n]+:\d+:\d+|index[ \t]+\d+|native)\)|[^\s()]+:\d+:\d+)[ \t]*(?=$|[\r\n])/gmu,
      '$1',
    )
    .replace(/[\u0000-\u001F\u007F-\u009F]/gu, ' ')
    .replace(/\p{Cf}/gu, '')
    .replace(/[\uD800-\uDFFF]/gu, '\uFFFD')
    .replace(/\s+/gu, ' ')
    .trim();
  if (!redacted) return undefined;
  return truncateUtf8(redacted, ERROR_MESSAGE_MAX_BYTES);
}

function normalizeForProtectedDetection(value: string): string {
  return value
    .replace(protectedMarkerPattern, (marker) =>
      marker.replace(/[\u0000-\u001F\u007F-\u009F\p{Cf}]/gu, ''),
    )
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/gu, '')
    .replace(/\p{Cf}/gu, '');
}

function redactSerializedPayloads(value: string): string {
  const markerPattern = /\b(?:request|response)[\s_-]+(?:body|payload)[ \t]*[:=][ \t]*/giu;
  let result = '';
  let cursor = 0;

  for (let match = markerPattern.exec(value); match; match = markerPattern.exec(value)) {
    result += value.slice(cursor, match.index);
    let payloadStart = markerPattern.lastIndex;
    let payloadEnd = payloadStart;
    while (payloadStart < value.length && /\s/u.test(value[payloadStart] ?? '')) payloadStart += 1;

    const opener = value[payloadStart];
    if (opener === '{' || opener === '[') {
      payloadEnd = findSerializedBlockEnd(value, payloadStart);
    } else {
      const lineEnd = value.slice(payloadStart).search(/[\r\n]/u);
      payloadEnd = lineEnd === -1 ? value.length : payloadStart + lineEnd;
    }

    result += '[redacted payload]';
    cursor = payloadEnd;
    markerPattern.lastIndex = payloadEnd;
  }

  return result + value.slice(cursor);
}

function findSerializedBlockEnd(value: string, start: number): number {
  const stack: string[] = [];
  let quote: '"' | "'" | undefined;
  let escaped = false;

  for (let index = start; index < value.length; index += 1) {
    const character = value[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === '{' || character === '[') {
      stack.push(character);
      continue;
    }
    if (character !== '}' && character !== ']') continue;
    const expected = character === '}' ? '{' : '[';
    if (stack.at(-1) !== expected) return value.length;
    stack.pop();
    if (stack.length === 0) return index + 1;
  }

  return value.length;
}

function buildEventBase(
  session: PiSessionInfo,
  input: {
    agentText: string;
    humanText?: string;
    createdAt: string;
    actionablePrompt?: ActionablePrompt;
    correlationId?: string;
  },
): Omit<AgentAdapterEvent, 'type' | 'status' | 'needHuman'> {
  return {
    sessionId: session.sessionId,
    provider: session.provider,
    agentText: input.agentText,
    ...(input.humanText !== undefined ? { humanText: input.humanText } : {}),
    projectName: session.projectName,
    contextText: buildContextText(session),
    workingDirectory: session.cwd,
    hbaseSessionKey: session.hbaseSessionKey ?? session.sessionId,
    harnessProvider: session.harnessProvider ?? session.provider,
    ...(input.actionablePrompt ? { actionablePrompt: input.actionablePrompt } : {}),
    ...(input.correlationId ? { correlationId: input.correlationId } : {}),
    createdAt: input.createdAt,
  };
}

type StructuredError = { types: string[]; codes: string[]; message?: string };

function extractStructuredError(
  value: unknown,
  seen = new WeakSet<object>(),
  depth = 0,
): StructuredError {
  if (typeof value === 'string') return { types: [], codes: [], message: explicitString(value) };
  if (!value || typeof value !== 'object' || depth >= ERROR_EXTRACTION_MAX_DEPTH || seen.has(value)) {
    return { types: [], codes: [] };
  }
  seen.add(value);
  const record = value as Record<string, unknown>;
  const nested = extractStructuredError(record.error, seen, depth + 1);
  const type = explicitString(record.type);
  const code = explicitString(record.code);
  return {
    types: [...(type ? [type] : []), ...nested.types],
    codes: [...(code ? [code] : []), ...nested.codes],
    message: extractErrorMessage(record.message, new WeakSet<object>(), depth + 1) ?? nested.message,
  };
}

function extractErrorMessage(
  value: unknown,
  seen = new WeakSet<object>(),
  depth = 0,
): string | undefined {
  if (typeof value === 'string' && value.trim()) return value;
  if (value instanceof Error && value.message.trim()) return value.message;
  if (!value || typeof value !== 'object' || depth >= ERROR_EXTRACTION_MAX_DEPTH || seen.has(value)) return undefined;
  seen.add(value);
  const record = value as Record<string, unknown>;
  return extractErrorMessage(record.message, seen, depth + 1)
    ?? extractErrorMessage(record.error, seen, depth + 1);
}

function explicitString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function isContextOverflowSignal(stableSignal: string): boolean {
  return CONTEXT_OVERFLOW_SIGNALS.has(stableSignal.replace(/[.\s:/-]/gu, '_').toLowerCase());
}

function classifyErrorKind(stopReason: string | undefined, stableSignal: string | undefined): NeedHumanErrorKind {
  if (stableSignal && isContextOverflowSignal(stableSignal)) return 'context_overflow';
  switch (stopReason) {
    case 'error':
      return 'provider_failure';
    case 'length':
      return 'response_length';
    case 'toolUse':
      return 'incomplete_tool_use';
    default:
      return 'unknown';
  }
}

function fallbackErrorMessage(stopReason: string | undefined): string {
  switch (stopReason) {
    case 'error':
      return 'Pi stopped after an unrecovered error.';
    case 'length':
      return 'Pi stopped after reaching the response length limit.';
    case 'toolUse':
      return 'Pi stopped while waiting to use a tool.';
    default: {
      const reason = sanitizeProtectedErrorMessage(stopReason);
      if (!reason) return 'Pi stopped for an unsupported reason.';
      const boundedReason = [...reason].slice(0, UNKNOWN_STOP_REASON_MAX_CHARACTERS).join('').trimEnd();
      return `Pi stopped for an unsupported reason: ${boundedReason}${boundedReason.length < reason.length ? '…' : ''}.`;
    }
  }
}

const PROVIDER_CODE_CREDENTIAL_PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{16,}\b/u,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /^(?:basic|bearer)[._:/-]/iu,
  /^(?:api[._:/-]?key|(?:access|refresh|id|auth|bearer|session)[._:/-]?token|client[._:/-]?secret|token|secret|password|authorization)[._:/-]/iu,
] as const;

function sanitizeProviderCode(value: string | undefined): string | undefined {
  if (!value || !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u.test(value)) return undefined;
  if (PROVIDER_CODE_CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value))) return undefined;
  return encoder.encode(value).byteLength <= PROVIDER_CODE_MAX_BYTES ? value : undefined;
}

function truncateUtf8(value: string, maxBytes: number): string {
  if (encoder.encode(value).byteLength <= maxBytes) return value;
  const ellipsis = '…';
  const targetBytes = maxBytes - encoder.encode(ellipsis).byteLength;
  let result = '';
  let byteLength = 0;
  for (const character of value) {
    const characterBytes = encoder.encode(character).byteLength;
    if (byteLength + characterBytes > targetBytes) break;
    result += character;
    byteLength += characterBytes;
  }
  return `${result.trimEnd()}${ellipsis}`;
}

function buildContextText(session: Pick<PiSessionInfo, 'nameText' | 'projectName'>): string {
  const name = session.nameText.trim();
  const project = session.projectName.trim();
  if (name && project && name !== project) return `${name} · ${project}`;
  return project || name;
}
