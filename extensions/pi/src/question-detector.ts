import type { ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentMessage } from '@earendil-works/pi-agent-core';
import { createHash } from 'node:crypto';
import { deriveLatestActivityText } from './session';

export type AgentEndClassification =
  | { type: 'question_requested'; assistantText: string; fingerprint: string }
  | { type: 'blocked'; assistantText: string; fingerprint: string; blockedReason: string }
  | { type: 'done'; assistantText: string; fingerprint: string }
  | { type: 'suppress_duplicate'; fingerprint: string; assistantText?: string; blockedReason?: string };

export interface ClassifyAgentEndInput {
  sessionId: string;
  activeLeafId?: string;
  messages?: AgentMessage[];
}

const QUESTION_PATTERNS: RegExp[] = [
  /\bwhat should i do\b/i,
  /\bhow should i\b/i,
  /\bplease clarify\b/i,
  /\bcan you confirm\b/i,
  /\bwhich\b.+\bwould you like\b/i,
  /\bdo you want me to\b/i,
];

const BLOCKED_PATTERNS: RegExp[] = [
  /\bi can't proceed until\b/i,
  /\bi cannot proceed until\b/i,
  /\bi need .+ before continuing\b/i,
  /\bwaiting for (your|user) (input|reply|confirmation|approval)\b/i,
  /\bpermission denied\b/i,
  /\bmissing credentials\b/i,
  /\brequires manual review\b/i,
  /\brequires manual intervention\b/i,
  /\bneeds manual review\b/i,
  /\bwaiting for permission\b/i,
  /\bwaiting for credentials\b/i,
  /\bmanual step\b/i,
];

const RETRYABLE_ERROR_PATTERNS: RegExp[] = [
  /\boverloaded\b/i,
  /\brate limit\b/i,
  /\btoo many requests\b/i,
  /\btimeout\b/i,
  /\btemporar(?:y|ily) unavailable\b/i,
  /\bupstream\b/i,
  /\bnetwork\b/i,
  /\b5\d\d\b/i,
  /\bwebsocket closed\b/i,
  /\bstream[_ -]?read[_ -]?error\b/i,
];

const emittedFingerprints = new Set<string>();

export function classifyAgentEnd(ctx: ExtensionContext, input: ClassifyAgentEndInput | string): AgentEndClassification {
  const normalizedInput = typeof input === 'string' ? { sessionId: input } : input;
  const text = deriveLatestActivityText(ctx, { eventMessages: normalizedInput.messages }) ?? '';
  const fingerprint = buildFingerprint(normalizedInput.sessionId, normalizedInput.activeLeafId, text);

  if (emittedFingerprints.has(fingerprint)) {
    return { type: 'suppress_duplicate', fingerprint };
  }

  if (looksLikeQuestion(text)) {
    return { type: 'question_requested', assistantText: text, fingerprint };
  }

  const blockedReason = extractBlockedReason(text);
  if (blockedReason) {
    return { type: 'blocked', assistantText: blockedReason, fingerprint, blockedReason };
  }

  return {
    type: 'done',
    assistantText: text || 'Task complete',
    fingerprint,
  };
}

export function markFingerprintEmitted(fingerprint: string): void {
  emittedFingerprints.add(fingerprint);
}

export function resetEmittedFingerprints(): void {
  emittedFingerprints.clear();
}

export function looksRetryableError(text: string): boolean {
  return RETRYABLE_ERROR_PATTERNS.some((pattern) => pattern.test(text));
}

export function looksLikeQuestion(text: string): boolean {
  const normalized = text.trim();
  if (!normalized) return false;
  if (normalized.endsWith('?')) return true;
  return QUESTION_PATTERNS.some((pattern) => pattern.test(normalized));
}

export function extractBlockedReason(text: string): string | undefined {
  const normalized = text.trim();
  if (!normalized) return undefined;
  if (BLOCKED_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return normalized;
  }
  return undefined;
}

function buildFingerprint(sessionId: string, activeLeafId: string | undefined, text: string): string {
  const hash = createHash('sha256')
    .update(`${sessionId}:${activeLeafId ?? 'no-leaf'}:${text}`)
    .digest('hex')
    .slice(0, 16);
  return hash;
}
