import { createHash } from 'node:crypto';

export type StoredAssistantClassification =
  | { type: 'question_requested'; assistantText: string; fingerprint: string }
  | { type: 'blocked'; assistantText: string; fingerprint: string; blockedReason: string }
  | { type: 'done'; assistantText: string; fingerprint: string }
  | { type: 'suppress_duplicate'; fingerprint: string; assistantText?: string; blockedReason?: string };

export interface ClassifyStoredAssistantInput {
  sessionId: string;
  activeLeafId?: string;
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

const emittedFingerprints = new Set<string>();

export function classifyStoredAssistantText(
  text: string | undefined,
  input: ClassifyStoredAssistantInput,
): StoredAssistantClassification {
  const normalizedText = text?.trim() ?? '';
  const fingerprint = buildFingerprint(input.sessionId, input.activeLeafId, normalizedText);

  if (emittedFingerprints.has(fingerprint)) return { type: 'suppress_duplicate', fingerprint };

  if (looksLikeQuestion(normalizedText)) {
    return { type: 'question_requested', assistantText: normalizedText, fingerprint };
  }

  const blockedReason = extractBlockedReason(normalizedText);
  if (blockedReason) return { type: 'blocked', assistantText: blockedReason, fingerprint, blockedReason };

  return {
    type: 'done',
    assistantText: normalizedText || 'Task complete',
    fingerprint,
  };
}

export function markFingerprintEmitted(fingerprint: string): void {
  emittedFingerprints.add(fingerprint);
}

export function resetEmittedFingerprints(): void {
  emittedFingerprints.clear();
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
  return createHash('sha256')
    .update(`${sessionId}:${activeLeafId ?? 'no-leaf'}:${text}`)
    .digest('hex')
    .slice(0, 16);
}
