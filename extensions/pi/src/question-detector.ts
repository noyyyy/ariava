import { createHash } from 'node:crypto';

export type StoredTerminalCandidate =
  | { type: 'need_human'; reason: 'question' | 'blocked'; agentText: string; fingerprint: string }
  | { type: 'done'; reason?: never; agentText: string; fingerprint: string };

type UnfingerprintedStoredTerminalCandidate =
  | { type: 'need_human'; reason: 'question' | 'blocked'; agentText: string }
  | { type: 'done'; reason?: never; agentText: string };

export type StoredAgentTextClassification = StoredTerminalCandidate & { suppressed: boolean };

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
): StoredAgentTextClassification {
  const normalizedText = text?.trim() ?? '';
  let candidate: UnfingerprintedStoredTerminalCandidate;
  if (looksLikeQuestion(normalizedText)) {
    candidate = { type: 'need_human', reason: 'question', agentText: normalizedText };
  } else {
    const blockedReason = extractBlockedReason(normalizedText);
    if (blockedReason) {
      candidate = { type: 'need_human', reason: 'blocked', agentText: blockedReason };
    } else {
      candidate = { type: 'done', agentText: normalizedText || 'Task complete' };
    }
  }
  const fingerprint = buildFingerprint(input, candidate, normalizedText);

  return {
    ...candidate,
    fingerprint,
    suppressed: emittedFingerprints.has(fingerprint),
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

function buildFingerprint(
  input: ClassifyStoredAssistantInput,
  candidate: UnfingerprintedStoredTerminalCandidate,
  text: string,
): string {
  const reason = candidate.type === 'need_human' ? candidate.reason : 'none';
  return createHash('sha256')
    .update(`${input.sessionId}:${input.activeLeafId ?? 'no-leaf'}:${candidate.type}:${reason}:${text}`)
    .digest('hex')
    .slice(0, 16);
}
