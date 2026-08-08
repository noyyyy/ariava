import {
  buildNotificationPreviewPlaintextBytes,
  type CanonicalEvent,
  type CanonicalSessionState,
  type EncryptedNotificationPreviewPlaintextV2,
} from '@ariava/protocol';

const MAX_BODY_GRAPHEMES = 200;
const segmenter = new Intl.Segmenter('en', { granularity: 'grapheme' });

export function buildNotificationPreview(
  event: CanonicalEvent,
  session: CanonicalSessionState,
): EncryptedNotificationPreviewPlaintextV2 | undefined {
  if (!isCanonicalTerminal(event)) return undefined;
  const fallback = event.type === 'done' ? 'Task completed.' : 'Ariava needs your attention.';
  const normalized = normalizeNotificationPreviewBody(sanitizePreviewText(event.agentText) || fallback);
  const preview: EncryptedNotificationPreviewPlaintextV2 = {
    version: 2,
    projectName: sanitizePreviewText(session.projectName) || 'Ariava',
    eventType: event.type,
    bodyText: normalized.bodyText,
    truncated: normalized.truncated,
  };
  try { buildNotificationPreviewPlaintextBytes(preview); return preview; } catch { return undefined; }
}

export function normalizeNotificationPreviewBody(value: string): { bodyText: string; truncated: boolean } {
  const normalized = value.trim().replace(/[\t ]*\r?\n(?:[\t ]*\r?\n){2,}[\t ]*/gu, '\n\n');
  const graphemes = Array.from(segmenter.segment(normalized), ({ segment }) => segment);
  if (graphemes.length <= MAX_BODY_GRAPHEMES) return { bodyText: normalized, truncated: false };
  return { bodyText: `${graphemes.slice(0, MAX_BODY_GRAPHEMES).join('')}…`, truncated: true };
}

function isCanonicalTerminal(event: CanonicalEvent): boolean {
  return (event.type === 'done' && event.status === 'idle')
    || (event.type === 'need_human' && event.status === 'need_human');
}

function sanitizePreviewText(value: string): string {
  return value
    .replace(/-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-\r\n]*PRIVATE KEY-----|$)/giu, '[redacted credential]')
    .replace(/\b(?:basic|bearer)\s+[^\s,;]+/giu, '[redacted credential]')
    .replace(
      /(?<![\p{L}\p{N}_])(?:api[\s_-]*key|private[\s_-]*key|client[\s_-]*secret|(?:access|refresh|id|auth|bearer|session)[\s_-]*token|token|secret|password|authorization)\s*[:=]?\s*(?:basic|bearer)?\s*[^\s,;]+/giu,
      '[redacted credential]',
    )
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/gu, '[redacted credential]')
    .replace(/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu, '[redacted credential]')
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu, '[redacted credential]')
    .replace(/(?:request|response)\s+(?:body|payload)\s*[:=][^\r\n]*/giu, '[redacted payload]')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\p{Cf}]/gu, '')
    .trim();
}
