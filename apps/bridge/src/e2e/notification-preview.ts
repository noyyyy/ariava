import {
  buildNotificationPreviewPlaintextBytes,
  type CanonicalEvent,
  type CanonicalSessionState,
  type EncryptedNotificationPreviewPlaintextV1,
} from '@ariava/protocol';

const MAX_BODY_GRAPHEMES = 200;
const segmenter = new Intl.Segmenter('en', { granularity: 'grapheme' });

export function buildNotificationPreview(
  event: CanonicalEvent,
  session: CanonicalSessionState,
): EncryptedNotificationPreviewPlaintextV1 | undefined {
  const state = previewState(event);
  if (!state) return undefined;

  const agentText = event.agentText.trim();
  const explicitError = state === 'error' ? event.contextText?.trim() : undefined;
  const source = agentText ? 'agentText' : explicitError ? 'error' : 'fallback';
  const selected = agentText || explicitError || fallbackFor(state);
  const normalized = normalizeNotificationPreviewBody(selected);

  const preview: EncryptedNotificationPreviewPlaintextV1 = {
    version: 1,
    projectName: session.projectName.trim() || 'Ariava',
    state,
    bodyText: normalized.bodyText,
    source,
    truncated: normalized.truncated,
  };
  try {
    buildNotificationPreviewPlaintextBytes(preview);
    return preview;
  } catch {
    return undefined;
  }
}

export function normalizeNotificationPreviewBody(value: string): { bodyText: string; truncated: boolean } {
  const normalized = value.trim().replace(/[\t ]*\r?\n(?:[\t ]*\r?\n){2,}[\t ]*/gu, '\n\n');
  const graphemes = Array.from(segmenter.segment(normalized), ({ segment }) => segment);
  if (graphemes.length <= MAX_BODY_GRAPHEMES) return { bodyText: normalized, truncated: false };
  return { bodyText: `${graphemes.slice(0, MAX_BODY_GRAPHEMES).join('')}…`, truncated: true };
}

function previewState(event: CanonicalEvent): EncryptedNotificationPreviewPlaintextV1['state'] | undefined {
  switch (event.type) {
    case 'done': return 'done';
    case 'need_human': return 'need_human';
  }
}

function fallbackFor(state: EncryptedNotificationPreviewPlaintextV1['state']): string {
  switch (state) {
    case 'done': return 'Task completed.';
    case 'need_human': return 'Ariava needs your attention.';
    case 'error': return 'The agent encountered an error.';
  }
}
