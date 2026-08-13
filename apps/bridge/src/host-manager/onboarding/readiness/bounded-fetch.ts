import type { StrictReadinessDependencies } from './check';

export async function fetchBounded(
  url: URL,
  init: RequestInit,
  timeoutMs: number,
  deps: Pick<StrictReadinessDependencies, 'fetch'>,
): Promise<Response> {
  const externalSignal = init.signal ?? undefined;
  throwIfAborted(externalSignal);
  const controller = linkedAbortController(externalSignal);
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await deps.fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  const error = new Error('Onboarding cancelled');
  error.name = 'AbortError';
  throw error;
}

export function linkedAbortController(signal: AbortSignal | null | undefined): AbortController {
  const controller = new AbortController();
  if (signal?.aborted) controller.abort(signal.reason);
  else signal?.addEventListener('abort', () => controller.abort(signal.reason), { once: true });
  return controller;
}

export function boundedPositive(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && value! > 0 ? Math.min(value!, 60_000) : fallback;
}
