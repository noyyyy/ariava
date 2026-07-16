export function isoNow(date = new Date()): string {
  return date.toISOString();
}

export function createId(prefix: string, now = Date.now(), random = Math.random()): string {
  const entropy = Math.floor(random * 1_000_000)
    .toString(36)
    .padStart(4, '0');
  return `${prefix}_${now.toString(36)}${entropy}`;
}

export function ensureArray<T>(value: T | T[] | undefined | null): T[] {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

export function clampText(value: string, max: number): string {
  const normalized = value.replace(/\s+/g, ' ').trim();
  if (normalized.length <= max) return normalized;
  return `${normalized.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function eventTypeToLabel(type: string): string {
  switch (type) {
    case 'approval_requested':
      return 'Needs approval';
    case 'question_requested':
      return 'Agent question';
    case 'blocked':
      return 'Session blocked';
    case 'done':
      return 'Task complete';
    case 'working':
      return 'In progress';
    case 'summary_updated':
      return 'Summary updated';
    case 'driver_error':
      return 'Driver error';
    case 'host_unavailable':
      return 'Host unavailable';
    default:
      return 'Agent update';
  }
}
