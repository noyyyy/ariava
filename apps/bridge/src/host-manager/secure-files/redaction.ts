export function redactSensitive(value: unknown, secrets: readonly string[] = []): unknown {
  const secretSet = [...secrets.filter(Boolean)].sort((a, b) => b.length - a.length);
  const sensitive = /(?:private.*key|secret|token|authorization|password)/iu;
  const visit = (item: unknown): unknown => {
    if (typeof item === 'string') {
      let result = item;
      for (const secret of secretSet) result = result.replaceAll(secret, '<redacted>');
      return result;
    }
    if (Array.isArray(item)) return item.map(visit);
    if (item && typeof item === 'object') {
      return Object.fromEntries(Object.entries(item).map(([key, entry]) => [key, sensitive.test(key) ? '<redacted>' : visit(entry)]));
    }
    return item;
  };
  return visit(value);
}
