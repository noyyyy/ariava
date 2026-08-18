/**
 * Minimal RFC 8785 (JCS) canonical JSON serialization for the Codex PoC harness.
 *
 * Implements the deterministic serialization rules required by the spec:
 * - object property names sorted by UTF-16 code units (lexicographic);
 * - arrays keep element order (but nested objects inside arrays are sorted);
 * - numbers serialized using ECMAScript `JSON.stringify` semantics (IEEE-754
 *   double, shortest round-trip representation) which matches RFC 8785 §3.2.3;
 * - strings serialized with JSON escaping, which for the ASCII subset used by
 *   the evidence schema matches RFC 8785 exactly (non-ASCII text is not
 *   permitted in evidence fields; unknown non-ASCII input is rejected by the
 *   codec before it reaches this function).
 *
 * No external dependencies.
 */

export type JcsValue =
  | null
  | boolean
  | number
  | string
  | JcsValue[]
  | { [key: string]: JcsValue };

function escapeString(value: string): string {
  return JSON.stringify(value);
}

function serialize(value: JcsValue, depth: number): string {
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: non-finite number cannot be canonicalized');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return escapeString(value);
  if (Array.isArray(value)) {
    if (depth > 100) throw new Error('JCS: maximum depth exceeded');
    return `[${value.map((entry) => serialize(entry, depth + 1)).join(',')}]`;
  }
  if (depth > 100) throw new Error('JCS: maximum depth exceeded');
  const keys = Object.keys(value).sort((left, right) => {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
  });
  const parts: string[] = [];
  for (const key of keys) {
    parts.push(`${escapeString(key)}:${serialize(value[key], depth + 1)}`);
  }
  return `{${parts.join(',')}}`;
}

/** Canonicalize any JSON-serializable value per RFC 8785. */
export function jcs(value: JcsValue): string {
  return serialize(value, 0);
}
