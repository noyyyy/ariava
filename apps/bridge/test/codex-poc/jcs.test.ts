import { describe, expect, test } from 'bun:test';
import { jcs } from './jcs';

describe('RFC 8785 JCS canonicalization', () => {
  test('sorts object properties lexicographically by UTF-16 code units', () => {
    const canonical = jcs({ b: 1, a: 2, c: 3 });
    expect(canonical).toBe('{"a":2,"b":1,"c":3}');
  });

  test('sorts nested objects recursively', () => {
    const canonical = jcs({ outer: { z: 1, a: { y: 2, b: 3 } } });
    expect(canonical).toBe('{"outer":{"a":{"b":3,"y":2},"z":1}}');
  });

  test('does not reorder array elements but sorts objects inside arrays', () => {
    const canonical = jcs([{ b: 2, a: 1 }, 3, { d: 4, c: 5 }]);
    expect(canonical).toBe('[{"a":1,"b":2},3,{"c":5,"d":4}]');
  });

  test('serializes numbers with shortest round-trip representation', () => {
    expect(jcs({ n: 333333333.3333333 })).toBe('{"n":333333333.3333333}');
    expect(jcs({ n: 1e30 })).toBe('{"n":1e+30}');
    expect(jcs({ n: 0.002 })).toBe('{"n":0.002}');
  });

  test('escapes strings deterministically', () => {
    expect(jcs({ s: 'a\nb' })).toBe('{"s":"a\\nb"}');
    expect(jcs({ s: 'quote"backslash\\' })).toBe('{"s":"quote\\"backslash\\\\"}');
  });

  test('handles null, booleans, arrays, empty objects', () => {
    expect(jcs(null)).toBe('null');
    expect(jcs(true)).toBe('true');
    expect(jcs([])).toBe('[]');
    expect(jcs({})).toBe('{}');
  });

  test('rejects non-finite numbers', () => {
    expect(() => jcs({ n: Number.NaN })).toThrow('non-finite');
    expect(() => jcs({ n: Number.POSITIVE_INFINITY })).toThrow('non-finite');
  });

  test('matches the RFC 8785 sample serialization for a nested object', () => {
    const canonical = jcs({ literals: [null, true, false], numbers: [333333333.3333333, 1e30, 4.5, 0.002, 1e-27], string: '€$\u000f\nA\'B"\\\"/' });
    // RFC 8785 §3.2.3 sample, exact UTF-8 bytes (hex) from the RFC.
    expect(Buffer.from(canonical, 'utf8').toString('hex')).toBe(
      '7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62657273223a5b3333333333333333332e333333333333332c31652b33302c342e352c302e3030322c31652d32375d2c22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c222f227d',
    );
  });

  test('sorts RFC 8785 appendix property names by UTF-16 code units', () => {
    const canonical = jcs({ '\u20ac': 'Euro Sign', '\r': 'Carriage Return', '\ufb33': 'Hebrew Letter Dalet With Dagesh', '1': 'One', '\ud83d\ude00': 'Emoji: Grinning Face', '\u0080': 'Control', '\u00f6': 'Latin Small Letter O With Diaeresis' });
    // RFC 8785 appendix A: property names sorted by UTF-16 code units; JSON.stringify
    // emits printable Unicode verbatim (only U+0022/U+005C/U+0000-U+001F escaped).
    expect(canonical).toBe('{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}');
  });
});
