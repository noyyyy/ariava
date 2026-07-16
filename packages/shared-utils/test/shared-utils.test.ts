import { describe, expect, test } from 'bun:test';
import { clampText, createId, ensureArray } from '../src';

describe('shared utils', () => {
  test('creates predictable ids when inputs are fixed', () => {
    expect(createId('evt', 1234, 0.5)).toMatch(/^evt_/);
  });

  test('normalizes arrays', () => {
    expect(ensureArray('x')).toEqual(['x']);
    expect(ensureArray(['x', 'y'])).toEqual(['x', 'y']);
    expect(ensureArray(null)).toEqual([]);
  });

  test('clamps text cleanly', () => {
    expect(clampText('  hello   world  ', 20)).toBe('hello world');
    expect(clampText('abcdefghijklmnopqrstuvwxyz', 8)).toBe('abcdefg…');
  });
});
