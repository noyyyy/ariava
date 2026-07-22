import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ARIAVA_SUCCESS_ART_SOURCE_SHA256, loadOnboardingSuccessAsset } from '../src/ui/onboarding-renderer';

const publicCoreRoot = join(import.meta.dir, '..', '..', '..');

describe('reviewed onboarding success assets', () => {
  test('records the exact public ariava.png source digest', () => {
    const digest = createHash('sha256').update(readFileSync(join(publicCoreRoot, 'ariava.png'))).digest('hex');
    expect(digest).toBe('a8d6fa09ed9569a97ec6ac3f493596b86b22df33957b1933ed6efc0a67016683');
    expect(ARIAVA_SUCCESS_ART_SOURCE_SHA256).toBe(digest);
  });

  test.each([['wide', 58], ['compact', 34]] as const)('%s fixture is bounded, text-only, and nonidentifying', (name, maximumWidth) => {
    const asset = loadOnboardingSuccessAsset(name);
    const lines = asset.split('\n');
    expect(lines.length).toBeGreaterThan(10);
    expect(Math.max(...lines.map((line) => line.length))).toBeLessThanOrEqual(maximumWidth);
    expect(asset).toMatch(/[+#]/);
    expect(asset).not.toMatch(/[\u001b\r\t]/);
    expect(asset).not.toMatch(/host_|watch_|pair|secret|\/Users\/|\/home\//i);
  });
});
