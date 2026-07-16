import { describe, expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

describe('public protocol source boundary', () => {
  test('does not expose Relay/watch/provider implementation details', () => {
    const sourceDir = join(import.meta.dir, '../src');
    const source = readdirSync(sourceDir)
      .filter((file) => file.endsWith('.ts'))
      .map((file) => readFileSync(join(sourceDir, file), 'utf8'))
      .join('\n');
    for (const forbidden of [
      ['dou', 'bao_'].join(''),
      ['APNS', 'NotificationPayload'].join(''),
      'apnsToken',
      'APNSStatus',
      ['PAIRING_CODE', 'HMAC'].join('_'),
      'issuePerWatch',
      'consumePerHost',
      'enrollmentPerIp',
      ['voice', 'ChunkBytes'].join(''),
      ['PairingCode', 'IssueResponse'].join(''),
      ['WatchPairing', 'CodeRequest'].join(''),
      ['WatchPairing', 'StatusResponse'].join(''),
      ['LinkedHost', 'Projection'].join(''),
    ]) expect(source.includes(forbidden)).toBe(false);
    expect(() => readFileSync(join(sourceDir, 'voice-reply.ts'), 'utf8')).toThrow();
  });
});
