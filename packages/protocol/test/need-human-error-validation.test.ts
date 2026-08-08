import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  isCanonicalNeedHumanErrorMessage,
  validateNeedHumanError,
} from '../src';

type TextDescriptor = {
  literal?: string;
  repeat?: string;
  count?: number;
  suffix?: string;
};

type ParityCase = {
  name: string;
  message: TextDescriptor;
  providerCode?: TextDescriptor;
  messageExpected?: boolean;
  retryExhausted?: boolean;
  expected: boolean;
};

type ParityFixture = {
  version: number;
  cases: ParityCase[];
};

function materialize(descriptor: TextDescriptor): string {
  if (descriptor.literal !== undefined) return descriptor.literal;
  if (descriptor.repeat !== undefined && descriptor.count !== undefined) {
    return descriptor.repeat.repeat(descriptor.count) + (descriptor.suffix ?? '');
  }
  throw new TypeError('invalid parity text descriptor');
}

const fixture = JSON.parse(readFileSync(
  join(import.meta.dir, 'fixtures', 'need-human-error-validation-v2.json'),
  'utf8',
)) as ParityFixture;

describe('NeedHumanError cross-language validation parity', () => {
  test('uses the reviewed fixture schema', () => {
    expect(fixture.version).toBe(2);
    expect(fixture.cases.length).toBeGreaterThan(0);
    expect(new Set(fixture.cases.map(({ name }) => name)).size).toBe(fixture.cases.length);
  });

  for (const parityCase of fixture.cases) {
    test(parityCase.name, () => {
      const message = materialize(parityCase.message);
      const providerCode = parityCase.providerCode === undefined
        ? undefined
        : materialize(parityCase.providerCode);
      const value = {
        kind: 'provider_failure',
        message,
        ...(providerCode === undefined ? {} : { providerCode }),
        retryExhausted: parityCase.retryExhausted ?? true,
      };

      expect(isCanonicalNeedHumanErrorMessage(message)).toBe(
        parityCase.messageExpected ?? parityCase.expected,
      );
      expect(validateNeedHumanError(value).success).toBe(parityCase.expected);
    });
  }
});
