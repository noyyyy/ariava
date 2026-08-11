import { describe, expect, test } from 'bun:test';
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { CanonicalEvent, CommandEnvelope } from '@ariava/protocol';
import type { AgentAdapter, AgentAdapterEvent } from '../src/adapter-interface';
import { buildDoneEvent, buildNeedHumanEvent, extractNeedHumanError } from '../src/events';
import ariavaPiExtension from '../src/index';
import type { PiSessionInfo } from '../src/session';

type WithoutBridgeIdentity<T> = T extends CanonicalEvent ? Omit<T, 'eventId' | 'hostId'> : never;
type TypesEqual<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends (<Value>() => Value extends Right ? 1 : 2)
    ? (<Value>() => Value extends Right ? 1 : 2) extends (<Value>() => Value extends Left ? 1 : 2) ? true : false
    : false;

const session: PiSessionInfo = {
  sessionId: 'session-1',
  provider: 'pi',
  projectName: 'demo',
  cwd: '/tmp/demo',
  nameText: 'Demo session',
  status: 'idle',
};

describe('canonical terminal event builders', () => {
  test('builds a complete producer-owned done DTO', () => {
    const event = buildDoneEvent(session, 'Finished safely.', 'Please finish.', '2026-08-07T00:00:00.000Z');

    expect(event).toEqual({
      sessionId: 'session-1',
      provider: 'pi',
      type: 'done',
      status: 'idle',
      agentText: 'Finished safely.',
      humanText: 'Please finish.',
      projectName: 'demo',
      contextText: 'Demo session · demo',
      workingDirectory: '/tmp/demo',
      hbaseSessionKey: 'session-1',
      harnessProvider: 'pi',
      createdAt: '2026-08-07T00:00:00.000Z',
    });
    expect(event).not.toHaveProperty('eventId');
    expect(event).not.toHaveProperty('hostId');
  });

  test('maps internal question and blocker classifications to protected need_human context', () => {
    expect(buildNeedHumanEvent(session, {
      reason: 'question',
      agentText: 'Which target should I use?',
      createdAt: '2026-08-07T00:00:00.000Z',
    })).toMatchObject({
      type: 'need_human',
      status: 'need_human',
      needHuman: { reason: 'question' },
      actionablePrompt: { type: 'question', label: 'Reply' },
    });
    expect(buildNeedHumanEvent(session, {
      reason: 'blocked',
      agentText: 'I need credentials before continuing.',
      createdAt: '2026-08-07T00:00:00.000Z',
    })).toMatchObject({
      type: 'need_human',
      status: 'need_human',
      needHuman: { reason: 'blocked' },
    });
  });
});

describe('structured final errors', () => {
  test.each([
    [{ stopReason: 'error', error: { code: 'context_length_exceeded', message: 'Too much context.' } }, 'context_overflow'],
    [{ stopReason: 'error', errorMessage: 'Provider failed.' }, 'provider_failure'],
    [{ stopReason: 'length' }, 'response_length'],
    [{ stopReason: 'toolUse' }, 'incomplete_tool_use'],
    [{ stopReason: 'futureReason' }, 'unknown'],
  ] as const)('maps reliable runtime signal %o to %s', (input, kind) => {
    expect(extractNeedHumanError(input)).toMatchObject({ kind, retryExhausted: true });
  });

  test('separates conservative type classification from explicit provider codes', () => {
    expect(extractNeedHumanError({
      stopReason: 'error',
      error: { type: 'context_length_exceeded', message: 'Type-only context failure.' },
    })).toEqual({
      kind: 'context_overflow',
      message: 'Type-only context failure.',
      retryExhausted: true,
    });
    expect(extractNeedHumanError({
      stopReason: 'error',
      error: { type: 'ProviderError', code: 'rate_limit_exceeded', message: 'Try later.' },
    })).toEqual({
      kind: 'provider_failure',
      message: 'Try later.',
      providerCode: 'rate_limit_exceeded',
      retryExhausted: true,
    });
    expect(extractNeedHumanError({
      stopReason: 'error',
      errorMessage: { type: 'ProviderError', code: 'stable_runtime_code', message: 'Structured runtime failure.' },
    })).toEqual({
      kind: 'provider_failure',
      message: 'Structured runtime failure.',
      providerCode: 'stable_runtime_code',
      retryExhausted: true,
    });
  });

  test('nested stable codes take precedence over generic outer code and type fields', () => {
    expect(extractNeedHumanError({
      stopReason: 'error',
      error: {
        code: 'provider_error',
        type: 'ProviderError',
        error: { code: 'context_length_exceeded', message: 'Nested context overflow.' },
      },
    })).toEqual({
      kind: 'context_overflow',
      message: 'Nested context overflow.',
      providerCode: 'context_length_exceeded',
      retryExhausted: true,
    });
    expect(extractNeedHumanError({
      stopReason: 'error',
      error: {
        code: 'provider_error',
        type: 'ProviderError',
        error: { type: 'context_window_exceeded', message: 'Nested type overflow.' },
      },
    })).toEqual({
      kind: 'context_overflow',
      message: 'Nested type overflow.',
      providerCode: 'provider_error',
      retryExhausted: true,
    });
  });

  test('recursively extracts string and object error fields with cycle and depth bounds', () => {
    expect(extractNeedHumanError({
      stopReason: 'error',
      error: { error: { type: 'ProviderError', error: 'nested runtime detail' } },
    })).toEqual({
      kind: 'provider_failure',
      message: 'nested runtime detail',
      retryExhausted: true,
    });
    expect(extractNeedHumanError({
      stopReason: 'error',
      error: { error: { code: 'nested_stable_code', error: { message: 'deep runtime detail' } } },
    })).toEqual({
      kind: 'provider_failure',
      message: 'deep runtime detail',
      providerCode: 'nested_stable_code',
      retryExhausted: true,
    });

    const cyclic: Record<string, unknown> = { type: 'ProviderError' };
    cyclic.error = cyclic;
    expect(extractNeedHumanError({ stopReason: 'error', error: cyclic })).toEqual({
      kind: 'provider_failure',
      message: 'Pi stopped after an unrecovered error.',
      retryExhausted: true,
    });
  });

  test('sanitizes controls, credentials, private keys, and multiline serialized payloads', () => {
    const message = [
      'Failure\u0000\u202E   details',
      'Authorization: Bearer secret-token',
      'api_key=sk-live-secret',
      'token: token-secret',
      '-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----',
      'request body:',
      '{',
      '  "password": "full-body",',
      '  "nested": { "access_token": "nested-secret" }',
      '}',
      'continued safe diagnostic',
      'response_payload = [',
      '  { "refresh_token": "refresh-secret" }',
      ']',
      'final safe detail',
    ].join('\n');
    const error = extractNeedHumanError({ stopReason: 'error', error: { message } });

    expect(error.message).not.toMatch(/[\u0000-\u001F\u007F-\u009F\p{Cf}]/u);
    for (const secret of [
      'secret-token', 'sk-live-secret', 'token-secret', 'private-material',
      'full-body', 'nested-secret', 'refresh-secret',
    ]) {
      expect(error.message).not.toContain(secret);
    }
    expect(error.message).toContain('continued safe diagnostic');
    expect(error.message).toContain('final safe detail');
    expect(error.message.match(/\[redacted payload\]/g)).toHaveLength(2);
    expect(error.message).not.toMatch(/authorization\s*:|bearer\s+|private key|request body\s*:|response_payload/i);
    expect(extractNeedHumanError({
      stopReason: 'error',
      errorMessage: '-----BEGIN PRIVATE KEY-----\nunterminated-private-material',
    }).message).toBe('[redacted credential]');
  });

  test('redacts standalone credentials while preserving mixed safe diagnostics', () => {
    const credentials = [
      'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      'AKIAIOSFODNN7EXAMPLE',
    ];
    const message = [
      'Provider failed safely before',
      ...credentials,
      'Authorization = Bearer labeled-auth-token',
      'api-key: labeled-api-key',
      'private_key = labeled-private-key',
      'request_body={"secret":"labeled-body"}',
      'after credential details remain useful',
    ].join('\n');

    const sanitized = extractNeedHumanError({ stopReason: 'error', error: { message } }).message;
    expect(sanitized).toContain('Provider failed safely before');
    expect(sanitized).toContain('after credential details remain useful');
    expect(sanitized.match(/\[redacted credential\]/g)?.length).toBeGreaterThanOrEqual(6);
    expect(sanitized).toContain('[redacted payload]');
    for (const credential of [...credentials, 'labeled-auth-token', 'labeled-api-key', 'labeled-private-key', 'labeled-body']) {
      expect(sanitized).not.toContain(credential);
    }
    expect(extractNeedHumanError({
      stopReason: 'error',
      errorMessage: 'A skirmish and task-id are safe words.',
    }).message).toBe('A skirmish and task-id are safe words.');
  });

  test('redacts quoted JSON and compound credential labels', () => {
    const message = [
      'safe prefix',
      '{"access_token":"access-secret", "refresh_token": "refresh-secret", "client_secret":"client-secret"}',
      "'id_token' = 'id-secret'",
      'safe suffix',
    ].join('\n');
    const sanitized = extractNeedHumanError({ stopReason: 'error', error: { message } }).message;

    expect(sanitized).toContain('safe prefix');
    expect(sanitized).toContain('safe suffix');
    expect(sanitized.match(/\[redacted credential\]/g)).toHaveLength(4);
    for (const secret of ['access-secret', 'refresh-secret', 'client-secret', 'id-secret']) {
      expect(sanitized).not.toContain(secret);
    }
  });

  test('normalizes inserted control and format characters before protected marker detection', () => {
    const message = [
      'safe prefix',
      'a\u200Bpi_k\u0000ey=hidden-api-key',
      'ac\u2060cess_to\u0007ken=hidden-access-token',
      'requ\u200Best_bo\u0000dy={"secret":"hidden-request-body"}',
      'Auth\u202Eorization: Ba\u200Bsic hidden-basic-value',
      '-----BE\u2060GIN PRI\u0000VATE KEY-----\nhidden-private-material\n-----END PRIVATE KEY-----',
      'safe suffix',
    ].join('\n');
    const sanitized = extractNeedHumanError({ stopReason: 'error', error: { message } }).message;

    expect(sanitized).toContain('safe prefix');
    expect(sanitized).toContain('safe suffix');
    expect(sanitized).toContain('[redacted payload]');
    expect(sanitized).not.toMatch(/[\u0000-\u001F\u007F-\u009F\p{Cf}]/u);
    for (const secret of [
      'hidden-api-key', 'hidden-access-token', 'hidden-request-body',
      'hidden-basic-value', 'hidden-private-material',
    ]) {
      expect(sanitized).not.toContain(secret);
    }
  });

  test('redacts complete standalone, folded, quoted, and control-obfuscated scheme credentials', () => {
    const secrets = [
      'QWxhZGRpbjpvcGVuIHNlc2FtZQ==',
      'abc token',
      'folded-basic-value',
      'hidden-bearer-value',
    ];
    const sanitized = extractNeedHumanError({
      stopReason: 'error',
      errorMessage: [
        `safe before; Basic ${secrets[0]}; safe middle`,
        `Bearer "${secrets[1]}"; safe quoted`,
        `Ba\u200Bs\u0000ic\n${secrets[2]}; safe folded`,
        `Be\u2060arer '${secrets[3]}'; safe after`,
      ].join('\n'),
    }).message;

    for (const text of ['safe before', 'safe middle', 'safe quoted', 'safe folded', 'safe after']) {
      expect(sanitized).toContain(text);
    }
    expect(sanitized.match(/\[redacted credential\]/g)).toHaveLength(4);
    for (const secret of secrets) expect(sanitized).not.toContain(secret);
    expect(sanitized).not.toMatch(/\b(?:basic|bearer)\b/iu);
  });

  test('redacts folded Authorization values without consuming following fields', () => {
    const separators = [
      ['LF', '\n'],
      ['CR', '\r'],
      ['CRLF', '\r\n'],
      ['LINE SEPARATOR', '\u2028'],
      ['PARAGRAPH SEPARATOR', '\u2029'],
    ] as const;

    for (const [separatorName, separator] of separators) {
      for (const scheme of ['Basic', 'Bearer', 'Custom']) {
        const credential = `${separatorName.toLowerCase().replaceAll(' ', '-')}-${scheme.toLowerCase()}-credential`;
        const nextField = `X-Request-Id: safe-${separatorName.toLowerCase().replaceAll(' ', '-')}-${scheme.toLowerCase()}`;
        const sanitized = extractNeedHumanError({
          stopReason: 'error',
          errorMessage: `safe before; Authorization:${separator}${scheme} ${credential}\n${nextField}; safe after`,
        }).message;

        expect(sanitized).toContain('safe before');
        expect(sanitized).toContain(nextField);
        expect(sanitized).toContain('safe after');
        expect(sanitized.match(/\[redacted credential\]/g)).toHaveLength(1);
        expect(sanitized).not.toContain(credential);
        expect(sanitized).not.toMatch(/authorization/iu);
      }
    }
  });

  test('removes stack frames but preserves safe text beginning with at', () => {
    const message = [
      'Provider failed',
      'at capacity while retrying',
      'at processRequest (/tmp/provider.ts:42:7)',
      'at async /tmp/runner.ts:9:3',
      'safe tail',
    ].join('\n');
    const sanitized = extractNeedHumanError({ stopReason: 'error', error: { message } }).message;

    expect(sanitized).toContain('at capacity while retrying');
    expect(sanitized).toContain('safe tail');
    expect(sanitized).not.toContain('processRequest');
    expect(sanitized).not.toContain('/tmp/runner.ts');
  });

  test('bounds message and rejects unstable provider codes deterministically', () => {
    const error = extractNeedHumanError({
      stopReason: 'error',
      error: { code: `bad code ${'x'.repeat(200)}`, message: `failure ${'🙂'.repeat(2_000)}` },
    });

    expect(new TextEncoder().encode(error.message).byteLength).toBeLessThanOrEqual(2_000);
    expect(error.message).toEndWith('…');
    expect(error.providerCode).toBeUndefined();
  });

  test.each([
    'sk-AAAAAAAAAAAAAAAA',
    'Bearer.token-value',
    'AKIAABCDEFGHIJKLMNOP',
    'token-secret',
    'access_token.secret-value',
    'client_secret.secret-value',
  ])('rejects credential-shaped provider code %s', (providerCode) => {
    const error = extractNeedHumanError({
      stopReason: 'error', error: { code: providerCode, message: 'Provider failed safely.' },
    });
    expect(error.providerCode).toBeUndefined();
  });

  test('replaces malformed surrogate code units with canonical Unicode', () => {
    const error = extractNeedHumanError({ stopReason: 'error', errorMessage: 'failure \uD800 detail' });
    expect(error.message).toBe('failure � detail');
    expect(new TextEncoder().encode(error.message).byteLength).toBeLessThanOrEqual(2_000);
  });
});

describe('ariavaPiExtension event mapping', () => {
  test('registers expected handlers with a complete canonical adapter API', async () => {
    const registered: string[] = [];
    const api = {
      on: (event: string, _handler: (event: unknown, ctx: ExtensionContext) => Promise<unknown>) => {
        registered.push(event);
      },
      sendUserMessage: () => {},
    } as unknown as ExtensionAPI;

    const testAdapter: AgentAdapter = {
      registerSession: async () => ({ sessionId: 's', registeredAt: '' }),
      unregisterSession: async () => {},
      pushEvent: async (_event: AgentAdapterEvent) => ({ eventId: 'evt-1' }),
      handleSession: async () => ({ ok: true, hostId: 'host-1', sessionId: 's', handledThroughEventId: 'evt-1' }),
      heartbeat: async () => {},
      pollCommands: async (_sessionId: string, _timeoutMs: number) => null as CommandEnvelope | null,
      submitResult: async () => {},
    };

    await ariavaPiExtension(api, testAdapter);

    expect(registered).toContain('session_start');
    expect(registered).toContain('session_shutdown');
    expect(registered).toContain('agent_start');
    expect(registered).toContain('agent_end');
    expect(registered).toContain('agent_settled');
  });

  test('adapter event DTO is exactly canonical minus Bridge-assigned identity fields', () => {
    type ExpectedAgentAdapterEvent = WithoutBridgeIdentity<CanonicalEvent>;
    const exactTypeBoundary: TypesEqual<AgentAdapterEvent, ExpectedAgentAdapterEvent> = true;
    const assertAssignable = (_event: AgentAdapterEvent): void => {};
    const event = buildDoneEvent(session, 'Complete.', undefined, '2026-08-07T00:00:00.000Z');
    assertAssignable(event);
    const canonicalAfterBridge: CanonicalEvent = { ...event, eventId: 'event-1', hostId: 'host-1' };
    expect(exactTypeBoundary).toBe(true);
    expect(canonicalAfterBridge).toMatchObject({ type: 'done', status: 'idle' });
  });
});
