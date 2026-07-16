import { afterEach, describe, expect, test } from 'bun:test';
import { base64UrlDecode, buildCanonicalRequest, contentSha256 } from '@ariava/protocol';
import { generateHostIdentity } from '../src/identity/host-identity';
import { RelayClient } from '../src/relay-client';

const servers: Array<{ stop(closeActiveConnections?: boolean): void }> = [];

afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});

describe('RelayClient handle transport', () => {
  test('posts the target event ID to the signed v2 Bridge handle endpoint', async () => {
    const identity = (await generateHostIdentity({ type: 'linux-json', path: '/tmp/identity.json' })).identity;
    const timestamp = '2026-07-16T00:00:00.000Z';
    const nonce = 'AAAAAAAAAAAAAAAAAAAAAA';
    let captured: { url: string; headers: Headers; body: string } | undefined;
    const server = Bun.serve({
      port: 0,
      fetch: async (request) => {
        captured = { url: request.url, headers: new Headers(request.headers), body: await request.text() };
        return Response.json({ ok: true, hostId: identity.hostId, sessionId: 'sess-1', handledThroughEventId: 'evt-2' });
      },
    });
    servers.push(server);
    const client = new RelayClient({
      baseUrl: `http://127.0.0.1:${server.port}`,
      signer: identity.signer,
      now: () => new Date(timestamp),
      nonce: () => nonce,
    });

    await client.handleSession('sess-1', {
      handledThroughEventId: 'evt-2', handledAt: '2026-07-16T00:00:01.000Z', action: 'pi_input',
    });

    expect(captured).toBeDefined();
    expect(new URL(captured!.url).pathname).toBe('/v2/bridge/sessions/sess-1/handle');
    const body = captured!.body;
    expect(JSON.parse(body)).toEqual({
      handledThroughEventId: 'evt-2', handledAt: '2026-07-16T00:00:01.000Z', action: 'pi_input',
    });
    const input = {
      entityType: 'host' as const,
      entityId: identity.hostId,
      keyId: identity.keyId,
      method: 'POST',
      path: '/v2/bridge/sessions/sess-1/handle',
      querySchema: { parameters: {} },
      contentSha256: await contentSha256(body),
      timestamp,
      nonce,
    };
    expect(captured!.headers.get('x-ariava-content-sha256')).toBe(input.contentSha256);
    expect(base64UrlDecode(captured!.headers.get('x-ariava-signature') ?? '', 64)).toHaveLength(64);
    expect(buildCanonicalRequest(input).path).toBe('/v2/bridge/sessions/sess-1/handle');
    expect(captured!.headers.has('x-host-auth')).toBe(false);
  });

});
