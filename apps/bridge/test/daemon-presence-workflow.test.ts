import { describe, expect, test } from 'bun:test';
import type { HostEnrollmentRequest, HostEnrollmentResponse, HostProjection } from '@ariava/protocol';
import { HostIdentityError, type HostIdentity } from '../src/identity';
import {
  performHostPresenceRegistration,
  type HostPresenceRegistrationDependencies,
} from '../src/daemon/presence-workflow';

/**
 * Focused runner tests for the Task 6 presence workflow extraction (plan
 * `2026-08-16-bridge-daemon-lifecycle-decomposition.md`, spec §5/§8/§9):
 * the narrow enrollment/register effect body — identity load, configured-
 * identity comparison, enrollment build, Relay enroll, stop guard, and the
 * authoritative Host projection write — with exact call order and error
 * contract, independently of `BridgeDaemon` single-flight/timer/health state.
 * No I/O, no secrets.
 */
function fakeIdentity(hostId = 'host-test'): HostIdentity {
  return {
    identityVersion: 2,
    hostId,
    keyId: 'key-test',
    algorithm: 'Ed25519',
    publicKey: 'pub-test',
    publicKeyFingerprint: 'fp-test',
    createdAt: '2026-08-16T00:00:00.000Z',
    privateKeyStorage: { type: 'linux-json', path: '/tmp/identity.json' },
    signer: {
      entityId: hostId,
      keyId: 'key-test',
      sign: async () => 'sig',
      signRequest: async () => ({
        'x-ariava-entity-id': hostId,
        'x-ariava-key-id': 'key-test',
        'x-ariava-timestamp': '2026-08-16T00:00:00.000Z',
        'x-ariava-nonce': 'nonce-test',
        'x-ariava-content-sha256': 'sha-test',
        'x-ariava-signature': 'sig-test',
      }),
    },
  };
}

function fakeEnrollmentRequest(hostId = 'host-test'): HostEnrollmentRequest {
  return {
    hostId, keyId: 'key-test', algorithm: 'Ed25519', publicKey: 'pub-test',
    hostName: 'Host', platform: 'linux', bridgeVersion: '0.3.0',
  };
}

function fakeHostProjection(hostId = 'host-test'): HostProjection {
  return {
    hostId, hostName: 'Relay host', platform: 'linux', bridgeVersion: '0.3.0',
    registeredAt: '2026-08-16T00:00:00.000Z', lastSeenAt: '2026-08-16T00:00:01.000Z',
    bridgeStatus: 'online',
  };
}

function registrationFixture(overrides?: Partial<HostPresenceRegistrationDependencies>) {
  const order: string[] = [];
  const identity = fakeIdentity();
  const request = fakeEnrollmentRequest();
  const host = fakeHostProjection();
  const response: HostEnrollmentResponse = { host };
  const deps: HostPresenceRegistrationDependencies = {
    loadIdentity: async () => { order.push('loadIdentity'); return identity; },
    matchesConfiguredIdentity: (loaded) => { order.push('matchesConfiguredIdentity'); expect(loaded).toBe(identity); return true; },
    buildEnrollment: async (loaded) => { order.push('buildEnrollment'); expect(loaded).toBe(identity); return request; },
    enrollHost: async (built) => { order.push('enrollHost'); expect(built).toBe(request); return response; },
    isStopped: () => { order.push('isStopped'); return false; },
    setHost: (projection) => { order.push('setHost'); expect(projection).toBe(host); },
    ...overrides,
  };
  return { deps, order, identity, request, host };
}

describe('performHostPresenceRegistration effect runner', () => {
  test('performs the registration effect body in exact order and writes the authoritative projection', async () => {
    const { deps, order } = registrationFixture();
    await performHostPresenceRegistration(deps);
    expect(order).toEqual(['loadIdentity', 'matchesConfiguredIdentity', 'buildEnrollment', 'enrollHost', 'isStopped', 'setHost']);
  });

  test('rejects when no Host identity is loaded without consulting evidence or the Relay', async () => {
    const { deps, order } = registrationFixture({ loadIdentity: async () => { order.push('loadIdentity'); return null; } });
    const error = await performHostPresenceRegistration(deps).then(() => null, (caught: unknown) => caught);
    expect(error).toBeInstanceOf(HostIdentityError);
    expect((error as HostIdentityError).code).toBe('ERR_IDENTITY_INVALID');
    expect((error as HostIdentityError).message).toBe('Host identity changed while daemon was running');
    expect(order).toEqual(['loadIdentity']);
  });

  test('rejects when the loaded identity no longer matches the configured identity', async () => {
    const { deps, order } = registrationFixture({ matchesConfiguredIdentity: () => { order.push('matchesConfiguredIdentity'); return false; } });
    const error = await performHostPresenceRegistration(deps).then(() => null, (caught: unknown) => caught);
    expect(error).toBeInstanceOf(HostIdentityError);
    expect((error as HostIdentityError).code).toBe('ERR_IDENTITY_INVALID');
    expect((error as HostIdentityError).message).toBe('Host identity changed while daemon was running');
    expect(order).toEqual(['loadIdentity', 'matchesConfiguredIdentity']);
  });

  test('skips the authoritative write when the daemon is already stopping', async () => {
    const { deps, order } = registrationFixture({ isStopped: () => { order.push('isStopped'); return true; } });
    await performHostPresenceRegistration(deps);
    expect(order).toEqual(['loadIdentity', 'matchesConfiguredIdentity', 'buildEnrollment', 'enrollHost', 'isStopped']);
  });

  test('propagates Relay enrollment failures without any state-store write', async () => {
    const relayFailure = new Error('Relay offline');
    const { deps, order } = registrationFixture({ enrollHost: async () => { order.push('enrollHost'); throw relayFailure; } });
    const error = await performHostPresenceRegistration(deps).then(() => null, (caught: unknown) => caught);
    expect(error).toBe(relayFailure);
    expect(order).toEqual(['loadIdentity', 'matchesConfiguredIdentity', 'buildEnrollment', 'enrollHost']);
  });

  test('passes the enrollment request built from the loaded identity to the Relay verbatim', async () => {
    let built: HostEnrollmentRequest | undefined;
    let enrolled: HostEnrollmentRequest | undefined;
    const { deps, host } = registrationFixture({
      buildEnrollment: async (loaded) => {
        const builtRequest = fakeEnrollmentRequest(loaded.hostId);
        built = builtRequest;
        return builtRequest;
      },
      enrollHost: async (request) => { enrolled = request; return { host }; },
    });
    await performHostPresenceRegistration(deps);
    expect(built).toEqual(fakeEnrollmentRequest());
    expect(enrolled).toBe(built);
  });
});
