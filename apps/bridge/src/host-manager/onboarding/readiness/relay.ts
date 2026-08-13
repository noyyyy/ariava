import { randomBytes } from 'node:crypto';
import type { HostEnrollmentResponse } from '@ariava/protocol';
import { base64UrlEncode, isCanonicalTimestamp } from '@ariava/protocol';
import { RelayClient, RelayClientError } from '../../../relay-client';
import { AriavaCliError } from '../../service/errors';
import type { StrictReadinessDependencies, StrictReadinessInput } from './check';
import { boundedPositive, fetchBounded, linkedAbortController } from './bounded-fetch';
import { readinessError } from './remediation';

export function defaultNonce(): string {
  return base64UrlEncode(randomBytes(16));
}

const defaultRelayDependencies: Pick<StrictReadinessDependencies, 'fetch' | 'createRelayClient' | 'nonce'> = {
  fetch,
  createRelayClient: (options, requestSignal) => new RelayClient(options, requestSignal),
  nonce: defaultNonce,
};

function resolveRelayDependencies(
  overrides: Partial<StrictReadinessDependencies>,
): Pick<StrictReadinessDependencies, 'fetch' | 'createRelayClient' | 'nonce'> {
  return { ...defaultRelayDependencies, ...overrides };
}

export async function checkRelay(
  input: Pick<StrictReadinessInput, 'config' | 'identity' | 'hostMetadata' | 'requestTimeoutMs' | 'signal'>,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<void> {
  const deps = resolveRelayDependencies(overrides);
  await checkRelayHealth(input, deps);
  await checkRelayEnrollment(input, deps);
}

export async function checkRelayHealth(
  input: Pick<StrictReadinessInput, 'config' | 'requestTimeoutMs' | 'signal'>,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<void> {
  const deps = resolveRelayDependencies(overrides);
  const timeoutMs = boundedPositive(input.requestTimeoutMs, 5_000);
  let health: Response;
  try {
    health = await fetchBounded(new URL('/health', input.config.relayBaseUrl), { signal: input.signal }, timeoutMs, deps);
  } catch (error) {
    if (input.signal?.aborted) throw error;
    throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay health could not be reached.');
  }
  if (health.status === 401 || health.status === 403) throw readinessError('ERR_RELAY_AUTH_FAILED', 'Relay rejected health access.');
  if (!health.ok) throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay health is unavailable.');
  try {
    const healthBody = await health.json() as unknown;
    if (!isExactOk(healthBody)) throw new Error('malformed health');
  } catch {
    throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay returned malformed health evidence.');
  }
}

export async function checkRelayEnrollment(
  input: Pick<StrictReadinessInput, 'config' | 'identity' | 'hostMetadata' | 'requestTimeoutMs' | 'signal'>,
  overrides: Partial<StrictReadinessDependencies> = {},
): Promise<void> {
  const deps = resolveRelayDependencies(overrides);
  const timeoutMs = boundedPositive(input.requestTimeoutMs, 5_000);
  const controller = linkedAbortController(input.signal);
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await deps.createRelayClient({
      baseUrl: input.config.relayBaseUrl,
      signer: input.identity.signer,
      fetch: deps.fetch,
      nonce: deps.nonce,
    }, () => controller.signal).enrollHost({
      hostId: input.identity.hostId,
      keyId: input.identity.keyId,
      algorithm: input.identity.algorithm,
      publicKey: input.identity.publicKey,
      ...input.hostMetadata,
    });
    assertEnrollmentResponse(response, input.identity.hostId, input.hostMetadata);
  } catch (error) {
    if (error instanceof RelayClientError) {
      if (error.status === 401 || error.status === 403) throw readinessError('ERR_RELAY_AUTH_FAILED', 'Relay rejected signed Host enrollment.');
      if (error.status === 409 || error.status === 410) throw readinessError('ERR_IDENTITY_INVALID', 'Relay rejected the persisted Host identity.', false);
      throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay signed Host enrollment is unavailable.');
    }
    if (error instanceof AriavaCliError) throw error;
    if (error instanceof TypeError || (error instanceof Error && error.name === 'AbortError')) {
      if (input.signal?.aborted) throw error;
      throw readinessError('ERR_RELAY_UNREACHABLE', 'Relay signed Host enrollment could not be reached.');
    }
    throw readinessError('ERR_IDENTITY_INVALID', 'Relay returned malformed Host enrollment evidence.', false);
  } finally {
    clearTimeout(timeout);
  }
}

function isExactOk(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).sort().join(',') === 'ok' && record.ok === true;
}

function assertEnrollmentResponse(
  response: HostEnrollmentResponse,
  hostId: string,
  metadata: StrictReadinessInput['hostMetadata'],
): void {
  const host = response?.host;
  if (!host || host.hostId !== hostId || host.hostName !== metadata.hostName || host.platform !== metadata.platform
    || host.bridgeVersion !== metadata.bridgeVersion || host.status === 'revoked'
    || !isCanonicalTimestamp(host.registeredAt) || !isCanonicalTimestamp(host.lastSeenAt)) {
    throw new Error('malformed enrollment');
  }
}
