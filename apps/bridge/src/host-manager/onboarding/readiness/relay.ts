import { randomBytes } from 'node:crypto';
import type { HostEnrollmentResponse, HostPlatform } from '@ariava/protocol';
import { base64UrlEncode, isCanonicalTimestamp } from '@ariava/protocol';
import type { HostIdentity } from '../../../identity/types';
import { RelayClient, RelayClientError } from '../../../relay-client';
import type { ResolvedAriavaConfig } from '../../config';
import { AriavaCliError } from '../../service/errors';
import { boundedPositive, fetchBounded, linkedAbortController } from './bounded-fetch';
import { readinessError } from './remediation';

export interface RelayReadinessDependencies {
  fetch: typeof fetch;
  createRelayClient(
    options: ConstructorParameters<typeof RelayClient>[0],
    requestSignal?: () => AbortSignal | undefined,
  ): Pick<RelayClient, 'enrollHost'>;
  nonce(): string;
}

export interface RelayHealthInput {
  config: Pick<ResolvedAriavaConfig, 'relayBaseUrl'>;
  requestTimeoutMs?: number;
  signal?: AbortSignal;
}

export interface RelayEnrollmentInput extends RelayHealthInput {
  identity: Pick<HostIdentity, 'hostId' | 'keyId' | 'algorithm' | 'publicKey' | 'signer'>;
  hostMetadata: { hostName: string; platform: HostPlatform; bridgeVersion: string };
}

export const defaultRelayReadinessDependencies: RelayReadinessDependencies = {
  fetch,
  createRelayClient: (options, requestSignal) => new RelayClient(options, requestSignal),
  // Signed-request nonces must be canonical base64url of exactly 16 bytes.
  nonce: () => base64UrlEncode(randomBytes(16)),
};

export async function checkRelay(
  input: RelayEnrollmentInput,
  overrides: Partial<RelayReadinessDependencies> = {},
): Promise<void> {
  const deps = { ...defaultRelayReadinessDependencies, ...overrides };
  await checkRelayHealth(input, deps);
  await checkRelayEnrollment(input, deps);
}

export async function checkRelayHealth(
  input: RelayHealthInput,
  overrides: Partial<RelayReadinessDependencies> = {},
): Promise<void> {
  const deps = { ...defaultRelayReadinessDependencies, ...overrides };
  const timeoutMs = boundedPositive(input.requestTimeoutMs, 5_000);
  let health: Response;
  try {
    health = await fetchBounded(new URL('/health', input.config.relayBaseUrl), { signal: input.signal }, timeoutMs, deps.fetch);
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
  input: RelayEnrollmentInput,
  overrides: Partial<RelayReadinessDependencies> = {},
): Promise<void> {
  const deps = { ...defaultRelayReadinessDependencies, ...overrides };
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
  metadata: RelayEnrollmentInput['hostMetadata'],
): void {
  const host = response?.host;
  if (!host || host.hostId !== hostId || host.hostName !== metadata.hostName || host.platform !== metadata.platform
    || host.bridgeVersion !== metadata.bridgeVersion || host.status === 'revoked'
    || !isCanonicalTimestamp(host.registeredAt) || !isCanonicalTimestamp(host.lastSeenAt)) {
    throw new Error('malformed enrollment');
  }
}
