import type {
  HostEnrollmentRequest,
  HostEnrollmentResponse,
  HostProjection,
} from '@ariava/protocol';
import { HostIdentityError, type HostIdentity } from '../identity';

/**
 * Narrow Host presence enrollment/register effect runner (spec §5
 * `presence-workflow.ts`, plan Task 6). Contains only the enrollment/register
 * effect body — identity load, configured-identity comparison, enrollment
 * request build, Relay enroll call, stop guard, and authoritative Host
 * projection write — and its exact error contract. Everything else about
 * presence stays in `BridgeDaemon` (spec §8): the presence Promise
 * single-flight (`presenceFlight`), the heartbeat timer handle, retry/
 * reconciliation scheduling, clock collection (`isoNow`/`nextRetryAt`),
 * runtime-health recording, and lifecycle/stop ownership.
 */
export interface HostPresenceRegistrationDependencies {
  /** Load the persisted Host identity; `null` when not initialized. */
  loadIdentity(): Promise<HostIdentity | null>;
  /** True when `identity` still matches the configured identity evidence. */
  matchesConfiguredIdentity(identity: HostIdentity): boolean;
  /** Build the signed enrollment request for `identity`. */
  buildEnrollment(identity: HostIdentity): Promise<HostEnrollmentRequest>;
  /** POST the built enrollment request to the Relay. */
  enrollHost(request: HostEnrollmentRequest): Promise<HostEnrollmentResponse>;
  /** Lifecycle signal: the daemon is stopping; skip the authoritative write. */
  isStopped(): boolean;
  /** Persist the authoritative Host projection returned by the Relay. */
  setHost(host: HostProjection): void;
}

/**
 * Performs the exact registration effect sequence the daemon previously ran
 * inline: load identity → compare against configured identity evidence →
 * build enrollment → enroll → stop guard → write the authoritative Host
 * projection. Errors and ordering are preserved verbatim: a missing or
 * changed identity throws `ERR_IDENTITY_INVALID` before any Relay call, the
 * Relay response is written only when the daemon is still running, and any
 * enrollment failure propagates to the caller without a state-store write.
 */
export async function performHostPresenceRegistration(
  deps: HostPresenceRegistrationDependencies,
): Promise<void> {
  const identity = await deps.loadIdentity();
  if (!identity || !deps.matchesConfiguredIdentity(identity)) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity changed while daemon was running');
  }
  const response = await deps.enrollHost(await deps.buildEnrollment(identity));
  if (deps.isStopped()) return;
  deps.setHost(response.host);
}
