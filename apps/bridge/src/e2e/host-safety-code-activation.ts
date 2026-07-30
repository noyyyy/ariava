import { createInterface } from 'node:readline/promises';
import type { E2EPendingLinkProjectionV1, EncryptionKeyBindingV1 } from '@ariava/protocol';
import type { HostEncryptionIdentity } from '../identity';
import {
  LocalLinkKeyring,
  prepareHostActivation,
  type HostActivationTransport,
} from './link-keyring';

const DEFAULT_PEER_WAIT_MS = 5 * 60_000;
const DEFAULT_PEER_POLL_MS = 1_500;

export type HostSafetyCodeActivationOutcome =
  | 'activated'
  | 'cancelled'
  | 'already-active'
  | 'skipped-no-e2e'
  | 'waiting-for-watch';

export interface HostSafetyCodeActivationInput {
  projection?: E2EPendingLinkProjectionV1;
  alreadyPaired?: boolean;
  hostIdentity: HostEncryptionIdentity;
  hostBinding: EncryptionKeyBindingV1;
  keyring: LocalLinkKeyring;
  transport: HostActivationTransport;
  write(line: string): void;
  confirmMatch(): Promise<boolean>;
  sleep?(ms: number): Promise<void>;
  now?(): number;
  peerWaitMs?: number;
  peerPollMs?: number;
}

/**
 * After pair-watch succeeds, display the Host Safety Code, wait for an explicit
 * human match, submit Host confirmation, poll for the Watch proof, then activate.
 *
 * Relay confirm is idempotent; peer proof may arrive after the Watch confirms.
 */
export async function runHostSafetyCodeActivation(
  input: HostSafetyCodeActivationInput,
): Promise<HostSafetyCodeActivationOutcome> {
  const projection = input.projection;
  if (!projection) {
    if (input.alreadyPaired) {
      input.write('Link already paired; no pending E2E Safety Code activation is required.');
      return 'already-active';
    }
    input.write('Pairing succeeded without an E2E pending projection; Safety Code activation was skipped.');
    return 'skipped-no-e2e';
  }

  if (projection.state === 'host_activated' || projection.state === 'watch_activated') {
    const usable = input.keyring.getUsable(projection.linkId, projection.linkGeneration, projection.epoch);
    if (usable?.status === 'active') {
      input.write(
        `E2E link ${projection.linkId} generation ${projection.linkGeneration} epoch ${projection.epoch} is already active locally.`,
      );
      return 'already-active';
    }
  }

  const prepared = await prepareHostActivation({
    projection,
    hostIdentity: input.hostIdentity,
    hostBinding: input.hostBinding,
    keyring: input.keyring,
  });

  input.write('');
  input.write(`Safety Code:  ${prepared.safetyCode}`);
  input.write('Confirm only if the Watch shows this exact code.');

  const matched = await input.confirmMatch();
  if (!matched) {
    input.write('Safety Code confirmation cancelled. Re-pair if the codes differed.');
    return 'cancelled';
  }

  input.write('Host confirmation submitted. Waiting for the Watch to confirm the same Safety Code...');

  const sleep = input.sleep ?? defaultSleep;
  const now = input.now ?? Date.now;
  const peerWaitMs = input.peerWaitMs ?? DEFAULT_PEER_WAIT_MS;
  const peerPollMs = input.peerPollMs ?? DEFAULT_PEER_POLL_MS;
  const deadline = now() + peerWaitMs;
  let lastError: unknown;

  while (now() <= deadline) {
    try {
      const pin = await prepared.complete(input.transport);
      input.write(
        `Pairing complete (E2E activated) for watch ${pin.watchDeviceId} (link ${pin.linkId}, generation ${pin.linkGeneration}, epoch ${pin.epoch}).`,
      );
      return 'activated';
    } catch (error) {
      lastError = error;
      if (!isWaitingForPeerProof(error)) throw error;
      await sleep(peerPollMs);
    }
  }

  const detail = lastError instanceof Error ? lastError.message : String(lastError ?? 'peer confirmation missing');
  throw new Error(
    `Timed out waiting for Watch Safety Code confirmation (${detail}). Keep the Watch Verify Safety Code sheet open, tap Codes Match, then re-run pair if needed.`,
  );
}

export async function promptSafetyCodeMatch(options: {
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream;
  interactive: boolean;
  codesMatchFlag: boolean;
}): Promise<boolean> {
  if (options.codesMatchFlag) return true;
  if (!options.interactive) {
    throw new Error(
      "Noninteractive Safety Code confirmation requires --codes-match after you verify the Watch shows the same code.",
    );
  }

  const rl = createInterface({ input: options.stdin, output: options.stdout });
  try {
    while (true) {
      const answer = (await rl.question('Codes match? [y/N] ')).trim().toLowerCase();
      // Default N: empty / n / no cancels. Only explicit y/yes continues.
      if (answer === 'y' || answer === 'yes') return true;
      if (answer === '' || answer === 'n' || answer === 'no') return false;
      options.stdout.write('Please answer y or N.\n');
    }
  } finally {
    rl.close();
  }
}

function isWaitingForPeerProof(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.message === 'peer confirmation proof is not available yet';
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
