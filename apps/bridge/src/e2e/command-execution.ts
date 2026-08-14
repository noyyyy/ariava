import {
  SIGNED_REQUEST_LIMITS,
  deriveEncryptedCommandDigest,
  validateEncryptedCommandEnvelopeV1,
  type CommandEnvelope,
  type EncryptedCommandEnvelopeV1,
} from '@ariava/protocol';
import type { PersistedCommandPinReferenceV1 } from '../types';

export interface PreparedEncryptedCommand {
  originalEncryptedCommand: EncryptedCommandEnvelopeV1;
  commandDigest: string;
  pinReference: PersistedCommandPinReferenceV1;
  loopbackCommand: CommandEnvelope;
}

export interface EncryptedCommandKeyring {
  prepare(command: EncryptedCommandEnvelopeV1, now?: Date): Promise<{
    pinReference: PersistedCommandPinReferenceV1;
    loopbackCommand: CommandEnvelope;
  }>;
}

export type EncryptedCommandPreparation =
  | { ok: true; prepared: PreparedEncryptedCommand }
  | { ok: false; code: 'e2e_key_unavailable' | 'e2e_epoch_unauthorized' | 'e2e_payload_invalid' };

/** Converts a strict Relay wire command into a pin-bound loopback command. */
export async function prepareCommandForExecution(
  command: EncryptedCommandEnvelopeV1,
  keyring?: EncryptedCommandKeyring,
  now: () => Date = () => new Date(Date.now()),
 ): Promise<EncryptedCommandPreparation> {
  if (!validateEncryptedCommandEnvelopeV1(command)) return { ok: false, code: 'e2e_payload_invalid' };
  const observedAt = now();
  if (!Number.isFinite(observedAt.getTime())
    || Date.parse(command.issuedAt) > observedAt.getTime() + SIGNED_REQUEST_LIMITS.clockSkewMs) {
    return { ok: false, code: 'e2e_epoch_unauthorized' };
  }
  if (!keyring) return { ok: false, code: 'e2e_key_unavailable' };
  try {
    const decoded = await keyring.prepare(command, observedAt);
    if (decoded.loopbackCommand.type !== command.type
      || decoded.loopbackCommand.commandId !== command.commandId
      || decoded.loopbackCommand.hostId !== command.hostId
      || decoded.loopbackCommand.sessionId !== command.sessionId
      || decoded.loopbackCommand.nonce !== command.nonce
      || decoded.loopbackCommand.watchDeviceId !== command.watchDeviceId) {
      return { ok: false, code: 'e2e_payload_invalid' };
    }
    return { ok: true, prepared: {
      originalEncryptedCommand: structuredClone(command),
      commandDigest: await deriveEncryptedCommandDigest(command),
      pinReference: structuredClone(decoded.pinReference),
      loopbackCommand: structuredClone(decoded.loopbackCommand),
    } };
  } catch (error) {
    return { ok: false, code: error instanceof CommandEpochAuthorizationError
      ? 'e2e_epoch_unauthorized' : 'e2e_payload_invalid' };
  }
}

export class CommandEpochAuthorizationError extends TypeError {}
