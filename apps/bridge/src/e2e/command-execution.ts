import type { CommandEnvelope, EncryptedCommandEnvelopeV1 } from '@ariava/protocol';

export interface EncryptedCommandKeyring {
  authorize(command: EncryptedCommandEnvelopeV1): Promise<boolean>;
  decodeReply(command: Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>): Promise<CommandEnvelope>;
}

export type EncryptedCommandPreparation =
  | { ok: true; command: CommandEnvelope }
  | { ok: false; code: 'e2e_key_unavailable' | 'e2e_epoch_unauthorized' | 'e2e_payload_invalid' };

/**
 * Converts Relay wire commands into the loopback-only Agent Adapter shape.
 * Every encrypted command is authorized against the local active pin before
 * either reply decryption or interrupt execution. The default production path
 * fails closed until the local keyring and pin verifier are configured.
 */
export async function prepareCommandForExecution(
  command: CommandEnvelope | EncryptedCommandEnvelopeV1,
  keyring?: EncryptedCommandKeyring,
): Promise<EncryptedCommandPreparation> {
  if (!('linkId' in command)) return { ok: true, command };
  if (!keyring) return { ok: false, code: 'e2e_key_unavailable' };
  try {
    if (!await keyring.authorize(command)) return { ok: false, code: 'e2e_epoch_unauthorized' };
  } catch {
    return { ok: false, code: 'e2e_epoch_unauthorized' };
  }
  if (command.type === 'interrupt') {
    return { ok: true, command: {
      commandId: command.commandId,
      hostId: command.hostId,
      sessionId: command.sessionId,
      type: 'interrupt',
      payload: {},
      issuedAt: command.issuedAt,
      expiresAt: command.expiresAt,
      nonce: command.nonce,
      watchDeviceId: command.watchDeviceId,
    } };
  }
  try {
    const decoded = await keyring.decodeReply(command);
    if (decoded.type !== 'reply' || typeof decoded.payload.text !== 'string' || !decoded.payload.text.trim()) {
      return { ok: false, code: 'e2e_payload_invalid' };
    }
    return { ok: true, command: decoded };
  } catch {
    return { ok: false, code: 'e2e_payload_invalid' };
  }
}
