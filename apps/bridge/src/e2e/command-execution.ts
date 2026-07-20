import type { CommandEnvelope, EncryptedCommandEnvelopeV1 } from '@ariava/protocol';

export interface EncryptedReplyCommandDecoder {
  decodeReply(command: Extract<EncryptedCommandEnvelopeV1, { type: 'reply' }>): Promise<CommandEnvelope>;
}

export type EncryptedCommandPreparation =
  | { ok: true; command: CommandEnvelope }
  | { ok: false; code: 'e2e_key_unavailable' | 'e2e_payload_invalid' };

/**
 * Converts Relay wire commands into the loopback-only Agent Adapter shape.
 * An encrypted reply is never interpreted as text without an injected keyring
 * decoder; the default production path fails closed until that keyring lands.
 */
export async function prepareCommandForExecution(
  command: CommandEnvelope | EncryptedCommandEnvelopeV1,
  decoder?: EncryptedReplyCommandDecoder,
): Promise<EncryptedCommandPreparation> {
  if (!('linkId' in command)) return { ok: true, command };
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
  if (!decoder) return { ok: false, code: 'e2e_key_unavailable' };
  try {
    const decoded = await decoder.decodeReply(command);
    if (decoded.type !== 'reply' || typeof decoded.payload.text !== 'string' || !decoded.payload.text.trim()) {
      return { ok: false, code: 'e2e_payload_invalid' };
    }
    return { ok: true, command: decoded };
  } catch {
    return { ok: false, code: 'e2e_payload_invalid' };
  }
}
