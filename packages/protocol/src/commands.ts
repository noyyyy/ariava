import type { EncryptedPayloadForRecipientV1 } from './encryption.js';

export const COMMAND_TYPES = ['reply', 'interrupt'] as const;
export type CommandType = (typeof COMMAND_TYPES)[number];

interface EncryptedCommandEnvelopeBaseV1 {
  commandId: string;
  hostId: string;
  sessionId: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  watchDeviceId: string;
  linkId: string;
  linkGeneration: number;
  epoch: number;
}

export interface EncryptedReplyCommandEnvelopeV1 extends EncryptedCommandEnvelopeBaseV1 {
  type: 'reply';
  payload: EncryptedPayloadForRecipientV1;
  targetAlertEventId: string;
}

export interface InterruptCommandEnvelopeV1 extends EncryptedCommandEnvelopeBaseV1 {
  type: 'interrupt';
  payload: Record<string, never>;
  targetAlertEventId?: never;
}

/** Relay/Watch wire command. Reply text can only exist inside the encrypted payload. */
export type EncryptedCommandEnvelopeV1 = EncryptedReplyCommandEnvelopeV1 | InterruptCommandEnvelopeV1;

/**
 * Decrypted loopback-only Agent Adapter command. This legacy name remains the
 * local extension boundary; Relay code must use EncryptedCommandEnvelopeV1.
 */
export interface CommandEnvelope {
  commandId: string;
  hostId: string;
  sessionId: string;
  type: CommandType;
  payload: Record<string, string | number | boolean | null | undefined>;
  targetAlertEventId?: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  watchDeviceId: string;
}
export type LocalAgentCommandEnvelope = CommandEnvelope;

export interface CommandResult {
  commandId: string;
  hostId: string;
  sessionId: string;
  accepted: boolean;
  status: 'queued' | 'delivered' | 'executed' | 'expired' | 'rejected' | 'failed';
  correlationId?: string;
  message: string;
  updatedAt: string;
}

export function isCommandExpired(command: Pick<CommandEnvelope | EncryptedCommandEnvelopeV1, 'expiresAt'>, now = new Date()): boolean {
  return new Date(command.expiresAt).getTime() <= now.getTime();
}

export function validateCommandType(type: string): type is CommandType {
  return (COMMAND_TYPES as readonly string[]).includes(type);
}
