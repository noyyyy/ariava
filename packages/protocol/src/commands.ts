export const COMMAND_TYPES = ['reply', 'interrupt'] as const;
export type CommandType = (typeof COMMAND_TYPES)[number];

export interface CommandEnvelope {
  commandId: string;
  hostId: string;
  sessionId: string;
  type: CommandType;
  payload: Record<string, string | number | boolean | null | undefined>;
  /** Required for reply; omitted for interrupt. Included in the signed v2 request body. */
  targetAlertEventId?: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  watchDeviceId: string;
}

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

export function isCommandExpired(command: Pick<CommandEnvelope, 'expiresAt'>, now = new Date()): boolean {
  return new Date(command.expiresAt).getTime() <= now.getTime();
}

export function validateCommandType(type: string): type is CommandType {
  return (COMMAND_TYPES as readonly string[]).includes(type);
}
