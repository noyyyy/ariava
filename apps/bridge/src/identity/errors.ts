export const HOST_IDENTITY_ERROR_CODES = [
  'ERR_IDENTITY_NOT_INITIALIZED',
  'ERR_IDENTITY_MISSING',
  'ERR_IDENTITY_INVALID',
  'ERR_IDENTITY_PERMISSIONS',
  'ERR_IDENTITY_RESET_REQUIRED',
] as const;

export type HostIdentityErrorCode = (typeof HOST_IDENTITY_ERROR_CODES)[number];

export class HostIdentityError extends Error {
  constructor(
    readonly code: HostIdentityErrorCode,
    message: string,
    readonly cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'HostIdentityError';
  }
}

export function identityError(
  code: HostIdentityErrorCode,
  message: string,
  cause?: unknown,
): HostIdentityError {
  return cause instanceof HostIdentityError ? cause : new HostIdentityError(code, message, cause);
}
