export class SecureFileError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'SecureFileError';
  }
}
