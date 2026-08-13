import { lstatSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { SecureFileError } from './error';

export function pathHasFilesystemEvidence(path: string): boolean {
  const absolute = requireAbsolute(path);
  try {
    lstatSync(absolute);
    return true;
  } catch (error) {
    if (isMissing(error)) return false;
    throw new SecureFileError(`Could not inspect secure path: ${absolute}`, error);
  }
}

function requireAbsolute(path: string): string {
  if (!isAbsolute(path)) throw new SecureFileError('Secure paths must be absolute');
  return resolve(path);
}

function isMissing(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT');
}
