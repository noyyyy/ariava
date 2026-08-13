import { constants } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { SecureFileError } from './error';

export function requireAbsolute(path: string): string {
  if (!isAbsolute(path)) throw new SecureFileError('Secure paths must be absolute');
  return resolve(path);
}

export function currentUid(): number {
  if (!process.getuid) throw new SecureFileError('Current uid is unavailable');
  return process.getuid();
}

export function noFollowFlag(): number {
  return typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
}

export function directoryFlag(): number {
  return typeof constants.O_DIRECTORY === 'number' ? constants.O_DIRECTORY : 0;
}
