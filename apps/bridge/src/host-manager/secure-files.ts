import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, resolve, sep } from 'node:path';

export class SecureFileError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'SecureFileError';
  }
}

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

export function ensureSecureDirectory(path: string, uid = currentUid()): void {
  const absolute = requireAbsolute(path);
  if (pathHasFilesystemEvidence(absolute)) {
    assertSecureDirectory(absolute, uid);
    return;
  }

  const missing: string[] = [];
  let cursor = absolute;
  while (!pathHasFilesystemEvidence(cursor)) {
    missing.push(cursor);
    const parent = dirname(cursor);
    if (parent === cursor) throw new SecureFileError(`Could not find an existing parent for: ${absolute}`);
    cursor = parent;
  }

  // The pre-existing boundary (for example ~/.config or /tmp) is not Ariava-controlled.
  // Every directory created or subsequently used by Ariava is checked explicitly below.
  for (const directory of missing.reverse()) {
    try {
      mkdirSync(directory, { mode: 0o700 });
    } catch (error) {
      // A concurrent creator is acceptable only when it created exactly the secure directory expected.
      if (!pathHasFilesystemEvidence(directory)) throw new SecureFileError(`Could not create secure directory: ${directory}`, error);
    }
    assertSecureDirectory(directory, uid);
  }
}

export function assertSecureDirectory(path: string, uid = currentUid()): void {
  const absolute = requireAbsolute(path);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch (error) {
    throw new SecureFileError(`Secure directory check failed: ${absolute}`, error);
  }
  if (stat.isSymbolicLink() || !stat.isDirectory() || stat.uid !== uid || (stat.mode & 0o077) !== 0) {
    throw new SecureFileError(`Secure directory check failed: ${absolute}`);
  }
}

export function assertSecureFile(path: string, uid = currentUid()): void {
  const absolute = requireAbsolute(path);
  assertSecureDirectory(dirname(absolute), uid);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch (error) {
    throw new SecureFileError(`Secure file check failed: ${absolute}`, error);
  }
  if (stat.isSymbolicLink() || !stat.isFile() || stat.uid !== uid || (stat.mode & 0o177) !== 0 || (stat.mode & 0o600) !== 0o600) {
    throw new SecureFileError(`Secure file check failed: ${absolute}`);
  }
}

export function repairSecureFileMode(path: string, uid = currentUid()): void {
  const absolute = requireAbsolute(path);
  assertSecureDirectory(dirname(absolute), uid);
  const stat = lstatSync(absolute);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.uid !== uid) {
    throw new SecureFileError(`Secure file repair refused: ${absolute}`);
  }
  let fd: number | undefined;
  try {
    fd = openSync(absolute, constants.O_RDONLY | noFollowFlag());
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.uid !== uid) throw new SecureFileError(`Secure file repair refused: ${absolute}`);
    fchmodSync(fd, 0o600);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function readSecureFile(path: string, uid = currentUid()): Buffer {
  const absolute = requireAbsolute(path);
  assertSecureFile(absolute, uid);
  let fd: number | undefined;
  try {
    fd = openSync(absolute, constants.O_RDONLY | noFollowFlag());
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o177) !== 0 || (stat.mode & 0o600) !== 0o600) {
      throw new SecureFileError(`Secure open-file check failed: ${absolute}`);
    }
    return readFileSync(fd);
  } catch (error) {
    throw error instanceof SecureFileError ? error : new SecureFileError(`Secure file read failed: ${absolute}`, error);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function readSecureJson<T>(path: string, uid = currentUid()): T {
  return JSON.parse(readSecureFile(path, uid).toString('utf8')) as T;
}

export function writeSecureJson(path: string, value: unknown, uid = currentUid()): void {
  writeSecureFile(path, Buffer.from(`${JSON.stringify(value, null, 2)}\n`), uid);
}

export function writeSecureJsonExclusive(path: string, value: unknown, uid = currentUid()): void {
  writeSecureFile(path, Buffer.from(`${JSON.stringify(value, null, 2)}\n`), uid, true);
}

export interface SecureFileWriteHooks {
  beforePromotion?(): void;
}

export function writeSecureFile(
  path: string,
  contents: Uint8Array,
  uid = currentUid(),
  exclusive = false,
  hooks: SecureFileWriteHooks = {},
): void {
  const absolute = requireAbsolute(path);
  const parent = dirname(absolute);
  ensureSecureDirectory(parent, uid);

  let parentFd: number | undefined;
  const temporary = `${absolute}.tmp-${process.pid}-${crypto.randomUUID()}`;
  let fd: number | undefined;
  let temporaryLinked = false;
  try {
    parentFd = openSync(parent, constants.O_RDONLY | directoryFlag() | noFollowFlag());
    assertRetainedParent(parent, parentFd, uid);

    if (pathHasFilesystemEvidence(absolute)) {
      assertSecureFile(absolute, uid);
      assertRetainedParent(parent, parentFd, uid);
      if (exclusive) throw new SecureFileError(`Secure target already exists: ${absolute}`);
    }

    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollowFlag(), 0o600);
    fchmodSync(fd, 0o600);
    writeFileSync(fd, contents);
    fsyncSync(fd);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o177) !== 0 || (stat.mode & 0o600) !== 0o600) {
      throw new SecureFileError(`Secure temporary file check failed: ${absolute}`);
    }
    closeSync(fd);
    fd = undefined;

    hooks.beforePromotion?.();
    assertRetainedParent(parent, parentFd, uid);
    if (exclusive) {
      // link(2) fails atomically when a target (including a symlink) won the race.
      linkSync(temporary, absolute);
      temporaryLinked = true;
      unlinkSync(temporary);
    } else {
      renameSync(temporary, absolute);
    }

    // Revalidate the retained directory immediately before syncing its entry update.
    assertRetainedParent(parent, parentFd, uid);
    fsyncSync(parentFd);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temporary); } catch {}
    if (temporaryLinked && parentFd !== undefined && retainedParentStillMatches(parent, parentFd, uid)) {
      try { unlinkSync(absolute); } catch {}
    }
    throw error instanceof SecureFileError ? error : new SecureFileError(`Secure atomic write failed: ${absolute}`, error);
  } finally {
    if (parentFd !== undefined) closeSync(parentFd);
  }
}

export interface OwnerControlledFileWriteHooks {
  beforePromotion?(): void;
}

/**
 * Atomically writes a non-secret file below an owner-controlled directory tree.
 * Existing directories may be readable by other users, but must be owned by the
 * current uid, must not be group/world writable, and no path component may be a
 * symlink. The retained parent descriptor closes the validation-to-rename race.
 */
export function writeOwnerControlledFile(
  path: string,
  contents: Uint8Array,
  controlledRoot: string,
  uid = currentUid(),
  hooks: OwnerControlledFileWriteHooks = {},
): void {
  const absolute = requireAbsolute(path);
  const root = requireAbsolute(controlledRoot);
  const parent = dirname(absolute);
  if (parent !== root && !parent.startsWith(`${root}${sep}`)) {
    throw new SecureFileError(`Owner-controlled file must remain below its root: ${absolute}`);
  }

  ensureOwnerControlledDirectory(parent, root, uid);
  const temporary = `${absolute}.tmp-${process.pid}-${crypto.randomUUID()}`;
  let parentFd: number | undefined;
  let fd: number | undefined;
  try {
    parentFd = openSync(parent, constants.O_RDONLY | directoryFlag() | noFollowFlag());
    assertOwnerControlledTree(root, parent, uid);
    assertRetainedOwnerControlledParent(parent, parentFd, uid);
    assertSafeReplaceableFile(absolute, uid);

    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollowFlag(), 0o600);
    fchmodSync(fd, 0o600);
    writeFileSync(fd, contents);
    fsyncSync(fd);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o177) !== 0 || (stat.mode & 0o600) !== 0o600) {
      throw new SecureFileError(`Owner-controlled temporary file check failed: ${absolute}`);
    }
    closeSync(fd);
    fd = undefined;

    hooks.beforePromotion?.();
    assertOwnerControlledTree(root, parent, uid);
    assertRetainedOwnerControlledParent(parent, parentFd, uid);
    assertSafeReplaceableFile(absolute, uid);
    renameSync(temporary, absolute);
    assertOwnerControlledTree(root, parent, uid);
    assertRetainedOwnerControlledParent(parent, parentFd, uid);
    fsyncSync(parentFd);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temporary); } catch {}
    throw error instanceof SecureFileError
      ? error
      : new SecureFileError(`Owner-controlled atomic write failed: ${absolute}`, error);
  } finally {
    if (parentFd !== undefined) closeSync(parentFd);
  }
}

function ensureOwnerControlledDirectory(path: string, controlledRoot: string, uid: number): void {
  const missing: string[] = [];
  let cursor = path;
  while (!pathHasFilesystemEvidence(cursor)) {
    missing.push(cursor);
    const parent = dirname(cursor);
    if (parent === cursor) throw new SecureFileError(`Could not find an existing parent for: ${path}`);
    cursor = parent;
  }
  for (const directory of missing.reverse()) {
    try {
      mkdirSync(directory, { mode: 0o700 });
    } catch (error) {
      if (!pathHasFilesystemEvidence(directory)) {
        throw new SecureFileError(`Could not create owner-controlled directory: ${directory}`, error);
      }
    }
  }
  assertOwnerControlledTree(controlledRoot, path, uid);
}

function assertOwnerControlledTree(root: string, target: string, uid: number): void {
  const relative = target === root ? '' : target.slice(root.length + 1);
  const paths = [root];
  let cursor = root;
  for (const component of relative.split(sep).filter(Boolean)) {
    cursor = `${cursor}${sep}${component}`;
    paths.push(cursor);
  }
  for (const path of paths) {
    let stat;
    try { stat = lstatSync(path); } catch (error) {
      throw new SecureFileError(`Owner-controlled directory check failed: ${path}`, error);
    }
    if (stat.isSymbolicLink() || !stat.isDirectory() || stat.uid !== uid || (stat.mode & 0o022) !== 0) {
      throw new SecureFileError(`Owner-controlled directory check failed: ${path}`);
    }
  }
}


function assertSafeReplaceableFile(path: string, uid: number): void {
  if (!pathHasFilesystemEvidence(path)) return;
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.uid !== uid || (stat.mode & 0o022) !== 0) {
    throw new SecureFileError(`Owner-controlled target check failed: ${path}`);
  }
}

function assertRetainedOwnerControlledParent(path: string, fd: number, uid: number): void {
  const retained = fstatSync(fd);
  const current = lstatSync(path);
  if (
    !retained.isDirectory() || !current.isDirectory() || current.isSymbolicLink()
    || retained.uid !== uid || current.uid !== uid
    || (retained.mode & 0o022) !== 0 || (current.mode & 0o022) !== 0
    || retained.dev !== current.dev || retained.ino !== current.ino
  ) {
    throw new SecureFileError(`Owner-controlled parent directory changed during atomic write: ${path}`);
  }
}

export function removeOwnerControlledFile(path: string, controlledRoot: string, uid = currentUid()): void {
  const absolute = requireAbsolute(path);
  const root = requireAbsolute(controlledRoot);
  const parent = dirname(absolute);
  let parentFd: number | undefined;
  try {
    parentFd = openSync(parent, constants.O_RDONLY | directoryFlag() | noFollowFlag());
    assertOwnerControlledTree(root, parent, uid);
    assertRetainedOwnerControlledParent(parent, parentFd, uid);
    if (!pathHasFilesystemEvidence(absolute)) return;
    assertSafeReplaceableFile(absolute, uid);
    unlinkSync(absolute);
    assertOwnerControlledTree(root, parent, uid);
    assertRetainedOwnerControlledParent(parent, parentFd, uid);
    fsyncSync(parentFd);
  } catch (error) {
    throw error instanceof SecureFileError
      ? error
      : new SecureFileError(`Owner-controlled file removal failed: ${absolute}`, error);
  } finally {
    if (parentFd !== undefined) closeSync(parentFd);
  }
}

export function removeSecureFile(path: string, uid = currentUid()): void {
  const absolute = requireAbsolute(path);
  const parent = dirname(absolute);
  assertSecureFile(absolute, uid);
  let parentFd: number | undefined;
  try {
    parentFd = openSync(parent, constants.O_RDONLY | directoryFlag() | noFollowFlag());
    assertRetainedParent(parent, parentFd, uid);
    unlinkSync(absolute);
    assertRetainedParent(parent, parentFd, uid);
    fsyncSync(parentFd);
  } catch (error) {
    throw error instanceof SecureFileError ? error : new SecureFileError(`Secure file removal failed: ${absolute}`, error);
  } finally {
    if (parentFd !== undefined) closeSync(parentFd);
  }
}

export function ensureAriavaSecureDirectories(paths: readonly string[], uid = currentUid()): void {
  for (const path of paths) ensureSecureDirectory(path, uid);
}

export function redactSensitive(value: unknown, secrets: readonly string[] = []): unknown {
  const secretSet = [...secrets.filter(Boolean)].sort((a, b) => b.length - a.length);
  const sensitive = /(?:private.*key|secret|token|authorization|password)/iu;
  const visit = (item: unknown): unknown => {
    if (typeof item === 'string') {
      let result = item;
      for (const secret of secretSet) result = result.replaceAll(secret, '<redacted>');
      return result;
    }
    if (Array.isArray(item)) return item.map(visit);
    if (item && typeof item === 'object') {
      return Object.fromEntries(Object.entries(item).map(([key, entry]) => [key, sensitive.test(key) ? '<redacted>' : visit(entry)]));
    }
    return item;
  };
  return visit(value);
}

function assertRetainedParent(path: string, fd: number, uid: number): void {
  const retained = fstatSync(fd);
  const current = lstatSync(path);
  if (
    !retained.isDirectory() || !current.isDirectory() || current.isSymbolicLink()
    || retained.uid !== uid || current.uid !== uid
    || (retained.mode & 0o077) !== 0 || (current.mode & 0o077) !== 0
    || retained.dev !== current.dev || retained.ino !== current.ino
  ) {
    throw new SecureFileError(`Secure parent directory changed during atomic write: ${path}`);
  }
}

function retainedParentStillMatches(path: string, fd: number, uid: number): boolean {
  try {
    assertRetainedParent(path, fd, uid);
    return true;
  } catch {
    return false;
  }
}

function currentUid(): number {
  if (!process.getuid) throw new SecureFileError('Current uid is unavailable');
  return process.getuid();
}

function requireAbsolute(path: string): string {
  if (!isAbsolute(path)) throw new SecureFileError('Secure paths must be absolute');
  return resolve(path);
}

function noFollowFlag(): number {
  return typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
}

function directoryFlag(): number {
  return typeof constants.O_DIRECTORY === 'number' ? constants.O_DIRECTORY : 0;
}

function isMissing(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT');
}
