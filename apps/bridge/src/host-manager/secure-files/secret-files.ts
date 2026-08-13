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
import { dirname } from 'node:path';
import { SecureFileError } from './error';
import { pathHasFilesystemEvidence } from './filesystem-evidence';
import { currentUid, directoryFlag, noFollowFlag, requireAbsolute } from './filesystem-safety';

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
    let created = false;
    try {
      mkdirSecureDirectory(directory);
      created = true;
    } catch (error) {
      // A concurrent creator is acceptable only when it created exactly the secure directory expected.
      if (!pathHasFilesystemEvidence(directory)) throw new SecureFileError(`Could not create secure directory: ${directory}`, error);
    }
    if (created) normalizeCreatedSecureDirectory(directory, uid);
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
  const mode = stat.mode & 0o777;
  if (stat.isSymbolicLink() || !stat.isDirectory() || stat.uid !== uid || mode !== 0o700) {
    throw new SecureFileError(
      `Secure directory check failed: ${absolute} (expected mode 0700, found ${mode.toString(8).padStart(4, '0')})`,
    );
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
  if (stat.isSymbolicLink() || !stat.isFile() || stat.uid !== uid || !hasExactSecureFileMode(stat.mode)) {
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
    if (!stat.isFile() || stat.uid !== uid || !hasExactSecureFileMode(stat.mode)) {
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

export function writeSecureJson(
  path: string, value: unknown, uid = currentUid(), hooks: SecureFileWriteHooks = {},
): void {
  writeSecureFile(path, Buffer.from(`${JSON.stringify(value, null, 2)}\n`), uid, false, hooks);
}

export function writeSecureJsonExclusive(
  path: string, value: unknown, uid = currentUid(), hooks: SecureFileWriteHooks = {},
): void {
  writeSecureFile(path, Buffer.from(`${JSON.stringify(value, null, 2)}\n`), uid, true, hooks);
}

export interface SecureFileWriteHooks {
  afterTemporaryWrite?(path: string): void;
  afterFileSync?(path: string): void;
  beforePromotion?(): void;
  afterPromotion?(path: string): void;
  afterDirectorySync?(path: string): void;
}

export interface SecureFileRemoveHooks {
  beforeUnlink?(path: string): void;
  afterUnlink?(path: string): void;
  afterDirectorySync?(path: string): void;
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
  let exclusiveTargetIdentity: { dev: number; ino: number } | undefined;
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
    hooks.afterTemporaryWrite?.(absolute);
    fsyncSync(fd);
    hooks.afterFileSync?.(absolute);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== uid || !hasExactSecureFileMode(stat.mode)) {
      throw new SecureFileError(`Secure temporary file check failed: ${absolute}`);
    }
    closeSync(fd);
    fd = undefined;

    hooks.beforePromotion?.();
    assertRetainedParent(parent, parentFd, uid);
    if (exclusive) {
      // link(2) fails atomically when a target (including a symlink) won the race.
      exclusiveTargetIdentity = { dev: stat.dev, ino: stat.ino };
      linkSync(temporary, absolute);
      temporaryLinked = true;
      unlinkSync(temporary);
    } else {
      renameSync(temporary, absolute);
    }
    hooks.afterPromotion?.(absolute);

    // Revalidate the retained directory immediately before syncing its entry update.
    assertRetainedParent(parent, parentFd, uid);
    fsyncSync(parentFd);
    hooks.afterDirectorySync?.(absolute);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temporary); } catch {}
    if (
      temporaryLinked && exclusiveTargetIdentity !== undefined && parentFd !== undefined
      && retainedParentStillMatches(parent, parentFd, uid)
    ) {
      try {
        const target = lstatSync(absolute);
        if (target.dev === exclusiveTargetIdentity.dev && target.ino === exclusiveTargetIdentity.ino) {
          // Node has no portable descriptor-relative conditional unlink; inode revalidation narrows but cannot eliminate the final-component race.
          unlinkSync(absolute);
        }
      } catch {}
    }
    throw error instanceof SecureFileError ? error : new SecureFileError(`Secure atomic write failed: ${absolute}`, error);
  } finally {
    if (parentFd !== undefined) closeSync(parentFd);
  }
}

export function removeSecureFileIfPresent(
  path: string, uid = currentUid(), hooks: SecureFileRemoveHooks = {},
): void {
  const absolute = requireAbsolute(path);
  const parent = dirname(absolute);
  let parentFd: number | undefined;
  try {
    parentFd = openSync(parent, constants.O_RDONLY | directoryFlag() | noFollowFlag());
    assertRetainedParent(parent, parentFd, uid);
    if (!pathHasFilesystemEvidence(absolute)) {
      assertRetainedParent(parent, parentFd, uid);
      return;
    }
    const target = secureTargetSnapshot(absolute, uid);
    assertRetainedParent(parent, parentFd, uid);
    hooks.beforeUnlink?.(absolute);
    assertRetainedParent(parent, parentFd, uid);
    assertRetainedSecureTarget(absolute, target, uid);
    unlinkSync(absolute);
    hooks.afterUnlink?.(absolute);
    assertRetainedParent(parent, parentFd, uid);
    fsyncSync(parentFd);
    hooks.afterDirectorySync?.(absolute);
  } catch (error) {
    throw error instanceof SecureFileError
      ? error
      : new SecureFileError(`Secure file removal failed: ${absolute}`, error);
  } finally {
    if (parentFd !== undefined) closeSync(parentFd);
  }
}

export function removeSecureFile(
  path: string, uid = currentUid(), hooks: SecureFileRemoveHooks = {},
): void {
  const absolute = requireAbsolute(path);
  const parent = dirname(absolute);
  assertSecureFile(absolute, uid);
  let parentFd: number | undefined;
  try {
    parentFd = openSync(parent, constants.O_RDONLY | directoryFlag() | noFollowFlag());
    assertRetainedParent(parent, parentFd, uid);
    unlinkSync(absolute);
    hooks.afterUnlink?.(absolute);
    assertRetainedParent(parent, parentFd, uid);
    fsyncSync(parentFd);
    hooks.afterDirectorySync?.(absolute);
  } catch (error) {
    throw error instanceof SecureFileError ? error : new SecureFileError(`Secure file removal failed: ${absolute}`, error);
  } finally {
    if (parentFd !== undefined) closeSync(parentFd);
  }
}

export function ensureAriavaSecureDirectories(paths: readonly string[], uid = currentUid()): void {
  for (const path of paths) ensureSecureDirectory(path, uid);
}

function mkdirSecureDirectory(path: string): void {
  const previousUmask = process.umask(0);
  try {
    mkdirSync(path, { mode: 0o700 });
  } finally {
    process.umask(previousUmask);
  }
}

function normalizeCreatedSecureDirectory(path: string, uid: number): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | directoryFlag() | noFollowFlag());
    assertCreatedSecureDirectory(path, fd, uid);
    fchmodSync(fd, 0o700);
    assertCreatedSecureDirectory(path, fd, uid, true);
  } catch (error) {
    throw error instanceof SecureFileError
      ? error
      : new SecureFileError(`Could not secure newly created directory: ${path}`, error);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function assertCreatedSecureDirectory(path: string, fd: number, uid: number, requireMode = false): void {
  const retained = fstatSync(fd);
  const current = lstatSync(path);
  if (
    !retained.isDirectory() || !current.isDirectory() || current.isSymbolicLink()
    || retained.uid !== uid || current.uid !== uid
    || retained.dev !== current.dev || retained.ino !== current.ino
    || (requireMode && ((retained.mode & 0o777) !== 0o700 || (current.mode & 0o777) !== 0o700))
  ) {
    throw new SecureFileError(`Newly created secure directory changed before validation: ${path}`);
  }
}

function secureTargetSnapshot(path: string, uid: number): ReturnType<typeof lstatSync> {
  let target;
  try {
    target = lstatSync(path);
  } catch (error) {
    throw new SecureFileError(`Secure file check failed: ${path}`, error);
  }
  if (target.isSymbolicLink() || !target.isFile() || target.uid !== uid || !hasExactSecureFileMode(target.mode)) {
    throw new SecureFileError(`Secure file check failed: ${path}`);
  }
  return target;
}

function assertRetainedSecureTarget(
  path: string,
  expected: ReturnType<typeof lstatSync>,
  uid: number,
): void {
  let current;
  try {
    current = secureTargetSnapshot(path, uid);
  } catch (error) {
    throw new SecureFileError(`Secure removal target changed before unlink: ${path}`, error);
  }
  if (expected.dev !== current.dev || expected.ino !== current.ino
    || expected.uid !== current.uid || expected.mode !== current.mode) {
    throw new SecureFileError(`Secure removal target changed before unlink: ${path}`);
  }
}

function assertRetainedParent(path: string, fd: number, uid: number): void {
  const retained = fstatSync(fd);
  const current = lstatSync(path);
  if (
    !retained.isDirectory() || !current.isDirectory() || current.isSymbolicLink()
    || retained.uid !== uid || current.uid !== uid
    || (retained.mode & 0o777) !== 0o700 || (current.mode & 0o777) !== 0o700
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

function hasExactSecureFileMode(mode: number): boolean {
  return (mode & 0o7777) === 0o600;
}
