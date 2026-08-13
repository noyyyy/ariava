import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, sep } from 'node:path';
import { SecureFileError } from './error';
import { pathHasFilesystemEvidence } from './filesystem-evidence';
import { currentUid, directoryFlag, noFollowFlag, requireAbsolute } from './filesystem-safety';

export interface OwnerControlledFileWriteHooks {
  beforePromotion?(): void;
}

/**
 * Atomically writes a non-secret file below an owner-controlled directory tree.
 * Existing directories may be readable by other users, but must be owned by the
 * current uid, must not be group/world writable, and no path component may be a
 * symlink. Retained-parent revalidation narrows and detects parent replacement,
 * but portable Node pathname rename cannot provide a descriptor-relative
 * zero-window guarantee.
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
    if (!stat.isFile() || stat.uid !== uid || !hasExactSecureFileMode(stat.mode)) {
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

export function removeOwnerControlledFile(path: string, controlledRoot: string, uid = currentUid()): void {
  const absolute = requireAbsolute(path);
  const root = requireAbsolute(controlledRoot);
  const parent = dirname(absolute);
  if (parent !== root && !parent.startsWith(`${root}${sep}`)) {
    throw new SecureFileError(`Owner-controlled file must remain below its root: ${absolute}`);
  }
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

function hasExactSecureFileMode(mode: number): boolean {
  return (mode & 0o7777) === 0o600;
}
