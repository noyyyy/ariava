export { SecureFileError } from './secure-files/error';
export { pathHasFilesystemEvidence } from './secure-files/filesystem-evidence';
export {
  type OwnerControlledFileWriteHooks,
  removeOwnerControlledFile,
  writeOwnerControlledFile,
} from './secure-files/owner-controlled-files';
export { redactSensitive } from './secure-files/redaction';
export {
  type SecureFileRemoveHooks,
  type SecureFileWriteHooks,
  assertSecureDirectory,
  assertSecureFile,
  ensureAriavaSecureDirectories,
  ensureSecureDirectory,
  readSecureFile,
  readSecureJson,
  removeSecureFile,
  removeSecureFileIfPresent,
  repairSecureFileMode,
  writeSecureFile,
  writeSecureJson,
  writeSecureJsonExclusive,
} from './secure-files/secret-files';
