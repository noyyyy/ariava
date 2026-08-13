import { afterEach, describe, expect, test } from 'bun:test';
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as secureFilesFacade from '../src/host-manager/secure-files';
import {
  pathHasFilesystemEvidence,
  redactSensitive,
  readSecureJson,
  removeOwnerControlledFile,
  removeSecureFileIfPresent,
  SecureFileError,
  writeOwnerControlledFile,
  writeSecureFile,
  writeSecureJson,
} from '../src/host-manager/secure-files';
import { SecureFileError as DirectSecureFileError } from '../src/host-manager/secure-files/error';
import { pathHasFilesystemEvidence as directPathHasFilesystemEvidence } from '../src/host-manager/secure-files/filesystem-evidence';
import {
  removeOwnerControlledFile as directRemoveOwnerControlledFile,
  writeOwnerControlledFile as directWriteOwnerControlledFile,
} from '../src/host-manager/secure-files/owner-controlled-files';
import { redactSensitive as directRedactSensitive } from '../src/host-manager/secure-files/redaction';

const roots: string[] = [];
function root(): string { const value = mkdtempSync(join(tmpdir(), 'ariava-secure-')); chmodSync(value, 0o700); roots.push(value); return value; }
afterEach(() => { for (const value of roots.splice(0)) rmSync(value, { recursive: true, force: true }); });

describe('secure JSON files', () => {
  test('creates controlled directories and atomic 0600 JSON', () => {
    const path = join(root(), 'state', 'bridge-state.json');
    writeSecureJson(path, { value: 1 });
    expect(lstatSync(join(path, '..')).mode & 0o777).toBe(0o700);
    expect(lstatSync(path).mode & 0o777).toBe(0o600);
    expect(readSecureJson(path)).toEqual({ value: 1 });
    expect(readFileSync(path, 'utf8')).toEndWith('\n');
  });

  test('normalizes newly created controlled directories when umask removes owner permissions', () => {
    const previous = process.umask(0o777);
    try {
      const path = join(root(), 'state', 'bridge-state.json');
      writeSecureJson(path, { value: 1 });
      expect(lstatSync(join(path, '..')).mode & 0o777).toBe(0o700);
    } finally {
      process.umask(previous);
    }
  });

  test('rejects group/world permissions and symlinks', () => {
    const base = root();
    const path = join(base, 'config.json');
    writeSecureJson(path, { value: 1 });
    chmodSync(path, 0o644);
    expect(() => readSecureJson(path)).toThrow();
    chmodSync(path, 0o600);
    const link = join(base, 'link.json');
    symlinkSync(path, link);
    expect(() => readSecureJson(link)).toThrow();
  });

  test('fails closed for an insecure controlled directory on every write', () => {
    const base = join(root(), 'custom-root');
    writeSecureJson(join(base, 'config.json'), {});
    chmodSync(base, 0o755);
    expect(() => writeSecureJson(join(base, 'state.json'), {})).toThrow();
  });

  test('rejects a controlled directory without owner execute permission', () => {
    const base = join(root(), 'custom-root');
    mkdirSync(base, { mode: 0o700 });
    chmodSync(base, 0o600);
    expect(() => writeSecureJson(join(base, 'config.json'), {})).toThrow(
      `Secure directory check failed: ${base} (expected mode 0700, found 0600)`,
    );
  });

  test('validates custom parent directories without Ariava path-name heuristics', () => {
    const base = join(root(), 'completely-custom-name');
    writeSecureJson(join(base, 'config.json'), {});
    chmodSync(base, 0o755);
    expect(() => readSecureJson(join(base, 'config.json'))).toThrow();
  });

  function captureSecureFileError(operation: () => void): SecureFileError {
    try {
      operation();
    } catch (error) {
      expect(error).toBeInstanceOf(SecureFileError);
      return error as SecureFileError;
    }
    throw new Error('Expected SecureFileError');
  }

  function temporaryFiles(directory: string, fileName: string): string[] {
    return readdirSync(directory).filter((entry) => entry.startsWith(`${fileName}.tmp-`));
  }

  test('compatibility facade preserves exact runtime exports and direct module identities', () => {
    expect(Object.keys(secureFilesFacade).sort()).toEqual([
      'SecureFileError',
      'assertSecureDirectory',
      'assertSecureFile',
      'ensureAriavaSecureDirectories',
      'ensureSecureDirectory',
      'pathHasFilesystemEvidence',
      'readSecureFile',
      'readSecureJson',
      'redactSensitive',
      'removeOwnerControlledFile',
      'removeSecureFile',
      'removeSecureFileIfPresent',
      'repairSecureFileMode',
      'writeOwnerControlledFile',
      'writeSecureFile',
      'writeSecureJson',
      'writeSecureJsonExclusive',
    ]);
    expect(directPathHasFilesystemEvidence).toBe(pathHasFilesystemEvidence);
    expect(directRedactSensitive).toBe(redactSensitive);
    expect(directRemoveOwnerControlledFile).toBe(removeOwnerControlledFile);
    expect(directWriteOwnerControlledFile).toBe(writeOwnerControlledFile);
    expect(DirectSecureFileError).toBe(SecureFileError);
    expect(() => directPathHasFilesystemEvidence('relative.json')).toThrow(DirectSecureFileError);
  });

  test('requires absolute paths with stable SecureFileError identity', () => {
    for (const operation of [
      () => pathHasFilesystemEvidence('relative.json'),
      () => writeSecureFile('relative.json', Buffer.from('secret')),
      () => writeOwnerControlledFile('relative.service', Buffer.from('unit'), root()),
    ]) {
      const error = captureSecureFileError(operation);
      expect(error.message).toContain('Secure paths must be absolute');
    }
  });

  test('observes filesystem evidence without applying file policy', () => {
    const base = root();
    const missing = join(base, 'missing.json');
    const regular = join(base, 'regular.json');
    const link = join(base, 'link.json');
    const dangling = join(base, 'dangling.json');
    writeFileSync(regular, 'public', { mode: 0o666 });
    symlinkSync(regular, link);
    symlinkSync(missing, dangling);

    expect(pathHasFilesystemEvidence(missing)).toBe(false);
    expect(pathHasFilesystemEvidence(regular)).toBe(true);
    expect(pathHasFilesystemEvidence(link)).toBe(true);
    expect(pathHasFilesystemEvidence(dangling)).toBe(true);
  });

  test('runs secure write hooks in durability order with target path arguments', () => {
    const target = join(root(), 'state.json');
    const events: string[] = [];
    writeSecureFile(target, Buffer.from('new'), undefined, false, {
      afterTemporaryWrite(path) { events.push(`afterTemporaryWrite:${path}`); },
      afterFileSync(path) { events.push(`afterFileSync:${path}`); },
      beforePromotion() { events.push('beforePromotion'); },
      afterPromotion(path) { events.push(`afterPromotion:${path}`); },
      afterDirectorySync(path) { events.push(`afterDirectorySync:${path}`); },
    });

    expect(events).toEqual([
      `afterTemporaryWrite:${target}`,
      `afterFileSync:${target}`,
      'beforePromotion',
      `afterPromotion:${target}`,
      `afterDirectorySync:${target}`,
    ]);
    expect(readFileSync(target, 'utf8')).toBe('new');
  });

  test('cleans temporary files when a secure write fails before promotion', () => {
    const base = root();
    const target = join(base, 'state.json');
    expect(() => writeSecureFile(target, Buffer.from('new'), undefined, false, {
      afterTemporaryWrite() { throw new Error('injected temporary write failure'); },
    })).toThrow('Secure atomic write failed');

    expect(pathHasFilesystemEvidence(target)).toBe(false);
    expect(temporaryFiles(base, 'state.json')).toEqual([]);
  });

  test('does not leak injected error markers through secure or owner-controlled wrappers', () => {
    const base = root();
    const marker = 'injected-secret-marker';
    const secureTarget = join(base, 'secure.json');
    const controlledRoot = join(base, 'controlled');
    const controlledTarget = join(controlledRoot, 'service.conf');

    for (const operation of [
      () => writeSecureFile(secureTarget, Buffer.from('secret'), undefined, false, {
        afterTemporaryWrite() { throw new Error(marker); },
      }),
      () => writeOwnerControlledFile(controlledTarget, Buffer.from('unit'), controlledRoot, undefined, {
        beforePromotion() { throw new Error(marker); },
      }),
    ]) {
      const error = captureSecureFileError(operation);
      expect(error.message).not.toContain(marker);
    }
    expect(pathHasFilesystemEvidence(controlledTarget)).toBe(false);
    expect(temporaryFiles(controlledRoot, 'service.conf')).toEqual([]);
  });

  test('cleans an exclusive promotion when its post-promotion hook fails', () => {
    const base = root();
    const target = join(base, 'state.json');
    expect(() => writeSecureFile(target, Buffer.from('new'), undefined, true, {
      afterPromotion() { throw new Error('injected promotion failure'); },
    })).toThrow('Secure atomic write failed');

    expect(pathHasFilesystemEvidence(target)).toBe(false);
    expect(temporaryFiles(base, 'state.json')).toEqual([]);
  });

  test('preserves a winner that collides before exclusive link promotion', () => {
    const base = root();
    const target = join(base, 'state.json');
    expect(() => writeSecureFile(target, Buffer.from('loser'), undefined, true, {
      beforePromotion() { writeFileSync(target, 'winner', { mode: 0o600 }); },
    })).toThrow('Secure atomic write failed');

    expect(readFileSync(target, 'utf8')).toBe('winner');
    expect(temporaryFiles(base, 'state.json')).toEqual([]);
  });

  test('preserves a replacement inode introduced after exclusive promotion', () => {
    const base = root();
    const target = join(base, 'state.json');
    const replacement = join(base, 'replacement.json');
    writeFileSync(replacement, 'winner', { mode: 0o600 });
    const replacementIdentity = lstatSync(replacement);

    expect(() => writeSecureFile(target, Buffer.from('loser'), undefined, true, {
      afterPromotion(path) {
        renameSync(replacement, path);
        throw new Error('injected post-promotion failure');
      },
    })).toThrow('Secure atomic write failed');

    const targetIdentity = lstatSync(target);
    expect(targetIdentity.dev).toBe(replacementIdentity.dev);
    expect(targetIdentity.ino).toBe(replacementIdentity.ino);
    expect(readFileSync(target, 'utf8')).toBe('winner');
    expect(temporaryFiles(base, 'state.json')).toEqual([]);
  });

  test('aborts atomic promotion if the parent directory is replaced', () => {
    const base = root();
    const parent = join(base, 'state');
    mkdirSync(parent, { mode: 0o700 });
    const displaced = join(base, 'state-displaced');
    const replacement = join(base, 'replacement');
    mkdirSync(replacement, { mode: 0o700 });
    const target = join(parent, 'state.json');
    expect(() => writeSecureFile(target, Buffer.from('new'), undefined, false, {
      beforePromotion() {
        renameSync(parent, displaced);
        renameSync(replacement, parent);
      },
    })).toThrow('Secure parent directory changed during atomic write');
    expect(pathHasFilesystemEvidence(target)).toBe(false);
    expect(pathHasFilesystemEvidence(join(displaced, 'state.json'))).toBe(false);
  });

  test('aborts atomic promotion if the parent directory mode changes', () => {
    const parent = join(root(), 'state');
    mkdirSync(parent, { mode: 0o700 });
    const target = join(parent, 'state.json');
    try {
      expect(() => writeSecureFile(target, Buffer.from('new'), undefined, false, {
        beforePromotion() { chmodSync(parent, 0o300); },
      })).toThrow('Secure parent directory changed during atomic write');
    } finally {
      chmodSync(parent, 0o700);
    }
    expect(pathHasFilesystemEvidence(target)).toBe(false);
  });

  test('owner-controlled service writes reject insecure modes, wrong owners, and symlinked directories', () => {
    const base = root();
    const target = join(base, 'systemd', 'user', 'ariava.service');
    writeOwnerControlledFile(target, Buffer.from('unit'), base);
    expect(readFileSync(target, 'utf8')).toBe('unit');
    expect(lstatSync(target).mode & 0o777).toBe(0o600);
    expect(lstatSync(join(base, 'systemd')).mode & 0o777).toBe(0o700);
    expect(lstatSync(join(base, 'systemd', 'user')).mode & 0o777).toBe(0o700);

    chmodSync(join(base, 'systemd'), 0o777);
    expect(() => writeOwnerControlledFile(target, Buffer.from('changed'), base)).toThrow();
    chmodSync(join(base, 'systemd'), 0o700);
    expect(() => writeOwnerControlledFile(target, Buffer.from('changed'), base, (process.getuid?.() ?? 0) + 1)).toThrow();

    rmSync(join(base, 'systemd'), { recursive: true, force: true });
    const elsewhere = join(base, 'elsewhere');
    mkdirSync(elsewhere, { mode: 0o700 });
    symlinkSync(elsewhere, join(base, 'systemd'));
    expect(() => writeOwnerControlledFile(target, Buffer.from('redirected'), base)).toThrow();

    rmSync(join(base, 'systemd'), { recursive: true, force: true });
    mkdirSync(join(base, 'systemd'), { mode: 0o700 });
    const finalElsewhere = join(base, 'final-elsewhere');
    mkdirSync(finalElsewhere, { mode: 0o700 });
    symlinkSync(finalElsewhere, join(base, 'systemd', 'user'));
    expect(() => writeOwnerControlledFile(target, Buffer.from('final-redirected'), base)).toThrow();
  });

  test('accepts owner-controlled readable ancestors without group or world writes', () => {
    const base = root();
    const controlledRoot = join(base, 'controlled');
    const parent = join(controlledRoot, 'user');
    mkdirSync(parent, { recursive: true, mode: 0o755 });
    chmodSync(controlledRoot, 0o755);
    chmodSync(parent, 0o755);
    const target = join(parent, 'ariava.service');

    writeOwnerControlledFile(target, Buffer.from('unit'), controlledRoot);
    expect(readFileSync(target, 'utf8')).toBe('unit');
    expect(() => removeOwnerControlledFile(target, controlledRoot)).not.toThrow();
    expect(pathHasFilesystemEvidence(target)).toBe(false);
  });

  test('owner-controlled service write aborts if the validated parent is replaced before promotion', () => {
    const base = root();
    const parent = join(base, 'systemd', 'user');
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    chmodSync(join(base, 'systemd'), 0o700);
    chmodSync(parent, 0o700);
    const displaced = join(base, 'user-displaced');
    const replacement = join(base, 'replacement');
    mkdirSync(replacement, { mode: 0o700 });
    const target = join(parent, 'ariava.service');
    expect(() => writeOwnerControlledFile(target, Buffer.from('unit'), base, undefined, {
      beforePromotion() {
        renameSync(parent, displaced);
        renameSync(replacement, parent);
      },
    })).toThrow('Owner-controlled parent directory changed during atomic write');
    expect(pathHasFilesystemEvidence(target)).toBe(false);
    expect(pathHasFilesystemEvidence(join(displaced, 'ariava.service'))).toBe(false);
  });

  test('rejects owner-controlled root escape, symlink targets, and insecure targets', () => {
    const base = root();
    const controlledRoot = join(base, 'controlled');
    const parent = join(controlledRoot, 'user');
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    chmodSync(controlledRoot, 0o700);
    chmodSync(parent, 0o700);
    const outsideTarget = join(base, 'outside.service');

    expect(() => writeOwnerControlledFile(outsideTarget, Buffer.from('unit'), controlledRoot)).toThrow(
      'Owner-controlled file must remain below its root',
    );

    const controlledTarget = join(parent, 'ariava.service');
    const expectTargetOperationsToFail = () => {
      expect(() => writeOwnerControlledFile(
        controlledTarget,
        Buffer.from('unit'),
        controlledRoot,
      )).toThrow('Owner-controlled target check failed');
      expect(() => removeOwnerControlledFile(controlledTarget, controlledRoot)).toThrow(
        'Owner-controlled target check failed',
      );
    };

    symlinkSync(outsideTarget, controlledTarget);
    expectTargetOperationsToFail();

    rmSync(controlledTarget);
    symlinkSync(join(base, 'missing.service'), controlledTarget);
    expectTargetOperationsToFail();

    rmSync(controlledTarget);
    writeFileSync(controlledTarget, 'insecure', { mode: 0o622 });
    chmodSync(controlledTarget, 0o622);
    expectTargetOperationsToFail();
    expect(readFileSync(controlledTarget, 'utf8')).toBe('insecure');
  });

  test('rejects owner-controlled removal outside its root before deleting anything', () => {
    const base = root();
    const controlledRoot = join(base, 'controlled');
    mkdirSync(controlledRoot, { mode: 0o700 });
    const outside = join(base, 'outside.service');
    writeFileSync(outside, 'outside', { mode: 0o600 });

    expect(() => removeOwnerControlledFile(outside, controlledRoot)).toThrow(
      'Owner-controlled file must remain below its root',
    );
    expect(readFileSync(outside, 'utf8')).toBe('outside');
    expect(() => removeOwnerControlledFile(join(base, 'missing.service'), controlledRoot)).toThrow(
      'Owner-controlled file must remain below its root',
    );
  });

  test('owner-controlled removal is idempotent and rejects an insecure ancestor', () => {
    const base = root();
    const controlledRoot = join(base, 'controlled');
    const parent = join(controlledRoot, 'user');
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    chmodSync(controlledRoot, 0o700);
    chmodSync(parent, 0o700);
    const target = join(parent, 'ariava.service');

    expect(() => removeOwnerControlledFile(target, controlledRoot)).not.toThrow();
    writeFileSync(target, 'unit', { mode: 0o600 });
    chmodSync(parent, 0o722);
    expect(() => removeOwnerControlledFile(target, controlledRoot)).toThrow(
      'Owner-controlled directory check failed',
    );
    expect(readFileSync(target, 'utf8')).toBe('unit');
  });

  test('validates secure parents even when the removal target is absent', () => {
    const base = root();
    const secureParent = join(base, 'secure-parent');
    mkdirSync(secureParent, { mode: 0o700 });
    expect(() => removeSecureFileIfPresent(join(secureParent, 'missing.json'))).not.toThrow();

    chmodSync(secureParent, 0o755);
    expect(() => removeSecureFileIfPresent(join(secureParent, 'missing.json'))).toThrow();
    chmodSync(secureParent, 0o700);
    expect(() => removeSecureFileIfPresent(
      join(secureParent, 'missing.json'),
      (process.getuid?.() ?? 0) + 1,
    )).toThrow();

    const symlinkTarget = join(base, 'symlink-target');
    mkdirSync(symlinkTarget, { mode: 0o700 });
    const symlinkParent = join(base, 'symlink-parent');
    symlinkSync(symlinkTarget, symlinkParent);
    expect(() => removeSecureFileIfPresent(join(symlinkParent, 'missing.json'))).toThrow();
  });

  test('runs secure removal hooks in unlink and directory-sync order', () => {
    const target = join(root(), 'journal.json');
    writeFileSync(target, 'original', { mode: 0o600 });
    const events: string[] = [];

    removeSecureFileIfPresent(target, undefined, {
      beforeUnlink(path) { events.push(`beforeUnlink:${path}`); },
      afterUnlink(path) {
        events.push(`afterUnlink:${path}`);
        expect(pathHasFilesystemEvidence(path)).toBe(false);
      },
      afterDirectorySync(path) { events.push(`afterDirectorySync:${path}`); },
    });

    expect(events).toEqual([
      `beforeUnlink:${target}`,
      `afterUnlink:${target}`,
      `afterDirectorySync:${target}`,
    ]);
  });

  test('preserves a replacement inode introduced immediately before secure unlink', () => {
    const base = root();
    const target = join(base, 'journal.json');
    const replacement = join(base, 'replacement.json');
    writeFileSync(target, 'original', { mode: 0o600 });
    writeFileSync(replacement, 'replacement', { mode: 0o600 });
    const events: string[] = [];

    expect(() => removeSecureFileIfPresent(target, undefined, {
      beforeUnlink(path) {
        events.push(`beforeUnlink:${path}`);
        renameSync(replacement, target);
      },
      afterUnlink(path) { events.push(`afterUnlink:${path}`); },
      afterDirectorySync(path) { events.push(`afterDirectorySync:${path}`); },
    })).toThrow(/changed|removal/i);

    expect(events).toEqual([`beforeUnlink:${target}`]);
    expect(readFileSync(target, 'utf8')).toBe('replacement');
  });

  test('agent adapter loader fails closed on dangling discovery symlink evidence', async () => {
    const base = root();
    const path = join(base, 'adapter.json');
    symlinkSync(join(base, 'missing-adapter.json'), path);
    const { readAgentAdapterConfig } = await import('../src/agent-adapter/config');
    expect(() => readAgentAdapterConfig(path)).toThrow();
  });

  test('agent adapter loader fails closed on malformed JSON and schema', async () => {
    const base = root();
    const { readAgentAdapterConfig } = await import('../src/agent-adapter/config');
    const malformed = join(base, 'malformed.json');
    writeFileSync(malformed, '{bad', { mode: 0o600 });
    expect(() => readAgentAdapterConfig(malformed)).toThrow();
    const invalid = join(base, 'invalid.json');
    writeSecureJson(invalid, { url: 'http://127.0.0.1:7272' });
    expect(() => readAgentAdapterConfig(invalid)).toThrow('Agent Adapter discovery file is invalid');
  });

  test('redacts nested arrays, objects, sensitive keys, and overlapping secrets', () => {
    expect(redactSensitive({
      privateSigningKey: 'visible-value',
      nested: [{ message: 'prefix-abcd-abc' }, { Authorization: 'header' }],
      safe: { passwordHint: 'hint', value: 'abcd' },
    }, ['', 'abc', 'abcd'])).toEqual({
      privateSigningKey: '<redacted>',
      nested: [{ message: 'prefix-<redacted>-<redacted>' }, { Authorization: '<redacted>' }],
      safe: { passwordHint: '<redacted>', value: '<redacted>' },
    });
  });

  test('leaves primitives unchanged and ignores empty supplied secrets', () => {
    for (const value of [null, undefined, 42, true, 'unchanged']) {
      expect(redactSensitive(value, [''])).toBe(value);
    }
  });
});
