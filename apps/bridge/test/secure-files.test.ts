import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  pathHasFilesystemEvidence,
  redactSensitive,
  readSecureJson,
  removeSecureFileIfPresent,
  writeOwnerControlledFile,
  writeSecureFile,
  writeSecureJson,
} from '../src/host-manager/secure-files';

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

  test('treats a dangling symlink as filesystem evidence', () => {
    const path = join(root(), 'dangling.json');
    symlinkSync(join(path, '..', 'missing.json'), path);
    expect(pathHasFilesystemEvidence(path)).toBe(true);
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

  test('preserves a replacement inode introduced immediately before secure unlink', () => {
    const base = root();
    const target = join(base, 'journal.json');
    const replacement = join(base, 'replacement.json');
    writeFileSync(target, 'original', { mode: 0o600 });
    writeFileSync(replacement, 'replacement', { mode: 0o600 });

    expect(() => removeSecureFileIfPresent(target, undefined, {
      beforeUnlink() {
        renameSync(replacement, target);
      },
    })).toThrow(/changed|removal/i);

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

  test('redacts nested sensitive fields and supplied secret values', () => {
    expect(redactSensitive({ agentAdapterSecret: 'abc', nested: { message: 'token=abc' } }, ['abc'])).toEqual({
      agentAdapterSecret: '<redacted>', nested: { message: 'token=<redacted>' },
    });
  });
});
