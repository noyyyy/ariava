import { describe, expect, test } from 'bun:test';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

/**
 * Host-domain reset recovery import-boundary policy (primary spec §9, §12;
 * journal-boundary spec §8, §11).
 *
 * Static structural assertions only: the recovery module must not import
 * `cli/context.ts`, the coordinator, the machine module, or raw journal store
 * internals beyond the public restore/removal seams
 * (`restoreHostDomainServiceAndConfirm` /
 * `removeAfterServiceRestoreConfirmed`), and it must not own the operation
 * lease (only type-import the opaque `HostIdentityOperationLease`). These are
 * source-import checks (not runtime claims); every test is registered in
 * `scripts/test-evidence-policy.registry.json` and validated by
 * `scripts/test-evidence.policy.test.ts` (TEST001/TEST002/AUDIT001).
 */

const bridgeRoot = realpathSync(join(import.meta.dir, '..'));
const sourceRoot = realpathSync(join(bridgeRoot, 'src'));
const recoveryModule = realpathSync(join(sourceRoot, 'cli', 'operations', 'host-domain-reset-recovery.ts'));

function moduleNameWithin(sourceRootPath: string, modulePath: string): string {
  return relative(sourceRootPath, modulePath).replace(/\\/gu, '/');
}

function resolveRelativeTsModule(importerPath: string, specifier: string): string | undefined {
  if (/\.[^/]+$/u.test(specifier) && !/\.(?:ts|tsx|js|mjs)$/u.test(specifier)) return undefined;
  const basePath = resolve(dirname(importerPath), specifier.replace(/\.(?:js|mjs)$/u, ''));
  const candidates = /\.(?:ts|tsx)$/u.test(basePath)
    ? [basePath]
    : [`${basePath}.ts`, `${basePath}.tsx`, resolve(basePath, 'index.ts'), resolve(basePath, 'index.tsx')];
  const match = candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
  if (!match) throw new Error(`Unable to resolve relative TypeScript import ${specifier} from ${importerPath}`);
  return realpathSync(match);
}

function relativeImportSpecifiers(modulePath: string): string[] {
  const source = readFileSync(modulePath, 'utf8');
  const specifiers: string[] = [];
  for (const match of source.matchAll(/\bfrom\s+['"]([^'"]+)['"]/gu)) {
    const specifier = match[1];
    if (specifier.startsWith('.')) specifiers.push(specifier);
  }
  return specifiers;
}

describe('host-domain reset recovery import boundary', () => {
  test('recovery does not import cli/context, the coordinator, or the machine', () => {
    const imports = relativeImportSpecifiers(recoveryModule)
      .map((specifier) => resolveRelativeTsModule(recoveryModule, specifier)!)
      .map((imported) => moduleNameWithin(sourceRoot, imported));
    expect(imports).not.toContain('cli/context.ts');
    expect(imports).not.toContain('cli/operations/host-domain-reset.ts');
    expect(imports).not.toContain('cli/operations/host-domain-reset-machine.ts');
  });

  test('recovery imports only the public store surface, never raw store internals', () => {
    const source = readFileSync(recoveryModule, 'utf8');
    // The store module itself owns the hardened restoration and removal
    // seams; schema/policy are only type-imported for journal types and are
    // never used for codec/policy evaluation.
    expect(source).not.toContain('parseHostDomainResetJournal');
    expect(source).not.toContain('encodeHostDomainResetJournal');
    expect(source).not.toContain('writeSecureJson');
    expect(source).not.toContain('removeSecureFileIfPresent');
    expect(source).not.toContain('acquireProcessAwareLock');
    expect(source).not.toContain('validateHostDomainResetTransition');
    expect(source).not.toContain('writeFileSync');
    expect(source).not.toContain('readFileSync');
  });

  test('recovery never acquires or fabricates the Host identity operation lease', () => {
    const source = readFileSync(recoveryModule, 'utf8');
    expect(source).not.toContain('withHostIdentityOperationLock');
    // Type-only import of the opaque lease is allowed; the lease is a parameter.
    expect(source).toContain('HostIdentityOperationLease');
  });

  test('recovery performs no raw journal unlink or arbitrary-path write', () => {
    const source = readFileSync(recoveryModule, 'utf8');
    expect(source).not.toContain('unlinkSync');
    expect(source).not.toContain('rmSync');
    expect(source).not.toContain('removeHostDomainResetJournal');
  });

  test('recovery never reads or writes the journal advancement lock or the raw journal path', () => {
    const source = readFileSync(recoveryModule, 'utf8');
    expect(source).not.toContain('.advance.lock');
    expect(source).not.toContain('.operation.lock');
    expect(source).not.toContain('journalAdvancementLockedError');
    expect(source).not.toContain('hostDomainResetJournalPath');
  });
});
