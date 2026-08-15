import { describe, expect, test } from 'bun:test';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

/**
 * Host-domain reset executor import-boundary policy (primary spec §8, §12;
 * journal-boundary spec §11).
 *
 * Static structural assertions only: the executor module must not reach the
 * journal store, `cli/context.ts`, the coordinator, the recovery module,
 * `node:fs`, `secure-files`, or `state-store`. These are source-import checks
 * (not runtime claims); every test is registered in
 * `scripts/test-evidence-policy.registry.json` and validated by
 * `scripts/test-evidence.policy.test.ts` (TEST001/TEST002/AUDIT001).
 */

const bridgeRoot = realpathSync(join(import.meta.dir, '..'));
const sourceRoot = realpathSync(join(bridgeRoot, 'src'));
const executorModule = realpathSync(join(sourceRoot, 'cli', 'operations', 'host-domain-reset-executor.ts'));

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
  // Text-level scan captures both runtime and type-only imports;
  // `Bun.Transpiler.scanImports` skips type-only imports.
  const specifiers: string[] = [];
  for (const match of source.matchAll(/\bfrom\s+['"]([^'"]+)['"]/gu)) {
    const specifier = match[1];
    if (specifier.startsWith('.')) specifiers.push(specifier);
  }
  return specifiers;
}

describe('host-domain reset executor import boundary', () => {
  test('executor does not import the journal store, coordinator, context, or recovery modules', () => {
    const imports = relativeImportSpecifiers(executorModule)
      .map((specifier) => resolveRelativeTsModule(executorModule, specifier)!)
      .map((imported) => moduleNameWithin(sourceRoot, imported));
    expect(imports).not.toContain('cli/operations/host-domain-reset-journal-store.ts');
    expect(imports).not.toContain('cli/operations/host-domain-reset.ts');
    expect(imports).not.toContain('cli/operations/host-domain-reset-recovery.ts');
    expect(imports).not.toContain('cli/context.ts');
  });

  test('executor performs no direct filesystem, secure-files, or state-store I/O', () => {
    const source = readFileSync(executorModule, 'utf8');
    expect(source).not.toContain("from 'node:fs'");
    expect(source).not.toContain("from '../../host-manager/secure-files'");
    expect(source).not.toContain("from '../../state-store'");
    expect(source).not.toContain('writeFileSync');
    expect(source).not.toContain('readFileSync');
    expect(source).not.toContain('unlinkSync');
  });

  test('executor imports only sanctioned effect and pure-policy modules', () => {
    const imports = relativeImportSpecifiers(executorModule)
      .map((specifier) => resolveRelativeTsModule(executorModule, specifier)!)
      .map((imported) => moduleNameWithin(sourceRoot, imported))
      .filter((name) => name.startsWith('cli/operations/'));
    const allowedPrefixes = [
      'cli/operations/host-domain-reset-artifacts.ts',
      'cli/operations/host-domain-reset-journal-binding.ts',
      'cli/operations/host-domain-reset-journal-policy.ts',
      'cli/operations/host-domain-reset-journal-schema.ts',
      'cli/operations/host-domain-reset-machine.ts',
      'cli/operations/identity-reset-legacy-evidence.ts',
      'cli/operations/initialize.ts',
    ];
    for (const name of imports) {
      expect(allowedPrefixes.some((prefix) => name === prefix), `unexpected executor import ${name}`).toBe(true);
    }
  });

  test('executor does not transitively import the journal store or context', () => {
    const queued = [executorModule];
    const visited = new Set<string>();
    const sanctionedBoundaryModules = [
      realpathSync(join(sourceRoot, 'cli', 'operations', 'host-domain-reset-artifacts.ts')),
      realpathSync(join(sourceRoot, 'cli', 'operations', 'identity-reset-legacy-evidence.ts')),
    ];
    while (queued.length > 0) {
      const modulePath = queued.shift()!;
      if (visited.has(modulePath)) continue;
      visited.add(modulePath);
      for (const specifier of relativeImportSpecifiers(modulePath)) {
        const imported = resolveRelativeTsModule(modulePath, specifier);
        if (!imported) continue;
        const name = moduleNameWithin(sourceRoot, imported);
        expect(name).not.toBe('cli/operations/host-domain-reset-journal-store.ts');
        expect(name).not.toBe('cli/context.ts');
        expect(name).not.toBe('cli/operations/host-domain-reset.ts');
        expect(name).not.toBe('cli/operations/host-domain-reset-recovery.ts');
        if (!sanctionedBoundaryModules.includes(imported)) queued.push(imported);
      }
    }
  });
});
