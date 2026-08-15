import { describe, expect, test } from 'bun:test';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

/**
 * Host-domain reset machine import-boundary policy (primary spec §12,
 * journal-boundary spec §11).
 *
 * Static structural assertions only: the machine module and its pure
 * schema/policy dependencies must not reach store, executor, recovery,
 * artifact, host-manager, state-store, relay, or I/O modules. These are
 * source-import checks (not runtime claims); every test is registered in
 * `scripts/test-evidence-policy.registry.json` and validated by
 * `scripts/test-evidence.policy.test.ts` (TEST001/TEST002/AUDIT001).
 */

const bridgeRoot = realpathSync(join(import.meta.dir, '..'));
const sourceRoot = realpathSync(join(bridgeRoot, 'src'));
const machineModule = realpathSync(join(sourceRoot, 'cli', 'operations', 'host-domain-reset-machine.ts'));
const schemaModule = realpathSync(join(sourceRoot, 'cli', 'operations', 'host-domain-reset-journal-schema.ts'));
const policyModule = realpathSync(join(sourceRoot, 'cli', 'operations', 'host-domain-reset-journal-policy.ts'));
const storeModule = realpathSync(join(sourceRoot, 'cli', 'operations', 'host-domain-reset-journal-store.ts'));

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

function transitiveRelativeModuleNames(entryPath: string, traversalStops: string[] = []): string[] {
  const stops = traversalStops.map((root) => realpathSync(root));
  const visited = new Set<string>();
  const queued = [entryPath];
  const names: string[] = [];
  while (queued.length > 0) {
    const modulePath = queued.shift()!;
    if (visited.has(modulePath)) continue;
    visited.add(modulePath);
    names.push(moduleNameWithin(sourceRoot, modulePath));
    for (const specifier of relativeImportSpecifiers(modulePath)) {
      const imported = resolveRelativeTsModule(modulePath, specifier);
      if (!imported || stops.includes(imported)) continue;
      const relativeName = relative(sourceRoot, imported);
      if (relativeName.startsWith('..') || resolve(sourceRoot, relativeName) !== imported) continue;
      queued.push(imported);
    }
  }
  return [...new Set(names)].sort();
}

describe('host-domain reset machine import boundary', () => {
  test('machine imports only the pure schema and policy modules', () => {
    const imports = relativeImportSpecifiers(machineModule).map((specifier) => (
      resolveRelativeTsModule(machineModule, specifier)!
    )).map((imported) => moduleNameWithin(sourceRoot, imported));

    expect(imports).toEqual([
      'cli/operations/host-domain-reset-journal-policy.ts',
      'cli/operations/host-domain-reset-journal-schema.ts',
    ]);
  });

  test('machine does not reach the store, executor, recovery, or artifact modules', () => {
    const reached = transitiveRelativeModuleNames(machineModule, []);
    expect(reached).not.toContain('cli/operations/host-domain-reset-journal-store.ts');
    expect(reached).not.toContain('cli/operations/host-domain-reset-executor.ts');
    expect(reached).not.toContain('cli/operations/host-domain-reset-recovery.ts');
    expect(reached).not.toContain('cli/operations/host-domain-reset-artifacts.ts');
  });

  test('machine performs no filesystem or process I/O', () => {
    const source = readFileSync(machineModule, 'utf8');
    expect(source).not.toContain("from 'node:fs'");
    expect(source).not.toContain("from 'node:child_process'");
    expect(source).not.toContain('readFileSync');
    expect(source).not.toContain('writeFileSync');
    expect(source).not.toContain('spawnSync');
    expect(source).not.toContain("from '../host-manager/secure-files'");
    expect(source).not.toContain("from '../../state-store'");
  });

  test('schema module does not import the store module', () => {
    const imports = relativeImportSpecifiers(schemaModule)
      .map((specifier) => resolveRelativeTsModule(schemaModule, specifier)!)
      .map((imported) => moduleNameWithin(sourceRoot, imported));
    expect(imports).not.toContain('cli/operations/host-domain-reset-journal-store.ts');
    expect(imports).not.toContain('cli/operations/host-domain-reset.ts');
  });

  test('policy module does not import the store module', () => {
    const imports = relativeImportSpecifiers(policyModule)
      .map((specifier) => resolveRelativeTsModule(policyModule, specifier)!)
      .map((imported) => moduleNameWithin(sourceRoot, imported));
    expect(imports).not.toContain('cli/operations/host-domain-reset-journal-store.ts');
    expect(imports).not.toContain('cli/operations/host-domain-reset.ts');
  });

  test('machine does not transitively import host-manager, state-store, or relay modules', () => {
    const reached = transitiveRelativeModuleNames(machineModule);
    expect(reached).toContain('cli/operations/host-domain-reset-journal-binding.ts');
    for (const forbiddenRoot of ['host-manager', 'state-store.ts', 'relay-client.ts', 'runtime-lock.ts']) {
      expect(reached.some((name) => name === forbiddenRoot || name.startsWith(`${forbiddenRoot}/`))).toBe(false);
    }
  });
});
