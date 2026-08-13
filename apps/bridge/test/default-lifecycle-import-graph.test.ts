import { afterEach, describe, expect, test } from 'bun:test';
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
  mkdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';

interface ImportEdge {
  importer: string;
  imported: string;
  runtime: boolean;
}

type ImportGraph = Map<string, ImportEdge[]>;

const bridgeRoot = realpathSync(join(import.meta.dir, '..'));
const sourceRoot = realpathSync(join(bridgeRoot, 'src'));
const lifecycleRoot = realpathSync(join(sourceRoot, 'cli', 'lifecycle'));
const onboardingRoot = realpathSync(join(sourceRoot, 'host-manager', 'onboarding'));
const temporaryRoots: string[] = [];

const DEFAULT_LEAVES = new Set([
  modulePath('cli/lifecycle/default-context.ts'),
  modulePath('cli/lifecycle/default-runtime.ts'),
]);

const DEFAULT_COMPOSITION = modulePath('cli/lifecycle/default.ts');
const PUBLIC_ENTRY_MODULES = [
  modulePath('public-cli.ts'),
  modulePath('public-cli-app.ts'),
];

const EXTERNAL_RESET_SCC_SEED = modulePath('cli/context.ts');
const EXTERNAL_RESET_SCC_MEMBERS = [
  EXTERNAL_RESET_SCC_SEED,
  modulePath('cli/operations/host-domain-reset.ts'),
  modulePath('cli/operations/initialize.ts'),
];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('default lifecycle import graph parser', () => {
  test('resolves multiline imports, re-exports, indexes, and type-only edges', () => {
    const root = fixture({
      'entry.ts': `
        import type {
          Contract,
        } from './contract';
        import {
          type RuntimeContract,
          runtimeValue,
        } from './runtime';
        export type {
          ExportedContract,
        } from './exported-contract';
        export {
          type ExportedRuntimeContract,
          runtimeExport,
        } from './exported-runtime';
        export * from './folder';
        export *
          as namespaceExport
          from './namespace-export';
        import './side-effect';
        /*
          import './also-not-an-import';
        */
      `,
      'contract.ts': 'export interface Contract {}',
      'runtime.ts': 'export interface RuntimeContract {}; export const runtimeValue = 1;',
      'exported-contract.ts': 'export interface ExportedContract {}',
      'exported-runtime.ts': 'export interface ExportedRuntimeContract {}; export const runtimeExport = 1;',
      'folder/index.ts': 'export const folderValue = 1;',
      'namespace-export.ts': 'export const namespaceValue = 1;',
      'side-effect.ts': 'globalThis;',
    });
    const entry = realpathSync(join(root, 'entry.ts'));

    expect(directRelativeImports(entry)).toEqual([
      { importer: entry, imported: realpathSync(join(root, 'contract.ts')), runtime: false },
      { importer: entry, imported: realpathSync(join(root, 'runtime.ts')), runtime: true },
      { importer: entry, imported: realpathSync(join(root, 'exported-contract.ts')), runtime: false },
      { importer: entry, imported: realpathSync(join(root, 'exported-runtime.ts')), runtime: true },
      { importer: entry, imported: realpathSync(join(root, 'folder/index.ts')), runtime: true },
      { importer: entry, imported: realpathSync(join(root, 'namespace-export.ts')), runtime: true },
      { importer: entry, imported: realpathSync(join(root, 'side-effect.ts')), runtime: true },
    ]);
  });

  test('masks multiline template contents that resemble static declarations', () => {
    const root = fixture({
      'entry.ts': [
        'const ignored = `',
        "  import { fake } from './missing-import';",
        '  export {',
        '    fakeExport,',
        "  } from './missing-export';",
        '  export *',
        '    as fakeNamespace',
        "    from './missing-namespace';",
        '`;',
        "import './real';",
      ].join('\n'),
      'real.ts': 'export const real = true;',
    });
    const entry = realpathSync(join(root, 'entry.ts'));

    expect(directRelativeImports(entry)).toEqual([
      { importer: entry, imported: realpathSync(join(root, 'real.ts')), runtime: true },
    ]);
  });

  test('namespace re-exports participate in runtime cycle detection', () => {
    const root = fixture({
      'a.ts': "import './b';",
      'b.ts': "export *\n  as namespaceExport\n  from './c';",
      'c.ts': "export * from './a';",
    });
    const modules = allTypeScriptModules(root);
    const graph = buildImportGraph(modules);

    expect(() => assertAcyclic(runtimeGraph(graph), new Set(modules), 'runtime fixture')).toThrow(
      'runtime fixture cycle: a.ts -> b.ts -> c.ts -> a.ts',
    );
  });

  test('distinguishes type-only cycles from runtime cycles', () => {
    const root = fixture({
      'a.ts': "import './b';",
      'b.ts': "export * from './c';",
      'c.ts': "import type { A } from './a'; export interface C {}",
    });
    const modules = allTypeScriptModules(root);
    const graph = buildImportGraph(modules);

    expect(() => assertAcyclic(graph, new Set(modules), 'fixture')).toThrow(
      'fixture cycle: a.ts -> b.ts -> c.ts -> a.ts',
    );
    expect(() => assertAcyclic(runtimeGraph(graph), new Set(modules), 'runtime fixture')).not.toThrow();
  });
});

describe('default lifecycle import direction', () => {
  const lifecycleModules = allTypeScriptModules(lifecycleRoot)
    .filter((path) => basename(path) !== 'dev.ts');
  const onboardingModules = allTypeScriptModules(onboardingRoot);
  const governedModules = new Set([
    ...lifecycleModules,
    ...onboardingModules,
    ...PUBLIC_ENTRY_MODULES,
  ]);
  const handlerModules = new Set(lifecycleModules.filter(isHandlerModule));
  const sourceModules = allTypeScriptModules(sourceRoot);
  const graph = buildImportGraph(sourceModules);
  const runtime = runtimeGraph(graph);

  test('keeps dependency contracts and runtime constants as leaves', () => {
    const contextEdges = graph.get(modulePath('cli/lifecycle/default-context.ts')) ?? [];
    expect(contextEdges.filter((edge) => edge.runtime)).toEqual([]);
    expect(graph.get(modulePath('cli/lifecycle/default-runtime.ts')) ?? []).toEqual([
      expect.objectContaining({ imported: modulePath('cli/app.ts'), runtime: true }),
      expect.objectContaining({ imported: modulePath('cli/package-authority.ts'), runtime: true }),
    ]);
  });

  test('prevents onboarding and readiness from importing the default lifecycle', () => {
    const lifecycleSet = new Set(lifecycleModules);
    const reverseEdges = onboardingModules.flatMap((module) => (
      (graph.get(module) ?? []).filter((edge) => lifecycleSet.has(edge.imported))
    ));
    expect(formatEdges(reverseEdges)).toEqual([]);
  });

  test('prevents handlers from importing composition or handler-importing modules', () => {
    const violations: string[] = [];
    for (const handler of handlerModules) {
      for (const edge of graph.get(handler) ?? []) {
        if (edge.imported === DEFAULT_COMPOSITION) {
          violations.push(`${display(handler)} -> ${display(DEFAULT_COMPOSITION)}`);
          continue;
        }
        const path = findPathToAny(edge.imported, handlerModules, graph);
        if (path) {
          violations.push(`${display(handler)} -> ${path.map(display).join(' -> ')}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  test('keeps default setup policy behind injected ports', () => {
    const setupPath = modulePath('cli/lifecycle/setup-command.ts');
    const setupSource = readFileSync(setupPath, 'utf8');
    const setupImports = graph.get(setupPath) ?? [];

    expect(setupSource).toContain('deps.validateSelection(selection, detection)');
    expect(setupSource).toContain('deps.normalizeError(error)');
    expect(setupSource).not.toContain('validateDefaultOnboardingSelection');
    expect(setupSource).not.toContain('normalizeDefaultOnboardingError');
    expect(setupSource).not.toContain('normalizeCliFailure');
    expect(setupImports.some((edge) => edge.imported === modulePath('identity/errors.ts'))).toBe(false);
  });

  test('has no runtime cycles within the governed import graph', () => {
    expect(() => assertAcyclic(runtime, governedModules, 'governed runtime import graph')).not.toThrow();
  });

  test('keeps the documented context-reset-initialize SCC outside governed modules', () => {
    const residual = stronglyConnectedComponent(EXTERNAL_RESET_SCC_SEED, runtime);
    for (const expected of EXTERNAL_RESET_SCC_MEMBERS) expect(residual.has(expected)).toBe(true);
    expect([...residual].filter((module) => governedModules.has(module)).map(display)).toEqual([]);
  });

  test('discovers all extracted handlers instead of relying on a fixed handler list', () => {
    expect([...handlerModules].map(display).sort()).toEqual([
      'cli/lifecycle/compatibility-commands.ts',
      'cli/lifecycle/host-reset-adapter.ts',
      'cli/lifecycle/internal-commands.ts',
      'cli/lifecycle/onboarding-adapter.ts',
      'cli/lifecycle/pi-commands.ts',
      'cli/lifecycle/service-commands.ts',
      'cli/lifecycle/setup-command.ts',
      'cli/lifecycle/uninstall-command.ts',
      'cli/lifecycle/upgrade-command.ts',
    ]);
    expect([...DEFAULT_LEAVES].every((leaf) => governedModules.has(leaf))).toBe(true);
  });
});

function directRelativeImports(importer: string): ImportEdge[] {
  const source = readFileSync(importer, 'utf8').replace(/^#![^\n]*(?:\n|$)/u, '');
  const statements = staticModuleStatements(source);
  const edges: ImportEdge[] = [];
  for (const { statement, specifier } of statements) {
    if (!specifier.startsWith('.')) continue;
    const imported = resolveRelativeTypeScriptModule(importer, specifier);
    if (!imported) continue;
    edges.push({
      importer,
      imported,
      runtime: new Bun.Transpiler({ loader: 'ts' }).scanImports(statement)
        .some((entry) => entry.kind === 'import-statement' && entry.path === specifier),
    });
  }
  return edges;
}

function staticModuleStatements(source: string): Array<{ statement: string; specifier: string }> {
  const maskedSource = maskCommentsAndTemplates(source);
  const pattern = /^\s*(?:(?:import\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?|export\s+(?:type\s+)?(?:\*(?:\s+as\s+[A-Za-z_$][\w$]*)?|\{[\s\S]*?\})\s+from\s+))(['"])(\.[^'"]+)\1\s*;?/gmu;
  const statements: Array<{ statement: string; specifier: string }> = [];
  for (const match of maskedSource.matchAll(pattern)) {
    statements.push({ statement: match[0], specifier: match[2]! });
  }
  return statements;
}

function maskCommentsAndTemplates(source: string): string {
  let result = '';
  let state: 'code' | 'single' | 'double' | 'template' | 'line-comment' | 'block-comment' = 'code';
  for (let index = 0; index < source.length; index += 1) {
    const value = source[index]!;
    const next = source[index + 1];
    if (state === 'line-comment') {
      if (value === '\n') { state = 'code'; result += value; }
      else result += ' ';
      continue;
    }
    if (state === 'block-comment') {
      if (value === '*' && next === '/') { result += '  '; index += 1; state = 'code'; }
      else result += value === '\n' ? '\n' : ' ';
      continue;
    }
    if (state === 'template') {
      if (value === '\\') {
        result += ' ';
        if (next !== undefined) { result += next === '\n' ? '\n' : ' '; index += 1; }
      } else if (value === '`') {
        result += ' ';
        state = 'code';
      } else {
        result += value === '\n' ? '\n' : ' ';
      }
      continue;
    }
    if (state === 'code') {
      if (value === '/' && next === '/') { result += '  '; index += 1; state = 'line-comment'; continue; }
      if (value === '/' && next === '*') { result += '  '; index += 1; state = 'block-comment'; continue; }
      if (value === "'") state = 'single';
      else if (value === '"') state = 'double';
      else if (value === '`') { state = 'template'; result += ' '; continue; }
      result += value;
      continue;
    }
    result += value;
    if (value === '\\') {
      if (next !== undefined) { result += next; index += 1; }
      continue;
    }
    if ((state === 'single' && value === "'")
      || (state === 'double' && value === '"')) state = 'code';
  }
  return result;
}

function resolveRelativeTypeScriptModule(importer: string, specifier: string): string | undefined {
  if (/\.[^/]+$/u.test(specifier) && !/\.(?:ts|tsx|js|mjs)$/u.test(specifier)) return undefined;
  const normalized = specifier.replace(/\.(?:js|mjs)$/u, '');
  const base = resolve(dirname(importer), normalized);
  const candidates = /\.(?:ts|tsx)$/u.test(base)
    ? [base]
    : [`${base}.ts`, `${base}.tsx`, join(base, 'index.ts'), join(base, 'index.tsx')];
  const match = candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
  if (!match) throw new Error(`Unable to resolve relative import ${specifier} from ${display(importer)}`);
  return realpathSync(match);
}

function buildImportGraph(modules: readonly string[]): ImportGraph {
  const graph: ImportGraph = new Map();
  for (const module of modules) graph.set(module, directRelativeImports(module));
  return graph;
}

function runtimeGraph(graph: ImportGraph): ImportGraph {
  return new Map([...graph].map(([module, edges]) => [
    module,
    edges.filter((edge) => edge.runtime),
  ]));
}

function assertAcyclic(graph: ImportGraph, governed: ReadonlySet<string>, label: string): void {
  const visited = new Set<string>();
  const active = new Map<string, number>();
  const stack: string[] = [];
  const visit = (module: string): void => {
    const cycleStart = active.get(module);
    if (cycleStart !== undefined) {
      const cycle = [...stack.slice(cycleStart), module].map(display).join(' -> ');
      throw new Error(`${label} cycle: ${cycle}`);
    }
    if (visited.has(module)) return;
    active.set(module, stack.length);
    stack.push(module);
    for (const edge of graph.get(module) ?? []) {
      if (governed.has(edge.imported)) visit(edge.imported);
    }
    stack.pop();
    active.delete(module);
    visited.add(module);
  };
  for (const module of [...governed].sort()) visit(module);
}

function findPathToAny(
  start: string,
  targets: ReadonlySet<string>,
  graph: ImportGraph,
): string[] | undefined {
  const queue: Array<{ module: string; path: string[] }> = [{ module: start, path: [start] }];
  const visited = new Set<string>();
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (targets.has(current.module)) return current.path;
    if (visited.has(current.module)) continue;
    visited.add(current.module);
    for (const edge of graph.get(current.module) ?? []) {
      queue.push({ module: edge.imported, path: [...current.path, edge.imported] });
    }
  }
  return undefined;
}

function stronglyConnectedComponent(seed: string, graph: ImportGraph): Set<string> {
  const forward = reachableFrom(seed, graph);
  const reverse: ImportGraph = new Map([...graph.keys()].map((module) => [module, []]));
  for (const [module, edges] of graph) {
    for (const edge of edges) {
      const importedEdges = reverse.get(edge.imported) ?? [];
      importedEdges.push({ importer: edge.imported, imported: module, runtime: edge.runtime });
      reverse.set(edge.imported, importedEdges);
    }
  }
  const backward = reachableFrom(seed, reverse);
  return new Set([...forward].filter((module) => backward.has(module)));
}

function reachableFrom(seed: string, graph: ImportGraph): Set<string> {
  const visited = new Set<string>();
  const queue = [seed];
  while (queue.length > 0) {
    const module = queue.shift()!;
    if (visited.has(module)) continue;
    visited.add(module);
    for (const edge of graph.get(module) ?? []) queue.push(edge.imported);
  }
  return visited;
}

function allTypeScriptModules(root: string): string[] {
  const modules: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) modules.push(...allTypeScriptModules(path));
    else if (entry.isFile() && /\.tsx?$/u.test(entry.name)) modules.push(realpathSync(path));
  }
  return modules.sort();
}

function isHandlerModule(path: string): boolean {
  return /(?:-command|-commands|-adapter)\.ts$/u.test(basename(path));
}

function formatEdges(edges: readonly ImportEdge[]): string[] {
  return edges.map((edge) => `${display(edge.importer)} -> ${display(edge.imported)}`);
}

function display(path: string): string {
  const sourceName = relative(sourceRoot, path);
  if (!isAbsolute(sourceName) && sourceName !== '..' && !sourceName.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
    return sourceName.replaceAll('\\', '/');
  }
  for (const root of temporaryRoots) {
    const fixtureName = relative(root, path);
    if (!isAbsolute(fixtureName) && fixtureName !== '..' && !fixtureName.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
      return fixtureName.replaceAll('\\', '/');
    }
  }
  return path;
}

function modulePath(name: string): string {
  return realpathSync(join(sourceRoot, name));
}

function fixture(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'ariava-default-import-graph-')));
  temporaryRoots.push(root);
  for (const [name, source] of Object.entries(files)) {
    const path = join(root, name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, source);
  }
  return root;
}
