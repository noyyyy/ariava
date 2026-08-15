import { describe, expect, test } from 'bun:test';
import {
  existsSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import * as ts from 'typescript';

interface ImportEdge {
  importer: string;
  imported: string;
}

interface DependencyDeclarationShape {
  specifier: string;
  typeOnly: boolean;
  kind: 'import' | 'dynamic-import' | 'import-type' | 'export-from';
}

interface ExportShape {
  name: string;
  kind: 'type' | 'value' | 'wildcard' | 'namespace' | 'default';
  localName: string;
}

type ImportGraph = Map<string, ImportEdge[]>;

const bridgeRoot = realpathSync(join(import.meta.dir, '..'));
const sourceRoot = realpathSync(join(bridgeRoot, 'src'));
const testRoot = realpathSync(join(bridgeRoot, 'test'));

const sourceModules = allTypeScriptModules(sourceRoot);
const journalGraph = buildImportGraph(sourceModules);

const JOURNAL_MODULES = {
  barrel: modulePath('cli/operations/host-domain-reset-journal.ts'),
  schema: modulePath('cli/operations/host-domain-reset-journal-schema.ts'),
  policy: modulePath('cli/operations/host-domain-reset-journal-policy.ts'),
  store: modulePath('cli/operations/host-domain-reset-journal-store.ts'),
  coordinator: modulePath('cli/operations/host-domain-reset.ts'),
};

const INTERNAL_JOURNAL_MODULES = new Set([
  JOURNAL_MODULES.schema,
  JOURNAL_MODULES.policy,
  JOURNAL_MODULES.store,
 ]);

const INTERNAL_JOURNAL_IMPORT_ALLOWLIST = new Set([
  JOURNAL_MODULES.coordinator,
  JOURNAL_MODULES.store,
  JOURNAL_MODULES.barrel,
]);

const FIXTURE_HELPER = realpathSync(join(testRoot, 'helpers', 'host-domain-reset-journal-fixture.ts'));

const ALLOWED_SURFACE: ExportShape[] = [
  valueExport('HOST_DOMAIN_RESET_JOURNAL_VERSION'),
  valueExport('HOST_DOMAIN_RESET_PHASES'),
  typeExport('HostDomainResetPhase'),
  typeExport('HostDomainResetRevokeState'),
  typeExport('HostDomainResetRevokeOutcome'),
  typeExport('HostDomainResetServiceBackend'),
  typeExport('HostDomainResetSigningCleanupV1'),
  typeExport('HostDomainResetJournalV1'),
  valueExport('identityResourceDigest'),
  valueExport('hostDomainResourceDigest'),
  valueExport('loadHostDomainResetJournal'),
  valueExport('advanceHostDomainResetJournal'),
  valueExport('assertHostDomainResetRuntimeStartAllowed'),
  valueExport('createHostDomainResetJournal'),
  valueExport('removeAfterServiceRestoreConfirmed'),
  typeExport('RestoreConfirmation'),
  typeExport('HostIdentityOperationLease'),
  typeExport('HostDomainResetJournalTransition'),
  typeExport('HostResetJournalViolation'),
].sort(compareExports);

const EXPECTED_SCHEMA_IMPORTS: DependencyDeclarationShape[] = [
  { specifier: 'node:crypto', typeOnly: false, kind: 'import' },
  { specifier: '../profile', typeOnly: true, kind: 'import' },
];

const EXPECTED_POLICY_IMPORTS: DependencyDeclarationShape[] = [
  { specifier: '../profile', typeOnly: true, kind: 'import' },
  { specifier: './host-domain-reset-journal-schema', typeOnly: false, kind: 'import' },
];

describe('host-domain reset journal boundary', () => {
  test('schema codec module imports only its pure leaves', () => {
    const source = readFileSync(JOURNAL_MODULES.schema, 'utf8');
    expect(dependenciesFromSource(source)).toEqual(EXPECTED_SCHEMA_IMPORTS);
    const mutations = [
      ...dependencyFormMutations(source, 'node:fs', 'Stats'),
      ...dependencyFormMutations(
        source,
        './host-domain-reset-journal-store',
        'HostDomainResetJournalStoreOptions',
      ),
    ];
    for (const mutation of mutations) {
      expect(dependenciesFromSource(mutation)).not.toEqual(EXPECTED_SCHEMA_IMPORTS);
    }
    const maskedLookalikes = [
      source,
      "/* import('node:fs', { with: { type: 'json' } }) */",
      "// type Hidden = import('node:fs').Stats",
      "const template = `export * from 'node:fs'; type Hidden = import('node:fs').Stats`;",
    ].join('\n');
    expect(dependenciesFromSource(maskedLookalikes)).toEqual(EXPECTED_SCHEMA_IMPORTS);
  });

  test('policy module imports no store or effect modules', () => {
    const source = readFileSync(JOURNAL_MODULES.policy, 'utf8');
    expect(dependenciesFromSource(source)).toEqual(EXPECTED_POLICY_IMPORTS);
    const mutations = [
      ...dependencyFormMutations(source, 'node:fs', 'Stats'),
      ...dependencyFormMutations(
        source,
        './host-domain-reset-journal-store',
        'HostDomainResetJournalStoreOptions',
      ),
    ];
    for (const mutation of mutations) {
      expect(dependenciesFromSource(mutation)).not.toEqual(EXPECTED_POLICY_IMPORTS);
    }
  });

  test('store module imports no coordinator or executor modules', () => {
    const edges = forbiddenStoreEdges(directRelativeDependencies(JOURNAL_MODULES.store));
    expect(formatEdges(edges)).toEqual([]);

    const source = readFileSync(JOURNAL_MODULES.store, 'utf8');
    const mutations = [
      ...dependencyFormMutations(source, './host-domain-reset', 'HostDomainResetResult'),
      ...dependencyFormMutations(source, './host-domain-reset-executor', 'HostDomainResetExecutor'),
    ];
    for (const mutation of mutations) {
      expect(formatEdges(forbiddenStoreEdges(
        directRelativeDependencies(JOURNAL_MODULES.store, mutation, resolveStoreMutationDependency),
      ))).not.toEqual([]);
    }
  });

  test('compatibility barrel exposes exactly the frozen §9 surface', () => {
    const source = readFileSync(JOURNAL_MODULES.barrel, 'utf8');
    expect(exportsFromSource(source)).toEqual(ALLOWED_SURFACE);

    const mutations = [
      `${source}\nexport const localLeak = true;\n`,
      `${source}\nexport * from './host-domain-reset-journal-store';\n`,
      `${source}\nexport type * from './host-domain-reset-journal-store';\n`,
      `${source}\nexport * as journalStore from './host-domain-reset-journal-store';\n`,
      `${source}\nexport type * as journalStoreTypes from './host-domain-reset-journal-store';\n`,
      `${source}\nexport { loadHostDomainResetJournal as aliasedLoad } from './host-domain-reset-journal-store';\n`,
      `${source}\nexport type { RestoreConfirmation as LeakedConfirmation } from './host-domain-reset-journal-store';\n`,
      `${source}\nexport { restoreHostDomainServiceAndConfirm as issueRestoreConfirmation } from './host-domain-reset-journal-store';\n`,
      `${source}\nexport { RestoreConfirmation } from './host-domain-reset-journal-store';\n`,
    ];
    for (const mutation of mutations) expect(exportsFromSource(mutation)).not.toEqual(ALLOWED_SURFACE);
  });

  test('daemon, profile probe, and status reach journal API only through the barrel', () => {
    expect(formatEdges(universalInternalJournalViolations(journalGraph))).toEqual([]);

    const consumer = modulePath('daemon.ts');
    const source = readFileSync(consumer, 'utf8');
    const governedInternals = [
      { specifier: './cli/operations/host-domain-reset-journal-schema', importedName: 'HostDomainResetJournalV1' },
      { specifier: './cli/operations/host-domain-reset-journal-policy', importedName: 'HostResetJournalViolation' },
      { specifier: './cli/operations/host-domain-reset-journal-store', importedName: 'HostDomainResetJournalStoreOptions' },
    ];
    const mutations = governedInternals.flatMap(({ specifier, importedName }) =>
      dependencyFormMutations(source, specifier, importedName),
    );
    for (const mutation of mutations) {
      const graph = new Map(journalGraph);
      graph.set(consumer, directRelativeDependencies(consumer, mutation));
      expect(formatEdges(universalInternalJournalViolations(graph))).not.toEqual([]);
    }
  });

  test('production never imports the test-tree journal fixture helper', () => {
    const violations = sourceModules.flatMap((module) =>
      (journalGraph.get(module) ?? []).filter((edge) => edge.imported === FIXTURE_HELPER),
    );
    expect(formatEdges(violations)).toEqual([]);

    const importer = JOURNAL_MODULES.coordinator;
    const source = readFileSync(importer, 'utf8');
    const mutations = dependencyFormMutations(
      source,
      '../../../test/helpers/host-domain-reset-journal-fixture',
      'HostDomainResetJournalFixture',
    );
    for (const mutation of mutations) {
      const mutationViolations = directRelativeDependencies(importer, mutation)
        .filter((edge) => edge.imported === FIXTURE_HELPER);
      expect(formatEdges(mutationViolations)).not.toEqual([]);
    }
  });
});

function dependenciesFromSource(source: string): DependencyDeclarationShape[] {
  const file = parseTypeScript(source);
  const dependencies: Array<DependencyDeclarationShape & { position: number }> = [];
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      dependencies.push({
        specifier: node.moduleSpecifier.text,
        typeOnly: importDeclarationIsTypeOnly(node),
        kind: 'import',
        position: node.getStart(file),
      });
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      dependencies.push({
        specifier: node.moduleSpecifier.text,
        typeOnly: exportDeclarationIsTypeOnly(node),
        kind: 'export-from',
        position: node.getStart(file),
      });
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword
      && node.arguments.length >= 1 && isLiteralModuleSpecifier(node.arguments[0]!)) {
      dependencies.push({
        specifier: node.arguments[0]!.text,
        typeOnly: false,
        kind: 'dynamic-import',
        position: node.getStart(file),
      });
    } else if (ts.isImportTypeNode(node)) {
      const specifier = importTypeModuleSpecifier(node);
      if (specifier) {
        dependencies.push({
          specifier: specifier.text,
          typeOnly: true,
          kind: 'import-type',
          position: node.getStart(file),
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return dependencies
    .sort((left, right) => left.position - right.position)
    .map(({ position: _position, ...dependency }) => dependency);
}

function importDeclarationIsTypeOnly(declaration: ts.ImportDeclaration): boolean {
  const clause = declaration.importClause;
  if (!clause) return false;
  if (clause.isTypeOnly) return true;
  return clause.name === undefined && ts.isNamedImports(clause.namedBindings)
    && clause.namedBindings.elements.length > 0
    && clause.namedBindings.elements.every((element) => element.isTypeOnly);
}

function exportDeclarationIsTypeOnly(declaration: ts.ExportDeclaration): boolean {
  if (declaration.isTypeOnly) return true;
  return declaration.exportClause !== undefined
    && ts.isNamedExports(declaration.exportClause)
    && declaration.exportClause.elements.length > 0
    && declaration.exportClause.elements.every((element) => element.isTypeOnly);
}

function isLiteralModuleSpecifier(node: ts.Node): node is ts.StringLiteralLike {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node);
}

function importTypeModuleSpecifier(node: ts.ImportTypeNode): ts.StringLiteralLike | undefined {
  if (!ts.isLiteralTypeNode(node.argument)) return undefined;
  return isLiteralModuleSpecifier(node.argument.literal) ? node.argument.literal : undefined;
}

function dependencyFormMutations(source: string, specifier: string, importedName: string): string[] {
  return [
    `${source}\nimport { ${importedName} as forbiddenStaticAlias } from '${specifier}';\n`,
    `${source}\nimport * as forbiddenStaticNamespace from '${specifier}';\n`,
    `${source}\nimport type { ${importedName} as ForbiddenStaticType } from '${specifier}';\n`,
    `${source}\nvoid import('${specifier}', { with: { type: 'json' } });\n`,
    `${source}\nvoid import(\`${specifier}\`, { with: { type: 'json' } });\n`,
    `${source}\nexport { ${importedName} as forbiddenAlias } from '${specifier}';\n`,
    `${source}\nexport type { ${importedName} as ForbiddenTypeAlias } from '${specifier}';\n`,
    `${source}\nexport * from '${specifier}';\n`,
    `${source}\nexport type * from '${specifier}';\n`,
    `${source}\nexport * as forbiddenNamespace from '${specifier}';\n`,
    `${source}\nexport type * as forbiddenTypeNamespace from '${specifier}';\n`,
    `${source}\ntype ForbiddenImportType = import('${specifier}').${importedName};\n`,
    `${source}\ntype ForbiddenTemplateImportType = import(\`${specifier}\`).${importedName};\n`,
  ];
}

function exportsFromSource(source: string): ExportShape[] {
  const file = parseTypeScript(source);
  const exports: ExportShape[] = [];
  for (const statement of file.statements) {
    if (ts.isExportDeclaration(statement)) {
      if (!statement.exportClause) {
        exports.push({ name: '*', kind: 'wildcard', localName: '*' });
      } else if (ts.isNamespaceExport(statement.exportClause)) {
        const name = statement.exportClause.name.text;
        exports.push({ name, kind: 'namespace', localName: '*' });
      } else {
        for (const element of statement.exportClause.elements) {
          exports.push({
            name: element.name.text,
            kind: statement.isTypeOnly || element.isTypeOnly ? 'type' : 'value',
            localName: element.propertyName?.text ?? element.name.text,
          });
        }
      }
      continue;
    }
    if (ts.isExportAssignment(statement)) {
      exports.push({ name: 'default', kind: 'default', localName: 'default' });
      continue;
    }
    if (!hasModifier(statement, ts.SyntaxKind.ExportKeyword)) continue;
    const kind = declarationExportKind(statement);
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        for (const name of bindingNames(declaration.name)) exports.push({ name, kind, localName: name });
      }
      continue;
    }
    const named = statement as ts.DeclarationStatement;
    const name = named.name?.getText(file) ?? 'default';
    exports.push({
      name: hasModifier(statement, ts.SyntaxKind.DefaultKeyword) ? 'default' : name,
      kind: hasModifier(statement, ts.SyntaxKind.DefaultKeyword) ? 'default' : kind,
      localName: name,
    });
  }
  return exports.sort(compareExports);
}

function declarationExportKind(statement: ts.Statement): 'type' | 'value' {
  return ts.isInterfaceDeclaration(statement) || ts.isTypeAliasDeclaration(statement)
    ? 'type'
    : 'value';
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  return name.elements.flatMap((element) => ts.isOmittedExpression(element) ? [] : bindingNames(element.name));
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((modifier) => modifier.kind === kind) === true;
}

function valueExport(name: string): ExportShape {
  return { name, kind: 'value', localName: name };
}

function typeExport(name: string): ExportShape {
  return { name, kind: 'type', localName: name };
}

function compareExports(left: ExportShape, right: ExportShape): number {
  return left.name.localeCompare(right.name) || left.kind.localeCompare(right.kind) || left.localName.localeCompare(right.localName);
}

function parseTypeScript(source: string): ts.SourceFile {
  return ts.createSourceFile('fixture.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

function directRelativeDependencies(
  importer: string,
  source = readFileSync(importer, 'utf8'),
  resolver = resolveRelativeTypeScriptModule,
): ImportEdge[] {
  const declarations = dependenciesFromSource(source);
  const edges: ImportEdge[] = [];
  for (const { specifier } of declarations) {
    if (!specifier.startsWith('.')) continue;
    const imported = resolver(importer, specifier);
    if (imported) edges.push({ importer, imported });
  }
  return edges;
}

function resolveStoreMutationDependency(importer: string, specifier: string): string | undefined {
  if (specifier === './host-domain-reset-executor') {
    return resolve(dirname(importer), 'host-domain-reset-executor.ts');
  }
  return resolveRelativeTypeScriptModule(importer, specifier);
}

function forbiddenStoreEdges(edges: readonly ImportEdge[]): ImportEdge[] {
  return edges.filter(
    (edge) => edge.imported === JOURNAL_MODULES.coordinator
      || /(?:state-machine|executor)\.ts$/u.test(basename(edge.imported)),
  );
}

function universalInternalJournalViolations(graph: ImportGraph): ImportEdge[] {
  return sourceModules.flatMap((module) => {
    if (INTERNAL_JOURNAL_IMPORT_ALLOWLIST.has(module)) return [];
    return (graph.get(module) ?? []).filter((edge) => {
      if (module === JOURNAL_MODULES.policy && edge.imported === JOURNAL_MODULES.schema) return false;
      return INTERNAL_JOURNAL_MODULES.has(edge.imported);
    });
  });
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
  for (const module of modules) graph.set(module, directRelativeDependencies(module));
  return graph;
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

function formatEdges(edges: readonly ImportEdge[]): string[] {
  return edges.map((edge) => `${display(edge.importer)} -> ${display(edge.imported)}`);
}

function display(path: string): string {
  const sourceName = relative(sourceRoot, path);
  if (!isAbsolute(sourceName) && sourceName !== '..' && !sourceName.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
    return sourceName.replaceAll('\\', '/');
  }
  const testName = relative(testRoot, path);
  if (!isAbsolute(testName) && testName !== '..' && !testName.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
    return `test/${testName.replaceAll('\\', '/')}`;
  }
  return path;
}

function modulePath(name: string): string {
  return realpathSync(join(sourceRoot, name));
}
