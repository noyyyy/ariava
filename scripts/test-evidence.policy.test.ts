import { afterEach, describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { formatViolation, runTestEvidenceCli, scanTestEvidence, TEST_EVIDENCE_RULES, TEST001_TRANSITIONAL_ENTRIES } from './test-evidence-policy.mjs';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function makeRoot(prefix = 'ariava-public-policy-') {
  const repositoryRoot = mkdtempSync(join(tmpdir(), prefix));
  roots.push(repositoryRoot);
  return repositoryRoot;
}

function writeFixture(repositoryRoot: string, path: string, source: string) {
  const absolutePath = join(repositoryRoot, path);
  mkdirSync(join(absolutePath, '..'), { recursive: true });
  writeFileSync(absolutePath, source);
}

function scan(source: string, path = 'scripts/example.test.ts') {
  const repositoryRoot = makeRoot();
  writeFixture(repositoryRoot, path, source);
  return scanTestEvidence({ repositoryRoot, paths: [path], transitionalEntries: [], policyRegistry: [] });
}

const testSource = (body: string) => `import { readFileSync } from 'node:fs';\ntest('fixture', () => { ${body} });\n`;

describe('Public TEST001 policy', () => {
  test('scans only the Public repository with explicit transitional debt', () => {
    expect(scanTestEvidence()).toEqual([]);
  });

  test('default discovery includes Pi extension tests', () => {
    const repositoryRoot = makeRoot();
    writeFixture(repositoryRoot, 'extensions/pi/test/new-source-claim.test.ts', testSource("const source = readFileSync('extensions/pi/src/index.ts', 'utf8'); expect(source).toContain('registerExtension');"));
    expect(scanTestEvidence({ repositoryRoot, policyRegistry: [], transitionalEntries: [] })).toEqual([expect.objectContaining({ ruleId: 'TEST001', path: 'extensions/pi/test/new-source-claim.test.ts', line: 2, target: 'extensions/pi/src/index.ts' })]);
  });

  test('publishes stable metadata without a policy filename exemption', () => {
    expect(TEST_EVIDENCE_RULES.TEST001.id).toBe('TEST001');
    expect(TEST_EVIDENCE_RULES.TEST001.exclude).not.toContain('**/*.policy.test.ts');
    const violations = scan(testSource("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('illegal runtime spelling');"), 'scripts/renamed-illegal.policy.test.ts');
    expect(violations).toHaveLength(1);
  });

  test('reconciles registered debt one-to-one and rejects an exact duplicate occurrence', () => {
    const repositoryRoot = makeRoot();
    const path = 'scripts/transitional.test.ts';
    const assertion = "const source = readFileSync('apps/bridge/src/cli.ts', 'utf8');\nexpect(source).toContain('registered');";
    const original = testSource(assertion);
    writeFixture(repositoryRoot, path, original);
    const [detected] = scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: [path], transitionalEntries: [] });
    const debt = [{ path, target: detected.target, testName: detected.testName, fingerprint: detected.fingerprint, task: 'Task 7', rationale: 'Fixture debt.' }];
    expect(scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: [path], transitionalEntries: debt })).toEqual([]);
    writeFixture(repositoryRoot, path, original.replace(' });', `\n${assertion} });`));
    const violations = scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: [path], transitionalEntries: debt });
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ ruleId: 'TEST001', fingerprint: detected.fingerprint, registryIssue: 'overmatched' });
  });

  test('keeps whitespace inside literals fingerprint-distinct', () => {
    const repositoryRoot = makeRoot();
    const path = 'scripts/literal-spacing.test.ts';
    writeFixture(repositoryRoot, path, testSource("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8');\nexpect(source).toContain('foo bar');\nexpect(source).toContain('foo  bar');"));
    const detected = scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: [path], transitionalEntries: [] });
    expect(detected).toHaveLength(2);
    expect(detected[0]?.fingerprint).not.toBe(detected[1]?.fingerprint);
    const debt = detected.map((violation) => ({ path, target: violation.target, testName: violation.testName, fingerprint: violation.fingerprint, task: 'Task 7', rationale: 'Fixture debt.' }));
    expect(scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: [path], transitionalEntries: debt })).toEqual([]);
  });

  test('reports stale and duplicate registry entries explicitly', () => {
    const repositoryRoot = makeRoot();
    const path = 'scripts/reconciliation.test.ts';
    writeFixture(repositoryRoot, path, testSource("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('registered');"));
    const [detected] = scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: [path], transitionalEntries: [] });
    const debt = { path, target: detected.target, testName: detected.testName, fingerprint: detected.fingerprint, task: 'Task 7', rationale: 'Fixture debt.' };
    const duplicate = scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: [path], transitionalEntries: [debt, { ...debt }] });
    expect(duplicate).toEqual([expect.objectContaining({ ruleId: 'TEST001', registryIssue: 'duplicate' })]);
    const stale = scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: [path], transitionalEntries: [{ ...debt, fingerprint: '0'.repeat(64) }] });
    expect(stale).toEqual([
      expect.objectContaining({ ruleId: 'TEST001', fingerprint: detected.fingerprint }),
      expect.objectContaining({ ruleId: 'TEST001', registryIssue: 'unmatched', fingerprint: '0'.repeat(64) }),
    ]);
    expect(formatViolation(stale[1]!)).toContain('unmatched transitional registry entry');
  });

  test('reports missing and renamed registry paths as unmatched', () => {
    const repositoryRoot = makeRoot();
    writeFixture(repositoryRoot, 'scripts/current-name.test.ts', testSource("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('current');"));
    const [detected] = scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: ['scripts/current-name.test.ts'], transitionalEntries: [] });
    const debt = { target: detected.target, testName: detected.testName, fingerprint: detected.fingerprint, task: 'Task 7', rationale: 'Fixture debt.' };
    const violations = scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: ['scripts/current-name.test.ts'], transitionalEntries: [
      { ...debt, path: 'scripts/missing.test.ts' },
      { ...debt, path: 'scripts/old-name.test.ts' },
    ] });
    expect(violations).toEqual([
      expect.objectContaining({ path: 'scripts/current-name.test.ts' }),
      expect.objectContaining({ path: 'scripts/missing.test.ts', registryIssue: 'unmatched' }),
      expect.objectContaining({ path: 'scripts/old-name.test.ts', registryIssue: 'unmatched' }),
    ]);
  });

  test('enumerates any transitional debt with ownership and rationale', () => {
    expect(Array.isArray(TEST001_TRANSITIONAL_ENTRIES)).toBe(true);
    expect(TEST001_TRANSITIONAL_ENTRIES.every((entry) => entry.path && entry.target && entry.testName && /^[a-f0-9]{64}$/.test(entry.fingerprint) && entry.task && entry.rationale)).toBe(true);
    expect(TEST001_TRANSITIONAL_ENTRIES.some((entry) => entry.path === 'scripts/test-evidence.policy.test.ts')).toBe(false);
  });

  test.each([
    ['TypeScript method text', "const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('async function runCli');"],
    ['TypeScript state production source', "const source = readFileSync('apps/bridge/src/state-store.ts', 'utf8'); expect(source).toContain('persist');"],
    ['Swift persistence production source', "const source = readFileSync('WatchPersistence.swift', 'utf8'); expect(source).toContain('save');"],
    ['Swift modifier text', "const source = readFileSync('WatchView.swift', 'utf8'); expect(source).toContain('.toolbar');"],
    ['JavaScript call text', "const source = readFileSync('scripts/build.mjs', 'utf8'); expect(source).toMatch(/spawnSync\\(/);"],
    ['Shell function body', "const source = readFileSync('scripts/install.sh', 'utf8'); expect(source).toContain('install_pi() {');"],
  ])('rejects %s with a path and line diagnostic', (_name, body) => {
    const path = 'scripts/illegal.test.ts';
    const violations = scan(testSource(body), path);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ ruleId: 'TEST001', path, line: 2 });
  });

  test('does not let a policy marker suppress an illegal assertion in a normal mixed file', () => {
    const violations = scan(testSource("const structural = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(structural).not.toContain('exec('); // test-evidence-policy: STRUCT001\nconst runtime = readFileSync('apps/bridge/src/app.ts', 'utf8'); expect(runtime).toContain('runCli(');"));
    expect(violations).toHaveLength(1);
    expect(violations[0]?.target).toBe('apps/bridge/src/app.ts');
  });

  test.each([
    ['fixture read', "const source = readFileSync('test/fixtures/sample.ts', 'utf8'); expect(source).toContain('function fixture()');"],
    ['temporary persisted output', "const source = readFileSync(join(tempHome, 'state.ts'), 'utf8'); expect(source).toContain('persisted');"],
    ['generated artifact', "const source = readFileSync('apps/bridge/dist/public-cli.js', 'utf8'); expect(source).toContain('main');"],
    ['packed artifact', "const source = readFileSync('artifacts/package/index.js', 'utf8'); expect(source).toContain('export');"],
    ['CLI output', "const result = Bun.spawnSync(['ariava', 'doctor']); expect(result.stdout.toString()).toContain('healthy');"],
    ['HTTP output', "const response = await adapter.fetch(request); expect(await response.text()).toContain('ok');"],
    ['documentation contract', "const source = readFileSync('README.md', 'utf8'); expect(source).toContain('ariava setup');"],
    ['negative source policy', "const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).not.toContain('exec(');"],
  ])('accepts %s', (_name, body) => {
    expect(scan(testSource(body))).toEqual([]);
  });

  test('detects helper readers wrapping join and common positive matcher chains', () => {
    const source = "import { readFileSync } from 'node:fs'; import { join } from 'node:path';\nconst read = (path: string) => readFileSync(join(repositoryRoot, path), 'utf8');\nconst implementation = read('apps/bridge/src/cli.ts');\nexpect(implementation).toEqual(expect.stringContaining('runCli('));\n";
    expect(scan(source)).toHaveLength(1);
  });

  test('detects raw imports and raw import.meta.glob sources', () => {
    const raw = "import implementation from '../apps/bridge/src/cli.ts?raw';\nexpect(implementation).toContain('runCli(');\n";
    expect(scan(raw)).toHaveLength(1);
    const glob = "const modules = import.meta.glob('../apps/bridge/src/**/*.ts', { query: '?raw', import: 'default', eager: true });\nexpect(Object.values(modules).join('\\n')).toContain('runCli(');\n";
    expect(scan(glob)).toHaveLength(1);
  });

  test.each([
    ['read call split', "const source = readFileSync(\n  'apps/bridge/src/cli.ts',\n  'utf8',\n); expect(source).toContain('runtime');"],
    ['expect split', "const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(\n  source,\n).toContain('runtime');"],
    ['matcher split', "const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source)\n  .toContain(\n    'runtime',\n  );"],
  ])('detects multiline %s', (_name, body) => {
    expect(scan(testSource(body))).toEqual([expect.objectContaining({ target: 'apps/bridge/src/cli.ts' })]);
  });

  test.each([
    ["readFileSync(resolve(repositoryRoot, 'fixtures', '..', 'src', 'cli.ts'), 'utf8')", 'fixtures/../src/cli.ts'],
    ["readFileSync(join(repositoryRoot, 'artifacts', '..', 'src', 'cli.ts'), 'utf8')", 'artifacts/../src/cli.ts'],
  ])('canonicalizes traversal before exclusions: %s', (readExpression, target) => {
    expect(scan(testSource(`const source = ${readExpression}; expect(source).toContain('runtime');`))).toEqual([expect.objectContaining({ target })]);
  });

  test.each([
    ['readFileSync', 'apps/bridge/src/readFileSync-helper.ts'],
    ['Bun.file', 'apps/bridge/src/Bun.file-helper.ts'],
    ['import.meta.glob', 'apps/bridge/src/import.meta.glob-helper.ts'],
  ])('does not mask production filenames containing %s', (_marker, target) => {
    const violations = scan(testSource(`const source = readFileSync('${target}', 'utf8'); expect(source).toContain('runtime behavior');`));
    expect(violations).toEqual([expect.objectContaining({ ruleId: 'TEST001', target })]);
  });

  test('formats CLI diagnostics with rule, relative path, line, and remediation', () => {
    const illegalSource = testSource("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('runCli(');");
    const violation = scan(illegalSource, 'scripts/illegal.test.ts')[0]!;
    expect(formatViolation(violation)).toBe('TEST001 scripts/illegal.test.ts:2 positively matches production implementation "apps/bridge/src/cli.ts". Execute the Public production API or process and assert observable output, or move a negative/structural rule to a registered .policy.test.ts suite.');
    const stderr: string[] = [];
    const repositoryRoot = makeRoot();
    writeFixture(repositoryRoot, 'scripts/illegal.test.ts', illegalSource);
    expect(runTestEvidenceCli({ repositoryRoot, policyRegistry: [], paths: ['scripts/illegal.test.ts'], transitionalEntries: [], stderr: (line: string) => stderr.push(line) })).toBe(1);
    expect(stderr).toEqual([formatViolation(violation)]);
  });

  test.each([
    ['reader and expect aliases', "import { readFileSync as load } from 'node:fs'; const check = expect; const source = load('apps/bridge/src/cli.ts', 'utf8'); check(source).toContain('runtime');"],
    ['includes true', "const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source.includes('runtime')).toBe(true);"],
    ['object matcher', "const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toMatchObject({ runtime: true });"],
    ['inline snapshot', "const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toMatchInlineSnapshot('runtime');"],
    ['literal concatenation', "const suffix = 'cli.ts'; const source = readFileSync('apps/bridge/src/' + suffix, 'utf8'); expect(source).toContain('runtime');"],
    ['static template', "const suffix = 'cli.ts'; const source = readFileSync(`apps/bridge/src/${suffix}`, 'utf8'); expect(source).toContain('runtime');"],
  ])('detects bounded %s evidence', (_name, source) => {
    expect(scan(source)).toEqual([expect.objectContaining({ ruleId: 'TEST001', target: 'apps/bridge/src/cli.ts' })]);
  });

  test('does not analyze arbitrary executable strings or dynamic templates', () => {
    expect(scan(testSource(`eval("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('runtime')");`))).toEqual([]);
    expect(scan(testSource("const suffix = runtimeName; const source = readFileSync(`apps/bridge/src/${suffix}`, 'utf8'); expect(source).toContain('runtime');"))).toEqual([]);
  });


  test.each([
    ['in-root file', false, false],
    ['escaping file', false, true],
    ['in-root directory', true, false],
    ['escaping directory', true, true],
  ])('default discovery rejects %s symlinks with their path', (_name, directoryLink, escaping) => {
    const repositoryRoot = makeRoot();
    const targetRoot = escaping ? makeRoot('ariava-public-default-outside-') : join(repositoryRoot, 'fixture-target');
    if (directoryLink) {
      writeFixture(targetRoot, 'nested/link-target.test.ts', testSource("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('runtime');"));
    } else {
      writeFixture(targetRoot, 'link-target.test.ts', testSource("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('runtime');"));
    }
    mkdirSync(join(repositoryRoot, 'scripts'), { recursive: true });
    const linkPath = directoryLink ? 'scripts/default-directory-link' : 'scripts/default-file-link.test.ts';
    const targetPath = directoryLink ? join(targetRoot, 'nested') : join(targetRoot, 'link-target.test.ts');
    symlinkSync(targetPath, join(repositoryRoot, linkPath));
    expect(() => scanTestEvidence({ repositoryRoot, policyRegistry: [], transitionalEntries: [] })).toThrow(`default discovery refuses symlink entry: ${linkPath}`);
  });

  test.each([
    ['file', false],
    ['directory', true],
  ])('explicitly scans an in-root %s symlink', (_name, directoryLink) => {
    const repositoryRoot = makeRoot();
    const targetPath = directoryLink ? 'fixture-target/nested' : 'fixture-target/link-target.test.ts';
    const sourcePath = directoryLink ? 'fixture-target/nested/link-target.test.ts' : targetPath;
    const linkPath = directoryLink ? 'scripts/explicit-directory-link' : 'scripts/explicit-file-link.test.ts';
    writeFixture(repositoryRoot, sourcePath, testSource("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('runtime');"));
    mkdirSync(join(repositoryRoot, 'scripts'), { recursive: true });
    symlinkSync(join(repositoryRoot, targetPath), join(repositoryRoot, linkPath));
    expect(scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: [linkPath], transitionalEntries: [] })).toEqual([
      expect.objectContaining({ ruleId: 'TEST001', path: directoryLink ? `${linkPath}/link-target.test.ts` : linkPath, target: 'apps/bridge/src/cli.ts' }),
    ]);
  });


  test('TEST002 validates exact Public sidecar metadata and runtime exclusions', () => {
    const repositoryRoot = makeRoot();
    const path = 'scripts/policy-case.test.ts';
    writeFixture(repositoryRoot, path, "test('static contract', () => { expect(true).toBe(true); });\n");
    const valid = { repository: 'public', path, testName: 'static contract', ruleId: 'STRUCT001', propositionClass: 'structural' };
    expect(scanTestEvidence({ repositoryRoot, paths: [path], transitionalEntries: [], policyRegistry: [valid] })).toEqual([]);
    const mutations = [
      [{ ...valid, testName: 'wrong test' }, 'matched 0'],
      [{ ...valid, path: 'scripts/stale.test.ts' }, 'stale policy metadata'],
      [{ ...valid, propositionClass: 'runtime' }, 'runtime-behavior proposition class'],
      [{ ...valid, proposition: 'call order before state transition renders UI runtime outcome' }, 'claims runtime behavior'],
      [{ ...valid, repository: 'private' }, 'wrong repository owner'],
    ];
    for (const [entry, message] of mutations) {
      const violations = scanTestEvidence({ repositoryRoot, paths: [path], transitionalEntries: [], policyRegistry: [entry] });
      expect(formatViolation(violations[0]!)).toContain(message);
    }
    const duplicate = scanTestEvidence({ repositoryRoot, paths: [path], transitionalEntries: [], policyRegistry: [valid, { ...valid }] });
    expect(formatViolation(duplicate[0]!)).toContain('duplicate policy metadata');
  });

  test('refuses lexical traversal and canonical file or directory symlink escapes', () => {
    const repositoryRoot = makeRoot();
    const outsideRoot = makeRoot('ariava-public-outside-');
    writeFixture(outsideRoot, 'outside.test.ts', testSource("const source = readFileSync('apps/bridge/src/cli.ts', 'utf8'); expect(source).toContain('runtime');"));
    mkdirSync(join(repositoryRoot, 'scripts'), { recursive: true });
    symlinkSync(join(outsideRoot, 'outside.test.ts'), join(repositoryRoot, 'scripts/file-link.test.ts'));
    symlinkSync(outsideRoot, join(repositoryRoot, 'scripts/directory-link'));
    expect(() => scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: ['../outside.test.ts'], transitionalEntries: [] })).toThrow('outside Public repository');
    expect(() => scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: ['scripts/file-link.test.ts'], transitionalEntries: [] })).toThrow('resolving symlinks');
    expect(() => scanTestEvidence({ repositoryRoot, policyRegistry: [], paths: ['scripts/directory-link'], transitionalEntries: [] })).toThrow('resolving symlinks');
  });
  test('authoritative Public CLI resolves registry from module path outside repository cwd', () => {
    const cwd = makeRoot('ariava-public-cli-cwd-');
    const result = spawnSync(process.execPath, [new URL('./test-evidence-policy.mjs', import.meta.url).pathname], { cwd, encoding: 'utf8' });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('TEST001/TEST002 Public test-evidence policy passed.');
  });

  test('production Public root with a selected path still enforces mandatory TEST002 metadata', () => {
    const violations = scanTestEvidence({ repositoryRoot: new URL('..', import.meta.url).pathname, paths: ['scripts/workflow-policy.test.ts'], transitionalEntries: [] });
    expect(violations.some((violation) => violation.ruleId === 'TEST002' && violation.message.includes('stale policy metadata path'))).toBe(true);
  });

  test('TEST002 accepts only actual test.each or it.each declarations', () => {
    const repositoryRoot = makeRoot();
    const path = 'scripts/parameterized.policy.test.ts';
    const entry = { repository: 'public', path, testName: 'case $name', ruleId: 'STRUCT001', propositionClass: 'structural' };
    writeFixture(repositoryRoot, path, "test.each([{ name: 'one' }])('case $name', () => {});\n");
    expect(scanTestEvidence({ repositoryRoot, paths: [path], transitionalEntries: [], policyRegistry: [entry] })).toEqual([]);
    writeFixture(repositoryRoot, path, "it.each([{ name: 'one' }])('case $name', () => {});\n");
    expect(scanTestEvidence({ repositoryRoot, paths: [path], transitionalEntries: [], policyRegistry: [entry] })).toEqual([]);
    writeFixture(repositoryRoot, path, "unrelated([{ name: 'one' }])('case $name', () => {});\n");
    expect(scanTestEvidence({ repositoryRoot, paths: [path], transitionalEntries: [], policyRegistry: [entry] })).toEqual([
      expect.objectContaining({ ruleId: 'TEST002', message: expect.stringContaining('matched 0') }),
    ]);
  });

});
