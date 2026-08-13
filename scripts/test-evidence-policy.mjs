#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectTestEvidenceSource } from './test-evidence-ast.mjs';
import { formatPolicySemanticViolation, inspectMandatoryPolicyMetadata } from './test-evidence-semantics.mjs';

const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const defaultPolicyRegistry = JSON.parse(readFileSync(fileURLToPath(new URL('./test-evidence-policy.registry.json', import.meta.url)), 'utf8'));

export const TEST_EVIDENCE_RULES = Object.freeze({
  TEST001: Object.freeze({
    id: 'TEST001',
    description: 'Normal Public tests must not claim runtime behavior by positively matching production implementation text.',
    include: ['**/*.test.ts'],
    exclude: ['**/fixtures/**', '**/dist/**', '**/bundle/**'],
    remediation: 'Execute the Public production API or process and assert observable output, or move a negative/structural rule to a registered .policy.test.ts suite.',
  }),
  TEST002: Object.freeze({
    id: 'TEST002',
    description: 'Public policy metadata may claim only negative, structural, artifact, configuration, workflow, package, or documentation contracts.',
  }),
});

export const TEST001_TRANSITIONAL_ENTRIES = Object.freeze([]);

const TEST_FILE = /\.test\.(?:ts|js|mjs)$/u;

function normalize(path) {
  return path.split(sep).join('/').replace(/^\.\//u, '');
}

function lineAt(source, index) {
  return source.slice(0, index).split('\n').length;
}

function normalizeAssertion(assertion) {
  return assertion.replace(/\r\n?/gu, '\n');
}

export function assertionFingerprint({ path, target, testName, assertion }) {
  return createHash('sha256').update(JSON.stringify([path, target, testName, normalizeAssertion(assertion)])).digest('hex');
}

function inspectSource(path, source) {
  return inspectTestEvidenceSource(path, source, ({ index, assertion, target, testName }) => {
    const normalizedAssertion = normalizeAssertion(assertion);
    return {
      ruleId: 'TEST001',
      path,
      line: lineAt(source, index),
      target,
      testName,
      assertion: normalizedAssertion,
      fingerprint: assertionFingerprint({ path, target, testName, assertion: normalizedAssertion }),
    };
  });
}

function walk(root, directory, paths) {
  if (!existsSync(directory)) return;
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(directory, entry.name);
    const repositoryPath = normalize(relative(root, path));
    if (entry.isSymbolicLink()) throw new Error(`TEST001 default discovery refuses symlink entry: ${repositoryPath}`);
    if (entry.isDirectory()) {
      if (/^(?:\.git|\.worktrees|node_modules|dist|bundle|build|DerivedData|artifacts?|fixtures?)$/u.test(entry.name)) continue;
      walk(root, path, paths);
    } else if (entry.isFile() && TEST_FILE.test(entry.name)) paths.push(path);
  }
}

function defaultPaths(root) {
  const paths = [];
  walk(root, root, paths);
  return paths.map((path) => normalize(relative(root, path)));
}

function canonicalPath(root, suppliedPath) {
  const absolutePath = resolve(root, suppliedPath);
  const lexicalPath = normalize(relative(root, absolutePath));
  if (lexicalPath === '..' || lexicalPath.startsWith('../')) throw new Error(`TEST001 path is outside Public repository scope: ${suppliedPath}`);
  const canonicalRoot = realpathSync(root);
  const canonical = realpathSync(absolutePath);
  const canonicalRelative = normalize(relative(canonicalRoot, canonical));
  if (canonicalRelative === '..' || canonicalRelative.startsWith('../')) throw new Error(`TEST001 path is outside Public repository scope after resolving symlinks: ${suppliedPath}`);
  return { absolutePath, lexicalPath };
}

export function scanTestEvidence(options = {}) {
  const root = resolve(options.repositoryRoot ?? repositoryRoot);
  const paths = options.paths ?? defaultPaths(root);
  const transitionalEntries = options.transitionalEntries ?? TEST001_TRANSITIONAL_ENTRIES;
  const policyRegistry = options.policyRegistry ?? defaultPolicyRegistry;
  const files = [];
  for (const suppliedPath of paths) {
    const resolved = canonicalPath(root, suppliedPath);
    if (statSync(resolved.absolutePath).isDirectory()) walk(root, resolved.absolutePath, files);
    else files.push(resolved.absolutePath);
  }
  const registry = new Map();
  const registeredKeys = new Set();
  const registryIssues = [];
  const entryKey = (entry) => JSON.stringify([entry.path, entry.target, entry.testName, entry.fingerprint]);
  for (const entry of transitionalEntries) {
    const key = entryKey(entry);
    registeredKeys.add(key);
    if (registry.has(key)) {
      registryIssues.push({ ruleId: 'TEST001', path: entry.path, line: 1, target: entry.target, testName: entry.testName, fingerprint: entry.fingerprint, registryIssue: 'duplicate' });
    } else {
      registry.set(key, entry);
    }
  }
  const violations = [];
  for (const absolutePath of files) {
    const path = normalize(relative(root, absolutePath));
    canonicalPath(root, path);
    const source = readFileSync(absolutePath, 'utf8');
    for (const violation of inspectSource(path, source)) {
      const key = entryKey(violation);
      if (registry.delete(key)) continue;
      if (registeredKeys.has(key)) violation.registryIssue = 'overmatched';
      violations.push(violation);
    }
  }
  const sources = new Map(files.map((absolutePath) => [normalize(relative(root, absolutePath)), readFileSync(absolutePath, 'utf8')]));
  violations.push(...inspectMandatoryPolicyMetadata({ repository: 'public', registry: policyRegistry, sources }));
  for (const entry of registry.values()) {
    violations.push({ ruleId: 'TEST001', path: entry.path, line: 1, target: entry.target, testName: entry.testName, fingerprint: entry.fingerprint, registryIssue: 'unmatched' });
  }
  return [...violations, ...registryIssues];
}

export function formatViolation(violation) {
  if (violation.ruleId === 'TEST002') return formatPolicySemanticViolation(violation);
  if (violation.registryIssue === 'overmatched') return `${violation.ruleId} ${violation.path}:${violation.line} overmatched transitional registry entry ${violation.fingerprint}; each current assertion occurrence requires its own exact entry.`;
  if (violation.registryIssue) return `${violation.ruleId} ${violation.path}: ${violation.registryIssue} transitional registry entry ${violation.fingerprint}; every entry must match exactly one current assertion occurrence.`;
  return `${violation.ruleId} ${violation.path}:${violation.line} positively matches production implementation ${JSON.stringify(violation.target)}. ${TEST_EVIDENCE_RULES.TEST001.remediation}`;
}

export function runTestEvidenceCli(options = {}) {
  const violations = scanTestEvidence(options);
  for (const violation of violations) (options.stderr ?? console.error)(formatViolation(violation));
  if (violations.length === 0) (options.stdout ?? console.log)('TEST001/TEST002 Public test-evidence policy passed.');
  return violations.length === 0 ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = runTestEvidenceCli();
