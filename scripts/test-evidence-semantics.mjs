import ts from 'typescript';

const ALLOWED_RULES = new Set(['STRUCT001', 'DOC001', 'CONFIG001', 'WORKFLOW001', 'ARTIFACT001', 'PACK001']);
const FORBIDDEN_CLAIM = /\b(?:call\s+order|before|after|async|await|schedul|retry|state\s+transition|transitions?\s+(?:to|from)|renders?|shows?|hides?|navigat|refreshes?|submits?|opens?|closes?|updates?|persists?|runtime\s+outcome|executes?\s+(?:before|after))\b/iu;

function staticTestName(node) {
  return ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : undefined;
}

function isTestIdentifier(node) {
  return ts.isIdentifier(node) && (node.text === 'test' || node.text === 'it');
}

function declaredTestNames(source) {
  const sourceFile = ts.createSourceFile('policy.test.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const names = [];
  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      let declaration = isTestIdentifier(node.expression);
      if (ts.isCallExpression(node.expression) && ts.isPropertyAccessExpression(node.expression.expression)) {
        const each = node.expression.expression;
        declaration = each.name.text === 'each' && isTestIdentifier(each.expression);
      }
      if (declaration) {
        const name = staticTestName(node.arguments[0]);
        if (name !== undefined) names.push(name);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return names;
}

export function inspectMandatoryPolicyMetadata({ repository, registry, sources }) {
  const violations = [];
  const seen = new Set();
  for (const entry of registry) {
    const key = JSON.stringify([entry.repository, entry.path, entry.testName]);
    if (seen.has(key)) {
      violations.push({ ruleId: 'TEST002', path: entry.path, line: 1, message: `duplicate policy metadata for exact test ${JSON.stringify(entry.testName)}` });
      continue;
    }
    seen.add(key);
    if (entry.repository !== repository) violations.push({ ruleId: 'TEST002', path: entry.path, line: 1, message: `policy metadata has wrong repository owner ${entry.repository}` });
    if (!ALLOWED_RULES.has(entry.ruleId)) violations.push({ ruleId: 'TEST002', path: entry.path, line: 1, message: `unknown or missing policy evidence rule ${entry.ruleId || '(missing)'}` });
    if (!['structural', 'artifact', 'text', 'documentation'].includes(entry.propositionClass)) violations.push({ ruleId: 'TEST002', path: entry.path, line: 1, message: `runtime-behavior proposition class cannot self-label as policy: ${entry.propositionClass}` });
    if (FORBIDDEN_CLAIM.test(entry.proposition ?? '')) violations.push({ ruleId: 'TEST002', path: entry.path, line: 1, message: `policy proposition claims runtime behavior: ${entry.proposition}` });
    const source = sources.get(entry.path);
    if (source === undefined) {
      violations.push({ ruleId: 'TEST002', path: entry.path, line: 1, message: `stale policy metadata path for exact test ${JSON.stringify(entry.testName)}` });
      continue;
    }
    const count = declaredTestNames(source).filter((name) => name === entry.testName).length;
    if (count !== 1) violations.push({ ruleId: 'TEST002', path: entry.path, line: 1, message: `policy metadata must match exactly one test declaration; matched ${count} for ${JSON.stringify(entry.testName)}` });
  }
  return violations;
}

export function formatPolicySemanticViolation(violation) {
  return `${violation.ruleId} ${violation.path}:${violation.line} ${violation.message}. Every retained policy case requires one exact repository/path/test/rule/class record and may describe only static policy evidence.`;
}
