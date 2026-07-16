import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const rootPackage = JSON.parse(readFileSync('package.json', 'utf8')) as {
  scripts: Record<string, string>;
};

function commandClosure(entry: string): string {
  const visited = new Set<string>();
  const commands: string[] = [];

  function visit(name: string) {
    if (visited.has(name)) return;
    visited.add(name);
    const command = rootPackage.scripts[name];
    expect(command, `missing script ${name}`).toBeString();
    commands.push(`${name}: ${command}`);
    for (const match of command.matchAll(/\bbun run ([\w:-]+)/gu)) {
      if (rootPackage.scripts[match[1]!]) visit(match[1]!);
    }
  }

  visit(entry);
  return commands.join('\n');
}

describe('transition verification ownership', () => {
  const publicEntry = rootPackage.scripts['verify:public'] ? 'verify:public' : 'verify';
  const isPublicCandidate = publicEntry === 'verify';

  test('Public Core verification includes its complete gate and no private runtime tooling', () => {
    const closure = commandClosure(publicEntry);
    for (const required of [
      'build:protocol',
      'build:shared-utils',
      'build:bridge',
      'build:pi-bundle',
      'extensions/pi typecheck',
      'extensions/pi test',
      'package:assert',
      isPublicCandidate ? 'boundary:check' : 'boundary:check:strict',
      isPublicCandidate ? 'bun test ./scripts' : 'verification-boundaries.test.ts',
    ]) {
      expect(closure).toContain(required);
    }
    for (const forbidden of [
      'apps/relay',
      'apps/watchos',
      'build:relay',
      'build:private',
      'test:private',
      'verify:private',
      'wrangler',
      'xcodebuild',
      ' asc ',
    ]) {
      expect(closure).not.toContain(forbidden);
    }
  });

  test('root verification remains the full ordered transition gate, or the candidate public-only gate', () => {
    if (isPublicCandidate) {
      expect(rootPackage.scripts.verify).toContain('bun run build');
      expect(rootPackage.scripts.verify).not.toContain('verify:private');
    } else {
      expect(rootPackage.scripts.verify).toBe('bun run verify:public && bun run verify:private');
    }
  });

  test('safe npm publishing invokes only the Public Core gate and rejects the private README', () => {
    const publisher = readFileSync('scripts/publish-npm-safe.sh', 'utf8');
    expect(publisher).toContain('bun run verify:public');
    expect(publisher).toContain('assert-publication-readme.mjs');
    expect(rootPackage.scripts.prepublishOnly).toContain('assert-publication-readme.mjs');
    expect(publisher).not.toMatch(/bun run verify(?:\s|$)/u);
  });
});
