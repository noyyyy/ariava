import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

const repositoryRoot = join(import.meta.dir, '..');
const installScript = join(repositoryRoot, 'scripts', 'install-pi-extension.sh');
const defaultSource = join(repositoryRoot, 'extensions', 'pi', 'bundle');
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(piExit = 0) {
  const root = mkdtempSync(join(tmpdir(), 'ariava-pi-helper-'));
  roots.push(root);
  const home = join(root, 'home');
  const bin = join(root, 'bin');
  const cwd = join(root, 'unrelated-cwd');
  const log = join(root, 'pi.log');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  mkdirSync(bin, { recursive: true, mode: 0o700 });
  mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const externalPartialState = join(home, '.pi', 'agent', 'packages', 'external-partial-state');
  const fakePi = [
    '#!/bin/sh',
    `printf '%s\\n' "$@" > ${JSON.stringify(log)}`,
    ...(piExit === 0 ? [] : [
      `mkdir -p ${JSON.stringify(join(home, '.pi', 'agent', 'packages'))}`,
      `printf 'owned by external pi installer\\n' > ${JSON.stringify(externalPartialState)}`,
    ]),
    `exit ${piExit}`,
    '',
  ].join('\n');
  writeFileSync(join(bin, 'pi'), fakePi);
  chmodSync(join(bin, 'pi'), 0o755);
  return {
    root, home, cwd, log, externalPartialState,
    env: {
      HOME: home,
      XDG_CONFIG_HOME: join(home, '.config'),
      PI_CODING_AGENT_DIR: join(home, '.pi', 'agent'),
      PATH: `${bin}${delimiter}/usr/bin${delimiter}/bin`,
    },
  };
}

async function run(args: string[], current: ReturnType<typeof fixture>, env = current.env) {
  const child = Bun.spawn({ cmd: ['/bin/bash', installScript, ...args], cwd: current.cwd, env, stdout: 'pipe', stderr: 'pipe' });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

describe('Pi extension install helper', () => {
  test('installs the generated bundle through the official Pi package command from an unrelated cwd', async () => {
    const current = fixture();
    const result = await run([], current);
    expect(result).toEqual({
      exitCode: 0,
      stdout: `Installing Ariava Pi extension package: ${defaultSource}\nReload pi or run /reload to load the extension.\n`,
      stderr: '',
    });
    expect(readFileSync(current.log, 'utf8').split('\n').filter(Boolean)).toEqual(['install', defaultSource]);
    expect(existsSync(join(current.home, '.pi', 'agent', 'extensions', 'ariava-pi'))).toBe(false);
  });

  test('passes an explicit npm source exactly and never widens it to latest, local copy, Git, or URL fallback', async () => {
    const current = fixture();
    const source = 'npm:@ariava/pi-extension@0.2.3';
    const result = await run(['--source', source], current);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain(source);
    expect(readFileSync(current.log, 'utf8').split('\n').filter(Boolean)).toEqual(['install', source]);
  });

  test('fails without Pi before creating extension state', async () => {
    const current = fixture();
    const env = { ...current.env, PATH: '/usr/bin:/bin' };
    const result = await run(['--source', 'npm:@ariava/pi-extension@0.2.3'], current, env);
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('pi CLI is required');
    expect(existsSync(join(current.home, '.pi'))).toBe(false);
    expect(existsSync(current.log)).toBe(false);
  });

  test('propagates Pi failure without deleting external state or creating helper-owned fallback state', async () => {
    const current = fixture(17);
    const result = await run([], current);
    expect(result.exitCode).toBe(17);
    expect(result.stdout).toBe(`Installing Ariava Pi extension package: ${defaultSource}\n`);
    expect(result.stderr).toBe('');
    expect(result.stdout).not.toContain('/reload');
    expect(readFileSync(current.log, 'utf8').split('\n').filter(Boolean)).toEqual(['install', defaultSource]);
    expect(readFileSync(current.externalPartialState, 'utf8')).toBe('owned by external pi installer\n');
    expect(existsSync(join(current.home, '.pi', 'agent', 'extensions', 'ariava-pi'))).toBe(false);
    expect(existsSync(join(current.home, '.ariava-pi-extension.tmp'))).toBe(false);
    expect(existsSync(join(current.cwd, '.ariava-pi-extension.tmp'))).toBe(false);
  });
});
