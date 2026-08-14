import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAriavaCli, resolveCliVersion, type AriavaCliApplicationContext } from '../src/cli/app';
import { ARIAVA_COMMAND_CATALOG } from '../src/cli/catalog';
import { createDefaultProfile } from '../src/cli/profiles/default';
import { createDevProfile } from '../src/cli/profiles/dev';
import { HostIdentityError } from '../src/identity';
import { RelayClientError } from '../src/relay-client';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

type EffectCounters = {
  profileFactories: number;
  descriptorValidations: number;
  preflights: number;
  configReads: number;
  configWrites: number;
  keychain: number;
  relay: number;
  spawn: number;
  service: number;
};

function zeroEffects(): EffectCounters {
  return {
    profileFactories: 0,
    descriptorValidations: 0,
    preflights: 0,
    configReads: 0,
    configWrites: 0,
    keychain: 0,
    relay: 0,
    spawn: 0,
    service: 0,
  };
}

function captureStream() {
  let output = '';
  return {
    stream: { write(chunk: unknown) { output += String(chunk); return true; } } as NodeJS.WritableStream,
    read: () => output,
  };
}

function fixture(profileId: 'default' | 'dev', execute?: (argv: string[], json: boolean) => Promise<number>) {
  const root = mkdtempSync(join(tmpdir(), `ariava-unified-shell-${profileId}-`));
  roots.push(root);
  const previousHome = process.env.HOME;
  const previousXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = root;
  process.env.XDG_CONFIG_HOME = join(root, '.config');
  const profile = profileId === 'default' ? createDefaultProfile() : createDevProfile();
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
  else process.env.XDG_CONFIG_HOME = previousXdg;

  const stdout = captureStream();
  const stderr = captureStream();
  const effects = zeroEffects();
  const calls: Array<{ route: 'shared' | 'legacy' | 'lifecycle'; argv: string[]; json: boolean }> = [];
  const invoke = async (route: 'shared' | 'legacy' | 'lifecycle', argv: string[], json: boolean) => {
    calls.push({ route, argv, json });
    if (execute) return execute(argv, json);
    effects.configReads += 1;
    effects.configWrites += 1;
    effects.keychain += 1;
    effects.relay += 1;
    effects.spawn += 1;
    effects.service += 1;
    return 0;
  };
  const context: AriavaCliApplicationContext = {
    profileId,
    profile: () => { effects.profileFactories += 1; return profile; },
    preflight: () => { effects.preflights += 1; },
    validateDescriptor: () => { effects.descriptorValidations += 1; profile.assertDescriptor(); },
    lifecycle: { execute: (argv, options) => invoke('lifecycle', argv, options.json) },
    legacy: { execute: (argv, options) => invoke('legacy', argv, options.json) },
    shared: {
      execute: async (argv, options) => {
        await invoke('shared', argv, options.json);
        return { envelope: { ok: true, code: 'ok', message: 'shared', data: {} }, human: 'shared' };
      },
    },
    output: { stdout: stdout.stream, stderr: stderr.stream },
    version: () => profileId === 'default' ? '1.2.3' : '0.0.0-dev',
    helpData: () => profileId === 'default' ? { runtime: { runtimeName: 'node' } } : {},
  };
  return { context, stdout, stderr, effects, calls };
}

describe('unified CLI application shell', () => {
  test.each(['default', 'dev'] as const)('$profile parses global --json once and delegates normalized argv', async (profile) => {
    const current = fixture(profile);
    expect(await runAriavaCli(['identity', 'status', '--json'], current.context)).toBe(0);
    expect(current.calls).toEqual([{ route: 'shared', argv: ['identity', 'status'], json: true }]);
  });

  test.each(['default', 'dev'] as const)('$profile routes status and doctor through the shared adapter', async (profile) => {
    for (const command of ['status', 'doctor'] as const) {
      const current = fixture(profile);
      expect(await runAriavaCli([command, '--json'], current.context)).toBe(0);
      expect(current.calls).toEqual([{ route: 'shared', argv: [command], json: true }]);
    }
  });

  test.each(['default', 'dev'] as const)('$profile renders profile-aware help and version without effects', async (profile) => {
    for (const argv of [[], ['help'], ['--help'], ['--version'], ['--json', '--version']] as string[][]) {
      const current = fixture(profile);
      expect(await runAriavaCli(argv, current.context)).toBe(0);
      expect(current.stderr.read()).toBe('');
      expect(current.calls).toEqual([]);
      expect(current.effects).toEqual(zeroEffects());
      expect(current.stdout.read()).not.toBe('');
    }

    const help = fixture(profile);
    expect(await runAriavaCli(['help'], help.context)).toBe(0);
    const text = help.stdout.read();
    expect(text).toContain('identity status');
    expect(text).toContain('identity reset --confirm');
    expect(text).not.toContain('host reset --confirm');
    expect(text).toContain('pair <PAIRING_CODE>');
    if (profile === 'default') {
      expect(text).toContain('service install');
      expect(text).not.toContain('  bridge                         Run the source Bridge');
      expect(text).not.toContain('  pi [ARGS...]');
    } else {
      expect(text).toContain('  bridge                         Run the source Bridge');
      expect(text).toContain('  pi [ARGS...]');
      expect(text).not.toContain('service install');
      expect(text).not.toContain('  logs');
    }
  });

  test('default version metadata is strict SemVer while dev falls back', () => {
    expect(resolveCliVersion('default', () => ({ version: '1.2.3-beta.1+build.5' }))).toBe('1.2.3-beta.1+build.5');
    const invalidVersions = [
      'not-semver',
      '1.2.3-01',
      '1.2.3-alpha..1',
      '1.2.3-',
      '1.2.3+',
      '1.2.3+build..1',
      ' 1.2.3',
      'v1.2.3',
    ];
    for (const version of invalidVersions) {
      expect(() => resolveCliVersion('default', () => ({ version })), version).toThrow('Invalid Ariava package version');
      expect(resolveCliVersion('dev', () => ({ version })), version).toBe('0.0.0-dev');
    }
    expect(() => resolveCliVersion('default', () => { throw new Error('missing'); })).toThrow('Unable to read Ariava package version');
    expect(resolveCliVersion('dev', () => { throw new Error('missing'); })).toBe('0.0.0-dev');
  });

  test.each(['default', 'dev'] as const)('$profile uses one output boundary for usage, identity, Relay, and generic failures', async (profile) => {
    const cases = [
      { name: 'usage', error: new Error('Usage: ariava identity status'), code: 'ERR_CLI' },
      { name: 'identity', error: new HostIdentityError('ERR_IDENTITY_NOT_INITIALIZED', 'identity missing'), code: 'ERR_IDENTITY_NOT_INITIALIZED' },
      { name: 'relay', error: new RelayClientError(503, 'relay unavailable'), code: 'ERR_RELAY' },
      { name: 'generic', error: new Error('boom'), code: 'ERR_CLI' },
    ];
    for (const currentCase of cases) {
      for (const json of [false, true]) {
        const current = fixture(profile, async () => { throw currentCase.error; });
        expect(await runAriavaCli(['identity', 'status', ...(json ? ['--json'] : [])], current.context), currentCase.name).toBe(1);
        expect(current.stdout.read()).toBe('');
        if (json) {
          expect(JSON.parse(current.stderr.read())).toMatchObject({ ok: false, code: currentCase.code });
        } else {
          expect(current.stderr.read().startsWith('ariava: ')).toBe(true);
          expect(() => JSON.parse(current.stderr.read())).toThrow();
        }
      }
    }
  });

  const denialMatrix = [
    { profile: 'dev' as const, argv: ['service', 'restart'], command: 'service' },
    { profile: 'dev' as const, argv: ['logs'], command: 'logs' },
    { profile: 'dev' as const, argv: ['install', 'pi'], command: 'install pi' },
    { profile: 'dev' as const, argv: ['upgrade', 'pi'], command: 'upgrade pi' },
    { profile: 'dev' as const, argv: ['remove', 'pi'], command: 'remove pi' },
    { profile: 'dev' as const, argv: ['upgrade'], command: 'upgrade' },
    { profile: 'dev' as const, argv: ['uninstall'], command: 'uninstall' },
    { profile: 'dev' as const, argv: ['dev', 'status'], command: 'dev' },
    { profile: 'dev' as const, argv: ['internal', 'bridge-daemon'], command: 'internal' },
    { profile: 'default' as const, argv: ['bridge'], command: 'bridge' },
    { profile: 'default' as const, argv: ['pi'], command: 'pi' },
  ];

  test.each(denialMatrix)('$profile denies $command before every effect', async ({ profile, argv, command }) => {
    for (const json of [false, true]) {
      const current = fixture(profile);
      expect(await runAriavaCli([...argv, ...(json ? ['--json'] : [])], current.context)).toBe(1);
      expect(current.stdout.read()).toBe('');
      expect(current.calls).toEqual([]);
      expect(current.effects).toEqual(zeroEffects());
      if (json) {
        expect(JSON.parse(current.stderr.read())).toEqual({
          ok: false,
          code: 'ERR_COMMAND_UNAVAILABLE_FOR_PROFILE',
          message: `Command \`${command}\` is unavailable for the ${profile} profile.`,
          data: { profile, command },
        });
      } else {
        expect(current.stderr.read()).toBe(`ariava: Command \`${command}\` is unavailable for the ${profile} profile.\n`);
      }
    }
  });

  test.each([
    { profile: 'default' as const, shared: ['init', 'config', 'status', 'doctor', 'pair', 'watches', 'identity', 'host'], legacy: [], lifecycle: ['setup', 'logs', 'upgrade', 'uninstall', 'service', 'install', 'remove', 'dev', 'internal'] },
    { profile: 'dev' as const, shared: ['init', 'config', 'status', 'doctor', 'pair', 'watches', 'identity', 'host'], legacy: [], lifecycle: ['setup', 'bridge', 'pi'] },
  ])('$profile catalog routes are exhaustive and staged', async ({ profile, shared, legacy, lifecycle }) => {
    const expected = new Map<string, 'shared' | 'legacy' | 'lifecycle'>([
      ...shared.map((command) => [command, 'shared'] as const),
      ...legacy.map((command) => [command, 'legacy'] as const),
      ...lifecycle.map((command) => [command, 'lifecycle'] as const),
    ]);
    for (const { command } of ARIAVA_COMMAND_CATALOG) {
      const current = fixture(profile);
      const route = expected.get(command);
      expect(await runAriavaCli([command, '--json'], current.context), `${profile}:${command}`).toBe(route ? 0 : 1);
      expect(current.calls, `${profile}:${command}`).toEqual(route
        ? [{ route, argv: [command], json: true }]
        : []);
      if (!route) {
        expect(JSON.parse(current.stderr.read()).code, `${profile}:${command}`).toBe('ERR_COMMAND_UNAVAILABLE_FOR_PROFILE');
        expect(current.effects, `${profile}:${command}`).toEqual(zeroEffects());
      }
    }
  });

  test.each(['default', 'dev'] as const)('$profile rejects version arguments through the shared usage boundary', async (profile) => {
    const current = fixture(profile);
    expect(await runAriavaCli(['--version', 'extra', '--json'], current.context)).toBe(1);
    expect(current.calls).toEqual([]);
    expect(current.effects).toEqual(zeroEffects());
    expect(JSON.parse(current.stderr.read())).toEqual({
      ok: false,
      code: 'ERR_CLI',
      message: 'Usage: ariava --version',
      data: {},
    });
  });

  test.each(['default', 'dev'] as const)('$profile renders duplicate global flags through the shared boundary', async (profile) => {
    const current = fixture(profile);
    expect(await runAriavaCli(['help', '--json', '--json'], current.context)).toBe(1);
    expect(current.calls).toEqual([]);
    expect(current.effects).toEqual(zeroEffects());
    expect(JSON.parse(current.stderr.read())).toEqual({
      ok: false,
      code: 'ERR_CLI',
      message: 'Global option --json may be specified only once.',
      data: {},
    });
  });
  test.each(['default', 'dev'] as const)('$profile shared streamed success adds no duplicate human output', async (profile) => {
    const current = fixture(profile);
    current.context.shared.execute = async () => ({
      envelope: { ok: true, code: 'ok', message: 'streamed', data: {} },
    });
    expect(await runAriavaCli(['pair', 'PEYX7K'], current.context)).toBe(0);
    expect(current.stdout.read()).toBe('');
    expect(current.stderr.read()).toBe('');
  });



});
