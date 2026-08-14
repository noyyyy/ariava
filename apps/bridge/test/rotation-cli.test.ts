import { describe, expect, test } from 'bun:test';
import { runAriavaCli, type AriavaCliApplicationContext } from '../src/cli/app';
import { commandSummary, findCatalogEntry, formatHelp } from '../src/cli/catalog';
import * as identity from '../src/identity';
import { RelayClient } from '../src/relay-client';

function captureStream() {
  let output = '';
  return {
    stream: { write(chunk: unknown) { output += String(chunk); return true; } } as NodeJS.WritableStream,
    read: () => output,
  };
}

function effectFreeContext(profileId: 'default' | 'dev') {
  const stdout = captureStream();
  const stderr = captureStream();
  const effects: string[] = [];
  const context: AriavaCliApplicationContext = {
    profileId,
    profile: () => { effects.push('profile'); throw new Error('profile effect'); },
    preflight: () => { effects.push('preflight'); throw new Error('preflight effect'); },
    validateDescriptor: () => { effects.push('descriptor'); throw new Error('descriptor effect'); },
    shared: {
      execute: async () => {
        effects.push('shared');
        throw new Error('shared effect');
      },
    },
    legacy: {
      execute: async () => {
        effects.push('legacy');
        throw new Error('legacy effect');
      },
    },
    lifecycle: {
      execute: async () => {
        effects.push('lifecycle');
        throw new Error('lifecycle effect');
      },
    },
    output: { stdout: stdout.stream, stderr: stderr.stream },
    version: () => '1.0.0',
    helpData: () => { effects.push('help'); throw new Error('help effect'); },
  };
  return { context, stdout, stderr, effects };
}

const removedSpellings = [
  ['host', 'rotate-key'],
  ['identity', 'rotate-key'],
  ['identity', 'rotate-signing-key'],
] as const;

describe('Host signing-key rotation removal', () => {
  test.each(['default', 'dev'] as const)('$profile catalog exposes only identity status and reset', (profile) => {
    expect(findCatalogEntry('host')).toBeUndefined();
    expect(findCatalogEntry('identity')?.summaries[profile]).toEqual([
      'ariava identity status',
      'ariava identity reset --confirm',
    ]);
    expect(commandSummary(profile)).not.toContain('ariava config agent-secret ensure|rotate');

    const help = formatHelp(profile);
    expect(help).toContain('identity status');
    expect(help).toContain('identity reset --confirm');
    expect(help).not.toMatch(/host rotate-key|host reset|identity rotate-key|identity rotate-signing-key/);
    expect(help).not.toContain('config agent-secret ensure');
    expect(help).not.toContain('config agent-secret rotate');
  });

  test.each(['default', 'dev'] as const)('$profile denies every removed spelling before all effects', async (profile) => {
    for (const argv of removedSpellings) {
      for (const json of [false, true]) {
        const current = effectFreeContext(profile);
        expect(await runAriavaCli([...argv, ...(json ? ['--json'] : [])], current.context)).toBe(1);
        expect(current.effects).toEqual([]);
        expect(current.stdout.read()).toBe('');
        const resetCommand = profile === 'dev'
          ? 'dev-profile-cli identity reset --confirm'
          : 'ariava identity reset --confirm';
        const message = `Signing keys cannot be rotated in place. Use \`${resetCommand}\` to replace the identity and re-pair Watches.`;
        if (json) {
          expect(JSON.parse(current.stderr.read())).toEqual({
            ok: false,
            code: 'ERR_CLI',
            message,
            data: {},
          });
        } else {
          expect(current.stderr.read()).toBe(`ariava: ${message}\n`);
        }
      }
    }
  });

  test.each(['default', 'dev'] as const)('$profile does not retain host reset as an alias', async (profile) => {
    const current = effectFreeContext(profile);
    expect(await runAriavaCli(['host', 'reset', '--confirm', '--json'], current.context)).toBe(1);
    expect(current.effects).toEqual([]);
    expect(JSON.parse(current.stderr.read())).toEqual({
      ok: false,
      code: 'ERR_CLI',
      message: 'Unknown command: host',
      data: {},
    });
  });

  test('Bridge runtime exports no signing-key rotation implementation or Relay methods', () => {
    expect(identity).not.toHaveProperty('generateHostRotationIdentity');
    expect(identity).not.toHaveProperty('rotateHostIdentity');
    expect(RelayClient.prototype).not.toHaveProperty('rotateKey');
    expect(RelayClient.prototype).not.toHaveProperty('recoverRotation');
  });
});
