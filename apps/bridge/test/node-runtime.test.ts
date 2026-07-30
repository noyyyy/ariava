import { describe, expect, test } from 'bun:test';
import { isSupportedNodeVersion, probeNodeRuntime } from '../src/runtime/node-runtime';
import { runPublicCli } from '../src/public-cli-app';

function sink() {
  let value = '';
  return {
    stream: { write(chunk: string | Uint8Array) { value += chunk.toString(); return true; } } as NodeJS.WritableStream,
    text: () => value,
  };
}

describe('production Node runtime contract', () => {
  test('accepts only Node 22 or newer version strings', () => {
    expect(isSupportedNodeVersion('v22.0.0')).toBe(true);
    expect(isSupportedNodeVersion('24.3.0')).toBe(true);
    expect(isSupportedNodeVersion('v21.9.0')).toBe(false);
    expect(isSupportedNodeVersion('bun 1.3.14')).toBe(false);
  });

  test('probes the exact runtime path with an argument array', () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const inspection = probeNodeRuntime('/absolute/node', {
      run(command, args) { calls.push({ command, args }); return { status: 0, stdout: 'v22.1.0\n', stderr: '' }; },
    });
    expect(calls).toEqual([{ command: '/absolute/node', args: ['--version'] }]);
    expect(inspection).toMatchObject({ runtimeName: 'node', runtimeVersion: 'v22.1.0', runtimeVersionSupported: true });
    expect(() => probeNodeRuntime('/absolute/node21', {
      run: () => ({ status: 0, stdout: 'v21.9.0\n', stderr: '' }),
    })).toThrow('Node.js 22 or newer');
  });

  test('help/version remain diagnostic while state-writing commands fail before dependencies run', async () => {
    const output = sink(); const errors = sink(); let serviceManagerCreated = false;
    const runtime = { runtimeName: 'bun', runtimeVersion: '1.3.14', runtimePath: '/bun', runtimeNameIsNode: false, runtimeVersionSupported: false };
    const deps = {
      stdout: output.stream, stderr: errors.stream, inspectRuntime: () => runtime,
      probeRuntimePath: () => runtime,
      createServiceManager: () => { serviceManagerCreated = true; throw new Error('must not run'); },
    };
    expect(await runPublicCli(['help', '--json'], deps)).toBe(0);
    expect(await runPublicCli(['version', '--json'], deps)).toBe(0);
    expect(await runPublicCli(['init', '--json'], deps)).toBe(1);
    expect(serviceManagerCreated).toBe(false);
    expect(errors.text()).toContain('ERR_NODE_RUNTIME_UNSUPPORTED');
    expect(errors.text()).toContain('Current runtime: bun 1.3.14');
  });
});
