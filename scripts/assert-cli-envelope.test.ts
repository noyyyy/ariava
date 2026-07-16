import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const helperPath = join(process.cwd(), 'scripts', 'assert-cli-envelope.mjs');

const neutralStatus = {
  ok: true,
  code: 'ok',
  message: 'Ariava host status.',
  data: {
    service: {
      backend: 'systemd-user',
      supported: true,
      supportReason: 'supported',
      installed: false,
      enabled: false,
      loaded: false,
      processRunning: false,
    },
  },
};

const healthyDoctor = {
  ok: true,
  code: 'ok',
  message: 'Ariava doctor completed.',
  data: {
    platform: 'linux',
    isWsl: false,
    serviceBackend: 'systemd-user',
    serviceSupported: true,
    serviceSupportReason: 'supported',
    serviceInstalled: true,
    serviceEnabled: true,
    serviceLoaded: true,
    serviceRunning: true,
    servicePathCurrent: true,
  },
};

const unhealthyDoctor = {
  ...healthyDoctor,
  ok: false,
  code: 'ERR_DOCTOR',
  message: 'Ariava doctor found issues.',
  data: { ...healthyDoctor.data, serviceInstalled: false, serviceRunning: false },
};

async function runHelper(payload: string, kind: 'status' | 'doctor', commandExit: number) {
  const root = mkdtempSync(join(tmpdir(), 'ariava-envelope-'));
  const input = join(root, 'output.json');
  writeFileSync(input, payload);
  try {
    const proc = Bun.spawn({
      cmd: [process.execPath, helperPath, input, kind, String(commandExit)],
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      proc.exited,
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    return { exitCode, stdout, stderr };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe('release CLI envelope assertion helper', () => {
  test('accepts status success and both doctor outcomes when exit and envelope agree', async () => {
    for (const [envelope, kind, commandExit] of [
      [neutralStatus, 'status', 0],
      [healthyDoctor, 'doctor', 0],
      [unhealthyDoctor, 'doctor', 1],
    ] as const) {
      const result = await runHelper(JSON.stringify(envelope), kind, commandExit);
      expect(result.exitCode, result.stderr).toBe(0);
    }
  });

  test('rejects malformed JSON', async () => {
    const result = await runHelper('{not-json', 'status', 0);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain('valid JSON');
  });

  test('rejects missing neutral service fields and backend identity', async () => {
    const missingStatusField = structuredClone(neutralStatus);
    delete (missingStatusField.data.service as Partial<typeof neutralStatus.data.service>).loaded;
    const missingStatusBackend = structuredClone(neutralStatus);
    delete (missingStatusBackend.data.service as Partial<typeof neutralStatus.data.service>).backend;
    const missingDoctorField = structuredClone(unhealthyDoctor);
    delete (missingDoctorField.data as Partial<typeof unhealthyDoctor.data>).serviceRunning;
    const missingDoctorBackend = structuredClone(unhealthyDoctor);
    delete (missingDoctorBackend.data as Partial<typeof unhealthyDoctor.data>).serviceBackend;

    for (const [envelope, kind] of [
      [missingStatusField, 'status'],
      [missingStatusBackend, 'status'],
      [missingDoctorField, 'doctor'],
      [missingDoctorBackend, 'doctor'],
    ] as const) {
      const result = await runHelper(JSON.stringify(envelope), kind, kind === 'status' ? 0 : 1);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain('service diagnostic');
    }
  });

  test('rejects status envelopes unless exit, ok, and code all indicate success', async () => {
    for (const [envelope, commandExit] of [
      [{ ...neutralStatus, ok: false }, 0],
      [{ ...neutralStatus, code: 'ERR_CLI' }, 0],
      [neutralStatus, 1],
    ] as const) {
      const result = await runHelper(JSON.stringify(envelope), 'status', commandExit);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain('status');
    }
  });

  test('rejects doctor envelopes when exit, ok, and code do not match', async () => {
    for (const [envelope, commandExit] of [
      [healthyDoctor, 1],
      [unhealthyDoctor, 0],
      [{ ...unhealthyDoctor, ok: true }, 1],
      [{ ...unhealthyDoctor, code: 'ERR_CLI' }, 1],
      [healthyDoctor, 2],
    ] as const) {
      const result = await runHelper(JSON.stringify(envelope), 'doctor', commandExit);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain('doctor');
    }
  });
});
