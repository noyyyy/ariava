export interface CliEnvelope<T = Record<string, unknown>> {
  ok: boolean;
  code: string;
  message: string;
  data: T;
}

export function okEnvelope<T>(code: string, message: string, data: T): CliEnvelope<T> {
  return { ok: true, code, message, data };
}

export function errorEnvelope<T = Record<string, unknown>>(code: string, message: string, data = {} as T): CliEnvelope<T> {
  return { ok: false, code, message, data };
}

export function printJson(value: unknown, stream: NodeJS.WritableStream = process.stdout): void {
  stream.write(`${JSON.stringify(value, null, 2)}\n`);
}
