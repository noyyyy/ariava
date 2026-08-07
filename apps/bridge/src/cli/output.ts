import { printJson } from '../host-manager/output';
import { formatHumanCliFailure, type CliFailure } from './failure';

export interface AriavaCliOutput {
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
}

export interface CliResult<T = Record<string, unknown>> {
  ok: boolean;
  code: string;
  message: string;
  data: T;
}

export function renderCliSuccess(
  output: AriavaCliOutput,
  json: boolean,
  envelope: CliResult<unknown>,
  human: string,
): void {
  if (json) printJson(envelope, output.stdout);
  else output.stdout.write(`${human}\n`);
}

export function renderCliFailure(output: AriavaCliOutput, json: boolean, failure: CliFailure): void {
  if (json) printJson(failure, output.stderr);
  else output.stderr.write(formatHumanCliFailure(failure));
}
