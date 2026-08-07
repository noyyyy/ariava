import type { AriavaProfileId } from './profile';
import type { AriavaCliApplicationContext } from './context';
import { commandLabel, commandSummary, findCatalogEntry, formatHelp } from './catalog';
import { commandUnavailableFailure, normalizeCliFailure } from './failure';
import { renderCliFailure, renderCliSuccess } from './output';

const SEMVER_IDENTIFIER = '(?:0|[1-9]\\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)';
const SEMVER_BUILD_IDENTIFIER = '[0-9A-Za-z-]+';
const SEMVER_PATTERN = new RegExp(
  `^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)`
  + `(?:-${SEMVER_IDENTIFIER}(?:\\.${SEMVER_IDENTIFIER})*)?`
  + `(?:\\+${SEMVER_BUILD_IDENTIFIER}(?:\\.${SEMVER_BUILD_IDENTIFIER})*)?$`,
);

export async function runAriavaCli(argv: string[], context: AriavaCliApplicationContext): Promise<number> {
  let parsed = { args: [...argv], json: argv.includes('--json') };
  try {
    parsed = parseGlobalArguments(argv);
    const command = parsed.args[0] ?? 'help';
    if (command === '--version') {
      if (parsed.args.length !== 1) throw new Error('Usage: ariava --version');
      const version = context.version();
      renderCliSuccess(
        context.output,
        parsed.json,
        { ok: true, code: 'ok', message: 'Ariava CLI version.', data: { version } },
        version,
      );
      return 0;
    }
    if (command === '--help' || command === 'help') {
      if (parsed.args.length > 1) throw new Error('Usage: ariava help');
      renderCliSuccess(
        context.output,
        parsed.json,
        {
          ok: true,
          code: 'ok',
          message: 'Ariava CLI',
          data: { commands: commandSummary(context.profileId), ...(context.helpData?.() ?? {}) },
        },
        formatHelp(context.profileId),
      );
      return 0;
    }

    const entry = findCatalogEntry(command);
    if (!entry) throw new Error(`Unknown command: ${command}`);
    const availability = entry.availability[context.profileId];
    if (!availability) {
      throw commandUnavailableFailure(context.profileId, commandLabel(entry, parsed.args));
    }
    context.preflight?.(parsed.args);
    context.validateDescriptor?.(parsed.args);
    if (availability.route === 'shared') {
      const result = await context.shared.execute(parsed.args, { json: parsed.json });
      if (parsed.json || result.human !== undefined) {
        renderCliSuccess(context.output, parsed.json, result.envelope, result.human ?? '');
      }
      return result.exitCode ?? 0;
    }
    const adapter = availability.route === 'lifecycle' ? context.lifecycle : context.legacy;
    return await adapter.execute(parsed.args, { json: parsed.json });
  } catch (error) {
    renderCliFailure(context.output, parsed.json, normalizeCliFailure(error));
    return 1;
  }
}

export function parseGlobalArguments(argv: readonly string[]): { args: string[]; json: boolean } {
  const args: string[] = [];
  let json = false;
  for (const argument of argv) {
    if (argument === '--json') {
      if (json) throw new Error('Global option --json may be specified only once.');
      json = true;
    } else {
      args.push(argument);
    }
  }
  return { args, json };
}

export function resolveCliVersion(
  profile: AriavaProfileId,
  readManifest: () => { version?: unknown },
): string {
  let manifest: { version?: unknown };
  try {
    manifest = readManifest();
  } catch (error) {
    if (profile === 'dev') return '0.0.0-dev';
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Unable to read Ariava package version from package.json: ${detail}`);
  }
  const version = typeof manifest.version === 'string' ? manifest.version : '';
  if (!SEMVER_PATTERN.test(version)) {
    if (profile === 'dev') return '0.0.0-dev';
    throw new Error(`Invalid Ariava package version in package.json: ${JSON.stringify(manifest.version ?? null)}`);
  }
  return version;
}

export type { AriavaCliApplicationContext } from './context';
