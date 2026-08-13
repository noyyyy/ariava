import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadInstallMetadata, mergeInstallMetadata } from '../../host-manager/config';
import type { AriavaAssetSource } from '../../host-manager/config';
import { installPiExtension, resolveDevPiSource } from '../../host-manager/pi-extension';
import { okEnvelope, printJson } from '../../host-manager/output';
import type { PublicCliDependencies } from './default-context';
import { formatDevSourceStatus, selectDefaultPresentation } from './default-presenters';

type CompatibilityCommandDependencies = Pick<PublicCliDependencies, 'stdout'>;

export async function runCompatibilityCommand(
  deps: CompatibilityCommandDependencies,
  argv: string[],
  json: boolean,
  releasePiVersion: string,
): Promise<void> {
  const command = argv[0];
  const target = argv[1];
  const from = readOption(argv, '--from');
  const installMetadata = loadInstallMetadata();

  if (command === 'install' && target === 'pi') {
    const sourcePath = resolveDevPiSource(from);
    const sourceKind: AriavaAssetSource['kind'] = from ? 'explicit-path' : 'dev-repo';
    const record = installPiExtension({ sourcePath, sourceKind, version: releasePiVersion, force: true });
    mergeInstallMetadata({ piExtension: record, piSource: record.source });
    print(deps, json, okEnvelope('ok', 'Installed dev pi extension.', record), `Installed dev pi extension from ${sourcePath}`);
    return;
  }

  if (command === 'upgrade' && target === 'pi') {
    const sourcePath = resolveDevPiSource(from);
    const sourceKind: AriavaAssetSource['kind'] = from ? 'explicit-path' : 'dev-repo';
    const record = installPiExtension({ sourcePath, sourceKind, version: releasePiVersion, force: true });
    mergeInstallMetadata({ piExtension: record, piSource: record.source });
    print(deps, json, okEnvelope('ok', 'Upgraded dev pi extension.', record), `Upgraded dev pi extension from ${sourcePath}`);
    return;
  }

  if (command === 'bridge' && target === 'use') {
    const sourcePath = from ? resolve(from) : resolve(process.cwd(), 'apps/bridge/dist/cli.js');
    if (!existsSync(sourcePath)) {
      throw new Error(`Dev bridge entry not found: ${sourcePath}. Run node ./scripts/build-bridge.mjs first or pass --from.`);
    }
    const source = {
      kind: from ? 'explicit-path' : 'dev-repo',
      path: sourcePath,
      updatedAt: new Date().toISOString(),
    } as AriavaAssetSource;
    mergeInstallMetadata({ bridgeSource: source });
    print(deps, json, okEnvelope('ok', 'Switched bridge source.', source), `Bridge source set to ${sourcePath}`);
    return;
  }

  if (command === 'status') {
    const data = {
      bridgeSource: installMetadata.bridgeSource ?? { kind: 'release-bundle' },
      piSource: installMetadata.piSource ?? { kind: 'release-bundle' },
    };
    print(deps, json, okEnvelope('ok', 'Ariava dev source status.', data), formatDevSourceStatus(data));
    return;
  }

  throw new Error('Usage: ariava dev install pi [--from <path>] | ariava dev upgrade pi [--from <path>] | ariava dev bridge use [--from <path>] | ariava dev status');
}

function readOption(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function print(
  deps: CompatibilityCommandDependencies,
  json: boolean,
  envelope: unknown,
  human: string,
): void {
  const presentation = selectDefaultPresentation(json, envelope, human);
  if (presentation.channel === 'json') {
    printJson(presentation.value, deps.stdout);
    return;
  }
  deps.stdout.write(`${presentation.value}\n`);
}
