import type { AriavaPiInstallRecord } from '../../host-manager/config';
import { okEnvelope, printJson } from '../../host-manager/output';
import {
  getPiExtensionStatus,
  installPiPackage,
  removePiPackage,
  upgradePiPackage,
  type PiExtensionStatus,
} from '../../host-manager/pi-extension';
import type { PiPackageLifecyclePorts, PublicCliDependencies } from './default-context';
import { formatPiStatus, selectDefaultPresentation } from './default-presenters';

type PiCommandDependencies = Pick<PublicCliDependencies,
  | 'stdout'
  | 'loadInstallMetadata'
  | 'mergeInstallMetadata'>;


export interface PiCommands {
  status(): {
    envelope: { ok: true; code: 'ok'; message: string; data: PiExtensionStatus };
    human: string;
  };
  install(argv: string[], json: boolean): Promise<void>;
  upgrade(argv: string[], json: boolean): Promise<void>;
  remove(argv: string[], json: boolean): Promise<void>;
  convergeExactPackage(): AriavaPiInstallRecord;
  exactStatus(): PiExtensionStatus;
}

const defaultLifecyclePorts: PiPackageLifecyclePorts = {
  install: installPiPackage,
  upgrade: upgradePiPackage,
  remove: removePiPackage,
  status: getPiExtensionStatus,
};

export function createPiCommands(
  deps: PiCommandDependencies,
  cliVersion: string,
  lifecycle: PiPackageLifecyclePorts = defaultLifecyclePorts,
): PiCommands {
  const persistRecord = (record: AriavaPiInstallRecord): AriavaPiInstallRecord => {
    deps.mergeInstallMetadata({ piExtension: record, piSource: record.source });
    return record;
  };

  return {
    status() {
      const piStatus = lifecycle.status(cliVersion);
      return {
        envelope: { ok: true, code: 'ok', message: 'pi extension status.', data: piStatus },
        human: formatPiStatus(piStatus),
      };
    },
    async install(argv, json) {
      if (argv[0] !== 'pi') throw new Error('Usage: ariava install pi');
      const record = persistRecord(lifecycle.install(cliVersion));
      print(
        deps,
        json,
        okEnvelope('ok', 'Installed Ariava pi package.', record),
        `Installed ${record.source.package} through pi at ${record.managedPath}. Reload pi or run /reload.`,
      );
    },
    async upgrade(argv, json) {
      if (argv[0] !== 'pi') throw new Error('Usage: ariava upgrade pi');
      const record = persistRecord(lifecycle.upgrade(cliVersion));
      print(
        deps,
        json,
        okEnvelope('ok', 'Upgraded Ariava pi package.', record),
        `Upgraded ${record.source.package} through pi at ${record.managedPath}. Reload pi or run /reload.`,
      );
    },
    async remove(argv, json) {
      if (argv[0] !== 'pi') throw new Error('Usage: ariava remove pi');
      lifecycle.remove();
      const installMetadata = deps.loadInstallMetadata();
      deps.mergeInstallMetadata({ ...installMetadata, piExtension: undefined, piSource: undefined });
      print(
        deps,
        json,
        okEnvelope('ok', 'Removed Ariava pi package.', {}),
        'Removed Ariava pi package through pi.',
      );
    },
    convergeExactPackage() {
      return persistRecord(lifecycle.upgrade(cliVersion));
    },
    exactStatus() {
      return lifecycle.status(cliVersion);
    },
  };
}

function print(
  deps: Pick<PiCommandDependencies, 'stdout'>,
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
