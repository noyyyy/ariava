import { BridgeDaemon, loadBridgeConfig } from '../../daemon';
import type { OnboardingResult } from '../../host-manager/onboarding/types';
import { renderOnboardingResult } from '../../ui/onboarding-renderer';
import type { PublicCliDependencies } from './default-context';

type InternalCommandDependencies = Pick<PublicCliDependencies, 'stdout'>;

export async function runInternalCommand(
  argv: string[],
  deps: InternalCommandDependencies,
): Promise<void> {
  const subcommand = argv[0];
  if (subcommand === 'render-onboarding-success') {
    if (argv.length !== 5 || argv[1] !== '--target' || argv[3] !== '--columns') {
      throw new Error('internal render-onboarding-success accepts only --target and --columns');
    }
    const target = argv[2];
    if (target !== 'host-ready' && target !== 'adapter-installed') {
      throw new Error('internal render-onboarding-success requires --target <host-ready|adapter-installed>');
    }
    const columns = Number.parseInt(argv[4] ?? '', 10);
    if (!Number.isSafeInteger(columns) || String(columns) !== argv[4] || columns < 1) {
      throw new Error('internal render-onboarding-success requires --columns <positive-integer>');
    }
    const result: OnboardingResult = {
      target,
      readiness: target === 'host-ready' ? 'host-ready' : 'reload-pending',
      steps: [{ id: 'completion', status: 'ready' }],
      nextActions: target === 'host-ready' ? [] : [{ id: 'reload-pi', command: '/reload' }],
    };
    deps.stdout.write(`${renderOnboardingResult(result, {
      terminal: {
        stdout: deps.stdout,
        stderr: deps.stdout,
        interactive: true,
        color: false,
        columns,
      },
    })}\n`);
    return;
  }

  if (subcommand !== 'bridge-daemon') throw new Error(`Unknown internal command: ${subcommand}`);
  const configPath = readOption(argv, '--config');
  if (!configPath || !configPath.startsWith('/')) {
    throw new Error('internal bridge-daemon requires --config <absolute-config-path>');
  }
  const daemon = new BridgeDaemon(loadBridgeConfig(configPath));
  await daemon.start();
  process.on('SIGINT', () => {
    daemon.stop();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    daemon.stop();
    process.exit(0);
  });
  await daemon.runForever();
}

function readOption(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}
