import type { AriavaCliCommandSuccess, AriavaProfileCliContext } from '../context';
import {
  watchesProfile,
  type WatchesProfileDependencies,
  type WatchesProfileInput,
} from '../operations/watches';

export interface WatchesCommandDependencies {
  context(): AriavaProfileCliContext;
  watches: WatchesProfileDependencies;
}

export async function runWatchesCommand(
  argv: string[],
  dependencies: WatchesCommandDependencies,
): Promise<AriavaCliCommandSuccess> {
  const input = parseWatchesInput(argv);
  const result = await watchesProfile(dependencies.context(), input, dependencies.watches);
  if (result.action === 'list') {
    return {
      envelope: {
        ok: true,
        code: 'ok',
        message: 'Linked watches.',
        data: { watches: result.watches },
      },
      human: JSON.stringify(result.watches, null, 2),
    };
  }
  return {
    envelope: {
      ok: true,
      code: 'ok',
      message: 'Watch link removed.',
      data: { watchDeviceId: result.watchDeviceId },
    },
    human: `Removed watch ${result.watchDeviceId}`,
  };
}

function parseWatchesInput(argv: string[]): WatchesProfileInput {
  const action = argv[0] ?? 'list';
  if (action === 'list' && argv.length <= 1) return { action: 'list' };
  if (action === 'remove' && argv.length === 2 && argv[1]) {
    return { action: 'remove', watchDeviceId: argv[1] };
  }
  throw new Error('Usage: ariava watches list | ariava watches remove <WATCH_DEVICE_ID>');
}
