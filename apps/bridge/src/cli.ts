#!/usr/bin/env node
import { BridgeDaemon, loadBridgeConfig } from './daemon';
import { RelayClientError } from './relay-client';
import { buildSimulatedEvent, buildSimulatedSession, type SimulationScenario } from './simulate';

function printJson(value: unknown, stream: NodeJS.WritableStream = process.stdout): void {
  stream.write(`${JSON.stringify(value, null, 2)}\n`);
}

function registerShutdownHandlers(daemon: BridgeDaemon): void {
  const stop = (): void => {
    daemon.stop();
    process.exit(0);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

async function main(): Promise<void> {
  const command = process.argv[2] ?? 'help';

  if (command === 'daemon') {
    const config = loadBridgeConfig();
    const daemon = new BridgeDaemon(config);
    const once = process.argv.includes('--once');
    await daemon.start();
    if (once) {
      try {
        printJson(await daemon.syncOnce());
      } finally {
        daemon.stop();
      }
      return;
    }
    registerShutdownHandlers(daemon);
    await daemon.runForever();
    return;
  }

  if (command === 'pair-watch' || command === 'pair') {
    const config = loadBridgeConfig();
    const daemon = new BridgeDaemon(config);
    const pairingCode = process.argv[3];
    if (!pairingCode) throw new Error('Usage: ariava pair <PAIRING_CODE>');
    const result = await daemon.pairWatch(pairingCode);
    printJson({ ok: true, ...result, relayBaseUrl: config.relayBaseUrl });
    return;
  }

  if (command === 'simulate') {
    const config = loadBridgeConfig();
    const scenario = (process.argv[3] as SimulationScenario | undefined) ?? 'blocked';
    const session = buildSimulatedSession(config.hostId, scenario);
    const event = buildSimulatedEvent(session, scenario);
    printJson({ scenario, session, event });
    return;
  }

  process.stdout.write(
    [
      'Ariava CLI',
      '',
      'Commands:',
      '  bun run ./apps/bridge/src/cli.ts daemon --once              Run one sync against the relay',
      '  bun run ./apps/bridge/src/cli.ts daemon                     Run the long-lived bridge loop',
      '  bun run ./apps/bridge/src/cli.ts pair <PAIRING_CODE>        Pair this host with a watch using its pairing code',
      '  bun run ./apps/bridge/src/cli.ts simulate [kind]            Emit a sample blocked/question/done payload',
    ].join('\n'),
  );
}

main().catch((error) => {
  if (error instanceof RelayClientError) {
    printJson(
      {
        ok: false,
        error: {
          type: 'relay_error',
          status: error.status,
          message: error.message,
        },
      },
      process.stderr,
    );
  } else {
    printJson(
      {
        ok: false,
        error: {
          type: 'cli_error',
          message: error instanceof Error ? error.message : String(error),
        },
      },
      process.stderr,
    );
  }
  process.exit(1);
});
