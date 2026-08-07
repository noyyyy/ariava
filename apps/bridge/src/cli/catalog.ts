import type { AriavaProfileId } from './profile';

export type AriavaCliCapability =
  | 'host-domain'
  | 'guided-setup'
  | 'user-service'
  | 'managed-pi-package'
  | 'stable-upgrade'
  | 'stable-uninstall'
  | 'source-bridge'
  | 'source-pi'
  | 'production-dev-source'
  | 'internal-production';

export type AriavaCliRoute = 'shared' | 'legacy' | 'lifecycle';

type AriavaHelpSection =
  | 'get-started'
  | 'status'
  | 'watch-pairing'
  | 'host-identity'
  | 'service'
  | 'pi'
  | 'configuration'
  | 'maintenance'
  | 'development'
  | 'profile-setup'
  | 'host-commands'
  | 'source-lifecycle';

interface AriavaCommandAvailability {
  capability: AriavaCliCapability;
  route: AriavaCliRoute;
}

interface AriavaCommandHelpBlock {
  section: AriavaHelpSection;
  order?: number;
  lines: readonly string[];
}

export interface AriavaCommandCatalogEntry {
  command: string;
  availability: Partial<Record<AriavaProfileId, AriavaCommandAvailability>>;
  commandLabel?: (argv: readonly string[]) => string;
  summaries: Partial<Record<AriavaProfileId, readonly string[]>>;
  help: Partial<Record<AriavaProfileId, readonly AriavaCommandHelpBlock[]>>;
}

export const ARIAVA_COMMAND_CATALOG: readonly AriavaCommandCatalogEntry[] = [
  {
    command: 'setup',
    availability: {
      default: { capability: 'guided-setup', route: 'lifecycle' },
      dev: { capability: 'guided-setup', route: 'lifecycle' },
    },
    summaries: {
      default: ['ariava setup [--extension pi ... | --no-extensions] [--resume] [--json] [--yes] [--relay-base-url <URL>]'],
      dev: ['ariava setup [--extension pi | --no-extensions]'],
    },
    help: {
      default: [{
        section: 'get-started',
        lines: [
          '  setup [options]                 Set up the Host, Bridge, and selected agent extensions',
          '    --extension pi                 Install an agent extension; repeat for multiple extensions',
          '    --no-extensions                Set up the Host and Bridge without agent extensions',
          '    --resume                      Resume an interrupted setup',
          '    --relay-base-url <URL>        Use a specific Relay URL',
          '    --yes                         Accept setup prompts where possible',
        ],
      }],
      dev: [{
        section: 'profile-setup',
        lines: [
          '  setup [--extension pi | --no-extensions]',
          '                                  Initialize dev state and run the source Bridge',
        ],
      }],
    },
  },
  {
    command: 'init',
    availability: {
      default: { capability: 'host-domain', route: 'shared' },
      dev: { capability: 'host-domain', route: 'shared' },
    },
    summaries: { default: ['ariava init'], dev: ['ariava init'] },
    help: {
      default: [{ section: 'get-started', lines: ['  init                            Initialize Host configuration and identity manually'] }],
      dev: [{ section: 'profile-setup', lines: ['  init                            Initialize the isolated dev Host identity'] }],
    },
  },
  {
    command: 'status',
    availability: {
      default: { capability: 'host-domain', route: 'shared' },
      dev: { capability: 'host-domain', route: 'shared' },
    },
    summaries: { default: ['ariava status [pi]'], dev: ['ariava status'] },
    help: {
      default: [{
        section: 'status',
        lines: [
          '  status                          Show Host, service, identity, and pi status',
          '  status pi                       Show pi extension status',
        ],
      }],
      dev: [{ section: 'host-commands', lines: ['  status                          Show isolated dev profile status'] }],
    },
  },
  {
    command: 'pair',
    availability: {
      default: { capability: 'host-domain', route: 'shared' },
      dev: { capability: 'host-domain', route: 'shared' },
    },
    summaries: {
      default: ['ariava pair <PAIRING_CODE> [--codes-match]'],
      dev: ['ariava pair <PAIRING_CODE> [--codes-match]'],
    },
    help: {
      default: [{ section: 'watch-pairing', lines: ['  pair <PAIRING_CODE> [--codes-match]  Pair this Host with a Watch and confirm Safety Code'] }],
      dev: [{
        section: 'host-commands',
        lines: [
          '  pair <PAIRING_CODE> [--codes-match]',
          '                                  Pair the dev Host with a Watch',
        ],
      }],
    },
  },
  {
    command: 'watches',
    availability: {
      default: { capability: 'host-domain', route: 'shared' },
      dev: { capability: 'host-domain', route: 'shared' },
    },
    summaries: {
      default: ['ariava watches list', 'ariava watches remove <WATCH_DEVICE_ID>'],
      dev: ['ariava watches list', 'ariava watches remove <WATCH_DEVICE_ID>'],
    },
    help: {
      default: [{
        section: 'watch-pairing',
        lines: [
          '  watches list                    List Watches linked to this Host',
          '  watches remove <WATCH_DEVICE_ID>',
          '                                  Remove one Watch link',
        ],
      }],
      dev: [{
        section: 'host-commands',
        lines: [
          '  watches list                    List Watches linked to the dev Host',
          '  watches remove <WATCH_DEVICE_ID>',
          '                                  Remove one dev Watch link',
        ],
      }],
    },
  },
  {
    command: 'identity',
    availability: {
      default: { capability: 'host-domain', route: 'shared' },
      dev: { capability: 'host-domain', route: 'shared' },
    },
    summaries: { default: ['ariava identity status'], dev: ['ariava identity status'] },
    help: {
      default: [{ section: 'host-identity', lines: ['  identity status                 Inspect the Host identity'] }],
      dev: [{ section: 'host-commands', lines: ['  identity status                 Inspect the dev Host identity'] }],
    },
  },
  {
    command: 'host',
    availability: {
      default: { capability: 'host-domain', route: 'shared' },
      dev: { capability: 'host-domain', route: 'shared' },
    },
    summaries: {
      default: ['ariava host rotate-key', 'ariava host reset --confirm'],
      dev: ['ariava host rotate-key', 'ariava host reset --confirm'],
    },
    help: {
      default: [{
        section: 'host-identity',
        lines: [
          '  host rotate-key                 Rotate the Host signing key',
          '  host reset --confirm            Replace the Host identity and remove all links',
        ],
      }],
      dev: [{
        section: 'host-commands',
        lines: [
          '  host rotate-key                 Rotate the dev Host signing key',
          '  host reset --confirm            Replace the dev Host identity and links',
        ],
      }],
    },
  },
  {
    command: 'doctor',
    availability: {
      default: { capability: 'host-domain', route: 'shared' },
      dev: { capability: 'host-domain', route: 'shared' },
    },
    summaries: { default: ['ariava doctor'], dev: ['ariava doctor'] },
    help: {
      default: [{ section: 'status', lines: ['  doctor                          Run configuration and installation checks'] }],
      dev: [{ section: 'host-commands', lines: ['  doctor                          Run isolated dev profile checks'] }],
    },
  },
  {
    command: 'logs',
    availability: { default: { capability: 'user-service', route: 'lifecycle' } },
    summaries: { default: ['ariava logs'] },
    help: { default: [{ section: 'status', lines: ['  logs                            Show Bridge service logs'] }] },
  },
  {
    command: 'upgrade',
    availability: { default: { capability: 'stable-upgrade', route: 'lifecycle' } },
    commandLabel: (argv) => argv[1] === 'pi' ? 'upgrade pi' : 'upgrade',
    summaries: { default: ['ariava upgrade [pi]'] },
    help: {
      default: [
        { section: 'pi', order: 2, lines: ['  upgrade pi                      Upgrade the Ariava pi extension'] },
        { section: 'maintenance', lines: ['  upgrade                         Upgrade Ariava, its service, and pi extension'] },
      ],
    },
  },
  {
    command: 'uninstall',
    availability: { default: { capability: 'stable-uninstall', route: 'lifecycle' } },
    summaries: { default: ['ariava uninstall [--purge] [--remove-pi]'] },
    help: {
      default: [{
        section: 'maintenance',
        lines: [
          '  uninstall [--purge] [--remove-pi]',
          '                                  Remove Ariava components and optional local data',
        ],
      }],
    },
  },
  {
    command: 'config',
    availability: {
      default: { capability: 'host-domain', route: 'shared' },
      dev: { capability: 'host-domain', route: 'shared' },
    },
    summaries: {
      default: ['ariava config path|show|get|set', 'ariava config agent-secret ensure|rotate'],
      dev: ['ariava config path|show|get|set', 'ariava config agent-secret ensure|rotate'],
    },
    help: {
      default: [{
        section: 'configuration',
        lines: [
          '  config path                     Print the active configuration path',
          '  config show                     Show configuration with secrets redacted',
          '  config get <KEY>                Read a configuration value',
          '  config set <KEY> <VALUE>        Set a configuration value',
          '  config agent-secret ensure      Create the Agent Adapter secret if absent',
          '  config agent-secret rotate      Replace the Agent Adapter secret',
        ],
      }],
      dev: [{
        section: 'host-commands',
        lines: [
          '  config path                     Print the dev configuration path',
          '  config show                     Show dev configuration with secrets redacted',
          '  config get <KEY>                Read a dev configuration value',
          '  config set <KEY> <VALUE>        Set a mutable dev configuration value',
          '  config agent-secret ensure      Create the dev Adapter secret if absent',
          '  config agent-secret rotate      Replace the dev Adapter secret',
        ],
      }],
    },
  },
  {
    command: 'service',
    availability: { default: { capability: 'user-service', route: 'lifecycle' } },
    summaries: { default: ['ariava service install|reinstall|status|start|stop|restart|uninstall'] },
    help: {
      default: [{
        section: 'service',
        lines: [
          '  service install                 Install and start the user service',
          '  service reinstall               Reinstall and start the user service',
          '  service status                  Show service state',
          '  service start|stop|restart       Control the service',
          '  service uninstall               Remove the user service',
        ],
      }],
    },
  },
  {
    command: 'install',
    availability: { default: { capability: 'managed-pi-package', route: 'lifecycle' } },
    commandLabel: () => 'install pi',
    summaries: { default: ['ariava install pi'] },
    help: { default: [{ section: 'pi', order: 1, lines: ['  install pi                      Install the Ariava pi extension'] }] },
  },
  {
    command: 'remove',
    availability: { default: { capability: 'managed-pi-package', route: 'lifecycle' } },
    commandLabel: () => 'remove pi',
    summaries: { default: ['ariava remove pi'] },
    help: { default: [{ section: 'pi', order: 3, lines: ['  remove pi                       Remove the Ariava pi extension'] }] },
  },
  {
    command: 'dev',
    availability: { default: { capability: 'production-dev-source', route: 'lifecycle' } },
    summaries: {
      default: [
        'ariava dev install pi [--from <path>]',
        'ariava dev upgrade pi [--from <path>]',
        'ariava dev bridge use [--from <path>]',
        'ariava dev status',
      ],
    },
    help: {
      default: [{
        section: 'development',
        lines: [
          '  dev install pi [--from <PATH>]  Install a pi extension from source',
          '  dev upgrade pi [--from <PATH>]  Upgrade a source-installed pi extension',
          '  dev bridge use [--from <PATH>]  Point the service at a development Bridge build',
          '  dev status                      Show active development sources',
        ],
      }],
    },
  },
  {
    command: 'internal',
    availability: { default: { capability: 'internal-production', route: 'lifecycle' } },
    summaries: {},
    help: {},
  },
  {
    command: 'bridge',
    availability: { dev: { capability: 'source-bridge', route: 'lifecycle' } },
    summaries: { dev: ['ariava bridge'] },
    help: { dev: [{ section: 'source-lifecycle', lines: ['  bridge                         Run the source Bridge in the foreground'] }] },
  },
  {
    command: 'pi',
    availability: { dev: { capability: 'source-pi', route: 'lifecycle' } },
    summaries: { dev: ['ariava pi [ARGS...]'] },
    help: { dev: [{ section: 'source-lifecycle', lines: ['  pi [ARGS...]                   Run Pi with the source Ariava extension'] }] },
  },
];

const HELP_LAYOUT: Record<AriavaProfileId, {
  title: string;
  sections: readonly { id: AriavaHelpSection; title: string }[];
  trailer: readonly string[];
}> = {
  default: {
    title: 'Ariava — Apple Watch-first collaboration for coding agents',
    sections: [
      { id: 'get-started', title: 'Get started:' },
      { id: 'status', title: 'Status and diagnostics:' },
      { id: 'watch-pairing', title: 'Watch pairing:' },
      { id: 'host-identity', title: 'Host identity:' },
      { id: 'service', title: 'Service management:' },
      { id: 'pi', title: 'pi integration:' },
      { id: 'configuration', title: 'Configuration:' },
      { id: 'maintenance', title: 'Maintenance:' },
      { id: 'development', title: 'Development:' },
    ],
    trailer: [
      'Examples:',
      '  npx --yes ariava@latest setup',
      '  ariava pair ABCD-1234',
      '  ariava doctor --json',
      '',
      'Run `ariava <command> --help` is not yet supported; use this command reference.',
    ],
  },
  dev: {
    title: 'Ariava — source development profile',
    sections: [
      { id: 'profile-setup', title: 'Profile setup:' },
      { id: 'host-commands', title: 'Host commands:' },
      { id: 'source-lifecycle', title: 'Source lifecycle:' },
    ],
    trailer: [],
  },
};

export function findCatalogEntry(command: string): AriavaCommandCatalogEntry | undefined {
  return ARIAVA_COMMAND_CATALOG.find((entry) => entry.command === command);
}

export function commandLabel(entry: AriavaCommandCatalogEntry, argv: readonly string[]): string {
  return entry.commandLabel?.(argv) ?? entry.command;
}

export function commandSummary(profile: AriavaProfileId): string[] {
  return ARIAVA_COMMAND_CATALOG.flatMap((entry) => entry.summaries[profile] ?? []);
}

export function formatHelp(profile: AriavaProfileId): string {
  const layout = HELP_LAYOUT[profile];
  const lines = [
    layout.title,
    '',
    'Usage:',
    '  ariava <command> [options]',
    '',
  ];
  for (const section of layout.sections) {
    lines.push(section.title);
    const blocks = ARIAVA_COMMAND_CATALOG.flatMap((entry) => entry.help[profile] ?? [])
      .filter((block) => block.section === section.id)
      .sort((left, right) => (left.order ?? 0) - (right.order ?? 0));
    for (const block of blocks) lines.push(...block.lines);
    lines.push('');
  }
  lines.push(...globalHelp());
  if (layout.trailer.length > 0) lines.push('', ...layout.trailer);
  return lines.join('\n');
}

function globalHelp(): string[] {
  return [
    'Global options:',
    '  --json                          Emit machine-readable JSON',
    '  --version                       Show the current Ariava CLI version',
    '  --help                          Show this help',
  ];
}
