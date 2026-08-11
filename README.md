<!-- ARIAVA_PUBLIC_REPO_README: PUBLISHABLE -->
<p align="center">
  <img src="https://raw.githubusercontent.com/noyyyy/ariava/main/ariava.png" alt="Ariava" width="160" height="160">
</p>

<h1 align="center">Ariava</h1>

<p align="center"><strong>Live Your Life. Your Agents Stay Close.</strong></p>

<p align="center">
  <a href="https://www.npmjs.com/package/ariava"><img src="https://img.shields.io/npm/v/ariava?style=flat-square&label=npm" alt="npm version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="Apache 2.0 license"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%2FWSL-lightgrey?style=flat-square" alt="macOS and Linux/WSL">
  <img src="https://img.shields.io/badge/Pi-supported-7c3aed?style=flat-square" alt="Pi supported">
</p>

> [!WARNING]
> Ariava is early-stage. Breaking changes are expected.

## Roadmap

- [x] Human Attention and Intervention
- [x] APN Notification
- [ ] **In progress:** Smart Alert
- [ ] **In progress:** Session Management
- [ ] End-to-end encryption
- [ ] Project management
- [ ] Invoke a new Pi session
- [ ] Codex/Claude Code/Cursor integration
- [ ] Summary and memory

## Getting Started

### Requirements

- Node.js 22 or newer and npm (the shipped CLI and service run on Node; end users do not need Bun)
- macOS, or Linux/WSL with a reachable systemd user service manager (see the [WSL installation guide](docs/install-guide.md#wsl))
- [Pi](https://pi.dev/) when selecting the Pi adapter

The shortest first-run path is:

```bash
npx --yes ariava@latest setup
```

Fresh production setup uses `https://ariava-relay.noyx.io`. Follow the prompts to set up the Bridge and optionally install the Pi extension; run `/reload` in an open Pi session after installation.

Pair your Watch separately:

```bash
ariava pair <PAIRING_CODE>
```

For manual setup:

```bash
npm install --global ariava
ariava init
ariava service install
ariava service status
ariava install pi
ariava doctor
```
## Usage

Check the Host, pair with a valid pairing code, inspect linked devices, or view service logs:

```bash
ariava status
ariava pair <PAIRING_CODE>
ariava watches list
ariava logs
```

The command surface is intentionally narrow. Ariava does not expose arbitrary shell execution, unrestricted input, a remote terminal, or a transcript browser.

## Canonical Runtime Model

Ariava uses one encrypted, versioned Session/Event model across Pi and the local Bridge:

- Event type is exactly `done | need_human`; Session status is exactly `idle | working | need_human`.
- Normal completion atomically produces one `done` Event and an `idle` Session. A question, blocker, or exhausted runtime error produces one `need_human` Event and a `need_human` Session.
- Clients derive Event labels and Session display state from canonical type, status, and protected context; neither is stored in the canonical runtime contract.
- Driver failures are Bridge health/log/retry concerns, not canonical Event types. Host availability is a Relay-presence concern, not a Session status.
- Protected envelopes use `event-content-v2`, `session-content-v2`, and `notification-preview-v2`; notification routing uses only `agent.done` and `agent.need_human`.
- This is an intentional breaking cutover. There is no compatibility decoder, negotiation, dual read/write, or fallback for the active model. The Bridge recognizes valid prior schema 2 runtime only to atomically reset it to empty schema 3 state; obsolete Sessions and Events are not replayed.

## Build from Source

Requirements: [Bun](https://bun.sh/) for workspace/build orchestration and Node.js 22+ for the production Bridge crypto/runtime gate.

```bash
git clone https://github.com/noyyyy/ariava.git
cd ariava
bun install --frozen-lockfile
bun run verify
```

### Isolated source development profile

Use the fixed `dev` profile when an installed Ariava Bridge is already running. It keeps source-development configuration, identity, state, discovery, and logs under `~/.config/ariava-dev`, uses the local Relay at `http://127.0.0.1:8790`, and exposes the loopback Agent Adapter on `127.0.0.1:7273`; the installed profile remains under `~/.config/ariava` on Adapter port `7272`. Existing persisted Relay values remain explicit overrides.

```bash
# Build the source Bridge and open the unified dev CLI
npm run dev:cli -- init

# Run the source Bridge in the foreground
npm run dev:cli -- bridge

# In another terminal, run Pi with only the source Ariava extension
npm run dev:cli -- pi <pi args...>

# Pair this isolated dev Host with a Watch pairing code, then confirm Safety Code
npm run dev:cli -- pair <PAIRING_CODE>
# Noninteractive: after verifying the Watch shows the same Safety Code
# npm run dev:cli -- pair <PAIRING_CODE> --codes-match

# Inspect paths, Host ID, Relay URL, and Adapter status (secret redacted)
npm run dev:cli -- status
```

For a guided one-command setup that initializes the dev profile and starts the source Bridge, run `npm run dev:setup`. The `pi` command launches `pi --no-extensions -e <source-extension>`, so other automatically discovered Pi extensions are intentionally disabled in that process. These commands do not install or modify a launchd/systemd service, do not replace the globally installed Ariava Pi extension, and do not read or write the installed Ariava profile.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and include the validation you performed.

## Security

Report suspected vulnerabilities privately by following [SECURITY.md](SECURITY.md). Never post identities, adapter secrets, configuration files, pairing material, or complete logs in a public issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
