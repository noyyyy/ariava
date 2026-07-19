<!-- ARIAVA_PUBLIC_CORE_README: PUBLISHABLE -->
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

- Node.js and npm
- macOS, or Linux/WSL with a reachable systemd user service manager
- [Pi](https://pi.dev/)

Install Ariava globally, initialize the Host, and install its user-scoped service:

```bash
npm install --global ariava
ariava init
ariava service install
ariava service status
```

Set your Relay URL, then restart the service:

```bash
ariava config set relayBaseUrl https://your-relay.example.com
ariava service restart
```

Install the Pi extension, then run `/reload` in an open Pi session or restart Pi:

```bash
ariava install pi
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

## Build from Source

Requirements: [Bun](https://bun.sh/) and Node.js.

```bash
git clone https://github.com/noyyyy/ariava.git
cd ariava
bun install --frozen-lockfile
bun run verify
```

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and include the validation you performed.

## Security

Report suspected vulnerabilities privately by following [SECURITY.md](SECURITY.md). Never post identities, adapter secrets, configuration files, pairing material, or complete logs in a public issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
