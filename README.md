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

## Build from Source

Requirements: [Bun](https://bun.sh/) and Node.js.

```bash
git clone https://github.com/noyyyy/ariava.git
cd ariava
bun install --frozen-lockfile
bun run verify
```

### Verification lanes

Public Core keeps shared, native-host, Docker pre-acceptance, and real integration evidence separate:

```bash
# Portable shared build, package, pi extension, and shared-test closure
bun run verify:shared

# Native macOS host gate
bun run verify:macos

# Local host dispatcher (macOS only; dispatches to verify:macos)
bun run verify:host

# Native Linux lane used by the Linux GitHub Actions job
bun run verify:linux

# Explicit Linux pre-acceptance from a Mac with Docker
bun run verify:linux:docker
```

Tests under the reviewed roots use filename ownership: `*.test.ts` is shared, `*.macos.test.ts` is macOS-only, `*.linux.test.ts` is Linux-only, and `*.integration.test.*` is opt-in. Launchd/systemd renderers, injected command runners, and portable fixtures stay shared. Native filesystem, path, identity-storage, and isolated host subprocess behavior belongs to the host-suffixed lanes.

`.github/workflows/ci.yml` exposes separate **Linux** (`ubuntu-latest` → `verify:linux`) and **macOS** (`macos-latest` → `verify:macos`) checks with the same Node 24.18.0, npm 11.18.0, and Bun 1.3.14 toolchain. These jobs prove the ordinary Public Core closure on real GitHub-hosted operating systems. They do not install a real launchd agent or systemd user service.

`verify:linux:docker` is an explicit pre-acceptance aid, not part of `verify`, `verify:host`, or `verify:macos`. It builds `node:24.18.0-bookworm-slim` at the reviewed multi-platform digest `sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d`, copies the source into a non-root disposable container workspace, and runs the full `bun run verify:linux` command. Its output records the selected platform and architecture; the normal Apple Silicon result is **Docker Linux arm64**, not amd64.

Docker proves Linux filesystem/path/runtime behavior and the complete Linux verification closure in that pinned container. It does **not** prove a real systemd user manager, journald lifecycle, VM restart, physical Linux logout/login behavior, WSL, or the GitHub Ubuntu runner. An explicit `ARIAVA_DOCKER_PLATFORM=linux/amd64 bun run verify:linux:docker` request is emulated on Apple Silicon and is labeled as such.

The destructive or stateful integration lanes remain opt-in:

```bash
# Uses the real macOS user Keychain/launchd domain; review the script before running
ARIAVA_RUN_REAL_MACOS_KEYCHAIN_LAUNCHD_TEST=1 ./scripts/test-macos-keychain-launchd.sh

# Creates and manages a disposable Linux VM for real systemd-user lifecycle evidence
./scripts/test-linux-systemd.sh
```

These integration commands can touch real user or VM state and are not ordinary CI. Neither one supplies WSL or physical Linux logout/login evidence.

### Isolated source development profile

Use the fixed `dev` profile when an installed Ariava Bridge is already running. It keeps source-development configuration, identity, state, discovery, and logs under `~/.config/ariava-dev`, and uses the loopback Agent Adapter on `127.0.0.1:7273`; the installed profile remains under `~/.config/ariava` on port `7272`.

```bash
# Create or reuse the isolated dev configuration and Host identity
bun run dev:init

# Run the source Bridge in the foreground
bun run dev:bridge

# In another terminal, run Pi with only the source Ariava extension
bun run dev:pi -- <pi args...>

# Inspect paths, Host ID, Relay URL, and Adapter status (secret redacted)
bun run dev:status
```

`dev:pi` launches `pi --no-extensions -e <source-extension>`, so other automatically discovered Pi extensions are intentionally disabled in that process. These commands do not install or modify a launchd/systemd service, do not replace the globally installed Ariava Pi extension, and do not read or write the installed Ariava profile.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and include the validation you performed.

## Security

Report suspected vulnerabilities privately by following [SECURITY.md](SECURITY.md). Never post identities, adapter secrets, configuration files, pairing material, or complete logs in a public issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
