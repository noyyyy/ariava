<!-- ARIAVA_PUBLIC_REPO_README: PUBLISHABLE -->
<p align="center">
  <img src="https://raw.githubusercontent.com/noyyyy/ariava/main/ariava.png" alt="Ariava" width="160" height="160">
</p>

<h1 align="center">Ariava</h1>

<p align="center"><strong>Live Your Life. Your Agents Stay Close.</strong></p>

<p align="center">
  English | <a href="./README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/ariava"><img src="https://img.shields.io/npm/v/ariava?style=flat-square&label=npm" alt="npm version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="Apache 2.0 license"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%2FWSL-lightgrey?style=flat-square" alt="macOS and Linux/WSL">
  <img src="https://img.shields.io/badge/Pi-supported-7c3aed?style=flat-square" alt="Pi supported">
</p>

> [!WARNING]
> Ariava is early-stage. Breaking changes are expected.

## What is Ariava?

Coding agents work while you don't. They grind through long tasks on your Mac — refactors, test suites, research, release notes — but when they finish, or when they hit a decision only you can make, they wait silently until you come back to the desk.

Ariava is an **Apple Watch-first companion for coding agents**. Your watch is the one screen that is always with you — notifications arrive on your wrist wherever you are, and acting on them takes seconds. It keeps your agents within arm's reach — literally:

- **Know when you're needed.** A tap on your wrist the moment an agent finishes a task or needs your judgment.
- **See what's happening.** Live session state — project, status, latest activity — at a glance, no laptop required.
- **Act from your wrist.** Send a quick **reply** to steer an agent, or **interrupt** a task that has gone off track. The command surface is deliberately small: reply and interrupt, nothing more.
- **Private by design.** End-to-end encryption, always. The relay only forwards ciphertext — no transcripts, no plaintext, no cloud copies of your work.

Ariava doesn't replace your terminal or your agents. It sets you free from sitting next to them.

*Walk away from the desk — your agents will tap you when they need you.*

## Roadmap

- [x] Human Attention and Intervention
- [x] APN Notification
- [x] End-to-end encryption
- [ ] **In progress:** Session Management
- [ ] Project management
- [ ] Invoke new session
- [ ] More integration
- [ ] Summary and memory

## Getting Started

Requires Node.js 22+ and npm, on macOS or Linux/WSL with a systemd user manager. [Pi](https://pi.dev/) is optional.

```bash
npx --yes ariava@latest setup
```

Install the Apple Watch app from [TestFlight](https://testflight.apple.com/join/EqhcRBp6), then pair:

```bash
ariava pair <PAIRING_CODE>
```

Manual setup:

```bash
npm install --global ariava
ariava init
ariava service install
ariava doctor
```

## Usage

```bash
ariava status
ariava pair <PAIRING_CODE>
ariava watches list
ariava logs
```

## Architecture

```text
Apple Watch  ↔  Relay  ↔  Local Bridge  ┬↔  Pi
                                        ├↔  DeepSeek
                                        └↔  Codex
```

The Watch and the local Bridge exchange keys and pair through the Relay.
The Relay only forwards encrypted messages.
The Bridge gets live session states from harness plugins and keeps that state locally.

## Alerts and sessions

Two alerts:

- **Done** — a human needs to review the result.
- **Need human** — the agent needs a human to guide what to do next.

A **session** is a live projection of one conversation (name, project, status, latest activity), not a transcript. The Bridge encrypts that and sends it to the Watch. The Watch sends back only **reply** and **interrupt**.

## Identity

Host and Watch each carry **two** identities, not one:

- **Signing** — Ed25519. Proves who you are. Device IDs come from this public key.
- **Encryption** — X25519. Used with ChaCha20-Poly1305 for end-to-end encryption. The Relay only sees ciphertext.

Host keys are created by `ariava init`. Watch keys are created on the Apple Watch.

Pairing checks two different codes:

1. **Pairing code** — the Watch shows a short-lived code; run `ariava pair <CODE>` on the Host. This tells the Relay which Watch and Host to link.
2. **Safety Code** — both sides then show the same code. Confirm they match. Pairing is not done until you do. This checks that the encryption keys were not swapped in transit: the Relay forwards ciphertext, but it could still try to replace public keys. If the codes differ, cancel and pair again.

```bash
ariava identity status
ariava identity reset --confirm
```

Reset the Watch identity in the Watch app. Either reset replaces both identities on that device and clears old links; pair again after.

## Build from Source

```bash
git clone https://github.com/noyyyy/ariava.git
cd ariava
bun install --frozen-lockfile
bun run verify
```

Isolated source development (without touching an installed Bridge) is in [docs/prod-vs-dev-cli.md](docs/prod-vs-dev-cli.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Report suspected vulnerabilities privately via [SECURITY.md](SECURITY.md). Never post identities, secrets, pairing material, or complete logs in a public issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
