<!-- ARIAVA_PUBLIC_CORE_README: PUBLISHABLE -->
# Ariava Public Core

Ariava is an Apple Watch-first collaboration system for coding agents. This repository contains the auditable local components: the Ariava Bridge, the pi extension, and their public protocol and shared utilities. The cloud Relay and watchOS application are separate product components and are not included here.

## Install and initialize

```bash
npm install --global ariava
ariava init
ariava service install
ariava service status
```

Install the bundled pi extension and reload pi:

```bash
ariava install pi
# Run /reload in an open pi session, or restart pi.
```

The Watch command surface is intentionally limited to `reply` and `interrupt`. Ariava does not expose arbitrary shell execution or a remote terminal.

## Build from source

Requirements: Bun and Node.js.

```bash
bun install --frozen-lockfile
bun run verify
```

## License and security

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE). Report security issues using the private process in [SECURITY.md](SECURITY.md); do not post identities, adapter secrets, configuration files, or complete logs in a public issue.
