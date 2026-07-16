<!-- ARIAVA_PUBLIC_CORE_README: PUBLISHABLE -->
# Ariava

**Live Your Life. Your Agents Stay Close.**

## Install and initialize

```bash
npm install --global ariava
ariava init
ariava service install
ariava service status
```

Install the official Pi package and reload pi:

```bash
ariava install pi
# Run /reload in an open pi session, or restart pi.
```

`ariava install pi` runs Pi's package installer for `npm:@ariava/pi-extension`, which records the package in Pi's global `settings.json` so Pi updates do not drop it.

The Watch command surface is intentionally limited to `reply` and `interrupt`. Ariava does not expose arbitrary shell execution, a remote terminal, or a transcript browser.

## Build from source

Requirements: Bun and Node.js.

```bash
bun install --frozen-lockfile
bun run verify
```

## License and security

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE). Report security issues using the private process in [SECURITY.md](SECURITY.md); do not post identities, adapter secrets, configuration files, or complete logs in a public issue.
