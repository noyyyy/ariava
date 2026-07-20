# AGENTS.md

This repository contains the Ariava Bridge, pi extension, protocol, and shared utilities.

## Boundaries

- Do not add arbitrary shell execution, unrestricted stdin, remote TTY, or generic command passthrough.
- Keep the Agent Adapter loopback-only and authenticated.
- Do not add Relay, watchOS, APNs, Cloudflare deployment, TestFlight, screenshots, private product documentation, or production credentials.
- Use Bun workspaces and do not add another package-manager lockfile.

## Validation

```bash
bun install --frozen-lockfile
bun run verify
bun run --cwd extensions/pi test
bun run --cwd extensions/pi typecheck
```

Use module-specific builds after changing protocol, shared-utils, Bridge, or pi. Keep public package assertions green.
