# AGENTS.md

This repository is Ariava Public Core. It contains the local Bridge, pi extension, public protocol, and shared utilities.

## Boundaries

- Keep the Watch command surface limited to `reply` and `interrupt`.
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

Use module-specific builds after changing protocol, shared-utils, Bridge, or pi. Keep public package and repository boundary assertions green.
