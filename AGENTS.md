# AGENTS.md

This repository contains the Ariava Bridge, pi extension, protocol, and shared utilities.

## Boundaries

- Do not add arbitrary shell execution, unrestricted stdin, remote TTY, or generic command passthrough.
- Keep the Agent Adapter loopback-only and authenticated.
- Do not add Relay, watchOS, APNs, Cloudflare deployment, TestFlight, screenshots, private product documentation, or production credentials.
- Use Bun workspaces and do not add another package-manager lockfile.

## Guided onboarding invariants

- The documented shortest first run is `npx --yes ariava@latest setup`; retain manual `init`, config, service, Pi install, doctor, and recovery commands.
- Fresh production configuration defaults to `https://ariava-relay.noyx.io`. Existing persisted values win. Keep source development explicitly on `http://127.0.0.1:8787`; ambient Relay environment overrides must not silently become service configuration.
- Before any production Host-state write, npx onboarding must install the exact executing `ariava` version into a positively verified, user-writable global npm prefix and re-enter its stable absolute CLI path. Never add sudo, a hidden prefix, or a shim manager.
- Keep bootstrap serialization outside `~/.config/ariava`; acquire `~/.config/ariava/onboarding.lock` only after stable re-entry. Locks are owner-only, token-owned, and process-start-aware. Stale recovery fails closed when liveness/start identity cannot be proven, especially on macOS.
- The production adapter catalog is closed: Pi or no agent extensions. Pi installation must use Pi's official package manager with exactly `npm:@ariava/pi-extension@<exact-cli-version>`; no latest/local/Git/URL/bundled fallback.
- Exact Pi installation is successful `reload-pending` and must tell users to run `/reload`. Do not claim `adapter-ready`: current Pi session registration does not prove extension version/capabilities, and onboarding must not change that registration contract.
- Watch pairing remains a separate explicit ownerless action: `ariava pair <PAIRING_CODE>`. Onboarding must not imply a Watch is connected.
- Strict onboarding readiness is read-only evidence aggregation and is separate from `ariava doctor`; preserve doctor's current health formula and exit behavior.
- Services remain per-user launchd on macOS and systemd user services on capable Linux/WSL. Never add root/system units, linger, detached/PID/profile/Task Scheduler fallbacks, or optimistic unsupported-platform behavior.

## Validation

```bash
bun install --frozen-lockfile
bun run verify
bun run --cwd extensions/pi test
bun run --cwd extensions/pi typecheck
```

Use module-specific builds after changing protocol, shared-utils, Bridge, or pi. Keep public package assertions green.
