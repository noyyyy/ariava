# AGENTS.md

This repository contains the Ariava Bridge, pi extension, protocol, and shared utilities.

## Boundaries

- Do not add arbitrary shell execution, unrestricted stdin, remote TTY, or generic command passthrough.
- Keep the Agent Adapter loopback-only and authenticated.
- Do not add Relay, watchOS, APNs, Cloudflare deployment, TestFlight, screenshots, private product documentation, or production credentials.
- Use Bun workspaces and do not add another package-manager lockfile.
- Profile-safe shared commands belong only to the shared command layer; never reimplement them in dev lifecycle/adapter code, and reject unavailable capabilities before any profile-state access or effect.

## Guided onboarding invariants

- The documented shortest first run is `npx --yes ariava@latest setup`; retain manual `init`, config, service, Pi install, doctor, and recovery commands.
- Fresh production configuration defaults to `https://ariava-relay.noyx.io`. Existing persisted values win. Keep source development explicitly on `http://127.0.0.1:8790`; ambient Relay environment overrides must not silently become service configuration.
- Before any production Host-state write, npx onboarding must install the exact executing `ariava` version into a positively verified, user-writable global npm prefix and re-enter its stable absolute CLI path. Never add sudo, a hidden prefix, or a shim manager.
- Keep bootstrap serialization outside `~/.config/ariava`; acquire `~/.config/ariava/onboarding.lock` only after stable re-entry. Locks are owner-only, token-owned, and process-start-aware. Stale recovery fails closed when liveness/start identity cannot be proven, especially on macOS.
- The production adapter catalog is closed: Pi or no agent extensions. Pi installation must use Pi's official package manager with exactly `npm:@ariava/pi-extension@<exact-cli-version>`; no latest/local/Git/URL/bundled fallback.
- Exact Pi installation is successful `reload-pending` and must tell users to run `/reload`. Do not claim `adapter-ready`: current Pi session registration does not prove extension version/capabilities, and onboarding must not change that registration contract.
- Watch pairing remains a separate explicit ownerless action: `ariava pair <PAIRING_CODE>`. Onboarding must not imply a Watch is connected.
- Strict onboarding readiness is read-only evidence aggregation and is separate from `ariava doctor`; preserve doctor's current health formula and exit behavior.
- Services remain per-user launchd on macOS and systemd user services on capable Linux/WSL. Never add root/system units, linger, detached/PID/profile/Task Scheduler fallbacks, or optimistic unsupported-platform behavior.

## Identity and command hardening boundaries

- Ariava does not rotate identity signing keys in place. Replace the identity with `ariava identity reset --confirm`, then re-pair Watches. Public default/dev identity actions are exactly `identity status` and confirmed `identity reset`; the `host` namespace is removed.
- Canonical identity load failure is fail-closed. Exact recognized legacy evidence is reachable only through confirmed reset; daemon, signer, Relay client, and onboarding readiness must never import its decoder.
- Confirmed Host reset clears the old signing/E2E domain, pins, execution journal, receipt outbox, runtime state, and links and creates one zero-link replacement. Network/401/5xx/config failures are not reset triggers.
- Relay commands are encrypted `reply`/`interrupt` envelopes. Submission `{ commandId, receivedAt }` is opaque storage acknowledgment only. At-most-once execution becomes terminal only through a Watch-verified fixed-length encrypted Host receipt; no plaintext result text or legacy interrupt fallback is allowed.
- Preserve X25519 E2E reattestation/link epochs and `ariava config agent-secret rotate`; neither is identity signing-key rotation.

## Test lanes and validation

Do not use source-text assertions to claim runtime behavior; execute the Public product flow instead, reserving source scans only for explicit repository-wide policy/static invariants without crossing the Public Repo boundary.

Protocol evolution tests must assert the current contract and executable upgrade, rejection, reset, or migration behavior. Do not maintain permanent historical field/token blacklists, scan generated bundles or npm tarballs for retired strings, or parse bundler output to allow legacy-decoder exceptions. A release-specific transition guard may be temporary only when the governing spec names its removal condition; remove it once that transition is complete.
Every retained Public policy case must have exact repository/path/test/rule/class metadata in `scripts/test-evidence-policy.registry.json`, validated by the independent `scripts/test-evidence.policy.test.ts` runner.
Keep Public `TEST001`/`TEST002` green through `bun run verify` without crossing the Public Repo boundary.

Reviewed test roots classify files by suffix:

- `*.test.ts` — shared Public Repo coverage;
- `*.macos.test.ts` — native macOS lane;
- `*.linux.test.ts` — native Linux lane;
- `*.integration.test.*` — explicit opt-in integration, excluded from ordinary lanes.

The Codex Exact-Release capability PoC lives under `apps/bridge/test/codex-poc/` and `scripts/codex-poc/`. It is a research harness only: it never touches production `apps/bridge/src/**`, `apps/relay/**`, or `apps/watchos/**`, adds no production Codex CLI/service/manifest wiring, and its evidence is written only to the gitignored `.artifacts/` directory. Real experiments are strictly opt-in (`ARIAVA_CODEX_POC_OPT_IN=1`), never run by ordinary lanes, and report UNAVAILABLE (typically INCONCLUSIVE) when preconditions are missing instead of skipping. The `codex:poc:inspect|run|review` scripts are the inventory/real-run/offline-review boundaries; they are dev-only and excluded from the published npm package.

Keep launchd/systemd renderers, fake or injected command runners, and portable fixtures in the shared lane. Put genuine host runtime behavior in the matching suffix-specific lane. Do not hide host ownership behind `skipIf` in shared tests.
Bun tests must preload an isolated temporary `HOME`, `XDG_CONFIG_HOME`, Pi directory, and cleared Ariava path overrides before importing application modules. Test helpers that temporarily mutate process-global environment values must restore them after every test; never allow a test process to resolve production paths under the developer's real home.

Copyable gates:

```bash
bun install --frozen-lockfile
bun run verify              # authoritative shared npm release-compatible closure
bun run verify:macos        # native macOS
bun run verify:host         # local Darwin dispatcher
bun run verify:linux        # native Linux / Public CI
bun run verify:linux:docker # explicit Docker pre-acceptance, normally from macOS
```

`verify:linux:docker` must stay explicit and must not be added to `verify`, `verify:macos`, or `verify:host`. It must run the complete `bun run verify:linux` closure as the image's non-root user, with no Docker socket, host home/config/credential mount, privileged mode, or systemd simulation. The reviewed base is `node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d`; update the digest, exact Node/npm/Bun pins, CI, tests, and docs together.

Report Docker evidence with its architecture. Apple Silicon defaults to Docker Linux arm64. Docker does not prove GitHub Ubuntu, a real systemd user manager, journald lifecycle, VM restart, physical logout/login, or WSL.

Real integration remains opt-in and stateful:

```bash
ARIAVA_RUN_REAL_MACOS_KEYCHAIN_LAUNCHD_TEST=1 ./scripts/test-macos-keychain-launchd.sh
./scripts/test-linux-systemd.sh
```

Use module-specific builds after changing protocol, shared-utils, Bridge, or pi. Keep public package assertions green. The GitHub workflow owns separate Linux (`verify:linux`) and macOS (`verify:macos`) jobs; both use pinned actions, frozen installs, least privilege, and exact Node 24.18.0, npm 11.18.0, and Bun 1.3.14. The tag publication workflow remains Ubuntu-only and calls authoritative `bun run verify`; never add publication credentials to ordinary CI.
