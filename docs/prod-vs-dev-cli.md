# Production vs Development CLI

This document compares the two command-line surfaces of the Bridge package:

- **Production (`default`) profile** — the installed `ariava` CLI (`apps/bridge/src/public-cli.ts`, lifecycle in `apps/bridge/src/cli/lifecycle/default.ts`).
- **Development (`dev`) profile** — the source-development CLI (`apps/bridge/src/dev-profile-cli.ts`, lifecycle in `apps/bridge/src/cli/lifecycle/dev.ts`), normally invoked through `bun run dev:cli -- <command>`.

Both profiles share one command shell (`apps/bridge/src/cli/app.ts`), one command catalog with per-profile availability (`apps/bridge/src/cli/catalog.ts`), one shared host-command layer (`apps/bridge/src/cli/commands/*`), one probe layer (`apps/bridge/src/cli/probes/profile.ts`), and identical output/error rendering (`apps/bridge/src/cli/output.ts`, `apps/bridge/src/cli/failure.ts`). The differences below are intentional product boundaries unless explicitly marked as convergence work.

## 1. Profile resources

| Resource | Production (`default`) | Development (`dev`) |
| --- | --- | --- |
| Config root | `~/.config/ariava` | `~/.config/ariava-dev` |
| Config file | `<root>/config.json` | `<root>/config.json` |
| Identity | `<root>/host-identity.json`, Keychain profile `default` | `<root>/host-identity.json`, Keychain profile `dev` (separate evidence account) |
| State | `<root>/state/bridge-state.json` | `<root>/state/bridge-state.json` |
| Agent Adapter discovery | `<root>/agent-adapter.json` — six-key protocol-4 `{url, secret, protocolVersion: 4, provider, profileId, hostId}` | `<root>/agent-adapter.json` — same six-key protocol-4 shape with dev profileId |
| Agent Adapter port | `7272` | `7273` |
| Default Relay base URL | `https://ariava-relay.noyx.io` | `http://127.0.0.1:8790` |
| Default host name | machine hostname | `<hostname> (Dev)` |
| pi extension log | `<root>/pi-extension.log` | `<root>/pi-extension.log` |

Both descriptors are validated by `apps/bridge/src/cli/profile.ts`: fixed resources per profile (ports, identity profile, root name), normalized absolute paths, no lexical or canonical (symlink) overlap with the counterpart profile.

Both profiles share the Agent Adapter Protocol 4 owner-bound wire: authenticated `GET /v2/health`, owner-bound `/v2/agent/**` operations carrying driver-instance/owner-lease headers, and the persistent six-key discovery above. The discovery file holds the persistent `agentAdapterSecret` shared by all providers; it is not Relay authentication. Pi Event publication is best-effort single-attempt: a normal Pi native API return submits `executed`, a throw after possible invocation stays internal `outcome_unknown`, and uncertain commands are never replayed.

## 2. Command surface

| Command | Production | Development | Route |
| --- | --- | --- | --- |
| `setup` | Guided onboarding (see §5) | Dev setup (init + source Bridge) | lifecycle |
| `init` | Init Host config + identity | Init isolated dev Host identity | shared |
| `config` | Full config surface | Same surface, dev file | shared |
| `status` | Host/service/identity/pi status | Isolated dev profile status | shared |
| `status pi` | Pi extension status | — (rejected) | shared |
| `doctor` | Full install/service checks | Isolated dev source checks | shared |
| `identity` | Inspect/reset Host identity | Same, dev identity | shared |
| `host` | — (rejected) | — (rejected) | removed compatibility namespace |
| `pair` | Pair a Watch with Safety Code | Same, dev Host | shared |
| `watches` | List/remove Watch links | Same, dev Host | shared |
| `service` | install/reinstall/status/start/stop/restart/uninstall | — (rejected) | lifecycle |
| `install pi` / `remove pi` | Managed pi package | — (rejected) | lifecycle |
| `upgrade` / `upgrade pi` | Self-upgrade + service + pi | — (rejected) | lifecycle |
| `uninstall` | Remove components | — (rejected) | lifecycle |
| `logs` | Bridge service logs | — (rejected) | lifecycle |
| `dev` | Manage dev sources in a production install | — (rejected) | lifecycle |
| `internal` | Internal production entry | — (rejected) | lifecycle |
| `bridge` | — (rejected) | Run the source Bridge in the foreground | lifecycle |
| `pi` | — (rejected) | Run Pi with the source extension | lifecycle |
| `--version` / `--help` | Published version / full reference | Source version / dev reference | shell |

Unavailable commands fail with `ERR_COMMAND_UNAVAILABLE_FOR_PROFILE` before any effect (verified by `apps/bridge/test/unified-cli-shell.test.ts`).

## 3. Per-command behavior

### Shared commands (must behave identically modulo profile data)

- **`init`** — identical flow (`operations/initialize.ts`); human message prefixes the profile: `Initialized Host identity …` vs `Initialized dev Host identity …`.
- **`config`** — identical subcommands and redaction. The mutation policy differs intentionally: the **default** profile allows setting `statePath`, `agentAdapterConfigPath`, `agentAdapterPort` (`DEFAULT_MUTABLE_RESOURCE_KEYS`); the **dev** profile rejects them (`ERR_IDENTITY_MANAGED_CONFIG`) because dev resources are fixed and fail closed on mismatch. `config show`, `get`, and `path` print structured output identically for both.
- **`status`** — both emit the same concise aligned human card (`Ariava` header, aligned labels); `--json` emits the envelope with profile-specific data (dev adds `profile: 'dev'` and source evidence; prod adds `service`/`piExtension`/identity evidence). Envelope message is profile-aware: `Ariava dev host status.` / `Ariava host status.` (converged).
- **`doctor`** — both print flat `key: value` check lines and exit `0`/`1`; the health formula is per-profile (prod checks service/metadata/pi install state; dev checks source Bridge/pi presence). The human formatter is one shared helper (converged).
- **`identity`** — exactly `status` and confirmed `reset`; messages and usage strings are profile-aware. `identity status` prints structured inspection JSON for both. `identity reset` without `--confirm` emits `ERR_CONFIRMATION_REQUIRED` before profile mutation. Confirmed reset removes the old signing/E2E domain, pins, journal/outbox, runtime state, and links, creates one canonical zero-link replacement, and requires Watch re-pairing. Ariava does not rotate identity signing keys in place. Replace the identity with `ariava identity reset --confirm`, then re-pair Watches.
- **Canonical identity failure** — daemon, signer, Relay client, and onboarding readiness load only canonical identity evidence. Exact recognized non-canonical/pending evidence is accepted only by the confirmed reset coordinator; unknown or inconclusive evidence fails closed. Network, `401`, `5xx`, and ordinary configuration errors preserve identity and are not reset triggers.
- **`pair` / `watches`** — identical, isolated to the selected profile.
- **`--version`** — production reads the installed package version (semver enforced; throws on invalid); dev reads the source `package.json` with a `0.0.0-dev` fallback instead of throwing.

### Output and error conventions (identical for both)

- Default output is human text; `--json` (global flag, once) switches to the machine envelope `{ ok, code, message, data }` on stdout, failures on stderr.
- Human failures are prefixed `ariava: ` for **both** profiles (`cli/failure.ts`).
- JSON status/doctor/config/identity/watches payloads never contain the Agent Adapter secret or private key material.
- Exit codes: `0` success, `1` any failure (doctor additionally returns `1` when unhealthy).

## 4. Intentional divergences

| Area | Production | Development | Why |
| --- | --- | --- | --- |
| Runtime preflight | Enforces a supported production Node runtime before every non-`setup` command; `init` additionally requires service support | No runtime gate; runtime only probed by `status`/`doctor` | Prod installs must run on supported runtimes; dev runs from source on the developer machine |
| Config env defaults | `allowProductionEnvironmentDefaults: true`, `saveBaseBeforeIdentity: true` | Both forced `false` | Dev must not silently inherit ambient production Relay/port overrides |
| Version resolution | Installed semver; invalid version is a hard error | Source version; invalid falls back to `0.0.0-dev` | Dev should never block on version metadata |
| Service lifecycle | Full `service` + `logs` + `upgrade`/`uninstall` surface | None | Dev runs the Bridge in the foreground; no user service exists |
| pi management | Managed npm package (`npm:@ariava/pi-extension@<exact-cli-version>`) | Source extension (`pi --no-extensions -e extensions/pi/index.ts`) | Prod installs use the published package; source dev uses the checkout. The Bridge and `@ariava/pi-extension` must be the exact same version; existing Pi sessions need `/reload` after the coordinated upgrade. |
| `setup` | Guided onboarding (§5) | `init` + foreground source Bridge + optional source pi | See §5 |
| Help | Full product reference + examples | Compact dev reference | Audience differs |
| `status pi` | Available | Rejected | Dev has no managed pi package to inspect |

## 5. `setup` differences

**Production `setup`** is the guided onboarding path: npx stable-CLI re-entry into a positively verified user-writable npm prefix, onboarding lock handling (`~/.config/ariava/onboarding.lock` after stable re-entry), service install, exact pi package install (`npm:@ariava/pi-extension@<exact-cli-version>`), and strict read-only readiness aggregation. It is separate from `ariava doctor`.

**Development `setup`** (`bun run dev:setup -- [--extension pi | --no-extensions]`) initializes the isolated dev identity and runs the source Bridge in the foreground with the source pi extension when selected. No npm prefix, service, lock, or readiness logic is involved.

## 6. Convergence fixes applied

These are places where the two profiles were expected to behave identically but had drifted; each is now converged and covered by tests.

| # | Area | Before | After |
| --- | --- | --- | --- |
| 1 | `status` human output (dev) | Raw `JSON.stringify` dump | Concise aligned card identical in style to production |
| 2 | `identity reset` without `--confirm` (dev) | Generic `ERR_CLI` | `ERR_CONFIRMATION_REQUIRED`, same machine contract as production |
| 3 | `config agent-secret rotate` (dev) | Told the user to restart the Ariava **service** | Tells the user to restart the **source Bridge** |
| 4 | `doctor` human formatter | Two near-duplicate formatters (`formatDoctor`, `formatDevDoctor`) | One shared `formatDoctorChecks` |
| 5 | `status` envelope message | Generic `Ariava host status.` for both | Profile-aware: `Ariava dev host status.` / `Ariava host status.` |
| 6 | `ariava dev status` human output | Raw JSON of two source fields | Concise card (`Bridge source` / `Pi source`) |

### Intentionally not converged

- Usage strings keep the binary name: dev commands that need a usage line say `dev-profile-cli …` (e.g. `dev-profile-cli identity status`), while production says `ariava …`. This is deliberate — `dev-profile-cli` is the only binary a source developer sees — and is asserted by tests.

## 7. Verification

- `node ./scripts/build-bridge.mjs` — builds both CLIs.
- `bun test ./apps/bridge/test/dev-profile-cli.test.ts` — dev surface, status card, doctor, identity/host, pair.
- `bun test ./apps/bridge/test/public-cli.test.ts` — production status baseline, dev status envelope, config/service lifecycle.
- `bun test ./apps/bridge/test/profile-domain-contract.test.ts` — both profiles: probes, config mutation policy, redaction, agent-secret messages.
- `bun test ./apps/bridge/test/identity-cli.test.ts` — confirmation contract, canonical identity/reset safety.
- `bun test ./apps/bridge/test/unified-cli-shell.test.ts` — routing/denial matrix, shared-command staging.
