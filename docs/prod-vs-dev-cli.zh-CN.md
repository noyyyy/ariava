# Production vs Development CLI

[English](./prod-vs-dev-cli.md) | 简体中文

本文比较 Bridge 包的两套命令行：

- **Production（`default`）profile** — 已安装的 `ariava` CLI（`apps/bridge/src/public-cli.ts`，lifecycle 在 `apps/bridge/src/cli/lifecycle/default.ts`）。
- **Development（`dev`）profile** — 源码开发 CLI（`apps/bridge/src/dev-profile-cli.ts`，lifecycle 在 `apps/bridge/src/cli/lifecycle/dev.ts`），通常通过 `bun run dev:cli -- <command>` 调用。

两套 profile 共用同一个 command shell（`apps/bridge/src/cli/app.ts`）、同一份带 per-profile availability 的 command catalog（`apps/bridge/src/cli/catalog.ts`）、同一层 shared host-command（`apps/bridge/src/cli/commands/*`）、同一层 probe（`apps/bridge/src/cli/probes/profile.ts`），以及相同的 output / error rendering（`apps/bridge/src/cli/output.ts`、`apps/bridge/src/cli/failure.ts`）。下面的差异是有意的产品边界，除非明确标成 convergence work。

## 1. Profile resources

| Resource | Production（`default`） | Development（`dev`） |
| --- | --- | --- |
| Config root | `~/.config/ariava` | `~/.config/ariava-dev` |
| Config file | `<root>/config.json` | `<root>/config.json` |
| Identity | `<root>/host-identity.json`，Keychain profile `default` | `<root>/host-identity.json`，Keychain profile `dev`（独立 evidence account） |
| State | `<root>/state/bridge-state.json` | `<root>/state/bridge-state.json` |
| Agent Adapter discovery | `<root>/agent-adapter.json` — six-key protocol-4 `{url, secret, protocolVersion: 4, provider, profileId, hostId}` | `<root>/agent-adapter.json` — 同样的 six-key protocol-4 shape，带 dev profileId |
| Agent Adapter port | `7272` | `7273` |
| Default Relay base URL | `https://ariava-relay.noyx.io` | `http://127.0.0.1:8790` |
| Default host name | machine hostname | `<hostname> (Dev)` |
| pi extension log | `<root>/pi-extension.log` | `<root>/pi-extension.log` |

两套 descriptor 都由 `apps/bridge/src/cli/profile.ts` 校验：每个 profile 的 resource 是固定的（port、identity profile、root name），路径是规范化后的绝对路径，与另一套 profile 不得有 lexical 或 canonical（symlink）重叠。

两套 profile 共用 Agent Adapter Protocol 4 owner-bound wire：authenticated `GET /v2/health`、owner-bound `/v2/agent/**` operations（带 driver-instance / owner-lease header），以及上面那份 persistent six-key discovery。Discovery file 保存所有 provider 共用的 persistent `agentAdapterSecret`；它不是 Relay authentication。Pi Event publication 是 best-effort、只试一次：Pi native API 正常返回就提交 `executed`，可能已经调用之后再 throw 则留在内部 `outcome_unknown`，不确定的 command 从不 replay。

## 2. Command surface

| Command | Production | Development | Route |
| --- | --- | --- | --- |
| `setup` | Guided onboarding（见 §5） | Dev setup（init + source Bridge） | lifecycle |
| `init` | Init Host config + identity | Init isolated dev Host identity | shared |
| `config` | Full config surface | 同样的 surface，dev file | shared |
| `status` | Host/service/identity/pi status | Isolated dev profile status | shared |
| `status pi` | Pi extension status | —（rejected） | shared |
| `doctor` | Full install/service checks | Isolated dev source checks | shared |
| `identity` | Inspect/reset Host identity | 同样，dev identity | shared |
| `host` | —（rejected） | —（rejected） | removed compatibility namespace |
| `pair` | Pair a Watch with Safety Code | 同样，dev Host | shared |
| `watches` | List/remove Watch links | 同样，dev Host | shared |
| `service` | install/reinstall/status/start/stop/restart/uninstall | —（rejected） | lifecycle |
| `install pi` / `remove pi` | Managed pi package | —（rejected） | lifecycle |
| `upgrade` / `upgrade pi` | Self-upgrade + service + pi | —（rejected） | lifecycle |
| `uninstall` | Remove components | —（rejected） | lifecycle |
| `logs` | Bridge service logs | —（rejected） | lifecycle |
| `dev` | Manage dev sources in a production install | —（rejected） | lifecycle |
| `internal` | Internal production entry | —（rejected） | lifecycle |
| `bridge` | —（rejected） | Run the source Bridge in the foreground | lifecycle |
| `pi` | —（rejected） | Run Pi with the source extension | lifecycle |
| `--version` / `--help` | Published version / full reference | Source version / dev reference | shell |

不可用的 command 会在任何 effect 之前以 `ERR_COMMAND_UNAVAILABLE_FOR_PROFILE` 失败（由 `apps/bridge/test/unified-cli-shell.test.ts` 验证）。

## 3. Per-command behavior

### Shared commands（除了 profile data 之外，行为必须相同）

- **`init`** — 流程相同（`operations/initialize.ts`）；human message 会带上 profile 前缀：`Initialized Host identity …` vs `Initialized dev Host identity …`。
- **`config`** — 相同的 subcommand 和 redaction。Mutation policy 有意不同：**default** profile 允许设置 `statePath`、`agentAdapterConfigPath`、`agentAdapterPort`（`DEFAULT_MUTABLE_RESOURCE_KEYS`）；**dev** profile 会拒绝（`ERR_IDENTITY_MANAGED_CONFIG`），因为 dev resource 是固定的，mismatch 就 fail closed。`config show`、`get`、`path` 两边打印的 structured output 相同。
- **`status`** — 两边都输出同样风格的 concise aligned human card（`Ariava` header、aligned labels）；`--json` 输出带 profile-specific data 的 envelope（dev 加 `profile: 'dev'` 和 source evidence；prod 加 `service` / `piExtension` / identity evidence）。Envelope message 按 profile 区分：`Ariava dev host status.` / `Ariava host status.`（已 converged）。
- **`doctor`** — 两边都打印扁平的 `key: value` check 行，exit `0` / `1`；health formula 按 profile（prod 检查 service / metadata / pi install state；dev 检查 source Bridge / pi presence）。Human formatter 是同一个 shared helper（已 converged）。
- **`identity`** — 只有 `status` 和带确认的 `reset`；message 和 usage string 按 profile 区分。`identity status` 两边都打印 structured inspection JSON。`identity reset` 不带 `--confirm` 会在 profile mutation 之前发出 `ERR_CONFIRMATION_REQUIRED`。确认后的 reset 会清掉旧的 signing / E2E domain、pin、journal / outbox、runtime state 和 link，再创建一份 canonical、零 link 的 replacement，然后需要重新 pair Watch。Ariava 不会就地 rotate identity signing key。用 `ariava identity reset --confirm` 替换 identity，再重新 pair Watch。
- **Canonical identity failure** — daemon、signer、Relay client 和 onboarding readiness 只加载 canonical identity evidence。可识别的 non-canonical / pending evidence 只被 confirmed reset coordinator 接受；unknown 或 inconclusive evidence 一律 fail closed。Network、`401`、`5xx` 以及普通 configuration error 会保留 identity，不会触发 reset。
- **`pair` / `watches`** — 行为相同，隔离在所选 profile 内。
- **`--version`** — production 读已安装 package version（强制 semver；invalid 就 throw）；dev 读源码 `package.json`，invalid 时 fallback 到 `0.0.0-dev` 而不是 throw。

### Output and error conventions（两边相同）

- 默认输出是 human text；`--json`（global flag，只能一次）切到 machine envelope `{ ok, code, message, data }` 写 stdout，failure 写 stderr。
- Human failure 两边都以 `ariava: ` 为前缀（`cli/failure.ts`）。
- JSON status / doctor / config / identity / watches payload 从不包含 Agent Adapter secret 或 private key material。
- Exit code：`0` success，`1` 任何 failure（doctor 在 unhealthy 时额外返回 `1`）。

## 4. Intentional divergences

| Area | Production | Development | Why |
| --- | --- | --- | --- |
| Runtime preflight | 每个非 `setup` 的 command 都先 enforce supported production Node runtime；`init` 额外要求 service support | 没有 runtime gate；runtime 只由 `status` / `doctor` probe | Prod install 必须跑在 supported runtime 上；dev 从开发者机器上的源码跑 |
| Config env defaults | `allowProductionEnvironmentDefaults: true`，`saveBaseBeforeIdentity: true` | 两边都强制 `false` | Dev 不得静默继承 ambient production Relay / port override |
| Version resolution | Installed semver；invalid version 是 hard error | Source version；invalid fallback 到 `0.0.0-dev` | Dev 不该被 version metadata 挡住 |
| Service lifecycle | 完整的 `service` + `logs` + `upgrade` / `uninstall` surface | 没有 | Dev 在前台跑 Bridge；不存在 user service |
| pi management | Managed npm package（`npm:@ariava/pi-extension@<exact-cli-version>`） | Source extension（`pi --no-extensions -e extensions/pi/index.ts`） | Prod install 用 published package；source dev 用 checkout。Bridge 和 `@ariava/pi-extension` 必须是完全相同的 version；协调 upgrade 之后，已打开的 Pi session 需要 `/reload`。 |
| `setup` | Guided onboarding（§5） | `init` + foreground source Bridge + optional source pi | 见 §5 |
| Help | Full product reference + examples | Compact dev reference | Audience 不同 |
| `status pi` | Available | Rejected | Dev 没有 managed pi package 可 inspect |

## 5. `setup` differences

**Production `setup`** 是 guided onboarding 路径：npx stable-CLI 重新进入经过正向验证的、user-writable 的 npm prefix，处理 onboarding lock（stable re-entry 之后才是 `~/.config/ariava/onboarding.lock`），安装 service，安装 exact pi package（`npm:@ariava/pi-extension@<exact-cli-version>`），以及 strict read-only readiness aggregation。它和 `ariava doctor` 是分开的。

**Development `setup`**（`bun run dev:setup -- [--extension pi | --no-extensions]`）初始化 isolated dev identity，并在前台跑 source Bridge；选了 pi 时带上 source pi extension。不涉及 npm prefix、service、lock 或 readiness logic。

## 6. Convergence fixes applied

这些是两套 profile 本应行为相同、后来发生 drift 的地方；现在都已 converged，并有 test 覆盖。

| # | Area | Before | After |
| --- | --- | --- | --- |
| 1 | `status` human output（dev） | 原始 `JSON.stringify` dump | Concise aligned card，风格与 production 相同 |
| 2 | `identity reset` 不带 `--confirm`（dev） | Generic `ERR_CLI` | `ERR_CONFIRMATION_REQUIRED`，machine contract 与 production 相同 |
| 3 | `config agent-secret rotate`（dev） | 让用户 restart Ariava **service** | 让用户 restart **source Bridge** |
| 4 | `doctor` human formatter | 两套几乎重复的 formatter（`formatDoctor`、`formatDevDoctor`） | 一份 shared `formatDoctorChecks` |
| 5 | `status` envelope message | 两边都是 generic `Ariava host status.` | Profile-aware：`Ariava dev host status.` / `Ariava host status.` |
| 6 | `ariava dev status` human output | 两个 source field 的 raw JSON | Concise card（`Bridge source` / `Pi source`） |

### Intentionally not converged

- Usage string 保留 binary name：需要 usage 行的 dev command 写 `dev-profile-cli …`（例如 `dev-profile-cli identity status`），production 写 `ariava …`。这是有意的 — 源码开发者看到的唯一 binary 就是 `dev-profile-cli` — 并由 test 断言。

## 7. Verification

- `node ./scripts/build-bridge.mjs` — 构建两套 CLI。
- `bun test ./apps/bridge/test/dev-profile-cli.test.ts` — dev surface、status card、doctor、identity/host、pair。
- `bun test ./apps/bridge/test/public-cli.test.ts` — production status baseline、dev status envelope、config/service lifecycle。
- `bun test ./apps/bridge/test/profile-domain-contract.test.ts` — 两套 profile：probes、config mutation policy、redaction、agent-secret messages。
- `bun test ./apps/bridge/test/identity-cli.test.ts` — confirmation contract、canonical identity / reset safety。
- `bun test ./apps/bridge/test/unified-cli-shell.test.ts` — routing / denial matrix、shared-command staging。
