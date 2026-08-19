<p align="center">
  <img src="https://raw.githubusercontent.com/noyyyy/ariava/main/ariava.png" alt="Ariava" width="160" height="160">
</p>

<h1 align="center">Ariava</h1>

<p align="center"><strong>Live Your Life. Your Agents Stay Close.</strong></p>

<p align="center">
  <a href="./README.md">English</a> | 简体中文
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/ariava"><img src="https://img.shields.io/npm/v/ariava?style=flat-square&label=npm" alt="npm version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="Apache 2.0 license"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%2FWSL-lightgrey?style=flat-square" alt="macOS and Linux/WSL">
  <img src="https://img.shields.io/badge/Pi-supported-7c3aed?style=flat-square" alt="Pi supported">
</p>

> [!WARNING]
> Ariava 仍处于早期阶段，breaking change 是预期的。

## Ariava 是什么？

Agent 的 loop 越来越长。它能在你的电脑上连续跑上几小时——重构、测试、调研、写文档——看着 Agent 的进度当监工，其实挺浪费时间的，人应该去做其他的事情。等它做完，或卡在只有你能拍板的问题上时，自然会来找你。

Ariava 是 **Apple Watch 优先的 Agent 伴侣**。手表是一块永远跟着你的屏幕——无论你在哪里，通知都会到手腕上，处理只需要几秒钟：

- **需要你时才打扰你。** Agent 完成任务、或需要你的判断时，手腕轻振提醒。
- **进展随时可见。** 项目、状态、最新动态——抬腕即知，不用打开电脑。
- **抬手即行动。** 发一条简短的语音 prompt 引导 Agent 就够了。
- **隐私友好。** 全程端到端加密，Relay 只转发密文。

Ariava 不是一个终端，也不是一个 Agent，而是让你不必守在它们旁边。

*离开电脑桌吧——需要你的时候，Agent 会轻敲你的手腕。*

## Getting Started

Requirements：

- **Node.js 22+ 和 npm**
- **macOS**，或带 systemd user manager 的 **Linux/WSL**
- **支持的 agent harness** —— Pi（支持列表在不断增加）

```bash
npx --yes ariava@latest setup
```

从 [TestFlight](https://testflight.apple.com/join/EqhcRBp6) 安装 Apple Watch app，然后 pair：

```bash
ariava pair <PAIRING_CODE>
```


## Usage

```bash
ariava status
ariava pair <PAIRING_CODE>
ariava watches list
ariava logs
ariava upgrade
```

## Roadmap

- [x] Human Attention and Intervention
- [x] APN Notification
- [x] End-to-end encryption
- [ ] **In progress:** Session Management
- [ ] Project management
- [ ] Invoke new session
- [ ] More Harness Integration
- [ ] Summary and memory

## Architecture

```text
Apple Watch  ↔  Relay  ↔  Local Bridge  ┬↔  Pi
                                        ├↔  DeepSeek
                                        └↔  Codex
```

Watch 和本地的 Bridge 通过 Relay 来进行密钥交换和配对，Relay 只转发 ciphertext，Bridge 通过多个 Harness 的 plugin 获取 Live Session States，并在本地 json 维护状态。

## Alerts and sessions

两种 alert：

- **Done** — 需要人类 review 结果。
- **Need human** — Agent 需要 human 指导下一步该怎么做。

**Session** 是一段对话当时状态的投影（name、project、status、latest activity），不是完整 transcript。Bridge 加密后发到 Watch。Watch 只回 **reply** 和 **interrupt**。

## Identity

Host 和 Watch **各自都有两种** identity，不是两边各一种：

- **Signing** — Ed25519。用来证明你是谁。Device ID 由这把 public key 派生。
- **Encryption** — X25519。和 ChaCha20-Poly1305 一起做 end-to-end encryption。Relay 只看到 ciphertext。

Host 的 key 由 `ariava init` 创建。Watch 的 key 在 Apple Watch 上创建。

Pairing 要核对两次不同的 code：

1. **Pairing code** — Watch 显示一个短时 code，在 Host 上跑 `ariava pair <CODE>`。这是告诉 Relay 要把哪台 Watch 和哪台 Host 连起来。
2. **Safety Code** — 两边各自算出同一个 code，确认一致。没确认完就不算 pair 成功。这是核对 encryption key 在路上有没有被换成别人的：Relay 转发的是 ciphertext，但仍可能替换 public key。Code 不一致就取消，重新 pair。

```bash
ariava identity status
ariava identity reset --confirm
```

Watch identity 在 Watch app 里 reset。任一侧 reset 都会换掉该设备上的两种 identity，并清掉旧 link，需要重新 pair。

## Build from Source

```bash
git clone https://github.com/noyyyy/ariava.git
cd ariava
bun install --frozen-lockfile
bun run verify
```

隔离的源码开发（不碰已安装的 Bridge）见 [docs/prod-vs-dev-cli.zh-CN.md](docs/prod-vs-dev-cli.zh-CN.md)。

## Contributing

提交 pull request 前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

## Security

按 [SECURITY.md](SECURITY.md) 私下报告可疑漏洞。不要在公开 issue 里贴 identity、secret、pairing 材料或完整 log。

## License

[Apache License, Version 2.0](LICENSE)。
