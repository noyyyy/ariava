import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

const repoRoot = process.cwd();
const scriptPath = join(repoRoot, "scripts", "test-linux-systemd.sh");
const roots: string[] = [];

function writeExecutable(path: string, source: string) {
  writeFileSync(path, source);
  chmodSync(path, 0o755);
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ariava-linux-systemd-test-"));
  const binDir = join(root, "bin");
  const commandLog = join(root, "commands.log");
  const outputDir = join(root, "output");
  mkdirSync(binDir, { recursive: true });
  roots.push(root);

  writeExecutable(join(binDir, "orbctl"), `#!/usr/bin/env bash
set -euo pipefail
{
  printf 'orbctl'
  printf ' %q' "$@"
  printf '\n'
} >> "$FAKE_COMMAND_LOG"
all="$*"
if [[ -n "\${FAKE_ORBCTL_FAIL_MATCH:-}" && "$all" == *"$FAKE_ORBCTL_FAIL_MATCH"* ]]; then
  echo "injected orbctl failure: $FAKE_ORBCTL_FAIL_MATCH" >&2
  exit 42
fi
if [[ "\${FAKE_ORBCTL_FAIL_CREATE_ONCE:-0}" == "1" && "\${1:-}" == "create" ]]; then
  marker="$FAKE_COMMAND_LOG.create-failed"
  if [[ ! -e "$marker" ]]; then
    : > "$marker"
    echo 'injected transient create failure' >&2
    exit 43
  fi
fi
if [[ "\${1:-}" == "run" && "$all" == *"cat >"* ]]; then
  cat >/dev/null
fi
if [[ "$all" == *"systemctl --user show-environment"* ]]; then
  echo 'HOME=/home/ariava-test'
fi
`);

  writeExecutable(join(binDir, "bun"), `#!/usr/bin/env bash
set -euo pipefail
{
  printf 'bun'
  printf ' %q' "$@"
  printf '\n'
} >> "$FAKE_COMMAND_LOG"
`);

  writeExecutable(join(binDir, "npm"), `#!/usr/bin/env bash
set -euo pipefail
{
  printf 'npm'
  printf ' %q' "$@"
  printf '\n'
} >> "$FAKE_COMMAND_LOG"
if [[ "\${1:-}" == "pack" ]]; then
  destination=''
  while (($#)); do
    if [[ "$1" == '--pack-destination' ]]; then destination="$2"; shift 2; else shift; fi
  done
  mkdir -p "$destination"
  printf 'fake tarball' > "$destination/ariava-test.tgz"
  echo 'ariava-test.tgz'
fi
`);

  return {
    root,
    commandLog,
    outputDir,
    env: {
      ...process.env,
      PATH: `${binDir}${delimiter}${process.env.PATH ?? "/usr/bin:/bin"}`,
      FAKE_COMMAND_LOG: commandLog,
    },
  };
}

function run(args: string[], environment: Record<string, string | undefined> = {}) {
  return Bun.spawnSync(["bash", scriptPath, ...args], {
    cwd: repoRoot,
    env: { ...process.env, ...environment },
    stdout: "pipe",
    stderr: "pipe",
  });
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("optional Linux systemd integration-test orchestrator", () => {
  test("shows help without requiring OrbStack", () => {
    const result = run(["--help"], { PATH: "/usr/bin:/bin" });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString()).toContain("optional Linux systemd integration test");
    expect(result.stdout.toString()).toContain("--tarball");
    expect(result.stdout.toString()).toContain("--keep-vm");
    expect(result.stdout.toString()).toContain("--output-dir");
    expect(result.stdout.toString()).toContain("--real-self-upgrade");
  });

  test("rejects unknown options and missing tarballs before creating a VM", () => {
    const unknown = run(["--wat"]);
    expect(unknown.exitCode).toBe(2);
    expect(unknown.stderr.toString()).toContain("Unknown option: --wat");

    const missing = run(["--tarball", "/definitely/missing/ariava.tgz"]);
    expect(missing.exitCode).toBe(2);
    expect(missing.stderr.toString()).toContain("Tarball not found");
  });

  test("uses a caller tarball, runs every VM phase, writes a summary, and cleans up", () => {
    const current = fixture();
    const tarball = join(current.root, "provided ariava.tgz");
    writeFileSync(tarball, "provided artifact");

    const result = run(["--tarball", tarball, "--output-dir", current.outputDir], current.env);
    expect(result.exitCode, result.stderr.toString()).toBe(0);

    const calls = readFileSync(current.commandLog, "utf8");
    expect(calls).toContain("orbctl create --isolated");
    expect(calls).toContain("ubuntu:24.04");
    expect(calls).toContain("orbctl run");
    expect(calls).toContain("-u root");
    expect(calls).toContain("linux-systemd-test.sh");
    expect(calls).toContain("orbctl restart");
    expect(calls).toContain("linux-systemd-after-restart-test.sh");
    expect(calls).toContain("linux-systemd-unavailable-test.sh");
    expect(calls).toContain("linux-systemd-real-upgrade-test.sh");
    expect(calls).toContain(String.raw`systemd\ --version`);
    expect(calls).not.toMatch(/orbctl run -m [^\n]+ \/home\/ariava-test\/linux-systemd-real-upgrade-test\.sh\n/);
    expect(calls).toContain("orbctl delete -f");
    expect(calls).not.toContain("bun run build:bridge");
    expect(calls).not.toContain("npm pack");

    const summary = readFileSync(join(current.outputDir, "summary.txt"), "utf8");
    expect(summary).toContain("result=PASS");
    expect(summary).toContain("scope=optional-linux-systemd-integration-test");
    expect(summary).toContain("wsl_tested=false");
    expect(summary).toContain("tarball_sha256=");
    expect(summary).toContain("real_self_upgrade=0");
    expect(summary).toContain("reconciliation_phase=reconciliation-only");
  });

  test("builds a tarball from the checkout when one is not supplied", () => {
    const current = fixture();
    const result = run(["--output-dir", current.outputDir], current.env);
    expect(result.exitCode, result.stderr.toString()).toBe(0);

    const calls = readFileSync(current.commandLog, "utf8");
    expect(calls).toContain("bun run build:bridge");
    expect(calls).toContain("npm pack --pack-destination");
    expect(calls).toContain("orbctl create --isolated");
  });

  test("retries one transient VM creation failure and cleans the partial name", () => {
    const current = fixture();
    const tarball = join(current.root, "ariava.tgz");
    writeFileSync(tarball, "artifact");

    const result = run(["--tarball", tarball, "--output-dir", current.outputDir], {
      ...current.env,
      FAKE_ORBCTL_FAIL_CREATE_ONCE: "1",
    });
    expect(result.exitCode, result.stderr.toString()).toBe(0);

    const calls = readFileSync(current.commandLog, "utf8");
    expect(calls.match(/orbctl create /g)?.length).toBe(2);
    expect(calls.match(/orbctl delete -f/g)?.length).toBeGreaterThanOrEqual(2);
  });

  test("cleans the VM after a failing guest phase", () => {
    const current = fixture();
    const tarball = join(current.root, "ariava.tgz");
    writeFileSync(tarball, "artifact");

    const result = run(["--tarball", tarball, "--output-dir", current.outputDir], {
      ...current.env,
      FAKE_ORBCTL_FAIL_MATCH: "/home/ariava-test/linux-systemd-test.sh",
    });
    expect(result.exitCode).not.toBe(0);
    expect(readFileSync(current.commandLog, "utf8")).toContain("orbctl delete -f");
  });

  test("keeps the VM only when explicitly requested", () => {
    const current = fixture();
    const tarball = join(current.root, "ariava.tgz");
    writeFileSync(tarball, "artifact");

    const result = run(["--tarball", tarball, "--output-dir", current.outputDir, "--keep-vm"], current.env);
    expect(result.exitCode, result.stderr.toString()).toBe(0);
    expect(readFileSync(current.commandLog, "utf8")).not.toContain("orbctl delete");
    expect(result.stdout.toString()).toContain("VM preserved:");
  });

  test("is not part of the default test or verify commands", () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
    expect(pkg.scripts.test).not.toContain("test-linux-systemd.sh");
    expect(pkg.scripts.verify).not.toContain("test-linux-systemd.sh");
  });
});

describe("Linux systemd guest phases", () => {
  test("capable phase exercises the ordinary-user lifecycle and unit safety", () => {
    const source = readFileSync(join(repoRoot, "scripts", "fixtures", "linux-systemd-test.sh"), "utf8");
    for (const token of [
      '[[ "$(id -u)" != "0" ]]',
      "npm install -g",
      "ariava init --json",
      "ariava service install --json",
      "systemctl --user is-enabled ariava.service",
      "systemctl --user is-active ariava.service",
      "ariava service status --json",
      "ariava service stop --json",
      "ariava service start --json",
      "ariava service restart --json",
      "ariava logs --json",
      "WantedBy=default.target",
      "User=|Group=",
      "sudo|loginctl|nohup|linger",
    ]) expect(source).toContain(token);
  });

  test("post-restart phase verifies autostart, upgrade reconciliation, and uninstall", () => {
    const source = readFileSync(join(repoRoot, "scripts", "fixtures", "linux-systemd-after-restart-test.sh"), "utf8");
    for (const token of [
      "systemctl --user is-enabled ariava.service",
      "systemctl --user is-active ariava.service",
      "ariava upgrade --json",
      "runtimePathMatchesCurrent",
      "ariava service uninstall --json",
      "installed !== false",
      "metadata.service",
      "hostId/keyId changed across restart or reconciliation-only upgrade",
    ]) expect(source).toContain(token);
    expect(source).toContain('env -u ARIAVA_UPGRADE_SELF_DONE ariava upgrade --json');
    expect(source).not.toContain('export ARIAVA_UPGRADE_SELF_DONE=1');
    expect(source).not.toContain("ARIAVA_OWNER_USER_ID");
    expect(source).not.toContain("ARIAVA_HOST_ID");
  });

  test("unavailable-bus phase requires generic Linux errors and no partial state", () => {
    const source = readFileSync(join(repoRoot, "scripts", "fixtures", "linux-systemd-unavailable-test.sh"), "utf8");
    for (const token of [
      "DBUS_SESSION_BUS_ADDRESS=unix:path:",
      "ariava status --json",
      "ariava doctor --json",
      "ERR_DOCTOR",
      "ERR_SYSTEMD_USER_UNAVAILABLE",
      "wsl\\.exe|systemd=true|\\[boot\\]",
      "config.json",
      "ariava.service",
      "install.json",
    ]) expect(source).toContain(token);
  });
});


describe("opt-in real npm upgrade phase", () => {
  test("labels the real npm upgrade evidence separately", () => {
    const upgrade = readFileSync(join(repoRoot, "scripts", "fixtures", "linux-systemd-real-upgrade-test.sh"), "utf8");
    expect(upgrade).toContain("REAL_NPM_SELF_UPGRADE_PHASE=PASS");
    expect(upgrade).toContain("env -u ARIAVA_UPGRADE_SELF_DONE ARIAVA_UPGRADE_PACKAGE_MANAGER=npm ariava upgrade --json");
    expect(upgrade).not.toContain("export ARIAVA_UPGRADE_SELF_DONE=1");
  });
});
