import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

const repoRoot = join(import.meta.dir, '..');
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
  printf 'orbctl\\0'
  printf '%s\\0' "$@"
  printf '\\0'
} >> "$FAKE_ORBCTL_LOG"
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
    orbctlLog: join(root, "orbctl.log"),
    outputDir,
    env: {
      ...process.env,
      PATH: `${binDir}${delimiter}${process.env.PATH ?? "/usr/bin:/bin"}`,
      FAKE_COMMAND_LOG: commandLog,
      FAKE_ORBCTL_LOG: join(root, "orbctl.log"),
    },
  };
}

function readCommandRecords(path: string): string[][] {
  const fields = readFileSync(path).toString("utf8").split("\0");
  const records: string[][] = [];
  let record: string[] = [];
  for (const field of fields) {
    if (field === "") {
      if (record.length > 0) records.push(record);
      record = [];
    } else {
      record.push(field);
    }
  }
  return records;
}

function assertOrbctlRootBoundary(calls: string[][]) {
  const runCalls = calls.filter(([command, operation]) => command === "orbctl" && operation === "run");
  const prerequisiteCalls = runCalls.filter((call) =>
    call.some((argument) => argument.includes("apt-get update >/tmp/ariava-apt-update.log")),
  );
  expect(prerequisiteCalls).toHaveLength(1);

  const prerequisite = prerequisiteCalls[0];
  expect(prerequisite.slice(0, 8)).toEqual([
    "orbctl",
    "run",
    "-m",
    prerequisite[3],
    "-u",
    "root",
    "sh",
    "-lc",
  ]);
  expect(prerequisite.filter((argument) => argument === "-u")).toHaveLength(1);
  expect(prerequisite.filter((argument) => argument === "root")).toHaveLength(1);

  const rootRunCalls = runCalls.filter((call) => call.includes("-u") || call.includes("root"));
  expect(rootRunCalls).toEqual([prerequisite]);

}

function addRootToRunCall(calls: string[][], predicate: (call: string[]) => boolean) {
  let mutated = false;
  const result = calls.map((call) => {
    if (mutated || call[0] !== "orbctl" || call[1] !== "run" || !predicate(call)) return call;
    mutated = true;
    return [...call.slice(0, 4), "-u", "root", ...call.slice(4)];
  });
  expect(mutated).toBe(true);
  return result;
}

function run(args: string[], environment: Record<string, string | undefined> = {}) {
  return Bun.spawnSync(["bash", scriptPath, ...args], {
    cwd: repoRoot,
    env: { ...process.env, ...environment },
    stdout: "pipe",
    stderr: "pipe",
  });
}

function guestFixture() {
  const root = mkdtempSync(join(tmpdir(), "ariava-systemd-guest-"));
  const home = join(root, "home");
  const binDir = join(home, ".npm-global", "bin");
  const commandLog = join(root, "guest-commands.log");
  const testTmp = join(root, "tmp");
  mkdirSync(binDir, { recursive: true });
  mkdirSync(testTmp, { recursive: true });
  roots.push(root);
  const logPrefix = `printf '%s\\n' "$0 $*" >> "$FAKE_COMMAND_LOG"`;
  writeExecutable(join(binDir, "npm"), `#!/usr/bin/env bash\nset -euo pipefail\n${logPrefix}\nif [[ "\${1:-}" == list ]]; then echo 'ariava@0.1.0'; fi\n`);
  writeExecutable(join(binDir, "node"), `#!/usr/bin/env bash\nexec "${process.execPath}" "$@"\n`);
  writeExecutable(join(binDir, "systemctl"), `#!/usr/bin/env bash\nset -euo pipefail\n${logPrefix}\ncase "$*" in\n  *show-environment*) echo "HOME=$HOME" ;;\n  *is-enabled*) echo enabled ;;\n  *is-active*) cat "$HOME/.fake-active" 2>/dev/null || echo active ;;\n  *disable*) echo inactive > "$HOME/.fake-active" ;;\nesac\n`);
  writeExecutable(join(binDir, "systemd-analyze"), `#!/usr/bin/env bash\nset -euo pipefail\n${logPrefix}\n`);
  writeExecutable(join(binDir, "ariava"), `#!/usr/bin/env bash\nset -euo pipefail\n${logPrefix}\nunit="$HOME/.config/systemd/user/ariava.service"\nconfig="$HOME/.config/ariava/config.json"\nif [[ "\${1:-}" == --version ]]; then if [[ -e "$HOME/.fake-version-read" ]]; then echo 0.2.0; else touch "$HOME/.fake-version-read"; echo 0.1.0; fi; exit 0; fi\nif [[ -n "\${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then\n  if [[ "\${1:-}" == status ]]; then printf '{"ok":true,"data":{"service":{"supportReason":"systemd-user-manager-unavailable"}}}'; exit 0; fi\n  code=ERR_SYSTEMD_USER_UNAVAILABLE; [[ "\${1:-}" == doctor ]] && code=ERR_DOCTOR\n  printf '{"code":"%s"}' "$code"; exit 1\nfi\ncase "$*" in\n  'status --json') printf '{"ok":true,"data":{}}' ;;\n  'doctor --json') printf '{"ok":true,"data":{}}' ;;\n  'init --json') mkdir -p "$(dirname "$config")"; printf '{"identity":{"hostId":"host_test","keyId":"key_test"}}' > "$config"; printf '{"ok":true}' ;;\n  'service install --json') mkdir -p "$(dirname "$unit")"; printf '[Service]\\nExecStart=/fake/ariava\\n[Install]\\nWantedBy=default.target\\n' > "$unit"; echo active > "$HOME/.fake-active"; printf '{"ok":true}' ;;\n  'service status --json') [[ -e "$unit" ]] && installed=true || installed=false; printf '{"ok":true,"data":{"backend":"systemd-user","installed":%s,"enabled":%s,"loaded":%s,"processRunning":%s,"runtimePathMatchesCurrent":true,"ariavaBinPathMatchesCurrent":true}}' "$installed" "$installed" "$installed" "$installed" ;;\n  'service stop --json') echo inactive > "$HOME/.fake-active"; printf '{"ok":true}' ;;\n  'service start --json'|'service restart --json') echo active > "$HOME/.fake-active"; printf '{"ok":true}' ;;\n  'logs --json') printf '{"ok":true,"data":{"backend":"systemd-user"}}' ;;\n  *'upgrade --json'*) touch "$HOME/.fake-upgraded"; echo active > "$HOME/.fake-active"; printf '{"ok":true}' ;;\n  'service uninstall --json') rm -f "$unit" "$HOME/.config/ariava/install.json"; printf '{"ok":true}' ;;\n  *) printf '{"ok":true}' ;;\nesac\n`);
  return { root, home, commandLog, testTmp, env: { ...process.env, HOME: home, FAKE_COMMAND_LOG: commandLog, ARIAVA_SYSTEMD_TEST_TMPDIR: testTmp } };
}

function runGuest(name: string, current: ReturnType<typeof guestFixture>) {
  return Bun.spawnSync(["bash", join(repoRoot, "scripts", "fixtures", name)], {
    cwd: repoRoot, env: current.env, stdout: "pipe", stderr: "pipe",
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

    const result = run(["--tarball", tarball, "--output-dir", current.outputDir, "--real-self-upgrade"], current.env);
    expect(result.exitCode, result.stderr.toString()).toBe(0);

    const calls = readFileSync(current.commandLog, "utf8");
    const orbctlCalls = readCommandRecords(current.orbctlLog);
    expect(orbctlCalls).toContainEqual(expect.arrayContaining(["orbctl", "create", "--isolated", "ubuntu:24.04"]));
    expect(orbctlCalls.some((call) => call[1] === "restart")).toBe(true);
    expect(orbctlCalls.some((call) => call[1] === "delete" && call[2] === "-f")).toBe(true);
    assertOrbctlRootBoundary(orbctlCalls);
    const forbiddenRootMutations: Array<[string, (call: string[]) => boolean]> = [
      ["transfer", (call) => call.some((argument) => argument.includes("cat >"))],
      ["user-manager polling", (call) => call.includes("systemctl") && call.includes("show-environment")],
      ["version collection", (call) => call.some((argument) => argument.includes('printf "os="'))],
      ["guest phase", (call) => call.some((argument) => argument.endsWith("/linux-systemd-test.sh"))],
    ];
    for (const [label, predicate] of forbiddenRootMutations) {
      expect(
        () => assertOrbctlRootBoundary(addRootToRunCall(orbctlCalls, predicate)),
        `${label} must run without root`,
      ).toThrow();
    }
    expect(calls).not.toContain("bun run ./scripts/build-bridge.mjs");
    expect(calls).not.toContain("npm pack");

    const summary = readFileSync(join(current.outputDir, "summary.txt"), "utf8");
    expect(summary).toContain("result=PASS");
    expect(summary).toContain("scope=optional-linux-systemd-integration-test");
    expect(summary).toContain("wsl_tested=false");
    expect(summary).toContain("tarball_sha256=");
    expect(summary).toContain("real_self_upgrade=1");
    expect(summary).toContain("reconciliation_phase=reconciliation-only");
  });

  test("builds a tarball from the checkout when one is not supplied", () => {
    const current = fixture();
    const result = run(["--output-dir", current.outputDir], current.env);
    expect(result.exitCode, result.stderr.toString()).toBe(0);

    const calls = readFileSync(current.commandLog, "utf8");
    const orbctlCalls = readCommandRecords(current.orbctlLog);
    expect(calls).toContain("bun run ./scripts/build-bridge.mjs");
    expect(calls).toContain("npm pack --pack-destination");
    expect(orbctlCalls.some((call) => call[1] === "create" && call.includes("--isolated"))).toBe(true);
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

    const orbctlCalls = readCommandRecords(current.orbctlLog);
    expect(orbctlCalls.filter((call) => call[1] === "create")).toHaveLength(2);
    expect(orbctlCalls.filter((call) => call[1] === "delete" && call[2] === "-f").length).toBeGreaterThanOrEqual(2);
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
    expect(readCommandRecords(current.orbctlLog).some((call) => call[1] === "delete" && call[2] === "-f")).toBe(true);
  });

  test("keeps the VM only when explicitly requested", () => {
    const current = fixture();
    const tarball = join(current.root, "ariava.tgz");
    writeFileSync(tarball, "artifact");

    const result = run(["--tarball", tarball, "--output-dir", current.outputDir, "--keep-vm"], current.env);
    expect(result.exitCode, result.stderr.toString()).toBe(0);
    expect(readCommandRecords(current.orbctlLog).some((call) => call[1] === "delete")).toBe(false);
    expect(result.stdout.toString()).toContain("VM preserved:");
  });

  test("is not part of the default test or verify commands", () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
    expect(pkg.scripts.test).not.toContain("test-linux-systemd.sh");
    expect(pkg.scripts.verify).not.toContain("test-linux-systemd.sh");
  });
});

describe("Linux systemd guest phases", () => {
  test("capable phase exercises the ordinary-user guest-script lifecycle", () => {
    const current = guestFixture();
    writeFileSync(join(current.home, "ariava-under-test.tgz"), "artifact");
    const result = runGuest("linux-systemd-test.sh", current);
    expect(result.exitCode, result.stderr.toString()).toBe(0);
    expect(result.stdout.toString()).toContain("CAPABLE_SYSTEMD_PHASE=PASS");
    const calls = readFileSync(current.commandLog, "utf8");
    for (const command of ["npm install -g", "ariava init --json", "ariava service install --json", "systemctl --user is-enabled", "ariava service stop --json", "ariava service restart --json", "ariava logs --json"]) expect(calls).toContain(command);
    expect(readFileSync(join(current.home, ".config/systemd/user/ariava.service"), "utf8")).toContain("WantedBy=default.target");
  });

  test("post-restart phase verifies autostart, upgrade reconciliation, and uninstall", () => {
    const current = guestFixture();
    writeFileSync(join(current.home, "ariava-under-test.tgz"), "artifact");
    mkdirSync(join(current.home, ".config", "ariava"), { recursive: true });
    mkdirSync(join(current.home, ".config", "systemd", "user"), { recursive: true });
    writeFileSync(join(current.home, ".config", "ariava", "config.json"), '{"identity":{"hostId":"host_test","keyId":"key_test"}}');
    writeFileSync(join(current.home, ".config", "systemd", "user", "ariava.service"), "[Install]\\nWantedBy=default.target\\n");
    writeFileSync(join(current.testTmp, "ariava-identity-before.json"), '{"hostId":"host_test","keyId":"key_test"}');
    const result = runGuest("linux-systemd-after-restart-test.sh", current);
    expect(result.exitCode, result.stderr.toString()).toBe(0);
    expect(result.stdout.toString()).toContain("AFTER_RESTART_SYSTEMD_PHASE=PASS");
    const calls = readFileSync(current.commandLog, "utf8");
    expect(calls).toContain("ariava upgrade --json");
    expect(calls).toContain("ariava service uninstall --json");
    expect(readFileSync(join(current.testTmp, "final-status.json"), "utf8")).toContain('"installed":false');
  });

  test("unavailable-bus phase requires generic Linux errors and no partial state", () => {
    const current = guestFixture();
    const result = runGuest("linux-systemd-unavailable-test.sh", current);
    expect(result.exitCode, result.stderr.toString()).toBe(0);
    expect(result.stdout.toString()).toContain("UNAVAILABLE_USER_BUS_PHASE=PASS");
    expect(readFileSync(current.commandLog, "utf8")).toContain("ariava service install --json");
    expect(readFileSync(join(current.testTmp, "unavailable-install.json"), "utf8")).toContain("ERR_SYSTEMD_USER_UNAVAILABLE");
    expect(readFileSync(join(current.testTmp, "unavailable-install.json"), "utf8")).not.toMatch(/wsl\.exe|systemd=true|\[boot\]/i);
    expect(() => readFileSync(join(current.home, ".config", "ariava", "config.json"), "utf8")).toThrow();
  });

});
