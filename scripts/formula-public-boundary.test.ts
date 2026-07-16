import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const formula = readFileSync("Formula/ariava.rb", "utf8");

describe("Public Core Homebrew Formula boundary", () => {
  test("fails closed until real public artifact metadata is reviewed", () => {
    expect(formula).toContain('homepage "https://github.com/noyyyy/ariava"');
    expect(formula).toContain('PUBLIC_ARTIFACT_URL = "ARIAVA_PUBLIC_ARTIFACT_URL_PENDING_REVIEW"');
    expect(formula).toContain('PUBLIC_ARTIFACT_SHA256 = "ARIAVA_PUBLIC_ARTIFACT_SHA256_PENDING_REVIEW"');
    expect(formula).toContain("PUBLIC_ARTIFACT_READY = false");
    expect(formula).toContain("disable!");
    expect(formula).toContain('odie "Public Core artifact metadata has not been reviewed" unless PUBLIC_ARTIFACT_READY');
    expect(formula).not.toMatch(/sha256\s+"[0-9a-f]{64}"/);
    expect(formula).not.toContain("ariava-private");
    expect(formula).not.toContain("example.invalid");
  });

  test("installs only compiled Public Core artifacts and the Node CLI", () => {
    for (const path of [
      "apps/bridge/dist",
      "packages/protocol/dist",
      "packages/shared-utils/dist",
      "extensions/pi/bundle",
      "apps/bridge/dist/public-cli.js",
    ]) expect(formula).toContain(path);
    expect(formula).toContain('depends_on "node"');
    expect(formula).toContain('chmod 0755, libexec/"apps/bridge/dist/public-cli.js"');
    for (const forbidden of ["apps/bridge/src", "docs", "notify.js", "herdr-plugin.toml", "bunfig.toml", "source \"${CONFIG_FILE}\""]) {
      expect(formula).not.toContain(forbidden);
    }
  });

  test("keeps service execution user-scoped and free of privilege escalation", () => {
    expect(formula).toContain('run [opt_bin/"ariava", "internal", "bridge-daemon", "--config"');
    expect(formula).toContain('shell_output("#{bin}/ariava help")');
    for (const forbidden of ["sudo", "root_url", "/Library/LaunchDaemons", "systemctl", "loginctl", "linger"] ) {
      expect(formula).not.toContain(forbidden);
    }
  });
});
