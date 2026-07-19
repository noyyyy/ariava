class Ariava < Formula
  desc "Apple Watch-first local bridge for coding-agent collaboration"
  homepage "https://github.com/noyyyy/ariava"

  # Publication is intentionally fail-closed until a reviewed Public Core
  # release artifact exists. The candidate review must replace both placeholders
  # with a versioned public npm tarball URL and its real SHA-256 together.
  PUBLIC_ARTIFACT_URL = "ARIAVA_PUBLIC_ARTIFACT_URL_PENDING_REVIEW".freeze
  PUBLIC_ARTIFACT_SHA256 = "ARIAVA_PUBLIC_ARTIFACT_SHA256_PENDING_REVIEW".freeze
  PUBLIC_ARTIFACT_READY = false

  url PUBLIC_ARTIFACT_URL
  version "0.1.4"
  sha256 PUBLIC_ARTIFACT_SHA256
  disable! date: "2026-07-16", because: "awaiting reviewed Public Core release artifact metadata"

  depends_on "node"

  def install
    odie "Public Core artifact metadata has not been reviewed" unless PUBLIC_ARTIFACT_READY

    libexec.install "package.json"
    (libexec/"apps/bridge").install "apps/bridge/dist"
    (libexec/"packages/protocol").install "packages/protocol/dist"
    (libexec/"packages/shared-utils").install "packages/shared-utils/dist"
    (libexec/"extensions/pi").install "extensions/pi/bundle"
    chmod 0755, libexec/"apps/bridge/dist/public-cli.js"
    bin.install_symlink libexec/"apps/bridge/dist/public-cli.js" => "ariava"
  end

  service do
    run [Formula["node"].opt_bin/"node", opt_libexec/"apps/bridge/dist/public-cli.js", "internal", "bridge-daemon", "--config", File.expand_path("~/.config/ariava/config.json")]
    keep_alive true
    log_path var/"log/ariava.log"
    error_log_path var/"log/ariava.log"
  end

  test do
    node_major = shell_output("#{Formula[\"node\"].opt_bin}/node --version").delete_prefix("v").split(".").first.to_i
    assert_operator node_major, :>=, 22
    assert_match "Ariava CLI", shell_output("#{bin}/ariava help")
    assert_match "true", shell_output("#{Formula[\"node\"].opt_bin}/node -e 'import(\"#{libexec}/apps/bridge/dist/e2e/node-crypto-self-test.js\").then(m => console.log(m.runNodeCryptoSelfTest()))'")
  end
end
