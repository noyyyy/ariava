# Runtime v2 golden vectors

`command-e2e-v1-vectors.json` freezes the separate breaking command contract:
encrypted `interrupt`, canonical command binding/digest, all four fixed 128-byte
terminal receipt plaintexts, and one complete Bridge-to-Watch encrypted receipt with
canonical binding/digest. It deliberately remains v1 because it introduces a new
command wire family rather than replacing runtime event/session v2.

`e2e-v2-vectors.json` freezes deterministic interoperability bytes for the
breaking event/session runtime v2 cutover. `notification-preview-v2-vector.json`
separately freezes preview v2 canonical plaintext, recipient-bound AAD, content
encryption, and key-wrap output. Active runtime fixture/package surfaces contain no
event/session/preview v1 fixture or decoder.

The runtime payload kinds are exactly `event-content-v2`, `session-content-v2`, and
`notification-preview-v2`. Command payload kinds are exactly `reply-content-v1`,
`interrupt-content-v1`, and `command-receipt-content-v1`. Event, Session, preview,
command, receipt, and wrap AAD use their reviewed domains; reply remains byte-compatible.
Identity bindings, link transcripts, pair-root derivation, and the crypto suite also
remain v1 key-ceremony contracts rather than runtime compatibility decoders.

`need-human-error-validation-v2.json` freezes Node/Swift protected-error validation
parity. The package must publish command E2E v1, both runtime v2 vectors, and this parity fixture and
must never contain an event/session/preview runtime v1 fixture.

The interoperability fixtures use fixed public test-only PKCS#8 inputs, DEKs, and nonces. Product tests
consume the checked-in expected bytes and never regenerate them through the helper
under test. Binary values are canonical unpadded RFC 4648 base64url; ChaChaPoly
ciphertext is `ciphertext || 16-byte tag`, with a separate 12-byte nonce.

The production acceptance matrix is **Swift CryptoKit ↔ Node `node:crypto`**. The
Node consumer verifies every binding and mutation in this milestone; the matching
Swift consumer belongs to the watchOS milestone. Any fixture-byte change is a
protocol-breaking change requiring explicit cross-language review.
