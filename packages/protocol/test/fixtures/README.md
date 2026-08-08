# Runtime v2 golden vectors

`e2e-v2-vectors.json` freezes deterministic interoperability bytes for the
breaking event/session runtime v2 cutover. `notification-preview-v2-vector.json`
separately freezes preview v2 canonical plaintext, recipient-bound AAD, content
encryption, and key-wrap output. Active runtime fixture/package surfaces contain no
event/session/preview v1 fixture or decoder.

The runtime payload kinds are exactly `event-content-v2`, `session-content-v2`, and
`notification-preview-v2`. Event, Session, preview, and wrap AAD use reviewed v2
domains; reply content remains the unrelated `reply-content-v1` command contract.
Identity bindings, link transcripts, pair-root derivation, and the crypto suite also
remain v1 key-ceremony contracts rather than runtime compatibility decoders.

`need-human-error-validation-v2.json` freezes Node/Swift protected-error validation
parity. The package must publish both runtime v2 vectors plus this parity fixture and
must never contain an event/session/preview runtime v1 fixture.

The interoperability fixtures use fixed public test-only PKCS#8 inputs, DEKs, and nonces. Product tests
consume the checked-in expected bytes and never regenerate them through the helper
under test. Binary values are canonical unpadded RFC 4648 base64url; ChaChaPoly
ciphertext is `ciphertext || 16-byte tag`, with a separate 12-byte nonce.

The production acceptance matrix is **Swift CryptoKit ↔ Node `node:crypto`**. The
Node consumer verifies every binding and mutation in this milestone; the matching
Swift consumer belongs to the watchOS milestone. Any fixture-byte change is a
protocol-breaking change requiring explicit cross-language review.
