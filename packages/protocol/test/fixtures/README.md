# Runtime interoperability golden vectors

`command-e2e-v1-vectors.json` freezes the separate command contract: encrypted
`interrupt`, canonical command binding/digest, all four fixed 128-byte terminal
receipt plaintexts, and one complete Bridge-to-Watch encrypted receipt with
canonical binding/digest. It remains v1 because commands and receipts are a
separate wire family, not because the Event/Session runtime remains v2.

`e2e-v3-vectors.json` freezes deterministic interoperability bytes for the
current Event/Session runtime v3 cutover. It covers exact protected plaintext,
`ariava-event-content-aad-v3` / `event-content-v3`,
`ariava-session-content-aad-v3` / `session-content-v3`, deterministic content
encryption, and recipient wraps.

`e2e-v2-vectors.json` remains byte-identical historical rejection/upgrade
evidence for the prior Event/Session runtime. It is not a current decoder
fixture. `notification-preview-v2-vector.json` separately freezes the unchanged
preview v2 canonical plaintext, recipient-bound AAD, content encryption, and
key-wrap output.

The current Event/Session payload kinds are exactly `event-content-v3` and
`session-content-v3`. Notification preview remains `notification-preview-v2`.
Command payload kinds are exactly `reply-content-v1`, `interrupt-content-v1`,
and `command-receipt-content-v1`. Event, Session, preview, command, receipt,
and wrap AAD use their reviewed domains; reply remains byte-compatible.
Identity bindings, link transcripts, pair-root derivation, and the crypto suite
remain v1 key-ceremony contracts rather than runtime compatibility decoders.

The package must publish command E2E v1, historical runtime v2, current runtime
v3, preview v2, and need-human parity fixtures. It must never contain an
Event/Session/preview runtime v1 fixture.

`need-human-error-validation-v2.json` freezes Node/Swift protected-error
validation parity; that validation contract is unchanged by the Event/Session
v3 cutover.

The interoperability fixtures use fixed public test-only PKCS#8 inputs, DEKs,
and nonces. Product tests consume the checked-in expected bytes and never
regenerate them through the helper under test. Binary values are canonical
unpadded RFC 4648 base64url; ChaChaPoly ciphertext is
`ciphertext || 16-byte tag`, with a separate 12-byte nonce.

The production acceptance matrix is **Swift CryptoKit ↔ Node `node:crypto`**.
The Node consumer verifies every binding and mutation in this milestone; the
matching Swift consumer belongs to the watchOS milestone. Any fixture-byte
change is a protocol-breaking change requiring explicit cross-language review.
