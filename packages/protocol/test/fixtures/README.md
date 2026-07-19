# E2E v1 golden vectors

`e2e-v1-vectors.json` freezes the production interoperability bytes for
X25519 + HKDF-SHA256 + ChaCha20-Poly1305. It was produced once from fixed
PKCS#8 inputs by an independent Node 22 script, then checked in. Product tests
consume the fixture; they do not regenerate expected values through the helper
under test.

The production acceptance matrix is **Swift CryptoKit ↔ Node 22 `node:crypto`**.
Bun runs protocol/state-machine tests only. Changing any byte in this fixture is
a protocol-breaking change and requires explicit review of Node and CryptoKit
results. Phase 0 checks in the Node consumer now; the matching CryptoKit consumer
and real-device evidence remain explicitly deferred to the watchOS phase.

Binary values are canonical unpadded RFC 4648 base64url. ChaChaPoly ciphertext
is `ciphertext || 16-byte tag`; nonce is a separate 12-byte field. The fixture's
transcript and wrap AAD include `linkGeneration`.
