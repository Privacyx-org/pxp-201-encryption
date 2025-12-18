# PXP-201 v0.1 — Test Vectors

This folder contains reproducible test vectors for PXP-201 v0.1.

## What is covered (v0.1)
- Raw payload encryption: AES-256-GCM
- Envelope hashing: SHA3-256(ciphertext) and optional SHA3-256(aad)
- WrappedKey wk1: secp256k1 ECDH + HKDF-SHA256 + AES-256-GCM

## Files
- `wk1.json` : deterministic test vectors for wk1 wrap/unwrap
- `raw.json` : deterministic test vectors for encryptTextRaw (fixed DEK/nonces)
- `runner.mjs` : validates vectors against the SDK implementation
