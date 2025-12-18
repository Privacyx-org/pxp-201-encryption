# PXP-201 — Privacyx Encryption Standard

PXP-201 defines a general-purpose encryption envelope format for Web2 + Web3:
- encrypt once (off-chain or on-chain)
- control who can decrypt (recipients or policies)
- interop via SDK profiles (AES-GCM / XChaCha20, ECIES/HPKE/etc.)

## Packages
- /spec — formal specification
- /sdk — reference JS/TS SDK
- /contracts — minimal on-chain registry

## Quickstart
```bash
npm install
npm run e2e

