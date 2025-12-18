# @privacyx/pxp201

Reference SDK for **PXP-201** (PrivacyX Encryption Standard) — draft v0.1.

## Install

\`\`\`bash
npm i @privacyx/pxp201
npm i @noble/secp256k1
\`\`\`

## Usage (recipients mode, wk1)

\`\`\`js
import * as secp from "@noble/secp256k1";
import {
  encryptTextRaw,
  decryptTextFromEnvelope,
  validateEnvelope,
  wrapDEK_secp256k1,
  unwrapDEK_secp256k1,
} from "@privacyx/pxp201";

const plaintext = "hello from PXP-201";
const aadText = "app:privacyx-demo|v0.1";

const recipientPriv = secp.utils.randomSecretKey();
const recipientPub = secp.getPublicKey(recipientPriv, true);
const recipientPrivHex = "0x" + Buffer.from(recipientPriv).toString("hex");
const recipientPubHex = "0x" + Buffer.from(recipientPub).toString("hex");

// Encrypt payload
const raw = await encryptTextRaw({
  plaintext,
  cipher: "AES-256-GCM",
  aadText,
});

// Wrap DEK for recipient
const wrappedKey = await wrapDEK_secp256k1({
  dek: raw.dek,
  recipientPubKeyHex: recipientPubHex,
  kid: "did:pkh:eip155:1:0xDEMO_RECIPIENT",
  aadText,
});

// Build envelope
const envelope = {
  v: "0.1",
  typ: "PXP201",
  cipher: "AES-256-GCM",
  kdf: "HKDF-SHA256",
  access: {
    mode: "RECIPIENTS",
    kem: "RECIPIENTS-SECP256K1-ECIES",
    recipients: [{ rid: "did:pkh:eip155:1:0xDEMO_RECIPIENT", wrappedKey }],
  },
  uri: "ipfs://bafybeigdyr...demo-ciphertext",
  ciphertextHash: raw.ciphertextHash,
  ...(raw.aadHash ? { aadHash: raw.aadHash } : {}),
  meta: { mime: "text/plain" },
  createdAt: Math.floor(Date.now() / 1000),
};

validateEnvelope(envelope);

// Unwrap + decrypt
const dek2 = await unwrapDEK_secp256k1({
  wrappedKey,
  recipientPrivKeyHex: recipientPrivHex,
  aadText,
});

const out = await decryptTextFromEnvelope({
  envelope,
  dek: dek2,
  ciphertextB64url: raw.ciphertextB64url,
  nonceB64url: raw.nonceB64url,
  aadText,
});

console.log(out);
\`\`\`

## Spec
See the repository `spec/PXP-201.md`.

## Test vectors (PXP-201 v0.1)

This package ships reproducible test vectors under `test-vectors/`.

Run them locally:

```bash
npm run build
npm run vectors
```

### What is covered (v0.1)
- **RAW**: AES-256-GCM encryption with fixed DEK + nonce
- **WK1**: secp256k1 ECDH + HKDF-SHA256 + AES-256-GCM (fixed ephPriv + IV)

> Note: deterministic options (`nonce`, `opts.ephPrivKey`, `opts.iv`) are intended for test vectors only.
