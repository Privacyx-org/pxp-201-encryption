# PXP-201 — PrivacyX Encryption Standard (Draft v0.1)

PXP-201 defines an interoperable **encryption envelope** format for Web2 + Web3:
- encrypt once (off-chain or on-chain referenced)
- share with recipients (multi-recipient wrapped keys)
- verify integrity before decrypt
- policy mode reserved for future versions

## Repository layout
- `spec/` — formal specification (PXP-201 draft v0.1)
- `sdk/` — reference JS/TS SDK (`@privacyx/pxp201`)
- `contracts/` — minimal on-chain registry (references + commitments only)
- `examples/` — end-to-end runnable examples

## Install & run the end-to-end demo
From the repo root:

\`\`\`bash
npm install
cd sdk && npm install && npm run build && cd ..
npm run e2e
\`\`\`

## SDK usage (recipients mode, wk1)

### Install

\`\`\`bash
npm i @privacyx/pxp201
npm i @noble/secp256k1
\`\`\`

### Example (Node ESM)

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

// Demo recipient keypair (in real life: wallet/DID key material)
const recipientPriv = secp.utils.randomSecretKey();
const recipientPub = secp.getPublicKey(recipientPriv, true);
const recipientPrivHex = "0x" + Buffer.from(recipientPriv).toString("hex");
const recipientPubHex = "0x" + Buffer.from(recipientPub).toString("hex");

// 1) Encrypt raw payload (no envelope yet)
const raw = await encryptTextRaw({
  plaintext,
  cipher: "AES-256-GCM",
  aadText,
});

// 2) Wrap DEK for the recipient (wk1 / secp256k1 ECIES)
const wrappedKey = await wrapDEK_secp256k1({
  dek: raw.dek,
  recipientPubKeyHex: recipientPubHex,
  kid: "did:pkh:eip155:1:0xDEMO_RECIPIENT",
  aadText,
});

// 3) Build + validate envelope
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

// 4) Receiver: unwrap DEK then decrypt ciphertext
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

console.log(out); // "hello from PXP-201"
\`\`\`

## Spec
See `spec/PXP-201.md`.

## License
MIT
