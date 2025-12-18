import {
  encryptTextRaw,
  decryptTextFromEnvelope,
  validateEnvelope,
  wrapDEK_secp256k1,
  unwrapDEK_secp256k1
} from "../sdk/dist/index.js";

try {
  const plaintext = "hello from PXP-201";
  const aadText = "app:privacyx-demo|v0.1";

  // Demo recipient keypair
  const secp = await import("@noble/secp256k1");
  const recipientPriv = secp.utils.randomSecretKey();
  const recipientPub = secp.getPublicKey(recipientPriv, true);

  const recipientPrivHex = "0x" + Buffer.from(recipientPriv).toString("hex");
  const recipientPubHex = "0x" + Buffer.from(recipientPub).toString("hex");

  // 1) Encrypt raw (no envelope yet)
  const raw = await encryptTextRaw({
    plaintext,
    cipher: "AES-256-GCM",
    aadText
  });

  // 2) Wrap DEK for recipient
  const wrappedKey = await wrapDEK_secp256k1({
    dek: raw.dek,
    recipientPubKeyHex: recipientPubHex,
    kid: "did:pkh:eip155:1:0xDEMO_RECIPIENT",
    aadText
  });

  // 3) Build envelope (now recipients is non-empty)
  const envelope = {
    v: "0.1",
    typ: "PXP201",
    cipher: "AES-256-GCM",
    kdf: "HKDF-SHA256",
    access: {
      mode: "RECIPIENTS",
      kem: "RECIPIENTS-SECP256K1-ECIES",
      recipients: [
        { rid: "did:pkh:eip155:1:0xDEMO_RECIPIENT", wrappedKey }
      ]
    },
    uri: "ipfs://bafybeigdyr...demo-ciphertext",
    ciphertextHash: raw.ciphertextHash,
    ...(raw.aadHash ? { aadHash: raw.aadHash } : {}),
    meta: { mime: "text/plain" },
    createdAt: Math.floor(Date.now() / 1000)
  };

  validateEnvelope(envelope);

  console.log("=== ENVELOPE (PXP201) ===");
  console.log(JSON.stringify(envelope, null, 2));
  console.log("");
  console.log("ciphertextB64url:", raw.ciphertextB64url);
  console.log("nonceB64url:", raw.nonceB64url);
  console.log("");

  // 4) Receiver unwraps DEK then decrypts ciphertext
  const dek2 = await unwrapDEK_secp256k1({
    wrappedKey,
    recipientPrivKeyHex: recipientPrivHex,
    aadText
  });

  const out = await decryptTextFromEnvelope({
    envelope,
    dek: dek2,
    ciphertextB64url: raw.ciphertextB64url,
    nonceB64url: raw.nonceB64url,
    aadText
  });

  console.log("=== DECRYPTED ===");
  console.log(out);
} catch (err) {
  console.error("E2E ERROR:", err);
  process.exit(1);
}
