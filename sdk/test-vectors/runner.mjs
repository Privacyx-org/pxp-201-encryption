import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import * as secp from "@noble/secp256k1";

import {
  encryptTextRaw,
  wrapDEK_secp256k1,
  unwrapDEK_secp256k1,
} from "../dist/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function load(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, name), "utf8"));
}

function assertEqual(label, a, b) {
  if (a !== b) throw new Error(`❌ ${label} mismatch\n${a}\n!==\n${b}`);
  console.log(`✅ ${label}`);
}

function assertBytesEqual(label, a, b) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  if (!aa.equals(bb)) throw new Error(`❌ ${label} bytes mismatch\n${aa.toString("hex")}\n!==\n${bb.toString("hex")}`);
  console.log(`✅ ${label}`);
}

function hexToU8(hex) {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  return Uint8Array.from(Buffer.from(h, "hex"));
}

function b64urlToU8(s) {
  return Uint8Array.from(Buffer.from(s, "base64url"));
}

async function run() {
  console.log("== PXP-201 v0.1 test vectors ==");

  // --- RAW vector ---
  const rawV = load("raw.json");

  const out = await encryptTextRaw({
    plaintext: rawV.plaintext,
    cipher: rawV.cipher,
    aadText: rawV.aadText,
    dek: hexToU8(rawV.dekHex),
    nonce: b64urlToU8(rawV.nonceB64url),
  });

  assertEqual("raw.nonceB64url", out.nonceB64url, rawV.nonceB64url);
  assertEqual("raw.ciphertextB64url", out.ciphertextB64url, rawV.ciphertextB64url);
  assertEqual("raw.ciphertextHash", out.ciphertextHash, rawV.ciphertextHash);
  assertEqual("raw.aadHash", out.aadHash, rawV.aadHash);

  console.log("✅ RAW vectors OK");

  // --- WK1 vector ---
  const wk1 = load("wk1.json");

  const dek = hexToU8(wk1.dekHex);
  const recipientPriv = hexToU8(wk1.recipientPrivHex);
  const recipientPrivHex = "0x" + Buffer.from(recipientPriv).toString("hex");

  const recipientPub = secp.getPublicKey(recipientPriv, true);
  const recipientPubHex = "0x" + Buffer.from(recipientPub).toString("hex");

  // Deterministic wrap
  const wrapped = await wrapDEK_secp256k1({
    dek,
    recipientPubKeyHex: recipientPubHex,
    kid: wk1.kid,
    aadText: wk1.aadText,
    opts: {
      ephPrivKey: hexToU8(wk1.ephPrivHex),
      iv: hexToU8(wk1.wrapIvHex),
    },
  });

  assertEqual("wk1.wrappedKey", wrapped, wk1.wrappedKey);

  // Unwrap must recover the same DEK
  const dek2 = await unwrapDEK_secp256k1({
    wrappedKey: wrapped,
    recipientPrivKeyHex: recipientPrivHex,
    aadText: wk1.aadText,
  });

  assertBytesEqual("wk1.unwrap(dek)", dek2, dek);

  console.log("✅ WK1 vectors OK");

  console.log("🎉 All vectors OK");
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
