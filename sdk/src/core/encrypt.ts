import type { Pxp201Envelope, Pxp201Cipher } from "./envelope.js";
import { validateEnvelope, Pxp201Error } from "./envelope.js";
import { bytesToUtf8, utf8ToBytes, b64urlEncode, b64urlDecode } from "../crypto/utils.js";
import { generateDEK, encryptSymmetric, decryptSymmetric } from "../crypto/symmetric.js";
import { hashHex } from "../crypto/hash.js";

export interface EncryptPayloadOptions {
  cipher: Pxp201Cipher;
  uri: string;
  access: Pxp201Envelope["access"];
  aadText?: string;
  meta?: Record<string, unknown>;
}

export interface EncryptedPayload {
  envelope: Pxp201Envelope;
  dek: Uint8Array; // demo only (recipient wrapping comes next)
  ciphertextB64url: string;
  nonceB64url: string;
}

export async function encryptTextToEnvelope(
  plaintext: string,
  opts: EncryptPayloadOptions
): Promise<EncryptedPayload> {
  const dek = generateDEK();
  const aad = opts.aadText ? utf8ToBytes(opts.aadText) : undefined;

  const pt = utf8ToBytes(plaintext);
  const { nonce, ciphertext } = await encryptSymmetric(opts.cipher, dek, pt, aad);

  const ciphertextHash = hashHex(ciphertext);
  const aadHash = aad ? hashHex(aad) : undefined;

  const envelope: Pxp201Envelope = {
    v: "0.1",
    typ: "PXP201",
    cipher: opts.cipher,
    kdf: "HKDF-SHA256",
    access: opts.access,
    uri: opts.uri,
    ciphertextHash,
    ...(aadHash ? { aadHash } : {}),
    ...(opts.meta ? { meta: opts.meta } : {}),
    createdAt: Math.floor(Date.now() / 1000),
  };

  validateEnvelope(envelope);

  return {
    envelope,
    dek,
    ciphertextB64url: b64urlEncode(ciphertext),
    nonceB64url: b64urlEncode(nonce),
  };
}

export async function decryptTextFromEnvelope(args: {
  envelope: Pxp201Envelope;
  dek: Uint8Array;
  ciphertextB64url: string;
  nonceB64url: string;
  aadText?: string;
}): Promise<string> {
  validateEnvelope(args.envelope);

  const ciphertext = b64urlDecode(args.ciphertextB64url);
  const nonce = b64urlDecode(args.nonceB64url);
  const aad = args.aadText ? utf8ToBytes(args.aadText) : undefined;

  const got = hashHex(ciphertext);
  if (got !== args.envelope.ciphertextHash) {
    throw new Pxp201Error("CRYPTO_INTEGRITY", "ciphertextHash mismatch");
  }

  const pt = await decryptSymmetric(
    args.envelope.cipher,
    args.dek,
    nonce,
    ciphertext,
    aad
  );
  return bytesToUtf8(pt);
}
