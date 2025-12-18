import type { Pxp201Cipher } from "./envelope.js";
import { utf8ToBytes, b64urlEncode } from "../crypto/utils.js";
import { generateDEK, encryptSymmetric } from "../crypto/symmetric.js";
import { hashHex } from "../crypto/hash.js";
import { Pxp201Error } from "./envelope.js";

export interface EncryptRawResult {
  dek: Uint8Array;
  ciphertextB64url: string;
  nonceB64url: string;
  ciphertextHash: `0x${string}`;
  aadHash?: `0x${string}`;
}

export async function encryptTextRaw(args: {
  plaintext: string;
  cipher: Pxp201Cipher;
  aadText?: string;

  // Test-vectors / deterministic mode
  dek?: Uint8Array;   // 32 bytes
  nonce?: Uint8Array; // 12 bytes (AES-GCM)
}): Promise<EncryptRawResult> {
  const dek = args.dek ?? generateDEK();
  if (dek.length !== 32) throw new Pxp201Error("RAW_DEK", "DEK must be 32 bytes");

  const aad = args.aadText ? utf8ToBytes(args.aadText) : undefined;

  const pt = utf8ToBytes(args.plaintext);
  const { nonce, ciphertext } = await encryptSymmetric(args.cipher, dek, pt, aad, { nonce: args.nonce });

  const ciphertextHash = hashHex(ciphertext);
  const aadHash = aad ? hashHex(aad) : undefined;

  return {
    dek,
    ciphertextB64url: b64urlEncode(ciphertext),
    nonceB64url: b64urlEncode(nonce),
    ciphertextHash,
    ...(aadHash ? { aadHash } : {}),
  };
}
