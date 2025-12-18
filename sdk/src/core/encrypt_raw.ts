import type { Pxp201Cipher } from "./envelope.js";
import { utf8ToBytes, b64urlEncode } from "../crypto/utils.js";
import { generateDEK, encryptSymmetric } from "../crypto/symmetric.js";
import { hashHex } from "../crypto/hash.js";

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
}): Promise<EncryptRawResult> {
  const dek = generateDEK();
  const aad = args.aadText ? utf8ToBytes(args.aadText) : undefined;

  const pt = utf8ToBytes(args.plaintext);
  const { nonce, ciphertext } = await encryptSymmetric(args.cipher, dek, pt, aad);

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
