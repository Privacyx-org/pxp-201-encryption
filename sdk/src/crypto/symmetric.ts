import { randomBytesN } from "./utils.js";
import { Pxp201Cipher, Pxp201Error } from "../core/envelope.js";

export interface EncryptResult {
  dek: Uint8Array;        // 32 bytes
  nonce: Uint8Array;      // 12 bytes for AES-GCM
  aad?: Uint8Array;       // optional
  ciphertext: Uint8Array; // includes auth tag (WebCrypto concatenates it)
}

export function generateDEK(): Uint8Array {
  return randomBytesN(32);
}

function requireSubtle(): SubtleCrypto {
  const g: any = globalThis as any;
  if (!g.crypto || !g.crypto.subtle) {
    throw new Pxp201Error("CRYPTO_SUBTLE", "WebCrypto subtle API not available in this runtime");
  }
  return g.crypto.subtle as SubtleCrypto;
}

// Force a real ArrayBuffer (not SharedArrayBuffer / ArrayBufferLike)
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

async function importAesKey(dek: Uint8Array): Promise<CryptoKey> {
  const subtle = requireSubtle();
  if (dek.length !== 32) throw new Pxp201Error("CRYPTO_DEK", "DEK must be 32 bytes");
  return subtle.importKey("raw", toArrayBuffer(dek), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptSymmetric(
  cipher: Pxp201Cipher,
  dek: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
  opts?: { nonce?: Uint8Array }
): Promise<Omit<EncryptResult, "dek">> {
  if (cipher !== "AES-256-GCM") {
    throw new Pxp201Error("CRYPTO_CIPHER", "Only AES-256-GCM is supported in v0.1");
  }

  const subtle = requireSubtle();
  const key = await importAesKey(dek);

  const nonce = opts?.nonce ?? randomBytesN(12);
  if (nonce.length !== 12) throw new Pxp201Error("CRYPTO_NONCE", "AES-GCM nonce must be 12 bytes");

  const params: AesGcmParams = {
    name: "AES-GCM",
    iv: toArrayBuffer(nonce),
    ...(aad ? { additionalData: toArrayBuffer(aad) } : {}),
    tagLength: 128,
  };

  const ctBuf = await subtle.encrypt(params, key, toArrayBuffer(plaintext));
  return { nonce, aad, ciphertext: new Uint8Array(ctBuf) };
}

export async function decryptSymmetric(
  cipher: Pxp201Cipher,
  dek: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  if (cipher !== "AES-256-GCM") {
    throw new Pxp201Error("CRYPTO_CIPHER", "Only AES-256-GCM is supported in v0.1");
  }

  if (nonce.length !== 12) throw new Pxp201Error("CRYPTO_NONCE", "AES-GCM nonce must be 12 bytes");

  const subtle = requireSubtle();
  const key = await importAesKey(dek);

  const params: AesGcmParams = {
    name: "AES-GCM",
    iv: toArrayBuffer(nonce),
    ...(aad ? { additionalData: toArrayBuffer(aad) } : {}),
    tagLength: 128,
  };

  const ptBuf = await subtle.decrypt(params, key, toArrayBuffer(ciphertext));
  return new Uint8Array(ptBuf);
}
