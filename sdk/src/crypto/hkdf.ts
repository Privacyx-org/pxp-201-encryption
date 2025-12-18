import { Pxp201Error } from "../core/envelope.js";

function requireSubtle(): SubtleCrypto {
  const g: any = globalThis as any;
  if (!g.crypto || !g.crypto.subtle) {
    throw new Pxp201Error("CRYPTO_SUBTLE", "WebCrypto subtle API not available");
  }
  return g.crypto.subtle as SubtleCrypto;
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

export async function hkdfSha256(params: {
  ikm: Uint8Array;
  salt?: Uint8Array;
  info?: Uint8Array;
  length: number;
}): Promise<Uint8Array> {
  const subtle = requireSubtle();

  const key = await subtle.importKey("raw", toArrayBuffer(params.ikm), "HKDF", false, ["deriveBits"]);

  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(params.salt ?? new Uint8Array(0)),
      info: toArrayBuffer(params.info ?? new Uint8Array(0)),
    },
    key,
    params.length * 8
  );

  return new Uint8Array(bits);
}
