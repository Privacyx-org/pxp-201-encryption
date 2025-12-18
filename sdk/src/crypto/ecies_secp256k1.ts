import * as secp from "@noble/secp256k1";
import { randomBytesN, b64urlEncode, b64urlDecode } from "./utils.js";
import { hkdfSha256 } from "./hkdf.js";
import { Pxp201Error } from "../core/envelope.js";

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

function requireSubtle(): SubtleCrypto {
  const g: any = globalThis as any;
  if (!g.crypto?.subtle) throw new Pxp201Error("CRYPTO_SUBTLE", "WebCrypto subtle API not available");
  return g.crypto.subtle as SubtleCrypto;
}

async function aesGcmEncrypt(key32: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array) {
  const subtle = requireSubtle();
  const iv = randomBytesN(12);

  const cryptoKey = await subtle.importKey("raw", toArrayBuffer(key32), { name: "AES-GCM" }, false, ["encrypt"]);
  const ctBuf = await subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), ...(aad ? { additionalData: toArrayBuffer(aad) } : {}), tagLength: 128 },
    cryptoKey,
    toArrayBuffer(plaintext)
  );

  return { iv, ct: new Uint8Array(ctBuf) };
}

async function aesGcmDecrypt(key32: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array) {
  const subtle = requireSubtle();

  const cryptoKey = await subtle.importKey("raw", toArrayBuffer(key32), { name: "AES-GCM" }, false, ["decrypt"]);
  const ptBuf = await subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), ...(aad ? { additionalData: toArrayBuffer(aad) } : {}), tagLength: 128 },
    cryptoKey,
    toArrayBuffer(ciphertext)
  );

  return new Uint8Array(ptBuf);
}

export type WrappedKeyV1 = {
  alg: "ECIES-secp256k1+HKDF-SHA256+AES-256-GCM";
  epk: string;   // 0x + compressed pubkey hex (33 bytes)
  nonce: string; // b64url(12)
  ct: string;    // b64url(ciphertext+tag)
  kid?: string;
};

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  return new Uint8Array(Buffer.from(h, "hex"));
}

function bytesToHex0x(bytes: Uint8Array): `0x${string}` {
  return ("0x" + Buffer.from(bytes).toString("hex")) as `0x${string}`;
}

export async function wrapDEK_secp256k1(args: {
  dek: Uint8Array;              // 32 bytes
  recipientPubKeyHex: string;   // 33-byte compressed hex
  kid?: string;
  aadText?: string;
}): Promise<string> {
  if (args.dek.length !== 32) throw new Pxp201Error("WRAP_DEK", "DEK must be 32 bytes");

  const recipPub = hexToBytes(args.recipientPubKeyHex);
  if (recipPub.length !== 33) throw new Pxp201Error("WRAP_PUB", "recipient pubkey must be 33 bytes compressed");

  const ephPriv = secp.utils.randomSecretKey();
  const ephPub = secp.getPublicKey(ephPriv, true);

  const shared = secp.getSharedSecret(ephPriv, recipPub, true);
  const ikm = shared.slice(1);

  const info = new TextEncoder().encode("PXP201:WK1");
  const aad = args.aadText ? new TextEncoder().encode(args.aadText) : undefined;

  const wrapKey = await hkdfSha256({ ikm, salt: ephPub, info, length: 32 });
  const { iv, ct } = await aesGcmEncrypt(wrapKey, args.dek, aad);

  const payload: WrappedKeyV1 = {
    alg: "ECIES-secp256k1+HKDF-SHA256+AES-256-GCM",
    epk: bytesToHex0x(ephPub),
    nonce: b64urlEncode(iv),
    ct: b64urlEncode(ct),
    ...(args.kid ? { kid: args.kid } : {}),
  };

  return "pxp201:wk1:" + b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
}

export async function unwrapDEK_secp256k1(args: {
  wrappedKey: string;
  recipientPrivKeyHex: string;
  aadText?: string;
}): Promise<Uint8Array> {
  if (!args.wrappedKey.startsWith("pxp201:wk1:")) {
    throw new Pxp201Error("UNWRAP_FMT", "Invalid wrappedKey prefix");
  }

  const blob = args.wrappedKey.slice("pxp201:wk1:".length);
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(blob))) as WrappedKeyV1;

  if (payload.alg !== "ECIES-secp256k1+HKDF-SHA256+AES-256-GCM") {
    throw new Pxp201Error("UNWRAP_ALG", "Unsupported wrappedKey alg");
  }

  const epk = hexToBytes(payload.epk);
  if (epk.length !== 33) throw new Pxp201Error("UNWRAP_EPK", "Invalid epk length");

  const priv = hexToBytes(args.recipientPrivKeyHex);
  if (priv.length !== 32) throw new Pxp201Error("UNWRAP_PRIV", "recipient privkey must be 32 bytes");

  const shared = secp.getSharedSecret(priv, epk, true);
  const ikm = shared.slice(1);

  const info = new TextEncoder().encode("PXP201:WK1");
  const aad = args.aadText ? new TextEncoder().encode(args.aadText) : undefined;

  const wrapKey = await hkdfSha256({ ikm, salt: epk, info, length: 32 });

  const iv = b64urlDecode(payload.nonce);
  const ct = b64urlDecode(payload.ct);

  const dek = await aesGcmDecrypt(wrapKey, iv, ct, aad);
  if (dek.length !== 32) throw new Pxp201Error("UNWRAP_DEK", "Invalid DEK length");
  return dek;
}
