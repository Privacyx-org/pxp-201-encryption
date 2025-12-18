import { sha3_256 as noble_sha3_256 } from "@noble/hashes/sha3.js";

export type Hex = `0x${string}`;

export function sha3_256(bytes: Uint8Array): Uint8Array {
  // noble returns Uint8Array(32)
  return noble_sha3_256(bytes);
}

export function toHex(bytes: Uint8Array): Hex {
  // avoid Buffer (browser-safe)
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return ("0x" + hex) as Hex;
}

export function hashHex(bytes: Uint8Array): Hex {
  return toHex(sha3_256(bytes));
}

