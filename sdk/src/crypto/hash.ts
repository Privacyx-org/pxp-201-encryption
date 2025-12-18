import { createHash } from "node:crypto";

export type Hex = `0x${string}`;

export function sha3_256(bytes: Uint8Array): Uint8Array {
  const h = createHash("sha3-256");
  h.update(Buffer.from(bytes));
  return new Uint8Array(h.digest());
}

export function toHex(bytes: Uint8Array): Hex {
  return ("0x" + Buffer.from(bytes).toString("hex")) as Hex;
}

export function hashHex(bytes: Uint8Array): Hex {
  return toHex(sha3_256(bytes));
}
