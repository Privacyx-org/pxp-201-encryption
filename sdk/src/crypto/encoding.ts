export function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function bytesToHex(b: Uint8Array): `0x${string}` {
  return ("0x" +
    Array.from(b)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("")) as `0x${string}`;
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// base64url (RFC 4648 §5)
export function bytesToBase64Url(bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(b64, "base64"));
}
