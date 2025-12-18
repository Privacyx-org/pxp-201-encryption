import { randomBytes as nodeRandomBytes } from "node:crypto";

export function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function b64urlEncode(bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export function randomBytesN(n: number): Uint8Array {
  // Browser / modern runtimes
  const g: any = globalThis as any;
  if (g.crypto && typeof g.crypto.getRandomValues === "function") {
    const out = new Uint8Array(n);
    g.crypto.getRandomValues(out);
    return out;
  }

  // Node fallback
  return new Uint8Array(nodeRandomBytes(n));
}
