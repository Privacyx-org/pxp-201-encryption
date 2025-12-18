import { randomBytes } from "@noble/hashes/utils.js";

export function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

// --- base64 helpers (universal: browser + node) ---
function bytesToBase64(bytes: Uint8Array): string {
  // Node path
  const g: any = globalThis as any;
  if (g.Buffer) return g.Buffer.from(bytes).toString("base64");

  // Browser path
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
  const g: any = globalThis as any;
  if (g.Buffer) return new Uint8Array(g.Buffer.from(b64, "base64"));

  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlEncode(bytes: Uint8Array): string {
  const b64 = bytesToBase64(bytes);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return base64ToBytes(b64);
}

export function randomBytesN(n: number): Uint8Array {
  return randomBytes(n);
}

