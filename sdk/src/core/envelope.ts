export type Hex = `0x${string}`;

export type Pxp201Cipher =
  | "AES-256-GCM"
  | "XCHACHA20-POLY1305";

export type Pxp201Kdf = "HKDF-SHA256";

export type Pxp201Kem =
  | "RECIPIENTS-SECP256K1-ECIES"
  | "RECIPIENTS-X25519-SEALED_BOX"
  | "POLICY-EXTERNAL"; // key released by a policy / gateway

export type Pxp201AccessMode = "RECIPIENTS" | "POLICY";

export interface Pxp201RecipientsAccess {
  mode: "RECIPIENTS";
  kem: Exclude<Pxp201Kem, "POLICY-EXTERNAL">;
  recipients: Array<{
    // recipient identifier (e.g., eth address, did:key, email hash)
    rid: string;
    // wrapped DEK (base64url) or a pointer to it
    wrappedKey: string;
  }>;
}

export interface Pxp201PolicyAccess {
  mode: "POLICY";
  kem: "POLICY-EXTERNAL";
  policy: {
    // policy id in your system (could be on-chain bytes32, uuid, etc.)
    policyId: string;
    // optional pointer to policy endpoint / contract
    ref?: string;
    // optional config hash / version
    configHash?: string;
  };
}

export type Pxp201Access = Pxp201RecipientsAccess | Pxp201PolicyAccess;

export interface Pxp201Envelope {
  v: "0.1";
  // domain separation for the envelope format
  typ: "PXP201";
  // crypto suite
  cipher: Pxp201Cipher;
  kdf: Pxp201Kdf;
  access: Pxp201Access;

  // where the ciphertext lives (ipfs://, ar://, https://, onchain://...)
  uri: string;

  // integrity binding
  ciphertextHash: Hex; // keccak256(ciphertext bytes) as 0x...
  // optional associated data hash (AAD)
  aadHash?: Hex;

  // optional metadata (non-sensitive)
  meta?: Record<string, unknown>;

  // timestamps (optional, informational)
  createdAt?: number; // unix seconds
}

export class Pxp201Error extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function isHex32(x: unknown): x is Hex {
  return typeof x === "string" && x.startsWith("0x") && x.length === 66;
}

export function validateEnvelope(env: unknown): asserts env is Pxp201Envelope {
  if (!env || typeof env !== "object") {
    throw new Pxp201Error("ENV_INVALID", "Envelope must be an object");
  }
  const e = env as any;

  if (e.v !== "0.1") throw new Pxp201Error("ENV_VERSION", "Unsupported envelope version");
  if (e.typ !== "PXP201") throw new Pxp201Error("ENV_TYPE", "Invalid envelope typ");
  if (e.kdf !== "HKDF-SHA256") throw new Pxp201Error("ENV_KDF", "Unsupported kdf");

  if (e.cipher !== "AES-256-GCM" && e.cipher !== "XCHACHA20-POLY1305") {
    throw new Pxp201Error("ENV_CIPHER", "Unsupported cipher");
  }

  if (typeof e.uri !== "string" || e.uri.length < 3) {
    throw new Pxp201Error("ENV_URI", "Invalid uri");
  }

  if (!isHex32(e.ciphertextHash)) {
    throw new Pxp201Error("ENV_CTHASH", "ciphertextHash must be 32-byte hex");
  }

  if (e.aadHash !== undefined && !isHex32(e.aadHash)) {
    throw new Pxp201Error("ENV_AADHASH", "aadHash must be 32-byte hex");
  }

  if (!e.access || typeof e.access !== "object") {
    throw new Pxp201Error("ENV_ACCESS", "Missing access object");
  }

  if (e.access.mode === "RECIPIENTS") {
    if (e.access.kem !== "RECIPIENTS-SECP256K1-ECIES" && e.access.kem !== "RECIPIENTS-X25519-SEALED_BOX") {
      throw new Pxp201Error("ENV_KEM", "Unsupported recipients KEM");
    }
    if (!Array.isArray(e.access.recipients) || e.access.recipients.length === 0) {
      throw new Pxp201Error("ENV_RECIPIENTS", "recipients must be non-empty array");
    }
    for (const r of e.access.recipients) {
      if (!r || typeof r !== "object") throw new Pxp201Error("ENV_RECIPIENT", "recipient entry invalid");
      if (typeof r.rid !== "string" || r.rid.length < 2) throw new Pxp201Error("ENV_RID", "recipient rid invalid");
      if (typeof r.wrappedKey !== "string" || r.wrappedKey.length < 8) {
        throw new Pxp201Error("ENV_WRAPPED", "recipient wrappedKey invalid");
      }
    }
    return;
  }

  if (e.access.mode === "POLICY") {
    if (e.access.kem !== "POLICY-EXTERNAL") {
      throw new Pxp201Error("ENV_KEM", "POLICY mode requires POLICY-EXTERNAL kem");
    }
    if (!e.access.policy || typeof e.access.policy !== "object") {
      throw new Pxp201Error("ENV_POLICY", "Missing policy object");
    }
    if (typeof e.access.policy.policyId !== "string" || e.access.policy.policyId.length < 2) {
      throw new Pxp201Error("ENV_POLICY_ID", "policyId invalid");
    }
    return;
  }

  throw new Pxp201Error("ENV_MODE", "Unknown access mode");
}
