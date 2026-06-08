import type {
  SnapshotSigningJwk,
  TransparencyLogInclusionProof,
  TransparencyLogInclusionResult,
  TransparencyLogSnapshot,
} from "./transparency-types.js";

const FORMAT_VERSION = "adjuro-transparency-log/1";
const LEAF_FORMAT = "<receipt_id>|<kid>|<iat_sec>|<tenant_id>";
const SHA256_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const textEncoder = new TextEncoder();
const strictTextDecoder = new TextDecoder("utf-8", { fatal: true });
let webCryptoPromise: Promise<Crypto> | undefined;

type ReceiptLeafClaims = {
  receiptId: string;
  tenantId: string;
  kid: string;
  iat: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeInteger(value: unknown, minimum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;
}

function isCanonicalComponent(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && !value.includes("|");
}

function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decodeBase64url(value: unknown): Uint8Array | null {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !/^[A-Za-z0-9_-]+$/.test(value) ||
    value.length % 4 === 1
  ) {
    return null;
  }

  try {
    const padding = "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return encodeBase64url(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function decodeHex32(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) return null;
  return Uint8Array.from({ length: SHA256_BYTES }, (_, i) =>
    Number.parseInt(value.slice(i * 2, i * 2 + 2), 16),
  );
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

async function getWebCrypto(): Promise<Crypto> {
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  webCryptoPromise ??= (async () => {
    const nodeCryptoSpecifier = "node:crypto";
    const nodeCrypto = (await import(nodeCryptoSpecifier)) as { webcrypto?: Crypto };
    if (!nodeCrypto.webcrypto?.subtle) throw new Error("WebCrypto is unavailable");
    return nodeCrypto.webcrypto;
  })();
  return webCryptoPromise;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const webCrypto = await getWebCrypto();
  return new Uint8Array(
    await webCrypto.subtle.digest("SHA-256", ownedArrayBuffer(bytes)),
  );
}

/** @internal RFC 6962 leaf hash helper, exported only for known-answer tests. */
export async function hashTransparencyLeaf(rawLeaf: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(1 + rawLeaf.length);
  input[0] = 0x00;
  input.set(rawLeaf, 1);
  return sha256(input);
}

/** @internal RFC 6962 node hash helper, exported only for known-answer tests. */
export async function hashTransparencyNode(
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  if (left.length !== SHA256_BYTES || right.length !== SHA256_BYTES) {
    throw new Error("RFC 6962 nodes must be 32-byte SHA-256 hashes");
  }
  const input = new Uint8Array(1 + left.length + right.length);
  input[0] = 0x01;
  input.set(left, 1);
  input.set(right, 1 + left.length);
  return sha256(input);
}

function parseJsonSegment(segment: string): Record<string, unknown> | null {
  const bytes = decodeBase64url(segment);
  if (!bytes) return null;
  try {
    const value: unknown = JSON.parse(strictTextDecoder.decode(bytes));
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

function parseReceiptLeafClaims(jws: unknown): ReceiptLeafClaims | "malformed_jws" | null {
  if (typeof jws !== "string") return "malformed_jws";
  const segments = jws.split(".");
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    return "malformed_jws";
  }

  const header = parseJsonSegment(segments[0]);
  const payload = parseJsonSegment(segments[1]);
  const signature = decodeBase64url(segments[2]);
  if (
    !header ||
    !payload ||
    header.alg !== "EdDSA" ||
    header.b64 === false ||
    !signature ||
    signature.length !== ED25519_SIGNATURE_BYTES
  ) {
    return "malformed_jws";
  }

  const receiptId = payload.receipt_id;
  const tenantId = payload.tenant_id;
  const kid = header.kid;
  const iat = payload.iat;

  if (
    !isCanonicalComponent(receiptId) ||
    !isCanonicalComponent(tenantId) ||
    !isCanonicalComponent(kid) ||
    !isSafeInteger(iat, 0)
  ) {
    return null;
  }
  if (payload.jti !== undefined && payload.jti !== receiptId) return null;

  return { receiptId, tenantId, kid, iat };
}

function validateProof(proof: unknown):
  | {
      value: TransparencyLogInclusionProof;
      root: Uint8Array;
      auditPath: Uint8Array[];
    }
  | null {
  if (!isRecord(proof)) return null;
  if (
    proof.status !== "included" ||
    !isCanonicalComponent(proof.receipt_id) ||
    !isSafeInteger(proof.leaf_index, 0) ||
    !isSafeInteger(proof.tree_size, 1) ||
    !isSafeInteger(proof.snapshot_id, 1) ||
    proof.format_version !== FORMAT_VERSION ||
    proof.leaf_format !== LEAF_FORMAT ||
    !Array.isArray(proof.audit_path) ||
    proof.audit_path.length > 53
  ) {
    return null;
  }

  const root = decodeHex32(proof.root_hash);
  if (!root) return null;
  const auditPath: Uint8Array[] = [];
  for (const node of proof.audit_path) {
    const decoded = decodeHex32(node);
    if (!decoded) return null;
    auditPath.push(decoded);
  }

  return {
    value: proof as unknown as TransparencyLogInclusionProof,
    root,
    auditPath,
  };
}

function validateSnapshot(snapshot: unknown):
  | {
      value: TransparencyLogSnapshot;
      root: Uint8Array;
      signature: Uint8Array;
    }
  | null {
  if (!isRecord(snapshot)) return null;
  if (
    !isSafeInteger(snapshot.snapshot_id, 1) ||
    !isSafeInteger(snapshot.tree_size, 1) ||
    !isCanonicalComponent(snapshot.snapshot_kid) ||
    typeof snapshot.signed_at !== "string" ||
    snapshot.signed_at.length === 0 ||
    snapshot.format_version !== FORMAT_VERSION
  ) {
    return null;
  }

  const root = decodeHex32(snapshot.root_hash);
  const signature = decodeBase64url(snapshot.signature);
  if (!root || !signature || signature.length !== ED25519_SIGNATURE_BYTES) return null;

  return {
    value: snapshot as unknown as TransparencyLogSnapshot,
    root,
    signature,
  };
}

function validatePinnedJwk(jwk: unknown): { value: SnapshotSigningJwk; x: Uint8Array } | null {
  if (!isRecord(jwk)) return null;
  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    !isCanonicalComponent(jwk.kid) ||
    (jwk.alg !== undefined && jwk.alg !== "EdDSA") ||
    (jwk.use !== undefined && jwk.use !== "sig") ||
    (jwk.key_ops !== undefined &&
      (!Array.isArray(jwk.key_ops) ||
        !jwk.key_ops.every((operation) => typeof operation === "string") ||
        !jwk.key_ops.includes("verify")))
  ) {
    return null;
  }
  const x = decodeBase64url(jwk.x);
  if (!x || x.length !== SHA256_BYTES) return null;
  return { value: jwk as SnapshotSigningJwk, x };
}

function largestPowerOfTwoBelow(value: number): number {
  let power = 1;
  while (power * 2 < value) power *= 2;
  return power;
}

function auditPathSiblingSides(
  leafIndex: number,
  treeSize: number,
): Array<"left" | "right"> | null {
  if (leafIndex >= treeSize) return null;

  const sides: Array<"left" | "right"> = [];
  let index = leafIndex;
  let size = treeSize;
  while (size > 1) {
    const split = largestPowerOfTwoBelow(size);
    if (index < split) {
      sides.push("right");
      size = split;
    } else {
      sides.push("left");
      index -= split;
      size -= split;
    }
  }
  return sides.reverse();
}

/** @internal RFC 6962 inclusion-root helper, exported only for known-answer tests. */
export async function calculateTransparencyRoot(
  leafHash: Uint8Array,
  auditPath: Uint8Array[],
  leafIndex: number,
  treeSize: number,
): Promise<Uint8Array | null> {
  const siblingSides = auditPathSiblingSides(leafIndex, treeSize);
  if (!siblingSides || siblingSides.length !== auditPath.length) return null;

  let current = leafHash;
  for (let i = 0; i < auditPath.length; i++) {
    current =
      siblingSides[i] === "left"
        ? await hashTransparencyNode(auditPath[i], current)
        : await hashTransparencyNode(current, auditPath[i]);
  }
  return current;
}

async function verifySnapshotRootSignature(
  root: Uint8Array,
  signature: Uint8Array,
  pinnedJwk: SnapshotSigningJwk,
): Promise<boolean> {
  try {
    const webCrypto = await getWebCrypto();
    const key = await webCrypto.subtle.importKey(
      "jwk",
      {
        kty: "OKP",
        crv: "Ed25519",
        x: pinnedJwk.x,
        ext: true,
        key_ops: ["verify"],
      },
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await webCrypto.subtle.verify(
      { name: "Ed25519" },
      key,
      ownedArrayBuffer(signature),
      ownedArrayBuffer(root),
    );
  } catch {
    return false;
  }
}

/**
 * Verify that receipt-derived data is included in an RFC 6962 Merkle root
 * authenticated by a caller-pinned Ed25519 snapshot key.
 *
 * This verifies inclusion only. It does not verify the receipt JWS signature;
 * use `verifyReceipt` separately for receipt authenticity.
 */
export async function verifyTransparencyLogInclusion(
  receiptJws: string,
  proof: TransparencyLogInclusionProof,
  snapshot: TransparencyLogSnapshot,
  snapshotJwk: SnapshotSigningJwk,
): Promise<TransparencyLogInclusionResult> {
  const claims = parseReceiptLeafClaims(receiptJws);
  if (claims === "malformed_jws") return { valid: false, reason: "malformed_jws" };
  if (!claims) return { valid: false, reason: "malformed_receipt_claims" };

  const checkedProof = validateProof(proof);
  if (!checkedProof) return { valid: false, reason: "malformed_proof" };
  const checkedSnapshot = validateSnapshot(snapshot);
  if (!checkedSnapshot) return { valid: false, reason: "malformed_snapshot" };
  const checkedJwk = validatePinnedJwk(snapshotJwk);
  if (!checkedJwk) return { valid: false, reason: "invalid_snapshot_key" };

  if (checkedProof.value.receipt_id !== claims.receiptId) {
    return { valid: false, reason: "receipt_proof_mismatch" };
  }
  if (
    checkedProof.value.snapshot_id !== checkedSnapshot.value.snapshot_id ||
    checkedProof.value.tree_size !== checkedSnapshot.value.tree_size ||
    !bytesEqual(checkedProof.root, checkedSnapshot.root)
  ) {
    return { valid: false, reason: "proof_snapshot_mismatch" };
  }
  if (checkedJwk.value.kid !== checkedSnapshot.value.snapshot_kid) {
    return { valid: false, reason: "snapshot_key_mismatch" };
  }

  const canonicalLeaf = `${claims.receiptId}|${claims.kid}|${claims.iat}|${claims.tenantId}`;
  const leafHash = await hashTransparencyLeaf(textEncoder.encode(canonicalLeaf));
  const calculatedRoot = await calculateTransparencyRoot(
    leafHash,
    checkedProof.auditPath,
    checkedProof.value.leaf_index,
    checkedProof.value.tree_size,
  );
  if (!calculatedRoot) return { valid: false, reason: "invalid_audit_path" };
  if (!bytesEqual(calculatedRoot, checkedSnapshot.root)) {
    return { valid: false, reason: "root_mismatch" };
  }
  if (
    !(await verifySnapshotRootSignature(
      checkedSnapshot.root,
      checkedSnapshot.signature,
      checkedJwk.value,
    ))
  ) {
    return { valid: false, reason: "snapshot_signature_invalid" };
  }

  return {
    valid: true,
    receipt_id: claims.receiptId,
    tenant_id: claims.tenantId,
    kid: claims.kid,
    iat: claims.iat,
    canonical_leaf: canonicalLeaf,
    leaf_hash: toHex(leafHash),
    root_hash: toHex(checkedSnapshot.root),
    leaf_index: checkedProof.value.leaf_index,
    tree_size: checkedProof.value.tree_size,
    snapshot_id: checkedSnapshot.value.snapshot_id,
    snapshot_kid: checkedSnapshot.value.snapshot_kid,
    root_authenticated: true,
    metadata_consistency_checked: true,
  };
}
