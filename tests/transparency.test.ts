import { expect, test } from "bun:test";
import { CompactSign, exportJWK, generateKeyPair } from "jose";
import {
  TRANSPARENCY_LOG_VERIFY_REASONS,
  verifyTransparencyLogInclusion,
  type SnapshotSigningJwk,
  type TransparencyLogInclusionProof,
  type TransparencyLogSnapshot,
} from "../src/index.ts";

const encoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function digest(input: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(input).buffer));
}

async function leaf(raw: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(1 + raw.length);
  input[0] = 0x00;
  input.set(raw, 1);
  return digest(input);
}

async function node(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(65);
  input[0] = 0x01;
  input.set(left, 1);
  input.set(right, 33);
  return digest(input);
}

function splitFor(size: number): number {
  let split = 1;
  while (split * 2 < size) split *= 2;
  return split;
}

async function rootOf(hashes: Uint8Array[]): Promise<Uint8Array> {
  if (hashes.length === 1) return hashes[0];
  const split = splitFor(hashes.length);
  return node(await rootOf(hashes.slice(0, split)), await rootOf(hashes.slice(split)));
}

async function proofOf(hashes: Uint8Array[], index: number): Promise<Uint8Array[]> {
  if (hashes.length === 1) return [];
  const split = splitFor(hashes.length);
  if (index < split) {
    return [...(await proofOf(hashes.slice(0, split), index)), await rootOf(hashes.slice(split))];
  }
  return [
    ...(await proofOf(hashes.slice(split), index - split)),
    await rootOf(hashes.slice(0, split)),
  ];
}

type Fixture = {
  jws: string;
  proof: TransparencyLogInclusionProof;
  snapshot: TransparencyLogSnapshot;
  snapshotJwk: SnapshotSigningJwk;
};

async function createFixture(treeSize = 5, leafIndex = treeSize - 1): Promise<Fixture> {
  const receiptId = "adj_rcpt_transparency_test";
  const receiptKid = "adjuro-root-test";
  const tenantId = "tenant-test";
  const iat = 1_747_000_000;
  const claims = { receipt_id: receiptId, jti: receiptId, tenant_id: tenantId, iat };

  const receiptKeys = await generateKeyPair("EdDSA");
  const jws = await new CompactSign(encoder.encode(JSON.stringify(claims)))
    .setProtectedHeader({ alg: "EdDSA", kid: receiptKid, typ: "JWT" })
    .sign(receiptKeys.privateKey);

  const canonical = `${receiptId}|${receiptKid}|${iat}|${tenantId}`;
  const rawLeaves = Array.from({ length: treeSize }, (_, index) =>
    encoder.encode(index === leafIndex ? canonical : `unrelated-leaf-${index}`),
  );
  const hashes = await Promise.all(rawLeaves.map(leaf));
  const root = await rootOf(hashes);
  const auditPath = await proofOf(hashes, leafIndex);

  const snapshotKid = "adjuro-log-snapshot-test";
  const snapshotKeys = await generateKeyPair("EdDSA", { extractable: true });
  const publicJwk = await exportJWK(snapshotKeys.publicKey);
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "Ed25519" },
      snapshotKeys.privateKey,
      Uint8Array.from(root).buffer,
    ),
  );
  const snapshotJwk: SnapshotSigningJwk = {
    ...publicJwk,
    kty: "OKP",
    crv: "Ed25519",
    kid: snapshotKid,
    alg: "EdDSA",
    use: "sig",
    key_ops: ["verify"],
  };

  const snapshot: TransparencyLogSnapshot = {
    snapshot_id: 7,
    tree_size: treeSize,
    root_hash: toHex(root),
    snapshot_kid: snapshotKid,
    signed_at: "2026-06-08T00:00:00.000Z",
    signature: base64url(signature),
    signing_key_jwk: { ...snapshotJwk, x: "ignored-embedded-key" },
    format_version: "adjuro-transparency-log/1",
  };
  const proof: TransparencyLogInclusionProof = {
    status: "included",
    receipt_id: receiptId,
    leaf_index: leafIndex,
    leaf_hash: toHex(hashes[leafIndex]),
    audit_path: auditPath.map(toHex),
    tree_size: treeSize,
    snapshot_id: snapshot.snapshot_id,
    root_hash: snapshot.root_hash,
    leaf: canonical,
    leaf_format: "<receipt_id>|<kid>|<iat_sec>|<tenant_id>",
    format_version: "adjuro-transparency-log/1",
  };

  return { jws, proof, snapshot, snapshotJwk };
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function replaceJwsPayload(jws: string, mutate: (payload: Record<string, unknown>) => void): string {
  const parts = jws.split(".");
  const payload = JSON.parse(
    new TextDecoder().decode(Uint8Array.from(atob(parts[1].replaceAll("-", "+").replaceAll("_", "/") + "=="), (c) => c.charCodeAt(0))),
  ) as Record<string, unknown>;
  mutate(payload);
  parts[1] = base64url(encoder.encode(JSON.stringify(payload)));
  return parts.join(".");
}

function replaceJwsHeader(jws: string, mutate: (header: Record<string, unknown>) => void): string {
  const parts = jws.split(".");
  const header = JSON.parse(
    new TextDecoder().decode(Uint8Array.from(atob(parts[0].replaceAll("-", "+").replaceAll("_", "/") + "=="), (c) => c.charCodeAt(0))),
  ) as Record<string, unknown>;
  mutate(header);
  parts[0] = base64url(encoder.encode(JSON.stringify(header)));
  return parts.join(".");
}

async function reasonFor(fixture: Fixture): Promise<string | undefined> {
  const result = await verifyTransparencyLogInclusion(
    fixture.jws,
    fixture.proof,
    fixture.snapshot,
    fixture.snapshotJwk,
  );
  return result.valid ? undefined : result.reason;
}

test("exports the transparency failure-reason runtime contract", () => {
  expect(TRANSPARENCY_LOG_VERIFY_REASONS).toEqual([
    "malformed_jws",
    "malformed_receipt_claims",
    "malformed_proof",
    "malformed_snapshot",
    "receipt_proof_mismatch",
    "proof_snapshot_mismatch",
    "invalid_audit_path",
    "root_mismatch",
    "invalid_snapshot_key",
    "snapshot_key_mismatch",
    "snapshot_signature_invalid",
  ]);
});

test("verifies a valid inclusion and accurately describes the trust boundary", async () => {
  const fixture = await createFixture();
  const result = await verifyTransparencyLogInclusion(
    fixture.jws,
    fixture.proof,
    fixture.snapshot,
    fixture.snapshotJwk,
  );

  expect(result).toMatchObject({
    valid: true,
    receipt_id: "adj_rcpt_transparency_test",
    tenant_id: "tenant-test",
    kid: "adjuro-root-test",
    iat: 1_747_000_000,
    tree_size: 5,
    leaf_index: 4,
    root_authenticated: true,
    metadata_consistency_checked: true,
  });
});

test("verifies single-leaf and multiple non-power-of-two tree positions", async () => {
  for (const [treeSize, leafIndex] of [
    [1, 0],
    [3, 0],
    [3, 2],
    [5, 1],
    [5, 4],
    [6, 5],
    [7, 3],
  ]) {
    expect(await reasonFor(await createFixture(treeSize, leafIndex))).toBeUndefined();
  }
});

test("never trusts proof leaf or leaf_hash", async () => {
  const fixture = await createFixture();
  fixture.proof.leaf = "attacker-controlled";
  fixture.proof.leaf_hash = "00".repeat(32);
  expect(await reasonFor(fixture)).toBeUndefined();
});

test("receipt signature validity remains the separate verifyReceipt responsibility", async () => {
  const fixture = await createFixture();
  const parts = fixture.jws.split(".");
  parts[2] = `${parts[2][0] === "A" ? "B" : "A"}${parts[2].slice(1)}`;
  fixture.jws = parts.join(".");
  expect(await reasonFor(fixture)).toBeUndefined();
});

test("rejects JWS-derived leaf tampering", async () => {
  const base = await createFixture();
  for (const mutate of [
    (fixture: Fixture) => {
      fixture.jws = replaceJwsPayload(fixture.jws, (payload) => {
        payload.tenant_id = "other-tenant";
      });
    },
    (fixture: Fixture) => {
      fixture.jws = replaceJwsPayload(fixture.jws, (payload) => {
        payload.iat = 1_747_000_001;
      });
    },
    (fixture: Fixture) => {
      fixture.jws = replaceJwsHeader(fixture.jws, (header) => {
        header.kid = "other-receipt-key";
      });
    },
  ]) {
    const fixture = clone(base);
    mutate(fixture);
    expect(await reasonFor(fixture)).toBe("root_mismatch");
  }

  const receiptMismatch = clone(base);
  receiptMismatch.jws = replaceJwsPayload(receiptMismatch.jws, (payload) => {
    payload.receipt_id = "adj_rcpt_other";
    payload.jti = "adj_rcpt_other";
  });
  expect(await reasonFor(receiptMismatch)).toBe("receipt_proof_mismatch");
});

test("rejects tampered audit node, index, tree size, root, and snapshot id", async () => {
  const base = await createFixture();

  const auditNode = clone(base);
  auditNode.proof.audit_path[0] =
    (auditNode.proof.audit_path[0][0] === "0" ? "1" : "0") +
    auditNode.proof.audit_path[0].slice(1);
  expect(await reasonFor(auditNode)).toBe("root_mismatch");

  const index = clone(base);
  index.proof.leaf_index = 3;
  expect(await reasonFor(index)).toBe("invalid_audit_path");

  const size = clone(base);
  size.proof.tree_size++;
  expect(await reasonFor(size)).toBe("proof_snapshot_mismatch");

  const root = clone(base);
  root.proof.root_hash = "00".repeat(32);
  expect(await reasonFor(root)).toBe("proof_snapshot_mismatch");

  const snapshotRoot = clone(base);
  snapshotRoot.snapshot.root_hash = "00".repeat(32);
  expect(await reasonFor(snapshotRoot)).toBe("proof_snapshot_mismatch");

  const snapshotId = clone(base);
  snapshotId.proof.snapshot_id++;
  expect(await reasonFor(snapshotId)).toBe("proof_snapshot_mismatch");
});

test("rejects tampered signature and signing key", async () => {
  const base = await createFixture();

  const signature = clone(base);
  signature.snapshot.signature =
    (signature.snapshot.signature[0] === "A" ? "B" : "A") + signature.snapshot.signature.slice(1);
  expect(await reasonFor(signature)).toBe("snapshot_signature_invalid");

  const other = await createFixture();
  const signingKey = clone(base);
  signingKey.snapshotJwk = { ...other.snapshotJwk, kid: base.snapshot.snapshot_kid };
  expect(await reasonFor(signingKey)).toBe("snapshot_signature_invalid");

  const keyId = clone(base);
  keyId.snapshotJwk.kid = "other-snapshot-key";
  expect(await reasonFor(keyId)).toBe("snapshot_key_mismatch");
});

test("strictly validates pinned Ed25519 JWK metadata", async () => {
  const base = await createFixture();
  const invalidKeys: Array<Partial<SnapshotSigningJwk>> = [
    { kty: "EC" as "OKP" },
    { crv: "X25519" as "Ed25519" },
    { x: base64url(new Uint8Array(31)) },
    { x: `${base.snapshotJwk.x}=` },
    { alg: "ES256" as "EdDSA" },
    { use: "enc" as "sig" },
    { key_ops: ["sign"] },
    { key_ops: "verify" as unknown as string[] },
  ];
  for (const patch of invalidKeys) {
    const fixture = clone(base);
    fixture.snapshotJwk = { ...fixture.snapshotJwk, ...patch };
    expect(await reasonFor(fixture)).toBe("invalid_snapshot_key");
  }
});

test("rejects malformed hex/base64url, indices, claims, and path lengths", async () => {
  const base = await createFixture();

  const malformedHex = clone(base);
  malformedHex.proof.audit_path[0] = "zz";
  expect(await reasonFor(malformedHex)).toBe("malformed_proof");

  const malformedRoot = clone(base);
  malformedRoot.snapshot.root_hash = "0".repeat(63);
  expect(await reasonFor(malformedRoot)).toBe("malformed_snapshot");

  const malformedSignature = clone(base);
  malformedSignature.snapshot.signature += "=";
  expect(await reasonFor(malformedSignature)).toBe("malformed_snapshot");

  const shortReceiptSignature = clone(base);
  shortReceiptSignature.jws = shortReceiptSignature.jws.replace(/\.[^.]+$/, ".AA");
  expect(await reasonFor(shortReceiptSignature)).toBe("malformed_jws");

  const unsupportedReceiptAlgorithm = clone(base);
  unsupportedReceiptAlgorithm.jws = replaceJwsHeader(
    unsupportedReceiptAlgorithm.jws,
    (header) => {
      header.alg = "HS256";
    },
  );
  expect(await reasonFor(unsupportedReceiptAlgorithm)).toBe("malformed_jws");

  const zeroSnapshotId = clone(base);
  zeroSnapshotId.proof.snapshot_id = 0;
  zeroSnapshotId.snapshot.snapshot_id = 0;
  expect(await reasonFor(zeroSnapshotId)).toBe("malformed_proof");

  const outOfRange = clone(base);
  outOfRange.proof.leaf_index = outOfRange.proof.tree_size;
  expect(await reasonFor(outOfRange)).toBe("invalid_audit_path");

  const shortPath = clone(base);
  shortPath.proof.audit_path.pop();
  expect(await reasonFor(shortPath)).toBe("invalid_audit_path");

  const longPath = clone(base);
  longPath.proof.audit_path.push("00".repeat(32));
  expect(await reasonFor(longPath)).toBe("invalid_audit_path");

  const nonNumericIat = clone(base);
  nonNumericIat.jws = replaceJwsPayload(nonNumericIat.jws, (payload) => {
    payload.iat = "1747000000";
  });
  expect(await reasonFor(nonNumericIat)).toBe("malformed_receipt_claims");

  const delimiter = clone(base);
  delimiter.jws = replaceJwsPayload(delimiter.jws, (payload) => {
    payload.tenant_id = "tenant|injected";
  });
  expect(await reasonFor(delimiter)).toBe("malformed_receipt_claims");

  expect(
    (
      await verifyTransparencyLogInclusion(
        "not.a.valid.jws",
        base.proof,
        base.snapshot,
        base.snapshotJwk,
      )
    ).valid,
  ).toBe(false);
});
