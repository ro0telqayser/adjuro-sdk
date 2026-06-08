import { expect, test } from "bun:test";
import {
  calculateTransparencyRoot,
  hashTransparencyLeaf,
  hashTransparencyNode,
} from "../src/transparency.ts";
import vectors from "./fixtures/rfc6962-vectors.json";

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) =>
    Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16),
  );
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function directSha256(bytes: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer)));
}

async function treeRoot(rawLeaves: Uint8Array[]): Promise<Uint8Array> {
  if (rawLeaves.length === 1) return hashTransparencyLeaf(rawLeaves[0]);
  let split = 1;
  while (split * 2 < rawLeaves.length) split *= 2;
  return hashTransparencyNode(
    await treeRoot(rawLeaves.slice(0, split)),
    await treeRoot(rawLeaves.slice(split)),
  );
}

test("RFC 6962 vector provenance is pinned to the retrievable Google CT source", () => {
  expect(vectors._meta.normative_source).toBe(
    "https://www.rfc-editor.org/rfc/rfc6962#section-2.1",
  );
  expect(vectors._meta.source_commit).toBe("0fe5116f42890853e9fcf5120f1f5129d64f64ea");
  expect(vectors._meta.source_git_blob_sha).toBe("a7190477759808de4e8d8500861f2e1a912db065");
  expect(vectors._meta.source_sha256).toBe(
    "dd7e213247b60728e7bb1e00477ea3dc8c7da53fcf0d66a6e57ae8c102466e2b",
  );
});

test("RFC 6962 leaf vectors apply the 0x00 prefix exactly once", async () => {
  for (const vector of vectors.leaf_hashes) {
    const raw = fromHex(vector.data_hex);
    const prefixed = new Uint8Array(1 + raw.length);
    prefixed[0] = 0x00;
    prefixed.set(raw, 1);

    expect(toHex(await hashTransparencyLeaf(raw))).toBe(vector.hash_hex);
    expect(await directSha256(prefixed)).toBe(vector.hash_hex);
    expect(await directSha256(raw)).not.toBe(vector.hash_hex);

    const doublePrefixed = new Uint8Array(1 + 32);
    doublePrefixed[0] = 0x00;
    doublePrefixed.set(fromHex(vector.hash_hex), 1);
    expect(await directSha256(doublePrefixed)).not.toBe(vector.hash_hex);
  }
});

test("RFC 6962 node vector applies the 0x01 prefix exactly once", async () => {
  const left = fromHex(vectors.node_hash.left_hex);
  const right = fromHex(vectors.node_hash.right_hex);
  const prefixed = new Uint8Array(1 + left.length + right.length);
  prefixed[0] = 0x01;
  prefixed.set(left, 1);
  prefixed.set(right, 1 + left.length);

  expect(toHex(await hashTransparencyNode(left, right))).toBe(vectors.node_hash.hash_hex);
  expect(await directSha256(prefixed)).toBe(vectors.node_hash.hash_hex);

  const unprefixed = new Uint8Array(left.length + right.length);
  unprefixed.set(left);
  unprefixed.set(right, left.length);
  expect(await directSha256(unprefixed)).not.toBe(vectors.node_hash.hash_hex);
});

test("Google CT known roots cover one through eight leaves, including non-power-of-two trees", async () => {
  const leaves = vectors.tree_leaves_hex.map(fromHex);
  for (let size = 1; size <= leaves.length; size++) {
    expect(toHex(await treeRoot(leaves.slice(0, size)))).toBe(vectors.tree_roots_hex[size - 1]);
  }
});

test("Google CT large unbalanced-tree inclusion vector reaches the published root", async () => {
  const vector = vectors.inclusion;
  const root = await calculateTransparencyRoot(
    fromHex(vector.leaf_hash_hex),
    vector.audit_path_hex.map(fromHex),
    vector.leaf_index,
    vector.tree_size,
  );
  expect(root && toHex(root)).toBe(vector.root_hash_hex);
});
