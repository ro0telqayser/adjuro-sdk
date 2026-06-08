import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { verifyTransparencyLogInclusion } from "adjuro";

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

const receiptId = "adj_rcpt_pack_smoke";
const receiptKid = "adjuro-root-pack-smoke";
const tenantId = "tenant-pack-smoke";
const iat = 1_747_000_000;
const header = base64url(JSON.stringify({ alg: "EdDSA", kid: receiptKid }));
const payload = base64url(
  JSON.stringify({ receipt_id: receiptId, jti: receiptId, tenant_id: tenantId, iat }),
);
const receiptKeys = generateKeyPairSync("ed25519");
const receiptSignature = sign(
  null,
  Buffer.from(`${header}.${payload}`, "ascii"),
  receiptKeys.privateKey,
);
const receiptJws = `${header}.${payload}.${base64url(receiptSignature)}`;

const canonicalLeaf = `${receiptId}|${receiptKid}|${iat}|${tenantId}`;
const root = createHash("sha256")
  .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalLeaf, "utf8")]))
  .digest();

const snapshotKid = "adjuro-log-snapshot-pack-smoke";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const snapshotJwk = {
  ...publicKey.export({ format: "jwk" }),
  kid: snapshotKid,
  alg: "EdDSA",
  use: "sig",
  key_ops: ["verify"],
};
const signature = sign(null, root, privateKey);

const proof = {
  status: "included",
  receipt_id: receiptId,
  leaf_index: 0,
  leaf_hash: "ignored",
  audit_path: [],
  tree_size: 1,
  snapshot_id: 1,
  root_hash: root.toString("hex"),
  leaf: "ignored",
  leaf_format: "<receipt_id>|<kid>|<iat_sec>|<tenant_id>",
  format_version: "adjuro-transparency-log/1",
};
const snapshot = {
  snapshot_id: 1,
  tree_size: 1,
  root_hash: root.toString("hex"),
  snapshot_kid: snapshotKid,
  signed_at: "2026-06-08T00:00:00.000Z",
  signature: base64url(signature),
  signing_key_jwk: { kty: "OKP", crv: "Ed25519", x: "ignored" },
  format_version: "adjuro-transparency-log/1",
};

const result = await verifyTransparencyLogInclusion(receiptJws, proof, snapshot, snapshotJwk);
if (!result.valid || result.root_hash !== root.toString("hex")) {
  throw new Error(`installed package smoke failed: ${JSON.stringify(result)}`);
}

console.log(`adjuro installed-package smoke passed on ${process.version}`);
