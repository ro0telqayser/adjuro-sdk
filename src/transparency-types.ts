/**
 * Public wire types for Adjuro transparency-log inclusion verification.
 *
 * The snapshot signature authenticates only `root_hash`. The remaining snapshot
 * metadata is checked for consistency between the proof, snapshot, and pinned key,
 * but is not covered by the current signature format.
 */

export type TransparencyLogVerifyReason =
  | "malformed_jws"
  | "malformed_receipt_claims"
  | "malformed_proof"
  | "malformed_snapshot"
  | "receipt_proof_mismatch"
  | "proof_snapshot_mismatch"
  | "invalid_audit_path"
  | "root_mismatch"
  | "invalid_snapshot_key"
  | "snapshot_key_mismatch"
  | "snapshot_signature_invalid";

/** Inclusion proof returned by the Adjuro transparency-log proof endpoint. */
export interface TransparencyLogInclusionProof {
  status: "included";
  receipt_id: string;
  leaf_index: number;
  leaf_hash: string;
  audit_path: string[];
  tree_size: number;
  snapshot_id: number;
  root_hash: string;
  leaf: string;
  leaf_format: string;
  format_version: "adjuro-transparency-log/1";
}

/** Snapshot returned by the Adjuro transparency-log snapshot endpoint. */
export interface TransparencyLogSnapshot {
  snapshot_id: number;
  tree_size: number;
  root_hash: string;
  snapshot_kid: string;
  signed_at: string;
  signature: string;
  signing_key_jwk?: Record<string, unknown> | null;
  format_version: "adjuro-transparency-log/1";
}

/** Caller-pinned Ed25519 public key used to authenticate the snapshot root. */
export interface SnapshotSigningJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  alg?: "EdDSA";
  use?: "sig";
  key_ops?: string[];
  [key: string]: unknown;
}

export interface TransparencyLogInclusionSuccess {
  valid: true;
  receipt_id: string;
  tenant_id: string;
  kid: string;
  iat: number;
  canonical_leaf: string;
  leaf_hash: string;
  root_hash: string;
  leaf_index: number;
  tree_size: number;
  snapshot_id: number;
  snapshot_kid: string;
  /** The snapshot signature cryptographically authenticates `root_hash` only. */
  root_authenticated: true;
  /** IDs, tree size, and kid agree across inputs but are not signed metadata. */
  metadata_consistency_checked: true;
}

export interface TransparencyLogInclusionFailure {
  valid: false;
  reason: TransparencyLogVerifyReason;
}

export type TransparencyLogInclusionResult =
  | TransparencyLogInclusionSuccess
  | TransparencyLogInclusionFailure;
