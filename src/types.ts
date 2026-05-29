/**
 * Public types for the `adjuro` verifier SDK.
 *
 * `VerifyResult` mirrors the server's verifier (adjuro/src/lib/verify.ts) exactly,
 * with one addition: `revoked` is set to `true` on the `reason: "revoked"` outcome.
 */

/**
 * Why a receipt did not verify. These map 1:1 to the server's reasons.
 *
 * The evidentiary distinction integrators must not miss:
 *  - `signature_invalid` → the receipt is FORGED or TAMPERED (the crypto fails).
 *  - `revoked`           → the signature is GENUINE, but the receipt was withdrawn
 *                          after issuance. The receipt was real; it is no longer in force.
 *  - `expired`           → the signature is GENUINE, but the receipt is past its `exp`.
 */
export type VerifyReason =
  | "malformed_jws"
  | "alg_unsupported"
  | "unknown_kid"
  | "signature_invalid"
  | "expired"
  | "revoked";

/** A JWK Set as published at `/.well-known/jwks.json`. */
export interface JWKSet {
  keys: Array<Record<string, unknown>>;
}

/**
 * The result of verifying a receipt.
 *
 * On success: `{ valid: true, kid, receipt_id, issued_at, expires_at, payload }`
 * — identical to the server's success shape.
 *
 * On failure: `{ valid: false, reason, ... }`. `kid` and `payload` are populated
 * when the failure occurred AFTER the signature verified (e.g. `expired`,
 * `revoked`) so callers can still read who signed it and what it said.
 */
export interface VerifyResult {
  /** `true` only if the signature verified AND the receipt is not expired/revoked. */
  valid: boolean;
  /** Present on every failure; absent on success. */
  reason?: VerifyReason;
  /** The signing key id from the JWS header (present once the header parsed). */
  kid?: string;
  /** The receipt id (`adj_rcpt_*`); equals the `jti` claim. */
  receipt_id?: string;
  /** ISO-8601 issuance time, from the `issued_at` claim. */
  issued_at?: string;
  /** ISO-8601 expiry time, from the `expires_at` claim. */
  expires_at?: string;
  /** `true` ONLY on `reason: "revoked"` — the signature was genuine but withdrawn. */
  revoked?: boolean;
  /** The decoded receipt payload (present once the signature verified). */
  payload?: Record<string, unknown>;
}

/** Options for {@link verifyReceipt}. */
export interface VerifyOptions {
  /**
   * Adjuro API origin used to fetch the JWKS and (optionally) revocation status.
   * Defaults to `https://api.adjuro.ai`.
   */
  baseUrl?: string;
  /**
   * Whether to check revocation via `GET /v1/revocations/:jti`. Defaults to `true`.
   * Set to `false` (together with a supplied `jwks`) to verify FULLY OFFLINE —
   * no network calls, no trust in Adjuro's servers at all.
   */
  checkRevocation?: boolean;
  /**
   * Pre-fetched public keys. When supplied, the SDK does NOT fetch the JWKS.
   * Combine with `checkRevocation: false` for fully-offline verification.
   */
  jwks?: JWKSet;
}
