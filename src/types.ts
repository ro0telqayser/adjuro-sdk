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
 *  - `expired`           → ONLY returned when the caller passed `requireUnexpired: true`,
 *                          i.e. it is acting as a pre-call authorization gate. Evidence
 *                          verification (the default) never returns this: a closed window
 *                          is reported via `authorization_window` on a SUCCESSFUL result.
 *                          Changed in 2.0.0 — see `authorization_window`.
 */
export type VerifyReason =
  | "malformed_jws"
  | "alg_unsupported"
  | "unknown_kid"
  | "signature_invalid"
  | "expired"
  | "revoked"
  // The four below apply ONLY to settlement receipts (`event_type:
  // "call_settlement"`). Mint-receipt verification is byte-for-byte unchanged.
  // This set MUST stay identical to the server's union — both are published
  // contracts, so a divergence means the SDK and the API disagree about the
  // same artifact.
  //  - `malformed_chain`        → a settlement receipt with no `parent_jti`.
  //  - `parent_not_found`       → the chain dangles, or no parent was supplied.
  //  - `parent_revoked`         → the parent was withdrawn; the leg it authorized falls with it.
  //  - `parent_tenant_mismatch` → the chain crosses tenants.
  | "malformed_chain"
  | "parent_not_found"
  | "parent_revoked"
  | "parent_tenant_mismatch";

/** A JWK Set as published at `/.well-known/jwks.json`. */
export interface JWKSet {
  keys: Array<Record<string, unknown>>;
}

/**
 * The result of verifying a receipt.
 *
 * On success: `{ valid: true, kid, receipt_id, attestation_id, authorization_window,
 * authorization_expired_at?, brand_verified, trust_tier, issued_at, expires_at, payload }`
 * — the server's success shape, with ONE deliberate difference.
 *
 * THE ONE DIFFERENCE: the SDK does not return `key_status`. JWKS carries no status
 * field, so an offline verifier cannot know whether a key is `active`, `rotating`
 * or `retired`. That is sound rather than a gap — a de-listed key stops being
 * published, so the SDK reaches `unknown_kid` exactly where the server reports
 * `key_revoked`. There is no honest way to derive it offline, so it is omitted
 * rather than guessed.
 *
 * On failure: `{ valid: false, reason, ... }`. `kid` and `payload` are populated
 * when the failure occurred AFTER the signature verified (e.g. `revoked`) so
 * callers can still read who signed it and what it said.
 */
export interface VerifyResult {
  /** `true` if the signature verified AND the receipt is not revoked. A CLOSED
   * authorization window does not make this false — see `authorization_window`. */
  valid: boolean;
  /** Present on every failure; absent on success. */
  reason?: VerifyReason;
  /** The signing key id from the JWS header (present once the header parsed). */
  kid?: string;
  /** The receipt id (`adj_rcpt_*`); equals the `jti` claim. Same value as
   * `attestation_id` — both spellings are populated on every success. */
  receipt_id?: string;
  /** The same id under its current name. Artifacts issued before the rename spell
   * the claim `receipt_id` in their signed payload, so both fields stay forever. */
  attestation_id?: string;
  /**
   * Whether the 24h authorization window (the `exp` claim) is still open.
   *
   * `"closed"` is NOT a failure and never makes `valid` false. A mint receipt
   * stops authorizing new calls after `exp`, but it never stops being evidence
   * that the call WAS authorized — and that is what a compliance reader is
   * checking, years later. Receipts with no `exp` (settlement receipts) report
   * `"open"`.
   *
   * Running a real-time pre-call gate instead of verifying evidence? Pass
   * `requireUnexpired: true` and a closed window becomes
   * `{ valid: false, reason: "expired" }`.
   */
  authorization_window?: "open" | "closed";
  /** ISO-8601 instant the authorization window closed; absent while it is open. */
  authorization_expired_at?: string;
  /**
   * Whether Adjuro vouched for the asserted `brand`, from the signed claim.
   *
   * `valid` is SIGNATURE-ONLY. Trust the brand if and only if this is `true`. A
   * genuine signature on a `brand_verified: false` receipt means the signature is
   * real but Adjuro has not verified who the brand is — checking only `valid` is
   * exactly how brand spoofing gets through. Fails closed: a missing or
   * merely-truthy claim reads `false`.
   */
  brand_verified?: boolean;
  /** Display-only trust tier from the signed claim; `"unverified"` when absent. */
  trust_tier?: string;
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
  /**
   * Opt in to pre-call GATE semantics: a receipt past its `exp` is rejected with
   * `reason: "expired"`. Defaults to `false`, which is EVIDENCE semantics — the
   * signature is what is being checked, and a closed window is reported via
   * `authorization_window` rather than failing verification.
   *
   * Set this ONLY if you are deciding whether a receipt may authorize a call
   * RIGHT NOW. If you are checking whether a call WAS authorized — an audit, a
   * compliance review, a courtroom — leave it unset.
   *
   * It does not propagate to the parent leg of a settlement chain: that parent is
   * being checked as evidence that the chain is genuine, not as authorization for
   * a new call.
   */
  requireUnexpired?: boolean;
  /**
   * The mint receipt this settlement receipt chains to, as a compact JWS.
   *
   * REQUIRED to verify an `event_type: "call_settlement"` receipt; ignored for
   * mint receipts. Passed in rather than fetched so verification stays offline —
   * an `adjuro-audit-packet/2` ZIP ships both `.jws` files side by side, so the
   * caller already holds it. Fetching the parent would put a network round-trip
   * (and trust in Adjuro's server) back into the one code path whose entire
   * purpose is to need neither.
   *
   * Its signature is VERIFIED, not merely decoded — see the chain block in
   * index.ts for why that distinction is load-bearing.
   */
  parentJws?: string;
}
