/**
 * adjuro — independent verifier for Adjuro Ed25519 receipts.
 *
 *   import { verifyReceipt } from "adjuro";
 *   const result = await verifyReceipt(receiptJws);
 *
 * TRUST MODEL — read this once:
 *   Signature verification is LOCAL. The SDK fetches Adjuro's PUBLIC signing keys
 *   (JWKS) and verifies the Ed25519 signature itself with `jose.compactVerify`. It
 *   never calls Adjuro's `/v1/verify` and trusts the answer — that would defeat
 *   independent verifiability. Only two things ever contact Adjuro: fetching the
 *   JWKS (public, cacheable, pinnable) and checking revocation (dynamic, optional).
 *
 *   With `{ jwks, checkRevocation: false }` the SDK verifies FULLY OFFLINE — no
 *   network, no trust in Adjuro at all. That is the strongest form of the guarantee.
 */
import type { JWK } from "jose";
import { verifyCore } from "./core.js";
import { fetchJwks } from "./jwks.js";
import { checkRevocation } from "./revocation.js";
import { verifyTransparencyLogInclusion } from "./transparency.js";
import type { JWKSet, VerifyOptions, VerifyReason, VerifyResult } from "./types.js";
import type { TransparencyLogVerifyReason } from "./transparency-types.js";

const DEFAULT_BASE_URL = "https://api.adjuro.ai";

/** The full set of failure reasons. Exported as a runtime contract. */
export const VERIFY_REASONS: readonly VerifyReason[] = [
  "malformed_jws",
  "alg_unsupported",
  "unknown_kid",
  "signature_invalid",
  "expired",
  "revoked",
  "malformed_chain",
  "parent_not_found",
  "parent_revoked",
  "parent_tenant_mismatch",
] as const;

/** The full set of transparency-log verification failure reasons. */
export const TRANSPARENCY_LOG_VERIFY_REASONS: readonly TransparencyLogVerifyReason[] = [
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
] as const;

/** Discriminator for the second signed leg. Mirrors the server's verify.ts. */
const SETTLEMENT_EVENT_TYPE = "call_settlement";

/**
 * Verify an Adjuro receipt JWS.
 *
 * @param jws  The compact JWS receipt string (`header.payload.signature`).
 * @param opts See {@link VerifyOptions}.
 * @returns    A {@link VerifyResult}. `valid: true` means the signature verified
 *             AND the receipt is neither expired nor revoked.
 *
 * @example Online (default) — fetches keys + checks revocation:
 *   const r = await verifyReceipt(jws);
 *
 * @example Fully offline — no network, no trust in Adjuro:
 *   const r = await verifyReceipt(jws, { jwks, checkRevocation: false });
 */
export async function verifyReceipt(jws: string, opts: VerifyOptions = {}): Promise<VerifyResult> {
  const baseUrl = opts.baseUrl ?? DEFAULT_BASE_URL;
  const shouldCheckRevocation = opts.checkRevocation ?? true;

  const jwks: JWKSet = opts.jwks ?? (await fetchJwks(baseUrl));
  const jwkLookup = async (kid: string): Promise<JWK | null> => {
    const match = (jwks.keys ?? []).find((k) => (k as { kid?: string }).kid === kid);
    return (match as JWK | undefined) ?? null;
  };

  // Steps a–e + result shape: ported verbatim from the server (see core.ts).
  const result = await verifyCore(jws, jwkLookup);

  // Revocation is checked LAST and only on an otherwise-valid receipt carrying a
  // jti — the same placement and guard as the server's verifyReceiptJws.
  if (result.valid && shouldCheckRevocation) {
    const jti = typeof result.payload?.jti === "string" ? result.payload.jti : "";
    if (jti.length > 0) {
      const rev = await checkRevocation(jti, baseUrl);
      if (rev.revoked) {
        // Signature was GENUINE; the receipt was withdrawn after issuance.
        return {
          valid: false,
          reason: "revoked",
          kid: result.kid,
          payload: result.payload,
          revoked: true,
        };
      }
    }
  }

  if (!result.valid) return result;

  // ── Chain validation — settlement receipts ONLY ────────────────────────────
  // A settlement receipt's signature proves Adjuro issued it, but the artifact's
  // claim is RELATIONAL: "this call was placed by the agent that consent record X
  // authorized". A valid signature over a dangling, revoked, or cross-tenant
  // parent asserts a binding that does not exist. Gated on event_type so mint
  // verification is completely untouched.
  if (result.payload?.event_type === SETTLEMENT_EVENT_TYPE) {
    const parentJti = result.payload.parent_jti;
    // Distinct from parent_not_found: this receipt never named a parent at all,
    // which is a defect in the artifact rather than a failure to resolve it.
    if (typeof parentJti !== "string" || parentJti.length === 0) {
      return { valid: false, reason: "malformed_chain", kid: result.kid, payload: result.payload };
    }
    if (!opts.parentJws) {
      return { valid: false, reason: "parent_not_found", kid: result.kid, payload: result.payload };
    }

    // VERIFY the parent — do not merely decode it. The server resolves the parent
    // from its own trusted database row; the SDK is handed bytes by the caller,
    // who may be the adversary. Decoding without verifying would let anyone mint a
    // plausible-looking parent and make ANY settlement receipt verify, which would
    // make this whole block decorative.
    //
    // `parentJws: undefined` on the recursive call bounds the recursion at one
    // level. A mint receipt carries no `event_type: "call_settlement"` so it never
    // re-enters this branch, but the depth is pinned explicitly rather than left
    // to depend on that.
    const parent = await verifyReceipt(opts.parentJws, { ...opts, parentJws: undefined });
    if (!parent.valid) {
      return {
        valid: false,
        // A revoked parent gets its own verdict. If the settlement leg survived
        // its parent's revocation, withdrawing consent would be defeated by
        // pointing at the settlement receipt instead of the mint receipt.
        reason: parent.reason === "revoked" ? "parent_revoked" : "parent_not_found",
        kid: result.kid,
        payload: result.payload,
      };
    }

    // The verified parent must be the one this receipt actually names, otherwise a
    // genuine parent for an unrelated call would satisfy the chain.
    if (parent.payload?.jti !== parentJti) {
      return { valid: false, reason: "parent_not_found", kid: result.kid, payload: result.payload };
    }

    // Without this a settlement receipt could name ANOTHER tenant's mint receipt
    // and inherit the authorization that receipt carries.
    if (
      typeof result.payload.tenant_id === "string" &&
      parent.payload?.tenant_id !== result.payload.tenant_id
    ) {
      return {
        valid: false,
        reason: "parent_tenant_mismatch",
        kid: result.kid,
        payload: result.payload,
      };
    }
  }

  return result;
}

export type { VerifyResult, VerifyReason, VerifyOptions, JWKSet } from "./types.js";
export { verifyTransparencyLogInclusion };
export type {
  SnapshotSigningJwk,
  TransparencyLogInclusionFailure,
  TransparencyLogInclusionProof,
  TransparencyLogInclusionResult,
  TransparencyLogInclusionSuccess,
  TransparencyLogSnapshot,
  TransparencyLogVerifyReason,
} from "./transparency-types.js";
