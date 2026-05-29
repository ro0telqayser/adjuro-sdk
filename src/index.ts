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
import type { JWKSet, VerifyOptions, VerifyReason, VerifyResult } from "./types.js";

const DEFAULT_BASE_URL = "https://api.adjuro.ai";

/** The full set of failure reasons. Exported as a runtime contract. */
export const VERIFY_REASONS: readonly VerifyReason[] = [
  "malformed_jws",
  "alg_unsupported",
  "unknown_kid",
  "signature_invalid",
  "expired",
  "revoked",
] as const;

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

  return result;
}

export type { VerifyResult, VerifyReason, VerifyOptions, JWKSet } from "./types.js";
