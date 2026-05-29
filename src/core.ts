/**
 * core.ts — the pure verification core.
 *
 * PORTED FAITHFULLY from the server's verifier so the SDK cannot drift:
 *  - `base64urlDecode`  ← adjuro/src/lib/jwk.ts
 *  - `decodeJwsHeader`  ← adjuro/src/lib/jws.ts
 *  - `verifyCore`       ← adjuro/src/lib/verify.ts :: verifyReceiptJws
 *                         (minus the DB-coupled default lookups, and minus the
 *                          revocation step which the caller performs last —
 *                          exactly where the server performs it).
 *
 * This file deliberately contains NO new cryptography. Signature verification is
 * `jose.compactVerify`, the same primitive the server and the in-browser widget use.
 */
import { compactVerify, importJWK } from "jose";
import type { JWK } from "jose";
import type { VerifyResult } from "./types.js";

/** Looks up the public JWK for a given `kid`. Returns `null` if unknown. */
export type JwkLookup = (kid: string) => Promise<JWK | null>;

type JwsHeader = { alg: string; kid: string; [k: string]: unknown };

// Ported verbatim from adjuro/src/lib/jwk.ts.
function base64urlDecode(str: string): Uint8Array {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const bin = atob(str.replaceAll("-", "+").replaceAll("_", "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Ported verbatim from adjuro/src/lib/jws.ts.
function decodeJwsHeader(jws: string): JwsHeader {
  const [headerB64] = jws.split(".");
  if (!headerB64) throw new Error("JWS missing header segment");
  const bytes = base64urlDecode(headerB64);
  return JSON.parse(new TextDecoder().decode(bytes)) as JwsHeader;
}

/**
 * Verify a compact JWS receipt against a JWK lookup. Performs, in order:
 * structural check → header parse → alg check → key lookup → Ed25519 signature
 * verification → payload parse → expiry check. Revocation is intentionally NOT
 * handled here; the caller checks it last (see index.ts), matching the server.
 *
 * `nowMs` is injectable purely so the expiry boundary is testable; it defaults to
 * the real clock, exactly like the server's `opts.nowMs ?? Date.now()`.
 */
export async function verifyCore(
  jws: string,
  jwkLookup: JwkLookup,
  nowMs: number = Date.now(),
): Promise<VerifyResult> {
  if (typeof jws !== "string" || jws.split(".").length !== 3) {
    return { valid: false, reason: "malformed_jws" };
  }

  let header: JwsHeader;
  try {
    header = decodeJwsHeader(jws);
  } catch {
    return { valid: false, reason: "malformed_jws" };
  }
  if (header.alg !== "EdDSA") {
    return { valid: false, reason: "alg_unsupported", kid: header.kid };
  }

  const jwk = await jwkLookup(header.kid);
  if (!jwk) return { valid: false, reason: "unknown_kid", kid: header.kid };

  const publicKey = await importJWK(jwk, "EdDSA");

  let payloadBytes: Uint8Array;
  try {
    ({ payload: payloadBytes } = await compactVerify(jws, publicKey));
  } catch {
    return { valid: false, reason: "signature_invalid", kid: header.kid };
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as Record<string, unknown>;
  } catch {
    return { valid: false, reason: "malformed_jws", kid: header.kid };
  }

  const nowSec = Math.floor(nowMs / 1000);
  if (typeof payload.exp === "number" && nowSec > payload.exp) {
    return { valid: false, reason: "expired", kid: header.kid, payload };
  }

  const receiptId =
    typeof payload.receipt_id === "string"
      ? payload.receipt_id
      : typeof payload.jti === "string"
        ? payload.jti
        : undefined;

  return {
    valid: true,
    kid: header.kid,
    receipt_id: receiptId,
    issued_at: typeof payload.issued_at === "string" ? payload.issued_at : undefined,
    expires_at: typeof payload.expires_at === "string" ? payload.expires_at : undefined,
    payload,
  };
}
