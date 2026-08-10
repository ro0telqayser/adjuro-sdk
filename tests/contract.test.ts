import { expect, test } from "bun:test";
import { verifyReceipt, VERIFY_REASONS } from "../src/index.ts";
import fixture from "./fixtures/known-receipt.json";

// These tests PIN the public contract. They are designed to fail loudly the
// moment a change would break a deployed verifier or diverge from the server.

const SUCCESS_KEYS = [
  "valid",
  "kid",
  "receipt_id",
  "issued_at",
  "expires_at",
  "payload",
].sort();

// Frozen receipt claim set — must match adjuro/src/lib/receipt-issuer.ts.
// "Changing any field name after V0 ships breaks every deployed verifier."
const RECEIPT_CLAIMS = [
  "iss",
  "jti",
  "iat",
  "exp",
  "issued_by",
  "receipt_id",
  "issued_at",
  "expires_at",
  "tenant_id",
  "trust_root_id",
  "agent_id",
  "brand",
  "event_type",
  "caller_number",
  "callee_hash",
  "campaign_id",
  "consent_id",
  "scope",
  "jurisdiction",
  "nonce",
].sort();

// WIDENED deliberately in 1.4.0 for settlement-chain verification. The four
// `parent_*`/`malformed_chain` members apply ONLY to settlement receipts
// (`event_type: "call_settlement"`); mint-receipt verification is unchanged, which
// the "a MINT receipt never enters the chain path" test pins independently.
//
// This list must stay identical to the SERVER's union in src/lib/verify.ts — both
// are published contracts, so drift means the SDK and the API disagree about the
// same artifact. Adding a member here without adding it there is a bug.
const REASONS = [
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
].sort();

test("CONTRACT: a valid VerifyResult has exactly the server's success keys", async () => {
  const result = await verifyReceipt(fixture.jws, {
    jwks: fixture.jwks,
    checkRevocation: false,
  });
  expect(Object.keys(result).sort()).toEqual(SUCCESS_KEYS);
});

test("CONTRACT: success result is STRICTLY equal to the server-produced fixture", async () => {
  const result = await verifyReceipt(fixture.jws, {
    jwks: fixture.jwks,
    checkRevocation: false,
  });
  expect(result).toStrictEqual(fixture.expected);
});

test("CONTRACT: the receipt claim names are frozen", () => {
  expect(Object.keys(fixture.expected.payload).sort()).toEqual(RECEIPT_CLAIMS);
});

test("CONTRACT: the VerifyReason set is frozen and exported", () => {
  expect([...VERIFY_REASONS].sort()).toEqual(REASONS);
});
