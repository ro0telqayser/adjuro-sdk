import { expect, test } from "bun:test";
import { verifyReceipt } from "../src/index.ts";
import vectors from "./fixtures/settlement-receipt-v1.json";
import { jwksOf, makeKey, sign, signRaw } from "./helpers/sign.ts";

// The cross-implementation contract with the server's buildSettlementPayload.
//
// These vectors freeze the EXACT signed byte string — signing is
// JSON.stringify(payload), so claim ORDER is part of the format and reordering two
// claims changes every signature ever produced. We sign each frozen `preimage`
// VERBATIM (signRaw, never re-stringify: a round-trip through JSON.parse would
// silently "fix" the very byte order under test) and assert the verifier's verdict.
//
// A verifier has no payload builder, so what these gate is that the SDK reads the
// right claims out of genuinely canonical bytes — not that it can reproduce them.

type Vector = { name: string; preimage: string };

test("every frozen vector is exercised", () => {
  // Guards against a vector being added upstream and silently never run here.
  expect((vectors as Vector[]).length).toBe(3);
});

for (const [i, vector] of (vectors as Vector[]).entries()) {
  test(`vector ${i}: ${vector.name}`, async () => {
    const claims = JSON.parse(vector.preimage) as Record<string, unknown>;
    const key = await makeKey("adjuro-root-test");

    const parent = await sign(key, {
      jti: claims.parent_jti,
      event_type: "voice_call",
      tenant_id: claims.tenant_id,
    });
    const jws = await signRaw(key, vector.preimage);

    const result = await verifyReceipt(jws, {
      jwks: jwksOf(key),
      checkRevocation: false,
      parentJws: parent,
    });

    expect(result.valid).toBe(true);
    // The claims a third party reads OFF the receipt to make the evidentiary
    // argument. If the SDK cannot surface these, the artifact is not evidence.
    expect(result.payload?.parent_jti).toBe(claims.parent_jti);
    expect(result.payload?.vapi_call_id).toBe(claims.vapi_call_id);
    expect(result.payload?.recording_sha256).toBe(claims.recording_sha256);
    // Evidence cannot expire — a settlement receipt is a permanent attestation
    // about a call that already happened.
    expect(result.payload?.exp).toBeUndefined();
  });
}

test("an unanswered call with NO recording still verifies", async () => {
  // The enrichment-not-precondition rule. Voicemail and no-answer seal with a null
  // digest; if that read as invalid, every unanswered call would look like a
  // verification failure rather than a normal outcome.
  const v = (vectors as Vector[]).find((x) => JSON.parse(x.preimage).recording_sha256 === null);
  expect(v).toBeDefined();

  const claims = JSON.parse(v!.preimage) as Record<string, unknown>;
  const key = await makeKey("adjuro-root-test");
  const parent = await sign(key, {
    jti: claims.parent_jti, event_type: "voice_call", tenant_id: claims.tenant_id,
  });

  const result = await verifyReceipt(await signRaw(key, v!.preimage), {
    jwks: jwksOf(key), checkRevocation: false, parentJws: parent,
  });

  expect(result.valid).toBe(true);
  expect(result.payload?.recording_sha256).toBeNull();
});
