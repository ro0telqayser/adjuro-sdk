import { afterEach, expect, test } from "bun:test";
import { verifyReceipt } from "../src/index.ts";
import { _clearJwksCache } from "../src/jwks.ts";
import fixture from "./fixtures/known-receipt.json";

const JTI = "adj_rcpt_x9k2tqp4f7a3w1n5b8c2d6e3";

let origFetch: typeof fetch;
afterEach(() => {
  if (origFetch) globalThis.fetch = origFetch;
  _clearJwksCache();
});

function mockRevocation(revoked: boolean): void {
  origFetch = globalThis.fetch;
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
    const url = String(input);
    if (url.includes(`/v1/revocations/${JTI}`)) {
      return new Response(
        JSON.stringify(
          revoked
            ? { jti: JTI, revoked: true, revoked_at: "2026-05-28T12:00:00.000Z" }
            : { jti: JTI, revoked: false, revoked_at: null },
        ),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected fetch: ${url}`);
  }) as typeof fetch;
}

// THE product nuance: a revoked receipt's signature is GENUINE. The math passes;
// the receipt was withdrawn after issuance. This MUST be distinguishable from a
// forged receipt (signature_invalid).
test("a revoked receipt is valid:false reason:'revoked' with a GENUINE signature", async () => {
  mockRevocation(true);

  const result = await verifyReceipt(fixture.jws, {
    jwks: fixture.jwks,
    checkRevocation: true,
  });

  expect(result.valid).toBe(false);
  expect(result.reason).toBe("revoked");
  expect(result.revoked).toBe(true);
  // The presence of kid + a fully-parsed payload proves the signature verified —
  // this is the evidentiary distinction from reason:"signature_invalid".
  expect(result.kid).toBe("adjuro-root-sample");
  expect(result.payload?.receipt_id).toBe(JTI);
});

test("a non-revoked receipt with checkRevocation:true stays valid:true", async () => {
  mockRevocation(false);

  const result = await verifyReceipt(fixture.jws, {
    jwks: fixture.jwks,
    checkRevocation: true,
  });

  expect(result.valid).toBe(true);
  expect(result.reason).toBeUndefined();
  expect(result.revoked).toBeUndefined();
});
