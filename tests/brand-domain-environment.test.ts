// 2.1.0: `brand_domain` and `environment`, mirroring the server's POST /v1/verify.
//
// Since October 2026 the Adjuro issuer signs two more trust claims:
//   - brand_domain: the approved domain behind brand_verified:true, else null;
//   - environment:  "sandbox" | "live", the issuing tenant's environment at signing.
// The server surfaces both on /v1/verify; the SDK result must carry exactly the
// server's success keys (tests/contract.test.ts), so it surfaces them too, with the
// same fail-safe rules:
//   - brand_domain is reported ONLY beside brand_verified === true — a domain shown
//     next to an unverified brand would read as a trust grant;
//   - environment is reported only when it is exactly "sandbox" or "live";
//   - receipts signed before the claims existed report null for both. Absence is not
//     a downgrade: those receipts verify exactly as before.
// Neither field is a trust input. The trust rule is unchanged: brand_verified === true.

import { expect, test } from "bun:test";
import { verifyReceipt } from "../src/index.ts";
import { jwksOf, makeKey, sign } from "./helpers/sign.ts";

const nowSec = () => Math.floor(Date.now() / 1000);

function payload(extra: Record<string, unknown>) {
  const iat = nowSec();
  return {
    iss: "https://adjuro.ai",
    jti: "adj_att_branddomain",
    attestation_id: "adj_att_branddomain",
    iat,
    exp: iat + 3600,
    issued_at: new Date(iat * 1000).toISOString(),
    expires_at: new Date((iat + 3600) * 1000).toISOString(),
    brand: "demo.adjuro.ai",
    event_type: "voice_call",
    ...extra,
  };
}

async function verify(extra: Record<string, unknown>) {
  const key = await makeKey("adjuro-root-test");
  const jws = await sign(key, payload(extra));
  return verifyReceipt(jws, { jwks: jwksOf(key), checkRevocation: false });
}

test("verified brand: brand_domain and environment are surfaced", async () => {
  const r = await verify({
    brand_verified: true,
    trust_tier: "verified",
    brand_domain: "demo.adjuro.ai",
    environment: "live",
  });
  expect(r.valid).toBe(true);
  expect(r.brand_verified).toBe(true);
  expect(r.brand_domain).toBe("demo.adjuro.ai");
  expect(r.environment).toBe("live");
});

test("sandbox attestation: environment 'sandbox', no domain", async () => {
  const r = await verify({
    brand_verified: false,
    trust_tier: "unverified",
    brand_domain: null,
    environment: "sandbox",
  });
  expect(r.brand_verified).toBe(false);
  expect(r.brand_domain).toBeNull();
  expect(r.environment).toBe("sandbox");
});

test("fail-safe: a brand_domain beside brand_verified:false is never surfaced", async () => {
  const r = await verify({ brand_verified: false, brand_domain: "chase.com", environment: "live" });
  expect(r.brand_domain).toBeNull();
});

test("fail-safe: a non-string brand_domain is ignored", async () => {
  const r = await verify({ brand_verified: true, brand_domain: { evil: true } });
  expect(r.brand_verified).toBe(true);
  expect(r.brand_domain).toBeNull();
});

test("an environment other than exactly 'sandbox' | 'live' reads null", async () => {
  for (const env of ["production", "LIVE", 1, true, ""]) {
    const r = await verify({ brand_verified: true, environment: env });
    expect(r.environment).toBeNull();
  }
});

test("a receipt signed before the claims existed: both null, verdict unchanged", async () => {
  const r = await verify({ brand_verified: true, trust_tier: "verified" });
  expect(r.valid).toBe(true);
  expect(r.brand_verified).toBe(true);
  expect(r.trust_tier).toBe("verified");
  expect(r.brand_domain).toBeNull();
  expect(r.environment).toBeNull();
});

test("neither field can create trust: brand_domain without brand_verified stays untrusted", async () => {
  const r = await verify({ trust_tier: "verified", brand_domain: "demo.adjuro.ai", environment: "live" });
  expect(r.brand_verified).toBe(false);
  expect(r.brand_domain).toBeNull();
});
