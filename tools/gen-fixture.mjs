#!/usr/bin/env bun
// tools/gen-fixture.mjs — ONE-TIME fixture generator (NOT shipped; not in package "files").
//
// Anti-drift proof generator. It:
//   1. Mints a fresh Ed25519 keypair + signs a PRODUCTION-shaped receipt payload
//      (claim set lifted from ../../adjuro/src/lib/receipt-issuer.ts), using jose
//      exactly as the server's tools/sign-sample.mjs does.
//   2. Runs the SERVER's REAL verifier (../../adjuro/src/lib/verify.ts ::
//      verifyReceiptJws) against that JWS, injecting an in-memory jwkLookup and a
//      no-op revocationCheck so NO database is touched.
//   3. Writes tests/fixtures/known-receipt.json = { jws, jwks, expected }, where
//      `expected` is byte-for-byte the object the server's verifier produced.
//
// The SDK's verify.test.ts then asserts the SDK produces === `expected`. If the
// SDK ever drifts from the server's verification semantics, that test fails.
//
// Run once and COMMIT the JSON output. Do not run in CI (jose generates a fresh
// random key each run, so re-running rewrites the fixture).
//
//   cd adjuro-sdk && bun tools/gen-fixture.mjs

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CompactSign, exportJWK, generateKeyPair } from "jose";

// The server's real verifier — the single source of truth we pin against.
import { verifyReceiptJws } from "../../adjuro/src/lib/verify.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "tests", "fixtures", "known-receipt.json");

const KID = "adjuro-root-sample"; // fixture key, NOT the production signing key
const RECEIPT_ID = "adj_rcpt_x9k2tqp4f7a3w1n5b8c2d6e3";

// Fixed, far-future timestamps so the fixture never expires and stays deterministic.
const iat = 1747000000; // 2025-05-11T...Z
const exp = 4102444800; // 2100-01-01T00:00:00Z
const issuedAtIso = new Date(iat * 1000).toISOString();
const expiresAtIso = new Date(exp * 1000).toISOString();

// Production receipt claim set — order + names mirror src/lib/receipt-issuer.ts
// (iss, jti, iat, exp, issued_by, receipt_id, issued_at, expires_at, tenant_id,
//  trust_root_id, ...payloadClaims) for a voice_call event.
const payload = {
  iss: "https://adjuro.ai",
  jti: RECEIPT_ID,
  iat,
  exp,
  issued_by: "https://adjuro.ai",
  receipt_id: RECEIPT_ID,
  issued_at: issuedAtIso,
  expires_at: expiresAtIso,
  tenant_id: "acme-collections-mid-atlantic",
  trust_root_id: "adjuro-root-2026w20",
  agent_id: "adj:7k9n2p4f8m1q5w3r6t2y8u4i",
  brand: "Acme Collections",
  event_type: "voice_call",
  caller_number: "+18005551212",
  callee_hash: "sha256-hmac:a8j1bzs9c5y2v7m6p4n3f8d2",
  campaign_id: "acct-recovery-q2-2026",
  consent_id: "crm-12847-consent-2026-03-14",
  scope: ["debt_collection"],
  jurisdiction: "US-CA",
  nonce: "a1b2c3d4e5f60718",
};

const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });

const jws = await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
  .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "JWT" })
  .sign(privateKey);

const publicJwk = await exportJWK(publicKey);
const jwk = { ...publicJwk, kid: KID, alg: "EdDSA", use: "sig" };
const jwks = { keys: [jwk] };

// Run the SERVER's real verifier with injected lookups — no DB, no network.
const expected = await verifyReceiptJws(jws, {
  jwkLookup: async (kid) => (kid === KID ? jwk : null),
  revocationCheck: async () => "not_revoked",
});

if (!expected.valid) {
  throw new Error(`server verifier rejected the freshly-signed fixture: ${JSON.stringify(expected)}`);
}

const fixture = {
  _meta: {
    description:
      "Anti-drift fixture. `jws` was signed with a throwaway Ed25519 key (NOT the production adjuro-root key). `expected` is the EXACT object the server's verifyReceiptJws() (adjuro/src/lib/verify.ts) returned for this jws with an in-memory jwkLookup and no revocation. The SDK must reproduce `expected` for the same input.",
    generated_by: "adjuro-sdk/tools/gen-fixture.mjs",
    server_source: "adjuro/src/lib/verify.ts :: verifyReceiptJws",
    jose_version: "6.2.3",
    fixture_kid: KID,
    note: "Fixed far-future exp (2100) so the receipt never expires; checkRevocation:false reproduces this exactly offline.",
  },
  jws,
  jwks,
  expected,
};

writeFileSync(OUT, `${JSON.stringify(fixture, null, 2)}\n`);

console.log(`[gen-fixture] kid=${KID}`);
console.log(`[gen-fixture] jws segments=${jws.split(".").length} length=${jws.length}`);
console.log(`[gen-fixture] server verifier result: valid=${expected.valid} kid=${expected.kid} receipt_id=${expected.receipt_id}`);
console.log(`[gen-fixture] wrote ${OUT}`);
