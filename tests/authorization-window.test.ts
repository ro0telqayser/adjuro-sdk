/**
 * The authorization window, brand trust, and the dual-spelled id.
 *
 * ── Why `exp` stopped being fatal ────────────────────────────────────────────
 * A mint receipt does two jobs. It AUTHORIZES a call about to be placed — that
 * job expires after 24h (the server's ATTESTATION_TTL_SECONDS) — and it is
 * EVIDENCE that the call was authorized, which never expires. These artifacts are
 * retained seven years to be read in a courtroom.
 *
 * Through 1.4.0 only the first reading was implemented, so every receipt older
 * than a day returned `{ valid: false, reason: "expired" }` — the same verdict a
 * FORGED signature gets. A customer who downloaded their own audit packet and
 * verified it the next day was told their evidence was void. Reproduced against
 * production on a real 106-day-old receipt whose signature was perfect.
 *
 * The fix is at the verifier, not in the format: signed bytes are immutable, so
 * dropping `exp` from new receipts would leave every already-issued receipt broken
 * forever — and those are the ones that matter in litigation.
 */
import { afterEach, expect, test } from "bun:test";
import { verifyReceipt } from "../src/index.ts";
import { _clearJwksCache } from "../src/jwks.ts";
import { jwksOf, makeKey, sign } from "./helpers/sign.ts";

afterEach(() => {
  _clearJwksCache();
});

const nowSec = () => Math.floor(Date.now() / 1000);

/** A mint receipt. `exp` is whatever the caller needs to exercise. */
function mintPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  const iat = nowSec() - 7200;
  return {
    iss: "https://adjuro.ai",
    jti: "adj_rcpt_windowtest0000000000000",
    iat,
    exp: iat + 86400,
    issued_by: "https://adjuro.ai",
    receipt_id: "adj_rcpt_windowtest0000000000000",
    issued_at: new Date(iat * 1000).toISOString(),
    expires_at: new Date((iat + 86400) * 1000).toISOString(),
    tenant_id: "tenant-window-test",
    trust_root_id: "adjuro-root",
    agent_id: "adj:windowtest",
    brand: "Window Test Co",
    event_type: "voice_call",
    ...over,
  };
}

const OFFLINE = { checkRevocation: false as const };

// ── Item 1: expiry is reported, not fatal ────────────────────────────────────

test("a past exp is REPORTED, not fatal — evidence outlives its authorization window", async () => {
  const key = await makeKey("adjuro-root-windowtest");
  const expSec = nowSec() - 3600;
  const jws = await sign(key, mintPayload({ iat: nowSec() - 7200, exp: expSec }));

  const r = await verifyReceipt(jws, { jwks: jwksOf(key), ...OFFLINE });

  expect(r.valid).toBe(true);
  expect(r.reason).toBeUndefined();
  expect(r.authorization_window).toBe("closed");
  expect(r.authorization_expired_at).toBe(new Date(expSec * 1000).toISOString());
});

test("requireUnexpired restores pre-call GATE semantics", async () => {
  const key = await makeKey("adjuro-root-windowtest");
  const jws = await sign(key, mintPayload({ iat: nowSec() - 7200, exp: nowSec() - 3600 }));

  const r = await verifyReceipt(jws, { jwks: jwksOf(key), ...OFFLINE, requireUnexpired: true });

  expect(r.valid).toBe(false);
  expect(r.reason).toBe("expired");
  // kid and payload survive the failure so a caller can still see who signed it.
  expect(r.kid).toBe("adjuro-root-windowtest");
  expect(r.payload).toBeDefined();
});

test("a receipt inside its window reports the window open", async () => {
  const key = await makeKey("adjuro-root-windowtest");
  const jws = await sign(key, mintPayload({ iat: nowSec() - 60, exp: nowSec() + 3600 }));

  const r = await verifyReceipt(jws, { jwks: jwksOf(key), ...OFFLINE });

  expect(r.valid).toBe(true);
  expect(r.authorization_window).toBe("open");
  expect(r.authorization_expired_at).toBeUndefined();
});

test("a receipt with NO exp at all reports the window open", async () => {
  // Settlement receipts omit `exp` by design — they are evidence about a call that
  // already happened, so there is no window to close.
  const key = await makeKey("adjuro-root-windowtest");
  const payload = mintPayload();
  delete payload.exp;
  const jws = await sign(key, payload);

  const r = await verifyReceipt(jws, { jwks: jwksOf(key), ...OFFLINE });

  expect(r.valid).toBe(true);
  expect(r.authorization_window).toBe("open");
  expect(r.authorization_expired_at).toBeUndefined();
});

// Relaxing expiry must not relax revocation. Expiry is the passage of time;
// revocation is Adjuro actively repudiating the artifact. The server had this
// exact bug — the old code short-circuited on expiry and masked the revocation.
test("revocation is still fatal on a receipt whose window has closed", async () => {
  const key = await makeKey("adjuro-root-windowtest");
  const jti = "adj_rcpt_windowtest0000000000000";
  const jws = await sign(key, mintPayload({ iat: nowSec() - 7200, exp: nowSec() - 3600 }));

  const orig = globalThis.fetch;
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
    if (String(input).includes(`/v1/revocations/${jti}`)) {
      return new Response(JSON.stringify({ jti, revoked: true, revoked_at: "2026-01-01T00:00:00.000Z" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch: ${String(input)}`);
  }) as typeof fetch;

  try {
    const r = await verifyReceipt(jws, { jwks: jwksOf(key), checkRevocation: true });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("revoked");
    expect(r.revoked).toBe(true);
  } finally {
    globalThis.fetch = orig;
  }
});

// ── Item 2: brand trust is surfaced ──────────────────────────────────────────
//
// `valid` is signature-only. The brand is trustworthy if and only if
// `brand_verified === true`. Through 1.4.0 the SDK did not surface this at all,
// so an integrator saw `valid: true` with nothing prompting them to check — which
// is precisely the unverified-brand spoofing case, reachable through the official
// verifier. Both claims are signed into the payload, so this costs no network call.

test("brand_verified and trust_tier are surfaced from the signed payload", async () => {
  const key = await makeKey("adjuro-root-windowtest");
  const jws = await sign(
    key,
    mintPayload({ brand_verified: true, trust_tier: "verified", exp: nowSec() + 3600 }),
  );

  const r = await verifyReceipt(jws, { jwks: jwksOf(key), ...OFFLINE });

  expect(r.valid).toBe(true);
  expect(r.brand_verified).toBe(true);
  expect(r.trust_tier).toBe("verified");
});

test("an ABSENT brand_verified claim reads false, never true", async () => {
  // Fail closed. A receipt that never asserted brand verification must not be
  // reported as brand-verified just because the claim is missing.
  const key = await makeKey("adjuro-root-windowtest");
  const jws = await sign(key, mintPayload({ exp: nowSec() + 3600 }));

  const r = await verifyReceipt(jws, { jwks: jwksOf(key), ...OFFLINE });

  expect(r.brand_verified).toBe(false);
  expect(r.trust_tier).toBe("unverified");
});

test("a truthy-but-not-true brand_verified claim still reads false", async () => {
  // Strict === true. A tenant-supplied "yes" or 1 must not be coerced into trust.
  const key = await makeKey("adjuro-root-windowtest");
  const jws = await sign(
    key,
    mintPayload({ brand_verified: "yes", trust_tier: 42, exp: nowSec() + 3600 }),
  );

  const r = await verifyReceipt(jws, { jwks: jwksOf(key), ...OFFLINE });

  expect(r.brand_verified).toBe(false);
  expect(r.trust_tier).toBe("unverified");
});

// ── Item 3: the dual-spelled id ──────────────────────────────────────────────

test("attestation_id is emitted alongside receipt_id, carrying the same value", async () => {
  const key = await makeKey("adjuro-root-windowtest");
  const jws = await sign(key, mintPayload({ exp: nowSec() + 3600 }));

  const r = await verifyReceipt(jws, { jwks: jwksOf(key), ...OFFLINE });

  expect(r.receipt_id).toBe("adj_rcpt_windowtest0000000000000");
  expect(r.attestation_id).toBe(r.receipt_id);
});

test("a payload spelling it attestation_id resolves both fields", async () => {
  const key = await makeKey("adjuro-root-windowtest");
  const payload = mintPayload({ exp: nowSec() + 3600 });
  payload.attestation_id = payload.receipt_id;
  delete payload.receipt_id;
  const jws = await sign(key, payload);

  const r = await verifyReceipt(jws, { jwks: jwksOf(key), ...OFFLINE });

  expect(r.attestation_id).toBe("adj_rcpt_windowtest0000000000000");
  expect(r.receipt_id).toBe(r.attestation_id);
});
