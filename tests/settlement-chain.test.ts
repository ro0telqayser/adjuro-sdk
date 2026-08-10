import { expect, test } from "bun:test";
import { VERIFY_REASONS, verifyReceipt } from "../src/index.ts";
import { jwksOf, makeKey, sign } from "./helpers/sign.ts";

test("a settlement receipt whose parent was not supplied is not valid", async () => {
  const key = await makeKey("adjuro-root-test");
  const jws = await sign(key, {
    jti: "adj_stl_aaa",
    event_type: "call_settlement",
    parent_jti: "adj_rcpt_bbb",
    tenant_id: "tenant-1",
  });

  const result = await verifyReceipt(jws, { jwks: jwksOf(key), checkRevocation: false });

  expect(result.valid).toBe(false);
  expect(result.reason).toBe("parent_not_found");
});

test("a parent signed by an untrusted key is rejected, not merely decoded", async () => {
  // THE attack this whole block exists to stop. The server resolves the parent
  // from its own database; the SDK is handed bytes by whoever calls it — which
  // may be the adversary. If the parent is decoded but not VERIFIED, anyone can
  // mint a plausible-looking parent and make any settlement receipt verify.
  const trusted = await makeKey("adjuro-root-test");
  const attacker = await makeKey("attacker-key");

  const forgedParent = await sign(attacker, {
    jti: "adj_rcpt_bbb",
    event_type: "voice_call",
    tenant_id: "tenant-1",
  });
  const jws = await sign(trusted, {
    jti: "adj_stl_aaa",
    event_type: "call_settlement",
    parent_jti: "adj_rcpt_bbb",
    tenant_id: "tenant-1",
  });

  const result = await verifyReceipt(jws, {
    jwks: jwksOf(trusted), // attacker's key is NOT trusted
    checkRevocation: false,
    parentJws: forgedParent,
  });

  expect(result.valid).toBe(false);
  expect(result.reason).toBe("parent_not_found");
});

test("a settlement receipt with no parent_jti at all is malformed, not merely unresolved", async () => {
  // Distinct from parent_not_found: this receipt never named a parent. That is a
  // defect in the artifact itself, not a failure to resolve something it claimed.
  const key = await makeKey("adjuro-root-test");
  const parent = await sign(key, { jti: "adj_rcpt_bbb", event_type: "voice_call", tenant_id: "t1" });
  const jws = await sign(key, { jti: "adj_stl_aaa", event_type: "call_settlement", tenant_id: "t1" });

  const result = await verifyReceipt(jws, {
    jwks: jwksOf(key), checkRevocation: false, parentJws: parent,
  });

  expect(result.valid).toBe(false);
  expect(result.reason).toBe("malformed_chain");
});

test("a chain that crosses tenants is refused", async () => {
  // Otherwise a settlement receipt could name ANOTHER tenant's mint receipt and
  // inherit the authorization that receipt carries.
  const key = await makeKey("adjuro-root-test");
  const parent = await sign(key, {
    jti: "adj_rcpt_bbb", event_type: "voice_call", tenant_id: "tenant-VICTIM",
  });
  const jws = await sign(key, {
    jti: "adj_stl_aaa", event_type: "call_settlement",
    parent_jti: "adj_rcpt_bbb", tenant_id: "tenant-ATTACKER",
  });

  const result = await verifyReceipt(jws, {
    jwks: jwksOf(key), checkRevocation: false, parentJws: parent,
  });

  expect(result.valid).toBe(false);
  expect(result.reason).toBe("parent_tenant_mismatch");
});

test("revoking the parent invalidates the settlement leg it authorized", async () => {
  // Closes a revocation bypass: if the settlement leg survived its parent's
  // revocation, withdrawing consent would be defeated by pointing at the
  // settlement receipt instead of the mint receipt.
  const key = await makeKey("adjuro-root-test");
  const parent = await sign(key, {
    jti: "adj_rcpt_REVOKED", event_type: "voice_call", tenant_id: "t1",
  });
  const jws = await sign(key, {
    jti: "adj_stl_aaa", event_type: "call_settlement",
    parent_jti: "adj_rcpt_REVOKED", tenant_id: "t1",
  });

  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL | Request) => {
    const u = String(url);
    // Only the PARENT is revoked; the settlement receipt itself is not.
    const revoked = u.includes("adj_rcpt_REVOKED");
    return new Response(JSON.stringify({ revoked }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  try {
    const result = await verifyReceipt(jws, {
      jwks: jwksOf(key), checkRevocation: true, parentJws: parent,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("parent_revoked");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("a well-formed chain verifies", async () => {
  const key = await makeKey("adjuro-root-test");
  const parent = await sign(key, { jti: "adj_rcpt_bbb", event_type: "voice_call", tenant_id: "t1" });
  const jws = await sign(key, {
    jti: "adj_stl_aaa", event_type: "call_settlement",
    parent_jti: "adj_rcpt_bbb", tenant_id: "t1",
    recording_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  });

  const result = await verifyReceipt(jws, {
    jwks: jwksOf(key), checkRevocation: false, parentJws: parent,
  });

  expect(result.valid).toBe(true);
  expect(result.reason).toBeUndefined();
});

test("a MINT receipt never enters the chain path", async () => {
  // The regression that protects every existing integrator. If the event_type gate
  // ever widens, mint verification starts demanding a parent that does not exist
  // and every current caller breaks. Mirrors the server test asserting the parent
  // lookup runs ZERO times for a mint receipt.
  const key = await makeKey("adjuro-root-test");
  const jws = await sign(key, {
    jti: "adj_rcpt_bbb", event_type: "voice_call", tenant_id: "t1",
  });

  let parentReads = 0;
  const result = await verifyReceipt(jws, {
    jwks: jwksOf(key),
    checkRevocation: false,
    get parentJws() {
      parentReads++;
      return undefined;
    },
  });

  expect(result.valid).toBe(true);
  expect(parentReads).toBe(0);
});

test("VERIFY_REASONS exports every reason the type union declares", async () => {
  // VERIFY_REASONS is a RUNTIME contract consumers switch on. If it drifts from
  // the type union, a caller exhaustively handling it silently misses cases.
  for (const r of [
    "malformed_chain", "parent_not_found", "parent_revoked", "parent_tenant_mismatch",
  ]) {
    expect(VERIFY_REASONS).toContain(r);
  }
});
