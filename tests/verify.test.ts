import { afterEach, expect, test } from "bun:test";
import { verifyReceipt } from "../src/index.ts";
import { _clearJwksCache } from "../src/jwks.ts";
import fixture from "./fixtures/known-receipt.json";

afterEach(() => {
  _clearJwksCache();
});

// ── The anti-drift contract ──────────────────────────────────────────────────
// `fixture.expected` is the EXACT object the server's verifyReceiptJws()
// (adjuro/src/lib/verify.ts) returned for `fixture.jws`. The SDK must reproduce
// it byte-for-byte. If this fails, the SDK has drifted from the server.
test("offline: reproduces the server's exact VerifyResult for the known receipt", async () => {
  const result = await verifyReceipt(fixture.jws, {
    jwks: fixture.jwks,
    checkRevocation: false,
  });
  expect(result).toEqual(fixture.expected);
});

test("offline mode makes ZERO network calls when jwks supplied and checkRevocation:false", async () => {
  const orig = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
    calls++;
    return orig(...args);
  }) as typeof fetch;
  try {
    const result = await verifyReceipt(fixture.jws, {
      jwks: fixture.jwks,
      checkRevocation: false,
    });
    expect(result.valid).toBe(true);
    expect(calls).toBe(0);
  } finally {
    globalThis.fetch = orig;
  }
});
