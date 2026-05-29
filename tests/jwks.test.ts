import { afterEach, expect, test } from "bun:test";
import { verifyReceipt } from "../src/index.ts";
import { _clearJwksCache } from "../src/jwks.ts";
import fixture from "./fixtures/known-receipt.json";

let origFetch: typeof fetch;
afterEach(() => {
  if (origFetch) globalThis.fetch = origFetch;
  _clearJwksCache();
});

test("fetches JWKS from /.well-known/jwks.json when none supplied, and caches it", async () => {
  origFetch = globalThis.fetch;
  let jwksCalls = 0;
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
    const url = String(input);
    if (url.endsWith("/.well-known/jwks.json")) {
      jwksCalls++;
      return new Response(JSON.stringify(fixture.jwks), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("/v1/revocations/")) {
      return new Response(JSON.stringify({ revoked: false, revoked_at: null }), { status: 200 });
    }
    throw new Error(`unexpected fetch: ${url}`);
  }) as typeof fetch;

  const r1 = await verifyReceipt(fixture.jws, { baseUrl: "https://api.example.test" });
  const r2 = await verifyReceipt(fixture.jws, { baseUrl: "https://api.example.test" });

  expect(r1.valid).toBe(true);
  expect(r2.valid).toBe(true);
  expect(jwksCalls).toBe(1); // second verify served from the in-memory cache
});

test("the default baseUrl is https://api.adjuro.ai", async () => {
  origFetch = globalThis.fetch;
  let hitHost = "";
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
    const url = String(input);
    if (url.endsWith("/.well-known/jwks.json")) {
      hitHost = new URL(url).host;
      return new Response(JSON.stringify(fixture.jwks), { status: 200 });
    }
    if (url.includes("/v1/revocations/")) {
      return new Response(JSON.stringify({ revoked: false, revoked_at: null }), { status: 200 });
    }
    throw new Error(`unexpected fetch: ${url}`);
  }) as typeof fetch;

  await verifyReceipt(fixture.jws);
  expect(hitHost).toBe("api.adjuro.ai");
});
