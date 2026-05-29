/**
 * jwks.ts — fetch + cache the public signing keys.
 *
 * Fetching the JWKS is one of only two things the SDK ever asks Adjuro for
 * (the other being revocation status). The keys are PUBLIC and signature
 * verification happens locally against them — fetching them does not mean
 * trusting Adjuro's answer about validity. Keys can also be supplied directly
 * (see `verifyReceipt`'s `jwks` option) to skip the network entirely.
 */
import type { JWKSet } from "./types.js";

// The endpoint advertises `Cache-Control: public, max-age=300`; mirror that TTL.
const DEFAULT_TTL_MS = 300_000;

const cache = new Map<string, { jwks: JWKSet; expiresAt: number }>();

function jwksUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/.well-known/jwks.json`;
}

/**
 * Fetch the JWKS for `baseUrl`, caching it for 5 minutes (the endpoint's own
 * cache lifetime). Throws if the endpoint is unreachable or returns non-2xx —
 * verification cannot proceed without public keys.
 */
export async function fetchJwks(baseUrl: string, nowMs: number = Date.now()): Promise<JWKSet> {
  const url = jwksUrl(baseUrl);
  const hit = cache.get(url);
  if (hit && hit.expiresAt > nowMs) return hit.jwks;

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Adjuro JWKS fetch failed: ${res.status} ${res.statusText} (${url})`);
  }
  const jwks = (await res.json()) as JWKSet;
  cache.set(url, { jwks, expiresAt: nowMs + DEFAULT_TTL_MS });
  return jwks;
}

/** Clear the in-memory JWKS cache. Exposed for tests and long-lived processes. */
export function _clearJwksCache(): void {
  cache.clear();
}
