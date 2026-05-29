/**
 * revocation.ts — public revocation lookup.
 *
 * Calls the unauthenticated `GET /v1/revocations/:jti` endpoint
 * (adjuro/src/routes/revocations.ts), which returns either:
 *   { jti, revoked: false, revoked_at: null }   — not revoked (or unknown)
 *   { jti, revoked: true,  revoked_at: <iso> }   — revoked
 *
 * Revocation is dynamic, so it is the ONE check that cannot be done offline.
 * It is optional: pass `checkRevocation: false` to skip it.
 */

export interface RevocationStatus {
  revoked: boolean;
  revoked_at: string | null;
}

/**
 * Look up revocation status for a receipt id (`jti`). Throws if the endpoint is
 * unreachable or returns non-2xx — the caller asked us to check revocation and we
 * could not, so we surface that rather than silently treating it as "not revoked".
 */
export async function checkRevocation(jti: string, baseUrl: string): Promise<RevocationStatus> {
  const url = `${baseUrl.replace(/\/+$/, "")}/v1/revocations/${encodeURIComponent(jti)}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Adjuro revocation lookup failed: ${res.status} ${res.statusText} (${url})`);
  }
  const body = (await res.json()) as { revoked?: boolean; revoked_at?: string | null };
  return { revoked: body.revoked === true, revoked_at: body.revoked_at ?? null };
}
