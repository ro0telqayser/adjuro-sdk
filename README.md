# adjuro

**Independent verifier for [Adjuro](https://adjuro.ai) receipts.** Verify an Ed25519-signed
compliance receipt — issued when an AI agent calls or acts on a brand's behalf — in five lines,
**without trusting Adjuro's servers for the answer.**

```js
// npm install adjuro
import { verifyReceipt } from "adjuro";

const result = await verifyReceipt(receiptJws);

// → { valid: true, kid: "adjuro-root-2026w20",
//      receipt_id: "adj_rcpt_x9k2tqp4...",
//      issued_at: "2026-05-19T14:32:23Z",
//      expires_at: "2027-05-19T14:32:23Z",
//      payload: { agent_id: "adj:7k9n...", scope: ["debt_collection"], ... } }
```

## Why this is trustworthy

The signature math runs **locally**, in your process, using [`jose`](https://github.com/panva/jose)'s
`compactVerify`. The SDK never calls Adjuro's `/v1/verify` and trusts the reply — that would defeat
the entire point of independent, court-admissible verification.

Adjuro is contacted for only two things, and you can eliminate both:

| What | Why | How to avoid it |
|---|---|---|
| **JWKS** (public signing keys) | To check the signature against the right key | Pass `jwks` yourself (pin them) |
| **Revocation status** | Dynamic — a real receipt can be withdrawn later | Pass `checkRevocation: false` |

### Fully offline mode (no network, zero trust in Adjuro)

```js
import { verifyReceipt } from "adjuro";

const result = await verifyReceipt(receiptJws, {
  jwks,                    // keys you fetched/pinned earlier
  checkRevocation: false,  // skip the revocation lookup
});
// No network call is made. The result depends only on the bytes and the keys.
```

This is the strongest form of the guarantee: hand the SDK the receipt and the public keys, and it
tells you — with no outside dependency — whether the signature is genuine.

## The three "not valid" outcomes are NOT the same

When `valid` is `false`, **`reason` tells you something a court needs to know.** Do not collapse these:

| `reason` | What it means | Plain English |
|---|---|---|
| `signature_invalid` | The cryptography fails | The receipt is **forged or tampered**. It was never genuinely issued by this key. |
| `revoked` | Signature is **genuine**, but withdrawn | The receipt **was real** and properly signed, then revoked after issuance. `revoked: true` is set, and `kid` + `payload` are present. |
| `expired` | Signature is **genuine**, past its `exp` | The receipt **was real**, but it is past its validity window. `kid` + `payload` are present. |

A `revoked` (or `expired`) receipt is evidence that a valid attestation existed and was later
withdrawn — categorically different from a `signature_invalid` receipt, which is evidence of forgery.

Other reasons: `malformed_jws` (not a well-formed three-segment JWS), `alg_unsupported` (header `alg`
is not `EdDSA`), `unknown_kid` (no published key matches the receipt's `kid`).

## API

```ts
verifyReceipt(jws: string, opts?: {
  baseUrl?: string;          // default "https://api.adjuro.ai"
  checkRevocation?: boolean; // default true
  jwks?: JWKSet;             // pre-fetched keys → skip the JWKS fetch
}): Promise<VerifyResult>
```

```ts
interface VerifyResult {
  valid: boolean;
  reason?: "malformed_jws" | "alg_unsupported" | "unknown_kid"
         | "signature_invalid" | "expired" | "revoked";
  kid?: string;          // signing key id (present once the header parsed)
  receipt_id?: string;   // the adj_rcpt_* id; equals the jti claim
  issued_at?: string;    // ISO-8601
  expires_at?: string;   // ISO-8601
  revoked?: boolean;     // true only on reason:"revoked"
  payload?: object;      // decoded receipt claims (present once the signature verified)
}
```

The exact failure-reason set is also exported at runtime as `VERIFY_REASONS`.

## Transparency-log inclusion

`verifyTransparencyLogInclusion` independently proves that the canonical data in a receipt JWS is
included in an RFC 6962 Merkle root authenticated by a caller-pinned snapshot key.

```ts
import {
  verifyReceipt,
  verifyTransparencyLogInclusion,
} from "adjuro";

// Fetch proof + snapshot from the public log, but pin the snapshot key yourself.
const receiptResult = await verifyReceipt(receiptJws, {
  jwks: pinnedReceiptJwks,
  checkRevocation: false,
});
const inclusionResult = await verifyTransparencyLogInclusion(
  receiptJws,
  proof,
  snapshot,
  pinnedSnapshotJwk,
);

if (receiptResult.valid && inclusionResult.valid) {
  console.log("authentic receipt included in authenticated root", inclusionResult.root_hash);
}
```

The inclusion verifier derives all committed receipt data from the compact JWS:

```text
<receipt_id>|<protected-header kid>|<numeric iat>|<tenant_id>
```

It never trusts `proof.leaf`, `proof.leaf_hash`, or `snapshot.signing_key_jwk`. It computes:

```text
leaf = SHA-256(0x00 || UTF8(canonical_leaf))
node = SHA-256(0x01 || left || right)
```

It then checks the audit-path geometry, index, tree size, proof/snapshot agreement, root, and the
Ed25519 signature over the raw 32-byte root.

### Snapshot trust boundary

The current snapshot signature covers **only the raw Merkle root bytes**:

- **Cryptographically authenticated:** `root_hash`.
- **Consistency-checked only, not signed:** `snapshot_id`, `tree_size`, and `snapshot_kid`.

The proof and snapshot must agree on ID, size, and root, and the snapshot kid must agree with the
caller-pinned JWK. Those checks detect inconsistent inputs but do not turn that metadata into signed
data. Do not represent the complete snapshot object as cryptographically signed.

Receipt authenticity is a separate property. `verifyTransparencyLogInclusion` parses the JWS to
derive the committed leaf but does not verify that JWS signature; call `verifyReceipt` as shown
above when both authenticity and inclusion are required.

```ts
verifyTransparencyLogInclusion(
  receiptJws: string,
  proof: TransparencyLogInclusionProof,
  snapshot: TransparencyLogSnapshot,
  snapshotJwk: SnapshotSigningJwk,
): Promise<TransparencyLogInclusionResult>
```

The pinned JWK must be an Ed25519 public key with matching `kid`, a 32-byte base64url `x`, and
compatible `alg`, `use`, and `key_ops` values when those optional fields are present. Failure reasons
are exported at runtime as `TRANSPARENCY_LOG_VERIFY_REASONS`.

### Examples

```js
// Online (default): fetch keys from api.adjuro.ai, verify locally, check revocation.
const r = await verifyReceipt(jws);
if (r.valid) {
  console.log("genuine, in-force receipt for", r.payload.agent_id);
} else if (r.reason === "revoked") {
  console.log("genuine receipt, but revoked at issuance-time was later withdrawn");
} else if (r.reason === "signature_invalid") {
  console.log("FORGED or tampered — not a real Adjuro receipt");
}

// Self-hosted / staging Adjuro:
await verifyReceipt(jws, { baseUrl: "https://api.staging.adjuro.ai" });
```

## How it works

Receipt signature verification:

1. Parse the JWS header → read the `kid` and confirm `alg` is `EdDSA` (RFC 8037 / pure Ed25519).
2. Resolve the public key: use the `jwks` you passed, or fetch `${baseUrl}/.well-known/jwks.json`
   (cached for 5 minutes, matching the endpoint's `Cache-Control`).
3. Verify the Ed25519 signature locally with `jose.compactVerify`.
4. Check `exp`.
5. If `checkRevocation` is on and the receipt has a `jti`, call the public, unauthenticated
   `GET ${baseUrl}/v1/revocations/:jti`. A genuine-but-revoked receipt returns `reason: "revoked"`.

The verification core is a faithful port of Adjuro's server-side verifier; a committed test fixture
pins the SDK's output to the exact result the server produces for the same input.

Transparency-log verification is intentionally independent of Adjuro's Merkle implementation. Its
known-answer tests are pinned to
[RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) and Google Certificate
Transparency's published Merkle vectors at commit
[`0fe5116f42890853e9fcf5120f1f5129d64f64ea`](https://github.com/google/certificate-transparency/blob/0fe5116f42890853e9fcf5120f1f5129d64f64ea/python/ct/crypto/merkle_test.py).

## Requirements

- Node.js ≥ 18 (uses the global `fetch`), Bun, or any modern browser bundler. ESM only.
- One dependency: [`jose`](https://www.npmjs.com/package/jose) (`^6.2.3`).

## License

[Apache-2.0](./LICENSE).
