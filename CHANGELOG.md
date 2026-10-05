# Changelog

All notable changes to the `adjuro` verifier SDK. Format loosely follows
[keep-a-changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Notes: issuer-side change, no SDK change required

- Attestations minted by the Adjuro API from October 2026 carry two additional signed claims:
  - `brand_domain`: the approved domain backing `brand_verified: true`, or `null`.
  - `environment`: `"sandbox"` or `"live"`, the issuing tenant's environment at signing.
- The issuer now applies one rule for `brand_verified: true`: the tenant is `live` **and** the
  signed `brand` exactly equals a domain the tenant has proven control of and that has been
  approved. A `sandbox` attestation never carries `brand_verified: true`.
- **2.0.0 is unaffected.** `verifyReceipt` already ignores claims it does not know, still reports
  `brand_verified` as `payload.brand_verified === true`, and returns the full signed payload, so
  both new claims are readable from it today. The trust rule is unchanged: trust the asserted
  brand if and only if `brand_verified === true`.
- Attestations signed before the change carry neither claim; their absence is not a downgrade.
- A later minor release may surface `brand_domain` and `environment` as first-class result
  fields. That would be additive.

## [2.0.0]

- Expiry is evidence metadata, not a verification failure: a receipt past its `exp` verifies
  `valid: true` and reports `authorization_window`. Opt into gate semantics with
  `requireUnexpired`.
- Adds `brand_verified`, `trust_tier` and the dual-spelled `attestation_id` to the result.
