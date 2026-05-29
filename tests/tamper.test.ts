import { expect, test } from "bun:test";
import { verifyReceipt } from "../src/index.ts";
import fixture from "./fixtures/known-receipt.json";

// Flip one byte of the signature segment — mirrors the "Tamper and re-verify"
// button in web/index.html. A genuine signature must no longer verify.
function tamperSignature(jws: string): string {
  const parts = jws.split(".");
  const sig = parts[2];
  const i = Math.floor(sig.length / 2);
  const repl = sig[i] === "A" ? "B" : "A";
  parts[2] = sig.slice(0, i) + repl + sig.slice(i + 1);
  return parts.join(".");
}

test("a tampered signature fails with reason 'signature_invalid' (forged/altered receipt)", async () => {
  const tampered = tamperSignature(fixture.jws);
  expect(tampered).not.toBe(fixture.jws);

  const result = await verifyReceipt(tampered, {
    jwks: fixture.jwks,
    checkRevocation: false,
  });

  expect(result.valid).toBe(false);
  expect(result.reason).toBe("signature_invalid");
  expect(result.kid).toBe("adjuro-root-sample");
});

test("a malformed JWS (not three segments) fails with reason 'malformed_jws'", async () => {
  const result = await verifyReceipt("not.a.jws.at.all", {
    jwks: fixture.jwks,
    checkRevocation: false,
  });
  expect(result.valid).toBe(false);
  expect(result.reason).toBe("malformed_jws");
});
