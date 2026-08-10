// Real Ed25519 signing for chain tests. No mocks: a chain verifier that is only
// ever exercised against stubbed signatures proves nothing about signatures.
import { CompactSign, exportJWK, generateKeyPair } from "jose";

export type TestKey = { kid: string; privateKey: CryptoKey; jwk: Record<string, unknown> };

export async function makeKey(kid: string): Promise<TestKey> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  const jwk = await exportJWK(publicKey);
  return { kid, privateKey, jwk: { ...jwk, kid, alg: "EdDSA", use: "sig" } };
}

/** Signs the EXACT string given — used for frozen vectors, where bytes are the contract. */
export async function signRaw(key: TestKey, payload: string): Promise<string> {
  return new CompactSign(new TextEncoder().encode(payload))
    .setProtectedHeader({ alg: "EdDSA", kid: key.kid, typ: "JWT" })
    .sign(key.privateKey);
}

export async function sign(key: TestKey, payload: Record<string, unknown>): Promise<string> {
  return signRaw(key, JSON.stringify(payload));
}

export const jwksOf = (...keys: TestKey[]) => ({ keys: keys.map((k) => k.jwk) });
