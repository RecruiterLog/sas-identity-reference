import { createKeyPairSignerFromBytes, type KeyPairSigner } from "@solana/kit";

/**
 * Parse a 64 byte keypair from either format a Solana user is likely to
 * already have:
 *
 *   - a JSON array of 64 numbers, exactly what `solana-keygen new` writes
 *   - the same 64 bytes base64 encoded, for environments that dislike brackets
 */
export async function signerFromSecret(raw: string): Promise<KeyPairSigner> {
  const value = (raw || "").trim();
  if (!value) {
    throw new Error(
      "No signing key supplied. Generate one with:\n" +
        "  solana-keygen new --no-bip39-passphrase -o issuer-key.json\n" +
        "then pass the file's contents. Never commit it and never store it in a database."
    );
  }

  let bytes: Uint8Array;
  if (value.startsWith("[")) {
    bytes = Uint8Array.from(JSON.parse(value) as number[]);
  } else {
    bytes = Uint8Array.from(Buffer.from(value, "base64"));
  }

  if (bytes.length !== 64) {
    throw new Error(
      `Signing key decoded to ${bytes.length} bytes, expected 64. ` +
        "It should be the full keypair (secret and public), not just the 32 byte seed."
    );
  }

  return createKeyPairSignerFromBytes(bytes);
}

// Memoized deliberately, and not as an optimisation.
//
// @solana/kit identifies signers by OBJECT IDENTITY, not by address. Two
// KeyPairSigner instances for the same key count as two different signers, so
// building one transaction from instructions created at several call sites --
// which is exactly what the setup flow does, credential and schema together --
// fails with "Multiple distinct signers were identified for address ...".
// Returning one instance per process is what makes a multi-instruction
// transaction possible at all.
//
// This is the single most confusing error in this integration, and nothing in
// the message points at object identity.
let cached: Promise<KeyPairSigner> | null = null;

/**
 * The issuer signer, from the environment.
 *
 * @param envVar Which variable holds the key. Kept a parameter so an
 *   application can use its own name.
 */
export async function getSigner(envVar = "SAS_ISSUER_SECRET_KEY"): Promise<KeyPairSigner> {
  if (!cached) {
    cached = signerFromSecret(process.env[envVar] || "").catch((err: unknown) => {
      // Never cache a failure: a process that gains the variable later, or a
      // test that sets it, would otherwise keep reporting it missing.
      cached = null;
      throw err;
    });
  }
  return cached;
}

/** For tests, and for a process that legitimately switches issuers. */
export function resetSignerCache(): void {
  cached = null;
}

export type SignerState = "ok" | "missing" | "malformed";

/**
 * Why the key is not usable, in a form safe to show an operator.
 *
 * Exists because "not set" and "set but unparseable" otherwise look identical,
 * which sends someone to check the wrong thing. Describes the SHAPE of the
 * value and never echoes it, because the value is a private key.
 */
export async function describeSignerState(
  envVar = "SAS_ISSUER_SECRET_KEY"
): Promise<{ state: SignerState; address: string | null; detail: string }> {
  const raw = (process.env[envVar] || "").trim();

  if (!raw) {
    return { state: "missing", address: null, detail: `${envVar} is not set in this environment.` };
  }

  try {
    const signer = await signerFromSecret(raw);
    return { state: "ok", address: signer.address, detail: "" };
  } catch (err) {
    const looksJson = raw.startsWith("[");
    const quoted = /^["']/.test(raw);
    const shape = looksJson
      ? "JSON array form"
      : quoted
        ? "wrapped in quotes, remove them"
        : "not a JSON array, so read as base64";
    return {
      state: "malformed",
      address: null,
      detail:
        `${envVar} is set (${raw.length} characters, ${shape}) but could not be read: ` +
        `${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
