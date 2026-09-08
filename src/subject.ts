// The pure layer: subject derivation and the attestation payload.
//
// No I/O and no network, deliberately. The subject derivation has to be
// reproducible by anyone in any implementation, or the credential cannot be
// checked independently, and a credential nobody outside the issuer can check
// is just a database row with extra steps.

import { createHash, randomBytes } from "node:crypto";
import { getBase58Decoder } from "@solana/kit";

/** Bump when the derivation or the payload's field set changes. */
export const ATTESTATION_VERSION = 1;

/**
 * How long a credential stays valid before it must be re-earned.
 *
 * An identity check going stale is a real thing. Without an expiry, a single
 * check would vouch for someone indefinitely, which is a claim no honest
 * issuer can make.
 */
export const DEFAULT_TTL_DAYS = 365;

export interface AttestationData {
  /** Format version, so a later change is distinguishable from tampering. */
  v: number;
  /** How identity was established, for example "gov-id+liveness". */
  method: string;
  /** Unix seconds. i64 on chain. */
  verifiedAt: bigint;
}

/**
 * A fresh per subject salt, 32 bytes hex.
 *
 * Store this on the subject's own database row and nowhere else. Deleting the
 * row destroys the salt, and with it any link between the on chain subject
 * address and a person. That is the erasure lever, and it only works if there
 * is exactly one copy.
 */
export function makeSubjectSalt(): string {
  return randomBytes(32).toString("hex");
}

/**
 * Derive the on chain subject address from an internal id and its salt.
 *
 * Deliberately NOT the internal id itself. Putting a primary key on chain
 * welds an internal identifier into an immutable public record, and makes an
 * erasure request impossible to honour: you cannot unpublish it, and anyone
 * holding a copy of your database can then link every attestation to a person
 * forever.
 *
 * A Solana address is 32 bytes, and SAS documents its attestation nonce as
 * either the wallet the attestation is associated with OR a randomly generated
 * address. A salted commitment is therefore a supported subject rather than a
 * workaround.
 *
 * @param domain A short label for what kind of subject this is. Included in
 *   the hash so the same id under two different schemes cannot collide.
 * @param internalId The issuer's own identifier for the subject.
 * @param salt From `makeSubjectSalt()`, stored beside the subject.
 */
export function deriveSubjectAddress(domain: string, internalId: string, salt: string): string {
  if (!domain || domain.includes(":")) {
    // A colon in the domain would let two different (domain, id) pairs
    // produce the same preimage, which is exactly the collision the domain
    // separator is here to prevent.
    throw new Error('deriveSubjectAddress: domain must be non-empty and must not contain ":"');
  }
  if (!internalId) throw new Error("deriveSubjectAddress: internalId is required");
  if (!salt) throw new Error("deriveSubjectAddress: salt is required");

  const digest = createHash("sha256")
    .update(`${domain}:v${ATTESTATION_VERSION}:${internalId}:${salt}`, "utf8")
    .digest();

  // A base58 encoded 32 byte digest is a syntactically valid Solana address
  // that provably has no private key, because finding one would mean inverting
  // SHA-256. Nothing can ever sign as this subject, which is correct: the
  // subject is an identifier, not an actor.
  return getBase58Decoder().decode(digest);
}

/**
 * The payload written on chain. Nothing identifying belongs in here.
 *
 * `method` is a parameter rather than a constant because a document check and
 * a national database check are genuinely different claims. Publishing one
 * blanket value for both would make the credential assert something untrue
 * about whichever half did not match, and unlike a display bug that is
 * permanent and public.
 */
export function buildAttestationData(verifiedAt: Date, method: string): AttestationData {
  if (!method) throw new Error("buildAttestationData: method is required");
  return {
    v: ATTESTATION_VERSION,
    method,
    verifiedAt: BigInt(Math.floor(verifiedAt.getTime() / 1000)),
  };
}

export function attestationExpiry(from: Date = new Date(), ttlDays: number = DEFAULT_TTL_DAYS): bigint {
  if (!Number.isFinite(ttlDays) || ttlDays <= 0) {
    throw new Error("attestationExpiry: ttlDays must be a positive number");
  }
  return BigInt(Math.floor(from.getTime() / 1000) + Math.floor(ttlDays * 24 * 60 * 60));
}

export function isExpired(expiry: bigint | number, now: Date = new Date()): boolean {
  return Number(expiry) * 1000 <= now.getTime();
}
