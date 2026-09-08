import { test } from "node:test";
import assert from "node:assert/strict";
import { getBase58Encoder } from "@solana/kit";
import {
  ATTESTATION_VERSION,
  makeSubjectSalt,
  deriveSubjectAddress,
  buildAttestationData,
  attestationExpiry,
  isExpired,
  DEFAULT_TTL_DAYS,
} from "../dist/index.js";

const DOMAIN = "example-subject";
const ID = "1f0e4a10-0000-4000-8000-000000000001";
const SALT = "a".repeat(64);

test("a subject address is a valid base58 encoding of 32 bytes", () => {
  const subject = deriveSubjectAddress(DOMAIN, ID, SALT);
  assert.match(subject, /^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
  // The bit that matters for SAS: it has to be usable as an address, which
  // means exactly 32 bytes once decoded.
  assert.equal(getBase58Encoder().encode(subject).length, 32);
});

test("derivation is deterministic", () => {
  assert.equal(deriveSubjectAddress(DOMAIN, ID, SALT), deriveSubjectAddress(DOMAIN, ID, SALT));
});

test("changing the salt changes the subject", () => {
  assert.notEqual(deriveSubjectAddress(DOMAIN, ID, SALT), deriveSubjectAddress(DOMAIN, ID, "b".repeat(64)));
});

test("changing the id changes the subject", () => {
  assert.notEqual(deriveSubjectAddress(DOMAIN, ID, SALT), deriveSubjectAddress(DOMAIN, `${ID}x`, SALT));
});

test("the domain separates two schemes sharing an id and salt", () => {
  assert.notEqual(
    deriveSubjectAddress("recruiter", ID, SALT),
    deriveSubjectAddress("candidate", ID, SALT)
  );
});

test("a colon in the domain is refused", () => {
  // Without this, ("a:b", "c") and ("a", "b:c") would build the same preimage,
  // which is exactly the collision the separator exists to prevent.
  assert.throws(() => deriveSubjectAddress("a:b", ID, SALT), /must not contain/);
  assert.throws(() => deriveSubjectAddress("", ID, SALT), /non-empty/);
});

test("a missing id or salt is refused rather than hashed as empty", () => {
  assert.throws(() => deriveSubjectAddress(DOMAIN, "", SALT), /internalId is required/);
  assert.throws(() => deriveSubjectAddress(DOMAIN, ID, ""), /salt is required/);
});

test("salts are 32 bytes and do not repeat", () => {
  const seen = new Set();
  for (let i = 0; i < 500; i++) {
    const s = makeSubjectSalt();
    assert.match(s, /^[0-9a-f]{64}$/);
    seen.add(s);
  }
  assert.equal(seen.size, 500);
});

test("the payload carries a version, a method and a second precision timestamp", () => {
  const at = new Date("2026-09-08T12:34:56.789Z");
  const data = buildAttestationData(at, "gov-id+liveness");
  assert.equal(data.v, ATTESTATION_VERSION);
  assert.equal(data.method, "gov-id+liveness");
  // Seconds, and truncated rather than rounded, so it can never be a moment in
  // the future. 2026-09-08T12:34:56.789Z is 1788870896789ms, so 1788870896s.
  assert.equal(data.verifiedAt, 1788870896n);
  assert.equal(new Date(Number(data.verifiedAt) * 1000).toISOString(), "2026-09-08T12:34:56.000Z");
});

test("a method is required, because the fallback would assert something untrue", () => {
  assert.throws(() => buildAttestationData(new Date(), ""), /method is required/);
});

test("expiry defaults to the documented TTL", () => {
  const from = new Date("2026-01-01T00:00:00.000Z");
  const expiry = attestationExpiry(from);
  assert.equal(Number(expiry) - Math.floor(from.getTime() / 1000), DEFAULT_TTL_DAYS * 86400);
});

test("a non-positive TTL is refused", () => {
  // A zero or negative TTL issues a credential that is already expired, which
  // is worse than refusing: it looks issued and never verifies.
  assert.throws(() => attestationExpiry(new Date(), 0), /positive number/);
  assert.throws(() => attestationExpiry(new Date(), -1), /positive number/);
  assert.throws(() => attestationExpiry(new Date(), NaN), /positive number/);
});

test("isExpired is inclusive at the boundary", () => {
  const now = new Date("2026-09-08T00:00:00.000Z");
  const exactly = BigInt(Math.floor(now.getTime() / 1000));
  assert.equal(isExpired(exactly, now), true, "an expiry equal to now counts as expired");
  assert.equal(isExpired(exactly + 1n, now), false);
  assert.equal(isExpired(exactly - 1n, now), true);
});

test("isExpired accepts a number as well as a bigint", () => {
  const now = new Date("2026-09-08T00:00:00.000Z");
  assert.equal(isExpired(Math.floor(now.getTime() / 1000) + 60, now), false);
});
