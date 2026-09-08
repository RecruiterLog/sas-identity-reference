// The self-custody claim, and the two subject kinds.
//
// Everything here runs offline. Signing is done with a locally generated
// ed25519 keypair, which is exactly what a wallet does, so the verification
// path is exercised for real rather than mocked.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import {
  challengeMessage,
  createChallenge,
  createMemoryChallengeStore,
  describeSubject,
  verifyWalletSignature,
  deriveSubjectAddress,
  makeSubjectSalt,
  CHALLENGE_TTL_MS,
} from "../dist/index.js";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(buf) {
  let n = BigInt("0x" + Buffer.from(buf).toString("hex"));
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of buf) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

/** A stand-in for a wallet: an ed25519 keypair that can sign a message. */
function makeWallet() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return {
    address: base58(raw),
    sign: (message) => base58(edSign(null, Buffer.from(message, "utf8"), privateKey)),
  };
}

test("a wallet's own signature over the challenge verifies", () => {
  const wallet = makeWallet();
  const { message } = createChallenge("ExampleIssuer");
  assert.equal(verifyWalletSignature(message, wallet.sign(message), wallet.address), true);
});

test("another wallet's signature does not", () => {
  const alice = makeWallet();
  const mallory = makeWallet();
  const { message } = createChallenge("ExampleIssuer");
  assert.equal(verifyWalletSignature(message, mallory.sign(message), alice.address), false);
});

test("a signature over a different message does not verify", () => {
  // The claim path rebuilds the message from the stored nonce rather than
  // trusting one supplied by the caller. Without that, a caller chooses what
  // they are signing.
  const wallet = makeWallet();
  const a = createChallenge("ExampleIssuer");
  const b = createChallenge("ExampleIssuer");
  assert.equal(verifyWalletSignature(a.message, wallet.sign(b.message), wallet.address), false);
});

test("malformed input is a failed proof, not an exception", () => {
  const wallet = makeWallet();
  const { message } = createChallenge("ExampleIssuer");
  const good = wallet.sign(message);
  for (const [sig, addr] of [
    ["", wallet.address],
    [good, ""],
    ["not-base58-!!!", wallet.address],
    [good, "not-base58-!!!"],
    [good.slice(0, 20), wallet.address],
    [good, wallet.address.slice(0, 10)],
  ]) {
    assert.equal(verifyWalletSignature(message, sig, addr), false);
  }
});

test("the challenge message names the issuer and says what signing does", () => {
  // It is read in a wallet popup by a person deciding whether to approve. A
  // prompt showing an opaque blob trains people to approve what they have not
  // understood.
  const msg = challengeMessage("ExampleIssuer", "abc123");
  assert.match(msg, /^ExampleIssuer: claim your verified identity credential/);
  assert.match(msg, /authorises no transaction/);
  assert.match(msg, /moves no funds/);
  assert.match(msg, /Nonce: abc123/);
});

test("nonces do not repeat", () => {
  const seen = new Set();
  for (let i = 0; i < 500; i++) seen.add(createChallenge("X").nonce);
  assert.equal(seen.size, 500);
});

test("the default TTL is five minutes", () => {
  const c = createChallenge("X");
  const ms = c.expiresAt.getTime() - Date.now();
  assert.ok(ms > CHALLENGE_TTL_MS - 2000 && ms <= CHALLENGE_TTL_MS);
});

test("a challenge can be taken exactly once", async () => {
  const store = createMemoryChallengeStore();
  const c = createChallenge("X");
  await store.put("subject-1", c);

  assert.ok(await store.take("subject-1", c.nonce));
  assert.equal(await store.take("subject-1", c.nonce), null, "a spent challenge is gone");
});

test("an expired challenge is refused", async () => {
  const store = createMemoryChallengeStore();
  const c = createChallenge("X", -1000);
  await store.put("subject-1", c);
  assert.equal(await store.take("subject-1", c.nonce), null);
});

test("a challenge belongs to one subject", async () => {
  const store = createMemoryChallengeStore();
  const c = createChallenge("X");
  await store.put("subject-1", c);
  assert.equal(await store.take("subject-2", c.nonce), null);
  assert.ok(await store.take("subject-1", c.nonce), "still there for its owner");
});

test("an unknown nonce is refused", async () => {
  const store = createMemoryChallengeStore();
  assert.equal(await store.take("subject-1", "never-issued"), null);
});

// --- the two subject kinds -------------------------------------------------

test("a derived subject is recognised and recomputable", () => {
  const salt = makeSubjectSalt();
  const subject = deriveSubjectAddress("recruiter", "user-1", salt);
  const d = describeSubject(subject, { domain: "recruiter", internalId: "user-1", salt });

  assert.equal(d.kind, "derived");
  assert.equal(d.recomputable, true);
});

test("a claimed subject is reported as self-custodied, NOT as a mismatch", () => {
  // The bug this encodes: a verifier recomputed the commitment, compared it to
  // the on-chain subject, and reported failure on a public page for every user
  // who had claimed their credential. The comparison was right; treating its
  // result as tampering was not.
  const wallet = makeWallet();
  const salt = makeSubjectSalt();
  const d = describeSubject(wallet.address, {
    domain: "recruiter",
    internalId: "user-1",
    salt,
  });

  assert.equal(d.kind, "self-custodied");
  assert.equal(d.recomputable, false);
  assert.doesNotMatch(d.detail, /tamper|invalid|fail/i);
});

test("an erased subject is unknown, and that is not a failure", () => {
  const wallet = makeWallet();
  const d = describeSubject(wallet.address);
  assert.equal(d.kind, "unknown");
  assert.equal(d.recomputable, false);
  assert.match(d.detail, /not a failure/);
});

test("the wrong salt reads as self-custodied, which is the honest answer", () => {
  // Nothing on chain distinguishes "claimed to a wallet" from "we have the
  // wrong salt". Claiming otherwise would be inventing certainty.
  const subject = deriveSubjectAddress("recruiter", "user-1", makeSubjectSalt());
  const d = describeSubject(subject, {
    domain: "recruiter",
    internalId: "user-1",
    salt: makeSubjectSalt(),
  });
  assert.equal(d.kind, "self-custodied");
});
