// Subject self-custody: moving a credential from a salted commitment the
// issuer controls to the subject's own wallet.
//
// This is the step people skip, and it is the one that makes an attestation
// worth more than a database row. Before it, the issuer holds a credential
// ABOUT someone. After it, the person holds a credential naming themselves,
// and can present it anywhere without the issuer being involved.
//
// It is also where the sharp edges are, so read "Two kinds of subject" below
// before touching anything that reads a credential.

import { createHash, createPublicKey, randomBytes, verify as verifyEd25519Signature } from "node:crypto";
import { getBase58Encoder, type KeyPairSigner } from "@solana/kit";
import { deriveSubjectAddress } from "./subject.js";
import { closeAttestation, issueAttestation, type IssueResult } from "./sas.js";
import type { ClusterSettings } from "./settings.js";

// ---------------------------------------------------------------------------
// Two kinds of subject
//
// A credential's subject is either:
//
//   derived        a salted commitment from deriveSubjectAddress(). Anyone
//                  holding the internal id and the salt can recompute it, so
//                  the binding between credential and person is checkable.
//
//   self-custodied the subject's own wallet address. Nothing on chain can
//                  re-derive it, because the binding rests on a wallet
//                  signature made once, off chain, at claim time.
//
// They are NOT interchangeable, and this is the failure that shipped. A
// verifier that recomputes the salted commitment and compares it to the
// on-chain subject works perfectly for the first kind and fails loudly for the
// second, on a public page, for exactly the users who took the extra step. It
// went unnoticed for a while because the claimed count was zero: nobody had
// used the path, so nothing had exercised it.
//
// The rule: anything reading a credential must know which kind it is looking
// at, and must not treat "the commitment does not match" as evidence of
// tampering. Use describeSubject() rather than comparing by hand.
// ---------------------------------------------------------------------------

export type SubjectKind = "derived" | "self-custodied" | "unknown";

export interface SubjectDescription {
  kind: SubjectKind;
  /** Whether the subject can be recomputed from the issuer's own records. */
  recomputable: boolean;
  detail: string;
}

/**
 * Work out which kind of subject an on-chain credential names.
 *
 * @param subject The subject address read from the credential.
 * @param expected The issuer's records: the internal id and salt for this
 *   person, if they still exist. Omit them after an erasure, or when the
 *   record is known to be self-custodied.
 */
export function describeSubject(
  subject: string,
  expected?: { domain: string; internalId: string; salt: string }
): SubjectDescription {
  if (!expected) {
    return {
      kind: "unknown",
      recomputable: false,
      detail:
        "No salt supplied, so the subject cannot be recomputed. This is the " +
        "normal state after an erasure, and is not a failure.",
    };
  }

  const derived = deriveSubjectAddress(expected.domain, expected.internalId, expected.salt);
  if (derived === subject) {
    return {
      kind: "derived",
      recomputable: true,
      detail: "The subject recomputes from the stored id and salt.",
    };
  }

  return {
    kind: "self-custodied",
    recomputable: false,
    // Deliberately not phrased as a mismatch or a warning. For a claimed
    // credential this is the expected result, and calling it a failure is the
    // bug this function exists to prevent.
    detail:
      "The subject is not the salted commitment, which means the credential " +
      "was claimed to a wallet. Its binding rests on a signature made at " +
      "claim time, which nothing on chain can re-check.",
  };
}

// ---------------------------------------------------------------------------
// The challenge
// ---------------------------------------------------------------------------

export interface Challenge {
  nonce: string;
  message: string;
  expiresAt: Date;
}

export const CHALLENGE_TTL_MS = 5 * 60 * 1000;

/**
 * The message the subject signs.
 *
 * Written to be read by a human in a wallet popup, because that is where it is
 * read. It names the issuer, says plainly what signing does, and says what it
 * does not do. A wallet prompt showing an opaque blob trains people to approve
 * things they have not understood, which is the behaviour every drainer relies
 * on.
 */
export function challengeMessage(issuerName: string, nonce: string): string {
  return [
    `${issuerName}: claim your verified identity credential`,
    "",
    "Signing this proves you control this wallet. It authorises no transaction",
    "and moves no funds.",
    "",
    `Nonce: ${nonce}`,
  ].join("\n");
}

export function createChallenge(issuerName: string, ttlMs = CHALLENGE_TTL_MS): Challenge {
  const nonce = randomBytes(24).toString("hex");
  return {
    nonce,
    message: challengeMessage(issuerName, nonce),
    expiresAt: new Date(Date.now() + ttlMs),
  };
}

/**
 * Where issued challenges live between the two requests.
 *
 * An interface rather than an implementation, because this is the part that
 * has to match your stack. What matters is the behaviour: a challenge is
 * consumed exactly once and expires.
 *
 * Do not be tempted to derive the challenge instead, from the wallet address
 * or a timestamp. A derived challenge is replayable forever by anyone who
 * captures one signature, and the signature is the whole proof.
 */
export interface ChallengeStore {
  put(subjectId: string, challenge: Challenge): Promise<void>;
  /** Returns the challenge and deletes it. Null if unknown, used or expired. */
  take(subjectId: string, nonce: string): Promise<Challenge | null>;
}

/**
 * A reference store, for tests and single-process tools.
 *
 * Not for production: it is per process, so it breaks the moment you run two
 * instances, and it does not survive a restart. Use your database.
 */
export function createMemoryChallengeStore(): ChallengeStore {
  const held = new Map<string, Challenge>();
  const key = (id: string, nonce: string) => `${id}:${nonce}`;

  return {
    async put(subjectId, challenge) {
      held.set(key(subjectId, challenge.nonce), challenge);
    },
    async take(subjectId, nonce) {
      const k = key(subjectId, nonce);
      const found = held.get(k);
      // Deleted whether or not it had expired: a challenge presented once is
      // spent, and leaving an expired one in place lets a caller keep probing.
      held.delete(k);
      if (!found) return null;
      if (found.expiresAt.getTime() <= Date.now()) return null;
      return found;
    },
  };
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

// A raw ed25519 public key wrapped as SPKI DER, which is the only form Node's
// crypto will build a KeyObject from. The prefix is the fixed ASN.1 header for
// a 32 byte ed25519 key, and there is no way to discover it from the Node
// documentation, which is why it is spelled out here.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Verify that `signature` over `message` was made by the key behind
 * `address`, all base58 as a wallet produces them.
 *
 * Returns false rather than throwing for malformed input. A bad address or a
 * truncated signature is a failed proof, not a server error, and treating it
 * as one turns a user's typo into a 500.
 */
export function verifyWalletSignature(
  message: string,
  signatureBase58: string,
  addressBase58: string
): boolean {
  try {
    const encoder = getBase58Encoder();
    const publicKeyBytes = Buffer.from(encoder.encode(addressBase58));
    const signatureBytes = Buffer.from(encoder.encode(signatureBase58));
    if (publicKeyBytes.length !== 32 || signatureBytes.length !== 64) return false;

    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKeyBytes]),
      format: "der",
      type: "spki",
    });
    return verifyEd25519Signature(null, Buffer.from(message, "utf8"), key, signatureBytes);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// The claim
// ---------------------------------------------------------------------------

export interface ClaimRequest {
  /** The issuer's own id for this person, used to look up their challenge. */
  subjectId: string;
  /** The wallet they say they control. */
  walletAddress: string;
  /** Their signature over the challenge message, base58. */
  signature: string;
  nonce: string;
  /** The credential's current subject, if one has already been issued. */
  previousSubject?: string | null;
  /**
   * How identity was established.
   *
   * REQUIRED, and not defaulted. The second bug that shipped here was a claim
   * route that omitted it and fell back to the document method, so somebody
   * verified against a national database had a permanent, public, on-chain
   * statement that they had presented a document. A credential that says the
   * wrong thing about a real person is worse than no credential.
   */
  method: string;
  verifiedAt: Date;
  ttlDays?: number;
}

export interface ClaimResult extends IssueResult {
  previousSubjectClosed: boolean;
}

/**
 * Move a credential to the subject's own wallet, after proving they hold it.
 *
 * The order matters. The signature is checked and the challenge consumed
 * before anything is written on chain, so a failed proof costs nothing and
 * cannot leave a half-completed claim behind.
 */
export async function claimToWallet(
  signer: KeyPairSigner,
  settings: ClusterSettings,
  store: ChallengeStore,
  issuerName: string,
  request: ClaimRequest
): Promise<ClaimResult> {
  const challenge = await store.take(request.subjectId, request.nonce);
  if (!challenge) {
    throw new Error("That challenge is unknown, already used, or expired. Request a new one.");
  }

  // Rebuilt from the nonce rather than trusting a message sent by the caller,
  // who would otherwise choose what they are signing.
  const expectedMessage = challengeMessage(issuerName, challenge.nonce);
  if (!verifyWalletSignature(expectedMessage, request.signature, request.walletAddress)) {
    throw new Error("That signature does not prove control of that wallet.");
  }

  // Close the old credential first, so two do not stand for the same person,
  // and so its rent comes back. Skipped when the subject is unchanged, which
  // issueAttestation handles with replace.
  let previousSubjectClosed = false;
  if (request.previousSubject && request.previousSubject !== request.walletAddress) {
    await closeAttestation(signer, settings, request.previousSubject);
    previousSubjectClosed = true;
  }

  const result = await issueAttestation(
    signer,
    settings,
    request.walletAddress,
    request.verifiedAt,
    request.method,
    request.ttlDays,
    // Covers claiming twice to the same wallet, where nothing was closed above
    // and an attestation already sits at that address.
    { replace: true }
  );

  return { ...result, previousSubjectClosed };
}

/** Exported for tests: the digest used by deriveSubjectAddress. */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
