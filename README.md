# sas-identity-reference

A worked [Solana Attestation Service](https://attest.solana.com) integration:
issuing an identity credential from a real KYC check, with a subject that
cannot be linked back to a person once their record is deleted.

Written because the SAS documentation covers the instructions well and the
integration decisions not at all, and the decisions are where the day goes.

## What this is for

You have run an identity check on someone, through Sumsub or Onfido or a
national database, and you want the result to be checkable by a third party
without them trusting you or contacting you. That is what an attestation is
good at.

The parts that are not obvious, and that this repository exists to show:

- **What to use as the subject.** Not your user's primary key.
- **What to put in the payload.** Nothing identifying, and a method field.
- **How to honour an erasure request** against an immutable ledger.
- **The encoding detail** that makes the serialiser fail with a message that
  tells you nothing.

## Do not use the internal id as the subject

The obvious move is to attest against your user's id. Do not.

Putting a primary key on chain welds an internal identifier into a permanent
public record. It makes an erasure request impossible to honour, because you
cannot unpublish it, and it means anyone who ever obtains a copy of your
database can link every attestation you have issued to a named person, forever.

Instead, derive the subject from the id and a per subject salt:

```js
import { makeSubjectSalt, deriveSubjectAddress } from "sas-identity-reference";

const salt = makeSubjectSalt();                            // store on the row
const subject = deriveSubjectAddress("recruiter", userId, salt);
```

`subject` is a base58 encoded SHA-256 digest, so it is a syntactically valid
Solana address that provably has no private key. Nothing can ever sign as it,
which is correct: a subject is an identifier, not an actor.

SAS documents its attestation nonce as either the wallet the attestation is
associated with **or** a randomly generated address, so a salted commitment is
a supported subject rather than a workaround. Once a subject links a real
wallet, use that instead.

## Self-custody: giving the credential to its subject

Before this step the issuer holds a credential *about* someone. After it, the
person holds a credential naming themselves and can present it anywhere without
the issuer being involved. It is the step that makes an attestation worth more
than a database row, and it is the one most integrations skip.

```js
import { createChallenge, claimToWallet, createMemoryChallengeStore } from "sas-identity-reference";

// 1. Issue a single-use challenge and show the message to the subject.
const challenge = createChallenge("ExampleIssuer");
await store.put(userId, challenge);
// challenge.message is what their wallet will display

// 2. They sign it. You verify, and the credential moves to their wallet.
const result = await claimToWallet(signer, settings, store, "ExampleIssuer", {
  subjectId: userId,
  walletAddress,
  signature,
  nonce: challenge.nonce,
  previousSubject: theirSaltedCommitment,
  method: "gov-id+liveness",
  verifiedAt,
});
```

The challenge is stored rather than derived. A derived challenge, from the
wallet address or a timestamp, is replayable forever by anyone who captures one
signature, and the signature is the entire proof. `ChallengeStore` is an
interface because that part has to match your stack; the in-memory
implementation is for tests and single-process tools, not production.

The message is rebuilt from the stored nonce rather than taken from the
request. Otherwise the caller chooses what they are signing.

One implementation detail with no discoverable documentation: Node's crypto
will only build an ed25519 `KeyObject` from SPKI DER, so a raw 32-byte wallet
key has to be wrapped with the fixed ASN.1 prefix `302a300506032b6570032100`.
That single constant is most of what makes `verifyWalletSignature` work.

## Two kinds of subject, and the bug that comes from ignoring it

A credential's subject is either **derived**, a salted commitment anyone with
the id and salt can recompute, or **self-custodied**, the subject's own wallet,
whose binding rests on a signature made once, off chain, at claim time and
which nothing on chain can re-check.

They are not interchangeable, and this is the failure that shipped in
production:

> A verifier recomputed the salted commitment, compared it to the on-chain
> subject, and reported failure. That is correct for a derived subject and
> wrong for a claimed one, so it failed loudly, on a public page, for precisely
> the users who had taken the extra step.

It went unnoticed because the claimed count was zero. Nobody had used the path,
so nothing had exercised it.

Use `describeSubject()` rather than comparing by hand:

```js
const d = describeSubject(onChainSubject, { domain, internalId, salt });
// d.kind: "derived" | "self-custodied" | "unknown"
```

Three things it deliberately does **not** do. It never calls a non-matching
commitment tampering. It reports a missing salt as `unknown` rather than as a
failure, because that is the normal state after an erasure. And it reports a
wrong salt as `self-custodied`, because nothing on chain distinguishes the two
and claiming otherwise would be inventing certainty.

## How erasure works

The salt is stored on the subject's own row and nowhere else. Delete the row
and the salt goes with it, at which point the on chain subject address is a
32 byte number nobody can connect to a person: reversing it means inverting
SHA-256, and there are 2^256 salts to guess.

`closeAttestation` then reclaims the account's rent. Worth being precise about
the order of importance: **closing the account is the tidy half. Destroying
the salt is the half that matters**, because it is the only one that holds
against somebody who archived the chain before you closed anything.

The guarantee therefore rests on one operational commitment the code cannot
enforce: no copy of a salt in a backup, a replica, an audit log or a warehouse
export. Anyone adopting this should be able to say where salts live and what
deletes them.

The same lever, applied to Merkle anchoring rather than attestations, is
[erasable-anchor](https://github.com/RecruiterLog/erasable-anchor).

## The payload

```
v          u8      format version
method     String   how identity was established, e.g. "gov-id+liveness"
verifiedAt i64      unix seconds
```

Nothing identifying. `method` is a parameter rather than a constant because a
document check and a national database lookup are genuinely different claims,
and publishing one blanket value for both makes the credential assert
something untrue about whichever half did not match. Unlike a display bug,
that is permanent and public.

That is not hypothetical either. It is the **second** bug that shipped here: a
claim route omitted the method and fell back to the document value, so somebody
verified against a national database got a permanent on-chain statement that
they had presented a document. `claimToWallet` requires `method` and does not
default it, which is why.

Credentials expire, 365 days by default. An identity check going stale is a
real thing, and without an expiry a single check vouches for someone
indefinitely, which is a claim no honest issuer can make.

## The encoding detail that costs a day

On chain, a Schema's `fieldNames` is a **single joined blob**: for each name, a
u32 little endian length followed by its UTF-8 bytes. The instruction that
*creates* a schema takes an array of strings and encodes that for you, so the
write path never shows you this. Reading the account back gives you the blob.

So this does not work:

```js
serializeAttestationData({ layout, fieldNames: ["v", "method"] }, data)
// Error: Input must be a 4-byte array
```

Nothing in that message suggests a missing length prefix. `encodeFieldNames`
and `decodeFieldNames` here are the missing halves, and having them is what
lets the serialisation layer be tested with no network and no funded wallet,
which is the highest risk code in the package.

Two more traps, both guarded in code:

- **`layout` and `fieldNames` are positional**, paired by index. Reorder either
  one, or change a type in place, and every attestation already issued is
  silently reinterpreted. Bump `SCHEMA_VERSION`, which derives a different PDA
  and leaves the old attestations readable under the old schema.
- **Only the first 32 bytes of a name seed a PDA.** Two names sharing their
  first 32 bytes derive the same address. `assertSeedFits` refuses rather than
  collides, by byte length rather than character count.

## The error that makes no sense

> Multiple distinct signers were identified for address ...

`@solana/kit` identifies signers by **object identity**, not by address. Two
`KeyPairSigner` instances built from the same key count as two different
signers, so building one transaction from instructions created at several call
sites fails. `getSigner()` memoises for exactly this reason, and nothing in the
error points at object identity.

## Dependency versions

`sas-lib@1.0.10` peer-requires `@solana/kit@^5`. This package therefore uses
kit 5 as well, which is why it compiles with no casts.

**If your application is on kit 8**, npm installs a second nested copy of kit
for sas-lib, and the two sets of types become nominally distinct: kit brands
its `Address` and encoded byte types, and a brand from one copy is not
assignable to the identically shaped brand from the other. It is a type level
problem only. At runtime an address is a string, an instruction is a plain
object, and the JSON-RPC contract is identical, so the values pass through
unchanged. Two contained casts at the boundary are the honest accommodation:

```ts
function sasRpc(url: string) {
  return createSolanaRpc(url) as unknown as Parameters<typeof fetchMaybeCredential>[0];
}
function asAppInstruction(ix: unknown) {
  return ix as Parameters<typeof sendInstructions>[0][number];
}
```

Do not reach for an npm `overrides` forcing sas-lib onto kit 8. That silently
assumes runtime compatibility across a major version of a library that signs
transactions spending real funds.

`@solana-program/compute-budget` is deliberately **not** a dependency: it
peer-requires kit ^2, and `SetComputeUnitPrice` is nine bytes of stable,
documented instruction data. See `setComputeUnitPriceInstruction` in
`src/submit.ts`.

## The CLI

```
npm run build
node bin/sas-ref.mjs --help
```

```
sas-ref subject recruiter <user-id>     derive a subject and a fresh salt
sas-ref address                         the issuer wallet and its PDAs
sas-ref balance
sas-ref setup                           create the credential and schema
sas-ref issue <subject> --method ...
sas-ref read <subject>
sas-ref close <subject>
```

Read commands are free. Write commands spend SOL, default to devnet, and
**refuse mainnet without `--yes`**. That guard is there because the difference
between the two clusters is one word in an environment variable and the
mistake is not recoverable.

The issuer key comes from `SAS_ISSUER_SECRET_KEY`, or `--key-file`. It accepts
either a JSON array of 64 bytes, which is what `solana-keygen new` writes, or
the same bytes base64 encoded. Never commit it, on any cluster: a devnet key
today is a mainnet key the moment somebody reuses it.

## Renewal is not a re-issue

The single most expensive thing in here to learn the hard way.

**SAS has no update instruction.** Create refuses an account that already
exists, and the message is not obviously about renewal:

```
Allocate: account 75RTot...ahT6 already in use
Program 22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG failed: custom program error: 0x0
```

Renewing therefore means **close, then create**. The trap is that a nightly job
written the obvious way looks correct and works for a year: a credential nears
expiry, you recompute the same subject from the same stored salt, and create
fails because last year's account is still at that address. The job then
retries every night while the credential sits expired.

`issueAttestation` checks first and refuses with a message that names the
remedy, rather than spending a fee on a transaction that cannot succeed. Pass
`{ replace: true }`, or `--replace` on the CLI, to close first.

Worth knowing: replace is two transactions and is **not atomic**. If the create
fails after the close succeeded, the subject has no credential until the next
run. That is the right way round, because a missing credential is a recoverable
state and a stale one is a false claim, but a caller should expect it.

## What has been verified

Being explicit, because "reference implementation" invites more trust than a
test count deserves.

**Offline, 40 tests:** subject derivation, the payload, expiry arithmetic
including the inclusive boundary, field name encoding and decoding with
multibyte names, a frozen serialisation vector checked byte for byte, the
layout mismatch guard, the PDA seed guard by byte length, and the CLI surface
including the mainnet refusal. The package builds against kit 5 with no casts.

The claim tests sign with a real locally generated ed25519 keypair, which is
what a wallet does, so signature verification is exercised rather than mocked:
a genuine signature passes, another wallet's fails, a signature over a
different message fails, and malformed input returns false instead of throwing.

**On chain, against mainnet:** every path has been run end to end. Creating the
credential and schema in one transaction, issuing, reading the credential back
and decoding it to the values that went in, the refusal on a second issue, the
`--replace` renewal reusing the same PDA with new values, closing and
reclaiming rent, reading a subject that has no credential, and re-running
`setup` to confirm it is idempotent.

That last group is what the offline vector alone could not establish. A
serialisation test can agree with itself and still be wrong about the format;
only reading a credential back off the chain and getting `gov-id+liveness` and
the right timestamp out of it settles that the payload was encoded correctly
against the schema account as it actually exists.

Total cost of the full run was about 0.0033 SOL, most of which is rent still
held by the credential and schema accounts.

## Licence

Apache 2.0. See `LICENSE` and `NOTICE`.
