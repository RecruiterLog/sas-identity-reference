// Credential, schema and attestation lifecycle.
//
// Every function here takes its signer and its cluster settings as arguments.
// Nothing reads a database, a settings singleton or an environment variable.
// That is the difference between a reference implementation and an extract of
// somebody's application: you should be able to drop this in without adopting
// where we happen to keep our configuration.

import { address, createSolanaRpc, type Address, type Instruction, type KeyPairSigner } from "@solana/kit";
import {
  deriveAttestationPda,
  deriveCredentialPda,
  deriveSchemaPda,
  fetchMaybeAttestation,
  fetchMaybeCredential,
  fetchMaybeSchema,
  fetchSchema,
  getCloseAttestationInstruction,
  getCreateAttestationInstruction,
  getCreateCredentialInstruction,
  getCreateSchemaInstruction,
} from "sas-lib";

import {
  CREDENTIAL_NAME,
  SCHEMA_DESCRIPTION,
  SCHEMA_FIELD_NAMES,
  SCHEMA_LAYOUT,
  SCHEMA_NAME,
  SCHEMA_VERSION,
  assertSeedFits,
  deserialize,
  serialize,
  type SchemaShape,
} from "./schema.js";
import { attestationExpiry, buildAttestationData, type AttestationData } from "./subject.js";
import { addressExplorerUrl, type ClusterSettings } from "./settings.js";
import { sendInstructions, type SubmitResult } from "./submit.js";

export interface SasAddresses {
  authority: Address;
  credential: Address;
  schema: Address;
}

/**
 * The credential and schema addresses.
 *
 * Both are PDAs derived from the issuer's wallet plus a fixed name, so they
 * are a pure function of the signing key. Nothing to store, and nothing that
 * can drift out of sync with what is on chain. Rotating the key moves them,
 * which is the honest outcome: a different issuer genuinely is a different
 * credential, and pretending otherwise would let a key holder inherit trust
 * they never earned.
 */
export async function getSasAddresses(signer: KeyPairSigner): Promise<SasAddresses> {
  assertSeedFits("CREDENTIAL_NAME", CREDENTIAL_NAME);
  assertSeedFits("SCHEMA_NAME", SCHEMA_NAME);

  const [credential] = await deriveCredentialPda({ authority: signer.address, name: CREDENTIAL_NAME });
  const [schema] = await deriveSchemaPda({ credential, name: SCHEMA_NAME, version: SCHEMA_VERSION });
  return { authority: signer.address, credential, schema };
}

export async function getAttestationAddress(
  signer: KeyPairSigner,
  subject: string
): Promise<Address> {
  const { credential, schema } = await getSasAddresses(signer);
  const [attestation] = await deriveAttestationPda({ credential, schema, nonce: address(subject) });
  return attestation;
}

export interface SetupResult extends SasAddresses {
  createdCredential: boolean;
  createdSchema: boolean;
  signature: string | null;
  explorerUrl: string | null;
}

/**
 * One time issuer setup: create the credential and the schema if absent.
 *
 * Idempotent by construction, because both are PDAs: a second run finds them
 * present and does nothing, rather than failing or duplicating. Safe to re-run
 * from a deploy script.
 */
export async function ensureCredentialAndSchema(
  signer: KeyPairSigner,
  settings: ClusterSettings
): Promise<SetupResult> {
  const { authority, credential, schema } = await getSasAddresses(signer);
  const rpc = createSolanaRpc(settings.rpcUrl) as never;

  const existingCredential = await fetchMaybeCredential(rpc, credential);
  const existingSchema = await fetchMaybeSchema(rpc, schema);

  const instructions: Instruction[] = [];

  if (!existingCredential.exists) {
    instructions.push(
      getCreateCredentialInstruction({
        payer: signer,
        credential,
        authority: signer,
        name: CREDENTIAL_NAME,
        // The issuer wallet is the only authorised signer, so attestations
        // under this credential can only come from it. That is the entire
        // basis of the claim being worth anything.
        signers: [authority],
      }) as unknown as Instruction
    );
  }

  if (!existingSchema.exists) {
    instructions.push(
      getCreateSchemaInstruction({
        payer: signer,
        authority: signer,
        credential,
        schema,
        name: SCHEMA_NAME,
        description: SCHEMA_DESCRIPTION,
        layout: SCHEMA_LAYOUT,
        // Note the asymmetry: the CREATE path takes plain strings and encodes
        // them, while reading the account back gives a joined length prefixed
        // blob. See schema.ts.
        fieldNames: [...SCHEMA_FIELD_NAMES],
      }) as unknown as Instruction
    );
  }

  if (instructions.length === 0) {
    return {
      authority,
      credential,
      schema,
      createdCredential: false,
      createdSchema: false,
      signature: null,
      explorerUrl: null,
    };
  }

  // Both in one transaction when both are missing. The schema cannot exist
  // without its credential, and doing them separately would leave a half built
  // issuer behind if the second failed.
  const result = await sendInstructions(instructions, signer, settings);

  return {
    authority,
    credential,
    schema,
    createdCredential: !existingCredential.exists,
    createdSchema: !existingSchema.exists,
    signature: result.signature,
    explorerUrl: result.explorerUrl,
  };
}

export interface IssueResult extends SubmitResult {
  subject: string;
  attestation: string;
  expiry: bigint;
  data: AttestationData;
}

/**
 * Issue a credential for one subject.
 *
 * NOT a re-issue. SAS has no update instruction, and create refuses an
 * account that already exists:
 *
 *   Allocate: account <attestation> already in use
 *   Program <sas> failed: custom program error: 0x0
 *
 * This is the trap in renewal. A credential expires, you recompute the same
 * subject from the same stored salt, and the create fails because the
 * attestation account from last year is still sitting at that address. A
 * nightly job written the obvious way retries forever while the credential
 * stays expired, and the error above does not obviously mean "close it first".
 *
 * Renewing means closing then creating, which `replace: true` does. Note that
 * it is two transactions and therefore not atomic: if the second fails, the
 * subject is left with no credential until the next run. That is the right
 * way round, since a missing credential is a recoverable state and a stale one
 * is a false claim, but a caller should know it can happen.
 *
 * @param subject A salted commitment from `deriveSubjectAddress`, or the
 *   subject's own wallet address once they have linked one. SAS treats both
 *   the same way.
 * @param method How identity was actually established.
 */
export async function issueAttestation(
  signer: KeyPairSigner,
  settings: ClusterSettings,
  subject: string,
  verifiedAt: Date,
  method: string,
  ttlDays?: number,
  options: { replace?: boolean } = {}
): Promise<IssueResult> {
  const { credential, schema } = await getSasAddresses(signer);
  const rpc = createSolanaRpc(settings.rpcUrl) as never;

  // Serialise against the schema account ON CHAIN, not against the local
  // constants. If the two have diverged, this fails loudly here instead of
  // writing misencoded data that nobody notices until a read.
  const schemaAccount = await fetchSchema(rpc, schema);

  const nonce = address(subject);
  const [attestation] = await deriveAttestationPda({ credential, schema, nonce });

  // Check before spending a fee on a transaction that cannot succeed, and
  // fail with something that names the remedy rather than with the program's
  // "already in use".
  const existing = await fetchMaybeAttestation(rpc, attestation);
  if (existing.exists) {
    if (!options.replace) {
      throw new Error(
        `An attestation already exists at ${attestation} for subject ${subject}. ` +
          "SAS has no update instruction, so create would fail with " +
          '"account already in use". Pass { replace: true } to close it first, ' +
          "which is what renewing a credential requires."
      );
    }
    await closeAttestation(signer, settings, subject);
  }

  const data = buildAttestationData(verifiedAt, method);
  const expiry = attestationExpiry(new Date(), ttlDays);
  const serialized = serialize(schemaAccount.data as unknown as SchemaShape, {
    v: data.v,
    method: data.method,
    verifiedAt: data.verifiedAt,
  });

  const result = await sendInstructions(
    [
      getCreateAttestationInstruction({
        payer: signer,
        authority: signer,
        credential,
        schema,
        attestation,
        nonce,
        data: serialized,
        expiry,
      }) as unknown as Instruction,
    ],
    signer,
    settings
  );

  return { ...result, subject, attestation, expiry, data };
}

export interface ReadResult {
  exists: boolean;
  attestation: string;
  subject: string;
  data: AttestationData | null;
  expiry: bigint | null;
  issuer: string | null;
  explorerUrl: string | null;
}

/**
 * Read a credential back off chain and decode it.
 *
 * This is what makes the claim checkable rather than merely asserted: the
 * decoded fields come from the chain, not from the issuer's database.
 */
export async function readAttestation(
  signer: KeyPairSigner,
  settings: ClusterSettings,
  subject: string
): Promise<ReadResult> {
  const { credential, schema } = await getSasAddresses(signer);
  const rpc = createSolanaRpc(settings.rpcUrl) as never;

  const nonce = address(subject);
  const [attestation] = await deriveAttestationPda({ credential, schema, nonce });

  const existing = await fetchMaybeAttestation(rpc, attestation);
  if (!existing.exists) {
    return {
      exists: false,
      attestation,
      subject,
      data: null,
      expiry: null,
      issuer: null,
      explorerUrl: null,
    };
  }

  const schemaAccount = await fetchSchema(rpc, schema);
  const decoded = deserialize<AttestationData>(
    schemaAccount.data as unknown as SchemaShape,
    Uint8Array.from(existing.data.data)
  );

  return {
    exists: true,
    attestation,
    subject,
    data: decoded,
    expiry: existing.data.expiry,
    issuer: existing.data.signer,
    explorerUrl: addressExplorerUrl(attestation, settings.cluster),
  };
}

/**
 * Close an attestation, reclaiming its rent.
 *
 * Two legitimate uses: erasure, and a verification later found to be invalid.
 *
 * Note what this is NOT for. If the credential attests to identity, do not
 * close it because the holder changed jobs or left an organisation. Revoking
 * an identity claim for an employment change makes it mean something it does
 * not say, and the holder is the one who pays for that.
 *
 * On erasure specifically: closing the account is the tidy half. The half that
 * actually matters is destroying the subject's salt, which is what makes the
 * subject address unlinkable to a person even for anyone who archived the
 * chain.
 */
export async function closeAttestation(
  signer: KeyPairSigner,
  settings: ClusterSettings,
  subject: string
): Promise<SubmitResult | null> {
  const { credential, schema } = await getSasAddresses(signer);
  const rpc = createSolanaRpc(settings.rpcUrl) as never;

  const nonce = address(subject);
  const [attestation] = await deriveAttestationPda({ credential, schema, nonce });

  // Nothing to close is a success, not an error. This runs from cleanup paths
  // that have to be safe to re-run.
  const existing = await fetchMaybeAttestation(rpc, attestation);
  if (!existing.exists) return null;

  return sendInstructions(
    [
      getCloseAttestationInstruction({
        payer: signer,
        authority: signer,
        credential,
        attestation,
      }) as unknown as Instruction,
    ],
    signer,
    settings
  );
}
