// sas-identity-reference
//
// A worked Solana Attestation Service integration: issuing an identity
// credential from a real KYC check, with a subject that cannot be linked back
// to a person once their record is deleted.
//
// Layered on purpose. subject.ts and schema.ts are pure and testable without a
// network or a funded wallet; submit.ts and sas.ts are the only files that
// touch the chain, and both take their signer and settings as arguments.

export {
  ATTESTATION_VERSION,
  DEFAULT_TTL_DAYS,
  makeSubjectSalt,
  deriveSubjectAddress,
  buildAttestationData,
  attestationExpiry,
  isExpired,
  type AttestationData,
} from "./subject.js";

export {
  LAYOUT,
  CREDENTIAL_NAME,
  SCHEMA_NAME,
  SCHEMA_VERSION,
  SCHEMA_DESCRIPTION,
  SCHEMA_FIELD_NAMES,
  SCHEMA_LAYOUT,
  MAX_PDA_SEED_BYTES,
  assertSeedFits,
  encodeFieldNames,
  decodeFieldNames,
  localSchemaShape,
  serialize,
  deserialize,
  type SchemaShape,
} from "./schema.js";

export {
  DEFAULT_RPC,
  settingsFor,
  txExplorerUrl,
  addressExplorerUrl,
  toWebsocketUrl,
  type Cluster,
  type ClusterSettings,
} from "./settings.js";

export {
  signerFromSecret,
  getSigner,
  resetSignerCache,
  describeSignerState,
  type SignerState,
} from "./signer.js";

export { sendInstructions, getBalanceLamports, type SubmitResult } from "./submit.js";

export {
  getSasAddresses,
  getAttestationAddress,
  ensureCredentialAndSchema,
  issueAttestation,
  readAttestation,
  closeAttestation,
  type SasAddresses,
  type SetupResult,
  type IssueResult,
  type ReadResult,
} from "./sas.js";
