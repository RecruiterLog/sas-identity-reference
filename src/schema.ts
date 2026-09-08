// The schema, and the encoding detail that costs everyone a day.
//
// SAS stores a schema's field names on chain as a single joined blob: for each
// name, a u32 little endian length followed by its UTF-8 bytes. The instruction
// that CREATES a schema takes an array of strings and encodes that for you, so
// the write path never shows you this. The read path hands the blob back raw.
//
// The consequence, which is not documented anywhere obvious: you cannot
// hand-build a schema object to pass to serializeAttestationData by writing
// `fieldNames: ["v", "method"]`. It fails with "Input must be a 4-byte array",
// which gives no hint that a length prefix is what is missing.
//
// encodeFieldNames below is the missing half, and it is what lets the
// serialisation layer be tested without a network or a funded wallet.

import { serializeAttestationData, deserializeAttestationData } from "sas-lib";

/**
 * Layout codes, from sas-lib's compactLayoutMapping. Only the ones used here
 * are named; the full table runs to 30 entries.
 */
export const LAYOUT = {
  u8: 0,
  u16: 1,
  u32: 2,
  u64: 3,
  i64: 8,
  bool: 10,
  string: 12,
} as const;

/** Identifies the issuer on chain. */
export const CREDENTIAL_NAME = "ExampleIssuer";

export const SCHEMA_NAME = "verified-identity";
export const SCHEMA_VERSION = 1;
export const SCHEMA_DESCRIPTION =
  "Holder passed a government-ID and liveness check vouched for by the issuer.";

/**
 * Field order is load bearing.
 *
 * `layout` and `fieldNames` are positional and SAS pairs them by index.
 * Reordering either one, or changing a type in place, silently reinterprets
 * every attestation already issued. Any change here needs SCHEMA_VERSION
 * bumped, which derives a different schema PDA and therefore leaves the old
 * attestations readable under the old schema.
 */
export const SCHEMA_FIELD_NAMES = ["v", "method", "verifiedAt"] as const;
export const SCHEMA_LAYOUT = new Uint8Array([LAYOUT.u8, LAYOUT.string, LAYOUT.i64]);

/**
 * A credential name longer than 32 bytes is silently truncated when seeding
 * the PDA, so two names sharing their first 32 bytes derive the same address.
 * Better to refuse than to collide.
 */
export const MAX_PDA_SEED_BYTES = 32;

export function assertSeedFits(label: string, value: string): void {
  const len = new TextEncoder().encode(value).length;
  if (len > MAX_PDA_SEED_BYTES) {
    throw new Error(
      `${label} is ${len} bytes; only the first ${MAX_PDA_SEED_BYTES} seed the PDA, ` +
        `so a longer value can collide with any other sharing its first ${MAX_PDA_SEED_BYTES}.`
    );
  }
}

/**
 * Encode field names the way the on chain Schema account stores them: each
 * name as a u32 little endian byte length followed by its UTF-8 bytes,
 * concatenated with no separator or outer length.
 */
export function encodeFieldNames(names: readonly string[]): Uint8Array {
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];

  for (const name of names) {
    const bytes = encoder.encode(name);
    parts.push(
      new Uint8Array([
        bytes.length & 0xff,
        (bytes.length >> 8) & 0xff,
        (bytes.length >> 16) & 0xff,
        (bytes.length >> 24) & 0xff,
      ]),
      bytes
    );
  }

  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** The inverse, for reading a schema account back. */
export function decodeFieldNames(blob: Uint8Array): string[] {
  const decoder = new TextDecoder();
  const names: string[] = [];
  let offset = 0;

  while (offset < blob.length) {
    if (offset + 4 > blob.length) {
      throw new Error("decodeFieldNames: truncated length prefix");
    }
    const len =
      blob[offset] | (blob[offset + 1] << 8) | (blob[offset + 2] << 16) | (blob[offset + 3] << 24);
    offset += 4;
    if (len < 0 || offset + len > blob.length) {
      throw new Error(`decodeFieldNames: length ${len} runs past the end of the blob`);
    }
    names.push(decoder.decode(blob.slice(offset, offset + len)));
    offset += len;
  }

  return names;
}

/**
 * The shape sas-lib's (de)serialiser needs. Matches the on chain account's
 * relevant fields, which is why it can be built by hand for a test.
 */
export interface SchemaShape {
  layout: Uint8Array;
  fieldNames: Uint8Array;
}

/** This package's schema, in the shape the serialiser wants. */
export function localSchemaShape(): SchemaShape {
  return { layout: SCHEMA_LAYOUT, fieldNames: encodeFieldNames(SCHEMA_FIELD_NAMES) };
}

/**
 * Serialise a payload against a schema.
 *
 * Prefer passing the schema account fetched FROM CHAIN rather than
 * `localSchemaShape()`. The on chain account is what actually governs the
 * encoding, so using it means a mismatch between your constants and reality
 * surfaces as a hard failure here, instead of as silently misencoded data that
 * nobody notices until someone tries to read a credential back.
 */
export function serialize(schema: SchemaShape, data: Record<string, unknown>): Uint8Array {
  return serializeAttestationData(schema as never, data as never) as Uint8Array;
}

export function deserialize<T>(schema: SchemaShape, bytes: Uint8Array): T {
  return deserializeAttestationData<T>(schema as never, bytes as never);
}
