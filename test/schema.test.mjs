// The schema layer, without a network or a funded wallet.
//
// This is the highest risk code in the package and the easiest to get silently
// wrong, because `layout` and `fieldNames` are positional and nothing checks
// they mean what you intended. It is testable offline only because the shape
// sas-lib's serialiser wants can be built by hand, which took reading its
// source to work out. See src/schema.ts.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  LAYOUT,
  SCHEMA_FIELD_NAMES,
  SCHEMA_LAYOUT,
  CREDENTIAL_NAME,
  SCHEMA_NAME,
  MAX_PDA_SEED_BYTES,
  assertSeedFits,
  encodeFieldNames,
  decodeFieldNames,
  localSchemaShape,
  serialize,
  deserialize,
} from "../dist/index.js";

const hex = (bytes) => Buffer.from(bytes).toString("hex");

test("field names encode as u32 little endian length prefixed UTF-8", () => {
  // "v" is one byte, so: 01 00 00 00 then 0x76.
  assert.equal(hex(encodeFieldNames(["v"])), "0100000076");
  assert.equal(hex(encodeFieldNames(["ab", "c"])), "0200000061620100000063");
});

test("encode and decode round trip, including unicode and an empty name", () => {
  for (const names of [
    ["v", "method", "verifiedAt"],
    ["single"],
    [],
    ["", "after an empty one"],
    ["Ünicode", "emoji 🙃"],
  ]) {
    assert.deepEqual(decodeFieldNames(encodeFieldNames(names)), names);
  }
});

test("a multibyte name is prefixed with its BYTE length, not its character count", () => {
  // The classic off by several: "Ü" is one character and two bytes.
  const encoded = encodeFieldNames(["Ü"]);
  assert.equal(encoded[0], 2);
  assert.deepEqual(decodeFieldNames(encoded), ["Ü"]);
});

test("a truncated blob is reported rather than decoded into nonsense", () => {
  const good = encodeFieldNames(["method"]);
  assert.throws(() => decodeFieldNames(good.slice(0, 2)), /truncated length prefix/);
  assert.throws(() => decodeFieldNames(good.slice(0, 6)), /runs past the end/);
});

test("this package's layout and field names line up", () => {
  // If these ever diverge, every attestation issued afterwards is misencoded,
  // and it fails at read time rather than at write time.
  assert.equal(SCHEMA_LAYOUT.length, SCHEMA_FIELD_NAMES.length);
  assert.deepEqual([...SCHEMA_LAYOUT], [LAYOUT.u8, LAYOUT.string, LAYOUT.i64]);
});

test("a fixed serialisation vector", () => {
  // Frozen deliberately. A change here means previously issued credentials no
  // longer decode, which is not something to discover from a support ticket.
  //
  //   01                 v, u8 = 1
  //   0f000000           u32 LE length 15
  //   676f76...          "gov-id+liveness"
  //   00f7bd6800000000   verifiedAt, i64 LE = 1757280000
  const bytes = serialize(localSchemaShape(), {
    v: 1,
    method: "gov-id+liveness",
    verifiedAt: 1757280000n,
  });
  assert.equal(bytes.length, 28);
  assert.equal(hex(bytes), "010f000000676f762d69642b6c6976656e65737300f7bd6800000000");
});

test("serialisation round trips through deserialisation", () => {
  const shape = localSchemaShape();
  const values = { v: 1, method: "gov-id+liveness", verifiedAt: 1757280000n };
  const decoded = deserialize(shape, serialize(shape, values));
  assert.equal(decoded.v, 1);
  assert.equal(decoded.method, "gov-id+liveness");
  assert.equal(decoded.verifiedAt, 1757280000n);
});

test("a longer method string changes only the length prefix and the bytes", () => {
  const shape = localSchemaShape();
  const a = serialize(shape, { v: 1, method: "nondoc", verifiedAt: 1757280000n });
  const b = serialize(shape, { v: 1, method: "gov-id+liveness", verifiedAt: 1757280000n });
  assert.equal(a.length, 1 + 4 + 6 + 8);
  assert.equal(b.length, 1 + 4 + 15 + 8);
  assert.equal(deserialize(shape, a).method, "nondoc");
});

test("a layout and field name count mismatch fails loudly", () => {
  const broken = { layout: new Uint8Array([LAYOUT.u8, LAYOUT.string]), fieldNames: encodeFieldNames(SCHEMA_FIELD_NAMES) };
  assert.throws(
    () => serialize(broken, { v: 1, method: "x", verifiedAt: 1n }),
    /field names and layout do not match/
  );
});

test("a hand built fieldNames array of plain strings is refused", () => {
  // This is the failure that costs a day. sas-lib expects the joined
  // length prefixed blob, and the error it gives ("Input must be a 4-byte
  // array") says nothing about a missing length prefix.
  assert.throws(() =>
    serialize({ layout: SCHEMA_LAYOUT, fieldNames: ["v", "method", "verifiedAt"] }, {
      v: 1,
      method: "x",
      verifiedAt: 1n,
    })
  );
});

test("PDA seed names fit in 32 bytes", () => {
  // Only the first 32 bytes seed the PDA, so a longer name silently collides
  // with any other sharing its first 32.
  assertSeedFits("CREDENTIAL_NAME", CREDENTIAL_NAME);
  assertSeedFits("SCHEMA_NAME", SCHEMA_NAME);
  assert.throws(() => assertSeedFits("test", "x".repeat(MAX_PDA_SEED_BYTES + 1)), /can collide/);
  // Byte length, not character length: 17 two byte characters is 34 bytes.
  assert.throws(() => assertSeedFits("test", "Ü".repeat(17)), /can collide/);
});
