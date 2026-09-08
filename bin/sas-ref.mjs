#!/usr/bin/env node
//
// A command line driver for the reference implementation, so the on chain
// flows can be exercised without writing an application first.
//
// Read commands are free. Write commands spend SOL and are irreversible, so
// they default to devnet and refuse mainnet without --yes. That guard exists
// because the difference between the two is one word in an environment
// variable, and the failure is not recoverable.

import { readFileSync } from "node:fs";
import {
  deriveSubjectAddress,
  makeSubjectSalt,
  signerFromSecret,
  describeSignerState,
  settingsFor,
  getSasAddresses,
  getAttestationAddress,
  getBalanceLamports,
  ensureCredentialAndSchema,
  issueAttestation,
  readAttestation,
  closeAttestation,
  isExpired,
  addressExplorerUrl,
} from "../dist/index.js";

const USAGE = `sas-ref <command> [options]

read only, no key needed:
  subject <domain> <id>       derive a subject address (--salt, else a fresh one)

read only, needs the issuer key:
  address                     the issuer wallet and its credential/schema PDAs
  balance                     the issuer wallet's balance
  read <subject>              read a credential back off chain and decode it

writes, spends SOL:
  setup                       create the credential and schema if absent
  issue <subject>             issue a credential (--method, --verified-at, --ttl)
  close <subject>             close a credential and reclaim its rent

options:
  --cluster <c>       devnet (default) or mainnet-beta
  --rpc <url>         override the cluster's default endpoint
  --key-env <name>    env var holding the keypair (default SAS_ISSUER_SECRET_KEY)
  --key-file <path>   read the keypair from a file instead of the environment
  --method <str>      how identity was established (default gov-id+liveness)
  --verified-at <iso> when it was established (default now)
  --ttl <days>        credential lifetime (default 365)
  --salt <hex>        subject salt, for the subject command
  --yes               required for any write against mainnet-beta
  --json              machine readable output

exit codes: 0 ok, 1 failed, 2 usage error`;

function parseArgs(argv) {
  const opts = { cluster: "devnet", keyEnv: "SAS_ISSUER_SECRET_KEY", json: false, yes: false };
  const positional = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = (name) => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new Error(`${name} requires a value`);
      return v;
    };

    if (a === "-h" || a === "--help") return { help: true };
    else if (a === "--cluster") opts.cluster = value("--cluster");
    else if (a === "--rpc") opts.rpc = value("--rpc");
    else if (a === "--key-env") opts.keyEnv = value("--key-env");
    else if (a === "--key-file") opts.keyFile = value("--key-file");
    else if (a === "--method") opts.method = value("--method");
    else if (a === "--verified-at") opts.verifiedAt = value("--verified-at");
    else if (a === "--ttl") opts.ttl = Number(value("--ttl"));
    else if (a === "--salt") opts.salt = value("--salt");
    else if (a === "--yes") opts.yes = true;
    else if (a === "--json") opts.json = true;
    else if (a.startsWith("-")) throw new Error(`unknown option ${a}`);
    else positional.push(a);
  }

  if (opts.cluster !== "devnet" && opts.cluster !== "mainnet-beta") {
    throw new Error(`--cluster must be devnet or mainnet-beta, got ${opts.cluster}`);
  }
  opts.command = positional[0];
  opts.args = positional.slice(1);
  return opts;
}

const WRITES = new Set(["setup", "issue", "close"]);

async function loadKey(opts) {
  if (opts.keyFile) return signerFromSecret(readFileSync(opts.keyFile, "utf8"));

  const state = await describeSignerState(opts.keyEnv);
  if (state.state !== "ok") throw new Error(state.detail);
  return signerFromSecret(process.env[opts.keyEnv]);
}

async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    console.error(`error: ${err.message}\n\n${USAGE}`);
    return 2;
  }
  if (opts.help || !opts.command) {
    console.log(USAGE);
    return opts.help ? 0 : 2;
  }

  const emit = (obj, lines) => {
    if (opts.json) console.log(JSON.stringify(obj, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
    else for (const l of lines) console.log(l);
  };

  // The guard. A mainnet write is irreversible and costs real money, and the
  // only thing separating it from a devnet write is one word.
  if (WRITES.has(opts.command) && opts.cluster === "mainnet-beta" && !opts.yes) {
    console.error(
      `refusing to run "${opts.command}" against mainnet-beta without --yes.\n` +
        "This spends real SOL and cannot be undone. Re-run with --yes if that is what you mean."
    );
    return 2;
  }

  const settings = settingsFor(opts.cluster, opts.rpc);

  try {
    switch (opts.command) {
      case "subject": {
        const [domain, id] = opts.args;
        if (!domain || !id) throw new Error("usage: sas-ref subject <domain> <id> [--salt hex]");
        const salt = opts.salt || makeSubjectSalt();
        const subject = deriveSubjectAddress(domain, id, salt);
        emit({ domain, id, salt, subject }, [
          `subject  ${subject}`,
          `salt     ${salt}`,
          opts.salt
            ? ""
            : "\nThis salt was generated just now. Store it on the subject's own row,\n" +
              "and nowhere else: deleting it is what makes the subject unlinkable.",
        ]);
        return 0;
      }

      case "address": {
        const signer = await loadKey(opts);
        const a = await getSasAddresses(signer);
        emit({ ...a, cluster: settings.cluster }, [
          `cluster     ${settings.cluster}`,
          `authority   ${a.authority}`,
          `credential  ${a.credential}`,
          `schema      ${a.schema}`,
          `\n${addressExplorerUrl(a.credential, settings.cluster)}`,
        ]);
        return 0;
      }

      case "balance": {
        const signer = await loadKey(opts);
        const lamports = await getBalanceLamports(signer, settings);
        if (lamports === null) throw new Error("could not read the balance");
        emit({ address: signer.address, lamports, sol: lamports / 1e9 }, [
          `${signer.address}`,
          `${(lamports / 1e9).toFixed(9)} SOL (${lamports} lamports) on ${settings.cluster}`,
        ]);
        return 0;
      }

      case "setup": {
        const signer = await loadKey(opts);
        const r = await ensureCredentialAndSchema(signer, settings);
        emit(r, [
          r.signature
            ? `created${r.createdCredential ? " credential" : ""}${r.createdSchema ? " schema" : ""}`
            : "credential and schema already exist, nothing to do",
          `credential  ${r.credential}`,
          `schema      ${r.schema}`,
          r.explorerUrl ? `\n${r.explorerUrl}` : "",
        ]);
        return 0;
      }

      case "issue": {
        const [subject] = opts.args;
        if (!subject) throw new Error("usage: sas-ref issue <subject> [--method ...]");
        const signer = await loadKey(opts);
        const verifiedAt = opts.verifiedAt ? new Date(opts.verifiedAt) : new Date();
        if (Number.isNaN(verifiedAt.getTime())) throw new Error(`--verified-at is not a date: ${opts.verifiedAt}`);

        const r = await issueAttestation(
          signer,
          settings,
          subject,
          verifiedAt,
          opts.method || "gov-id+liveness",
          opts.ttl
        );
        emit(r, [
          `issued for   ${r.subject}`,
          `attestation  ${r.attestation}`,
          `method       ${r.data.method}`,
          `verified at  ${new Date(Number(r.data.verifiedAt) * 1000).toISOString()}`,
          `expires      ${new Date(Number(r.expiry) * 1000).toISOString()}`,
          `\n${r.explorerUrl}`,
        ]);
        return 0;
      }

      case "read": {
        const [subject] = opts.args;
        if (!subject) throw new Error("usage: sas-ref read <subject>");
        const signer = await loadKey(opts);
        const r = await readAttestation(signer, settings, subject);

        if (!r.exists) {
          emit({ ...r, expired: null }, [
            `no credential at ${r.attestation}`,
            `for subject ${subject} on ${settings.cluster}`,
          ]);
          return 0;
        }

        const expired = isExpired(r.expiry);
        emit({ ...r, expired }, [
          `attestation  ${r.attestation}`,
          `issuer       ${r.issuer}`,
          `version      ${r.data.v}`,
          `method       ${r.data.method}`,
          `verified at  ${new Date(Number(r.data.verifiedAt) * 1000).toISOString()}`,
          `expires      ${new Date(Number(r.expiry) * 1000).toISOString()}${expired ? "  (EXPIRED)" : ""}`,
          `\n${r.explorerUrl}`,
        ]);
        // An expired credential is a real answer, not an error, so this still
        // exits 0. Callers that care should read the `expired` field.
        return 0;
      }

      case "close": {
        const [subject] = opts.args;
        if (!subject) throw new Error("usage: sas-ref close <subject>");
        const signer = await loadKey(opts);
        const attestation = await getAttestationAddress(signer, subject);
        const r = await closeAttestation(signer, settings, subject);

        emit({ closed: !!r, attestation, ...(r || {}) }, [
          r ? `closed ${attestation}` : `nothing to close at ${attestation}`,
          r ? `\n${r.explorerUrl}` : "",
          "\nClosing the account is the tidy half of an erasure. The half that",
          "matters is destroying the subject's salt, which is what makes the",
          "subject address unlinkable even to somebody who archived the chain.",
        ]);
        return 0;
      }

      default:
        console.error(`error: unknown command ${opts.command}\n\n${USAGE}`);
        return 2;
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

process.exit(await main(process.argv.slice(2)));
