// Transaction assembly and confirmation. The only file here that touches the
// network.

import {
  address,
  appendTransactionMessageInstructions,
  assertIsTransactionWithBlockhashLifetime,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  getSignatureFromTransaction,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type Instruction,
  type KeyPairSigner,
} from "@solana/kit";
import { toWebsocketUrl, txExplorerUrl, type ClusterSettings } from "./settings.js";

export interface SubmitResult {
  signature: string;
  cluster: ClusterSettings["cluster"];
  explorerUrl: string;
}

const DEFAULT_PRIORITY_FEE = 10_000;

const COMPUTE_BUDGET_PROGRAM = address("ComputeBudget111111111111111111111111111111");
const SET_COMPUTE_UNIT_PRICE = 3;

/**
 * SetComputeUnitPrice, built by hand rather than pulled from
 * `@solana-program/compute-budget`.
 *
 * Not stubbornness: that package peer-requires @solana/kit ^2, while sas-lib
 * pins ^5, so installing both means either a forced resolution or a second
 * nested copy of kit. For nine bytes of stable, documented instruction data,
 * neither is worth it, and a reference implementation is better off with one
 * less dependency to explain.
 *
 * Layout: a u8 discriminator of 3, then microLamports as u64 little endian.
 */
export function setComputeUnitPriceInstruction(microLamports: number | bigint): Instruction {
  const data = new Uint8Array(9);
  data[0] = SET_COMPUTE_UNIT_PRICE;
  new DataView(data.buffer).setBigUint64(1, BigInt(microLamports), true);
  return { programAddress: COMPUTE_BUDGET_PROGRAM, data } as Instruction;
}

/**
 * Send instructions as one transaction and wait for confirmation.
 *
 * Confirmed, not merely submitted. An unconfirmed signature can still be
 * dropped, and recording it as issued would leave your database asserting a
 * credential that no chain actually carries.
 */
export async function sendInstructions(
  instructions: Instruction[],
  signer: KeyPairSigner,
  settings: ClusterSettings
): Promise<SubmitResult> {
  if (instructions.length === 0) {
    throw new Error("sendInstructions: refusing to send a transaction with no instructions");
  }

  const rpc = createSolanaRpc(settings.rpcUrl);
  const rpcSubscriptions = createSolanaRpcSubscriptions(toWebsocketUrl(settings.rpcUrl));

  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send();

  const priorityFee = settings.priorityFeeMicroLamports ?? DEFAULT_PRIORITY_FEE;

  // Built in one pipe rather than by reducing over the instructions. Kit
  // tracks a transaction message's size limit in its type, so folding
  // instructions in with `reduce` produces a type the next step no longer
  // accepts. The plural append takes them all at once and keeps the chain
  // intact.
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(signer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, m),
    (m) =>
      appendTransactionMessageInstructions(
        [setComputeUnitPriceInstruction(priorityFee), ...instructions],
        m
      )
  );

  const signed = await signTransactionMessageWithSigners(message);
  assertIsTransactionWithBlockhashLifetime(signed);

  await sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions })(signed, {
    commitment: "confirmed",
  });

  const signature = getSignatureFromTransaction(signed);
  return { signature, cluster: settings.cluster, explorerUrl: txExplorerUrl(signature, settings.cluster) };
}

/** Lamport balance of the issuer wallet, or null if it cannot be read. */
export async function getBalanceLamports(
  signer: KeyPairSigner,
  settings: ClusterSettings
): Promise<number | null> {
  try {
    const rpc = createSolanaRpc(settings.rpcUrl);
    const { value } = await rpc.getBalance(signer.address).send();
    return Number(value);
  } catch {
    return null;
  }
}
