export type Cluster = "devnet" | "mainnet-beta";

export interface ClusterSettings {
  cluster: Cluster;
  rpcUrl: string;
  /**
   * Priority fee in microLamports per compute unit. 10,000 on a 200k CU
   * transaction is about 0.000002 SOL, well under the base fee, and enough to
   * clear the queue for something issued a handful of times a day.
   */
  priorityFeeMicroLamports?: number;
}

export const DEFAULT_RPC: Record<Cluster, string> = {
  devnet: "https://api.devnet.solana.com",
  "mainnet-beta": "https://api.mainnet-beta.solana.com",
};

export function settingsFor(cluster: Cluster, rpcUrl?: string): ClusterSettings {
  return { cluster, rpcUrl: rpcUrl?.trim() || DEFAULT_RPC[cluster] };
}

export function txExplorerUrl(signature: string, cluster: Cluster): string {
  return `https://explorer.solana.com/tx/${signature}${cluster === "devnet" ? "?cluster=devnet" : ""}`;
}

export function addressExplorerUrl(address: string, cluster: Cluster): string {
  return `https://explorer.solana.com/address/${address}${cluster === "devnet" ? "?cluster=devnet" : ""}`;
}

/**
 * The websocket endpoint, derived from the RPC URL rather than configured
 * separately so the two cannot drift apart and leave confirmations hanging
 * against a different node.
 *
 * The port special case is not cosmetic. Public providers serve websockets on
 * the same host and port, but a local `solana-test-validator` serves RPC on
 * 8899 and PubSub on 8900. Without this, confirmations against a local
 * validator hang forever with no error, because the socket connects to a port
 * nothing is listening on.
 */
export function toWebsocketUrl(rpcUrl: string): string {
  const ws = rpcUrl.replace(/^http:/, "ws:").replace(/^https:/, "wss:");
  try {
    const url = new URL(ws);
    if (url.port === "8899") {
      url.port = "8900";
      return url.toString().replace(/\/$/, "");
    }
  } catch {
    // Not a parseable URL. Fall through and let the RPC client complain about
    // it, rather than swallowing the problem here.
  }
  return ws;
}
