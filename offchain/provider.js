// The PROVIDER's program.
// Stores the ciphertext chunks, answers each period's random challenge with chunks + Merkle proofs.
const { splitIntoChunks, buildTree, getProof } = require("./merkle");

class Provider {
  constructor(contract) {
    this.contract = contract; // StorageMarket connected to the provider's signer
    this.chunks = null;       // array of Buffers (the stored file)
    this.tree = null;
  }

  /** Receive the ciphertext from the user (off-chain handover) and index it. */
  store(blob) {
    this.chunks = splitIntoChunks(blob).map((c) => Buffer.from(c));
    this.tree = buildTree(this.chunks);
  }

  /**
   * Accept a deal ONLY if the data we hold hashes to the on-chain root.
   * This is what protects the provider from a user who committed to a different file.
   */
  async accept(dealId) {
    const deal = await this.contract.getDeal(dealId);
    if (deal.root !== this.tree.root) throw new Error("root mismatch: refusing to accept");
    if (Number(deal.numChunks) !== this.chunks.length) throw new Error("chunk count mismatch");
    const tx = await this.contract.acceptDeal(dealId, { value: deal.collateral });
    return tx.wait();
  }

  /** Answer the current period's challenge. Throws if we no longer hold a challenged chunk. */
  async prove(dealId) {
    const idx = (await this.contract.getChallenge(dealId)).map(Number);
    const chunks = [];
    const proofs = [];
    for (const i of idx) {
      if (!this.chunks[i]) throw new Error(`cannot prove: chunk ${i} was deleted`);
      chunks.push(this.chunks[i]);
      proofs.push(getProof(this.tree, i));
    }
    const tx = await this.contract.submitProof(dealId, chunks, proofs);
    return tx.wait();
  }

  async withdraw() {
    return (await this.contract.withdraw()).wait();
  }

  /** For tests/demo: simulate a dishonest provider that threw data away to save disk. */
  forget(indices) {
    for (const i of indices) this.chunks[i] = null;
  }
}

module.exports = { Provider };
