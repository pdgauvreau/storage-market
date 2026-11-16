// The PROVIDER's program: store chunks, answer each period's challenge with chunks + Merkle proofs.
const { splitIntoChunks, buildTree, getProof } = require("./merkle");

class Provider {
  constructor(contract) {
    this.contract = contract; // StorageMarket connected to the provider's wallet
  }

  /** Receive the ciphertext from the user and index it. */
  store(blob) {
    this.chunks = splitIntoChunks(blob).map((c) => Buffer.from(c));
    this.tree = buildTree(this.chunks);
  }

  /** Accept only if what we hold matches the on-chain root, then lock the collateral. */
  async accept(dealId) {
    const deal = await this.contract.getDeal(dealId);
    if (deal.root !== this.tree.root) throw new Error("root mismatch: refusing to accept");
    return (await this.contract.acceptDeal(dealId, { value: deal.collateral })).wait();
  }

  /** Read this period's challenge, fetch those chunks, post them with their proofs. */
  async prove(dealId) {
    const indices = (await this.contract.getChallenge(dealId)).map(Number);
    const chunks = indices.map((i) => {
      if (!this.chunks[i]) throw new Error(`cannot prove: chunk ${i} was deleted`);
      return this.chunks[i];
    });
    const proofs = indices.map((i) => getProof(this.tree, i));
    return (await this.contract.submitProof(dealId, chunks, proofs)).wait();
  }

  /** For tests/demo: pretend to be a provider that threw some chunks away. */
  forget(indices) {
    indices.forEach((i) => (this.chunks[i] = null));
  }

  async withdraw() {
    return (await this.contract.withdraw()).wait();
  }
}

module.exports = { Provider };
