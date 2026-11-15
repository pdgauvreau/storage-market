// The USER's program.
// What the user keeps after handing the file over:  key (secret)  +  root (32 bytes).
// Everything else (blob, chunks, tree) can be thrown away.
const { newKey, encrypt, decrypt } = require("./crypto");
const { splitIntoChunks, buildTree } = require("./merkle");

class User {
  constructor(contract) {
    this.contract = contract; // StorageMarket connected to the user's signer
  }

  /**
   * Encrypt + chunk + build tree.
   * Returns `blob` (to send to the provider) and remembers only key/root/numChunks.
   */
  prepare(plaintext) {
    this.key = newKey();
    const blob = encrypt(plaintext, this.key);
    const chunks = splitIntoChunks(blob);
    const tree = buildTree(chunks);
    this.root = tree.root;
    this.numChunks = chunks.length;
    return blob;
  }

  /** Open the deal and escrow the full payment (price * periods). */
  async createDeal({ provider, numPeriods, periodBlocks, responseBlocks, numChallenges,
                     acceptWindowBlocks, pricePerPeriod, collateral }) {
    const terms = {
      provider, root: this.root, numChunks: this.numChunks, numPeriods, periodBlocks,
      responseBlocks, numChallenges, acceptWindowBlocks, pricePerPeriod, collateral,
    };
    const tx = await this.contract.createDeal(terms, { value: pricePerPeriod * BigInt(numPeriods) });
    const receipt = await tx.wait();
    const ev = receipt.logs.map((l) => this.contract.interface.parseLog(l)).find((e) => e && e.name === "DealProposed");
    this.dealId = ev.args.dealId;
    return { dealId: this.dealId, gasUsed: receipt.gasUsed };
  }

  /** Provider failed? Anyone can call this, the user does because the user gets paid. */
  async claimFailure(dealId = this.dealId) {
    return (await this.contract.claimFailure(dealId)).wait();
  }

  async withdraw() {
    return (await this.contract.withdraw()).wait();
  }

  /** Later: get the blob back from the provider, check it, decrypt it. */
  retrieve(blob) {
    const tree = buildTree(splitIntoChunks(blob));
    if (tree.root !== this.root) throw new Error("provider returned data that does not match the stored root");
    return decrypt(blob, this.key);
  }
}

module.exports = { User };
