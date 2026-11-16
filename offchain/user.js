// The USER's program. After handing the file over, the user keeps only: key (secret) + root.
const { newKey, encrypt, decrypt } = require("./crypto");
const { splitIntoChunks, buildTree } = require("./merkle");

class User {
  constructor(contract) {
    this.contract = contract; // StorageMarket connected to the user's wallet
  }

  /** Encrypt, chunk, build the tree. Returns the blob to give to the provider. */
  prepare(plaintext) {
    this.key = newKey();
    const blob = encrypt(plaintext, this.key);
    const chunks = splitIntoChunks(blob);
    this.root = buildTree(chunks).root;
    this.numChunks = chunks.length;
    return blob;
  }

  /** Open the deal and escrow price * periods. */
  async createDeal({ provider, numPeriods, periodBlocks, pricePerPeriod, collateral }) {
    const tx = await this.contract.createDeal(
      provider, this.root, this.numChunks, numPeriods, periodBlocks, pricePerPeriod, collateral,
      { value: pricePerPeriod * BigInt(numPeriods) }
    );
    const receipt = await tx.wait();
    this.dealId = await this.contract.dealCount();
    return { dealId: this.dealId, gasUsed: receipt.gasUsed };
  }

  /** Provider missed a deadline: collect collateral + refund. Anyone could call this. */
  async claimFailure(dealId = this.dealId) {
    return (await this.contract.claimFailure(dealId)).wait();
  }

  /** Get the blob back, check it matches the root we kept, then decrypt. */
  retrieve(blob) {
    if (buildTree(splitIntoChunks(blob)).root !== this.root) throw new Error("data does not match the stored root");
    return decrypt(blob, this.key);
  }
}

module.exports = { User };
