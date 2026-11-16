// The USER's program. After handing the file over, the user keeps only: key (secret) + root.
const crypto = require("crypto");
const { splitIntoChunks, buildTree } = require("./merkle");

// Confidentiality: the file is encrypted BEFORE it leaves the user's machine.
// AES-256-GCM = encryption + tamper detection.
// blob = iv (12 bytes) || ciphertext || auth tag (16 bytes). The blob is what gets chunked and stored.
function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12); // fresh random IV per file
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
}

function decrypt(blob, key) {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ciphertext = blob.subarray(12, blob.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]); // throws if altered
}

class User {
  constructor(contract) {
    this.contract = contract; // StorageMarket connected to the user's wallet
  }

  /** Encrypt, chunk, build the tree. Returns the blob to give to the provider. */
  prepare(plaintext) {
    this.key = crypto.randomBytes(32);
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
