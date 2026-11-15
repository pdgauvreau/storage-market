const { expect } = require("chai");
const { ethers } = require("hardhat");
const { mine } = require("@nomicfoundation/hardhat-network-helpers");
const crypto = require("crypto");

const { User } = require("../offchain/user");
const { Provider } = require("../offchain/provider");
const { buildTree, splitIntoChunks, getProof } = require("../offchain/merkle");

const PRICE = ethers.parseEther("1");
const COLLATERAL = ethers.parseEther("3");
const TERMS = {
  numPeriods: 5,
  periodBlocks: 100,
  responseBlocks: 50,
  numChallenges: 3,
  acceptWindowBlocks: 20,
  pricePerPeriod: PRICE,
  collateral: COLLATERAL,
};

describe("StorageMarket", function () {
  let market, userSigner, providerSigner, other;
  let user, provider, file, dealId;

  // Jump forward so the next tx lands inside the response window of the next unproven period.
  // We stop one block AFTER the period start: the challenge seed is blockhash(periodStart), and a
  // read-only call can only see it once the latest block is past periodStart.
  async function advanceToNextPeriod() {
    const d = await market.getDeal(dealId);
    const target = Number(d.startBlock) + Number(d.nextPeriod) * Number(d.periodBlocks) + 1;
    const now = await ethers.provider.getBlockNumber();
    if (target > now) await mine(target - now);
  }

  async function setup(fileBytes = 1024 * 1024, accept = true) {
    [userSigner, providerSigner, other] = await ethers.getSigners();
    market = await (await ethers.getContractFactory("StorageMarket")).deploy();
    user = new User(market.connect(userSigner));
    provider = new Provider(market.connect(providerSigner));
    file = crypto.randomBytes(fileBytes);

    const blob = user.prepare(file);          // user encrypts + commits
    provider.store(blob);                      // off-chain handover
    const res = await user.createDeal({ provider: providerSigner.address, ...TERMS });
    dealId = res.dealId;
    if (accept) await provider.accept(dealId);
    return { blob, createGas: res.gasUsed };
  }

  describe("happy path with a 1 MB file", function () {
    it("pays the provider period by period and returns the collateral", async function () {
      const { blob } = await setup();

      // 1 MB + 28 bytes of IV/tag = 1025 chunks, tree depth 11
      expect((await market.getDeal(dealId)).numChunks).to.equal(1025n);
      expect((await market.getDeal(dealId)).depth).to.equal(11n);

      // confidentiality: the plaintext never appears in what the provider/chain sees
      expect(blob.includes(file.subarray(0, 64))).to.equal(false);

      for (let k = 0; k < TERMS.numPeriods; k++) {
        await advanceToNextPeriod();
        await provider.prove(dealId);
        // payment released only after each proof
        expect(await market.balances(providerSigner.address)).to.equal(
          PRICE * BigInt(k + 1) + (k + 1 === TERMS.numPeriods ? COLLATERAL : 0n)
        );
      }
      expect((await market.getDeal(dealId)).status).to.equal(3n); // Completed

      // withdraw and check real ether moved
      const before = await ethers.provider.getBalance(providerSigner.address);
      const r = await provider.withdraw();
      const after = await ethers.provider.getBalance(providerSigner.address);
      expect(after - before + r.gasUsed * r.gasPrice).to.equal(PRICE * 5n + COLLATERAL);

      // user can fetch the blob back, verify the root and decrypt
      expect(user.retrieve(blob).equals(file)).to.equal(true);
    });

    it("works for tiny and non-power-of-two files too", async function () {
      for (const size of [1, 1023, 1025, 5000]) {
        await setup(size);
        await advanceToNextPeriod();
        await provider.prove(dealId);
        expect((await market.getDeal(dealId)).nextPeriod).to.equal(1n);
      }
    });
  });

  describe("provider failures", function () {
    it("missed deadline: collateral goes to user and unspent payment is refunded", async function () {
      await setup();
      // prove periods 0 and 1, then go silent in period 2
      for (let k = 0; k < 2; k++) { await advanceToNextPeriod(); await provider.prove(dealId); }
      await advanceToNextPeriod();

      // too early: window of period 2 still open
      await expect(market.claimFailure(dealId)).to.be.revertedWith("window still open");

      await mine(TERMS.responseBlocks + 1);
      await user.claimFailure(dealId);

      expect((await market.getDeal(dealId)).status).to.equal(4n); // Failed
      // user gets collateral + 3 unpaid periods; provider keeps the 2 it earned
      expect(await market.balances(userSigner.address)).to.equal(COLLATERAL + PRICE * 3n);
      expect(await market.balances(providerSigner.address)).to.equal(PRICE * 2n);

      // the provider can no longer prove
      await expect(provider.prove(dealId)).to.be.reverted;
    });

    it("anyone (not only the user) can trigger the slash", async function () {
      await setup();
      await mine(TERMS.periodBlocks);
      await market.connect(other).claimFailure(dealId);
      expect(await market.balances(userSigner.address)).to.equal(COLLATERAL + PRICE * 5n);
    });

    it("a provider that deleted exactly the challenged chunks cannot prove", async function () {
      await setup();
      await advanceToNextPeriod();
      const idx = (await market.getChallenge(dealId)).map(Number);
      provider.forget(idx);
      await expect(provider.prove(dealId)).to.be.rejectedWith("was deleted");
    });

    it("garbage data instead of the real chunk is rejected", async function () {
      await setup();
      await advanceToNextPeriod();
      const idx = (await market.getChallenge(dealId)).map(Number);
      const chunks = idx.map(() => crypto.randomBytes(1024));
      const proofs = idx.map((i) => getProof(provider.tree, i));
      await expect(market.connect(providerSigner).submitProof(dealId, chunks, proofs))
        .to.be.revertedWith("invalid merkle proof");
    });

    it("a valid chunk + valid proof from the WRONG position is rejected (position binding)", async function () {
      await setup();
      await advanceToNextPeriod();
      const idx = (await market.getChallenge(dealId)).map(Number);
      // provider answers with chunk (i+1) and its genuine proof instead of chunk i
      const wrong = idx.map((i) => (i + 1) % provider.chunks.length);
      const chunks = wrong.map((i) => provider.chunks[i]);
      const proofs = wrong.map((i) => getProof(provider.tree, i));
      await expect(market.connect(providerSigner).submitProof(dealId, chunks, proofs))
        .to.be.revertedWith("invalid merkle proof");
    });

    it("a proof of the wrong length is rejected", async function () {
      await setup();
      await advanceToNextPeriod();
      const idx = (await market.getChallenge(dealId)).map(Number);
      const chunks = idx.map((i) => provider.chunks[i]);
      const proofs = idx.map((i) => getProof(provider.tree, i).slice(1));
      await expect(market.connect(providerSigner).submitProof(dealId, chunks, proofs))
        .to.be.revertedWith("invalid merkle proof");
    });

    it("answering after the window closed is rejected", async function () {
      await setup();
      await advanceToNextPeriod();
      await mine(TERMS.responseBlocks + 1);
      await expect(provider.prove(dealId)).to.be.revertedWith("outside response window");
    });

    it("only the named provider can post proofs", async function () {
      await setup();
      await advanceToNextPeriod();
      const idx = (await market.getChallenge(dealId)).map(Number);
      const chunks = idx.map((i) => provider.chunks[i]);
      const proofs = idx.map((i) => getProof(provider.tree, i));
      await expect(market.connect(other).submitProof(dealId, chunks, proofs))
        .to.be.revertedWith("not the provider");
    });
  });

  describe("deal setup", function () {
    it("rejects the wrong escrow amount", async function () {
      [userSigner, providerSigner] = await ethers.getSigners();
      market = await (await ethers.getContractFactory("StorageMarket")).deploy();
      const terms = { provider: providerSigner.address, root: ethers.ZeroHash, numChunks: 10, ...TERMS };
      await expect(market.createDeal(terms, { value: PRICE })).to.be.revertedWith("wrong escrow amount");
    });

    it("provider refuses a deal whose root does not match the data it received", async function () {
      await setup(5000, false);
      const evil = new Provider(market.connect(providerSigner));
      evil.store(crypto.randomBytes(5000 + 28)); // different data than the user committed to
      await expect(evil.accept(dealId)).to.be.rejectedWith("root mismatch");
    });

    it("provider must post exactly the agreed collateral", async function () {
      await setup(5000, false);
      await expect(market.connect(providerSigner).acceptDeal(dealId, { value: 1n }))
        .to.be.revertedWith("wrong collateral");
    });

    it("user is refunded if the provider never accepts", async function () {
      await setup(5000, false);
      await expect(user.contract.cancelProposal(dealId)).to.be.revertedWith("still waiting for provider");
      await mine(TERMS.acceptWindowBlocks + 1);
      await user.contract.cancelProposal(dealId);
      expect(await market.balances(userSigner.address)).to.equal(PRICE * 5n);
      await expect(provider.accept(dealId)).to.be.reverted; // too late to accept
    });
  });

  describe("randomness", function () {
    it("different periods challenge different positions", async function () {
      await setup();
      const seen = new Set();
      for (let k = 0; k < TERMS.numPeriods; k++) {
        await advanceToNextPeriod();
        (await market.getChallenge(dealId)).forEach((i) => seen.add(Number(i)));
        await provider.prove(dealId);
      }
      expect(seen.size).to.be.greaterThan(5); // 15 draws from 1025 chunks
    });
  });

  describe("off-chain Merkle code agrees with the contract", function () {
    it("proof built in JS verifies on-chain for every challenged index", async function () {
      await setup();
      await advanceToNextPeriod();
      await provider.prove(dealId); // succeeds only if JS and Solidity hash identically
      const t = buildTree(splitIntoChunks(crypto.randomBytes(3000)));
      expect(t.depth).to.equal(2);
    });
  });
});
