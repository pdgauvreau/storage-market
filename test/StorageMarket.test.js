const { expect } = require("chai");
const { ethers } = require("hardhat");
const { mine } = require("@nomicfoundation/hardhat-network-helpers");
const crypto = require("crypto");

const { User } = require("../offchain/user");
const { Provider } = require("../offchain/provider");
const { getProof } = require("../offchain/merkle");

const PRICE = ethers.parseEther("1");
const COLLATERAL = ethers.parseEther("3");
const PERIODS = 5;
const PERIOD_BLOCKS = 100;
const RESPONSE_BLOCKS = 50; // must equal StorageMarket.RESPONSE_BLOCKS
const ACCEPT_BLOCKS = 20;   // must equal StorageMarket.ACCEPT_BLOCKS

describe("StorageMarket", function () {
  let market, userWallet, providerWallet, stranger;
  let user, provider, file, dealId;

  // Move the chain to one block past the start of the next unproven period.
  // (The challenge seed is the hash of the start block, readable once the chain is past it.)
  async function goToNextPeriod() {
    const d = await market.getDeal(dealId);
    const target = Number(d.startBlock) + Number(d.nextPeriod) * PERIOD_BLOCKS + 1;
    const now = await ethers.provider.getBlockNumber();
    if (target > now) await mine(target - now);
  }

  async function setup(fileSize = 1024 * 1024, accept = true) {
    [userWallet, providerWallet, stranger] = await ethers.getSigners();
    market = await (await ethers.getContractFactory("StorageMarket")).deploy();
    user = new User(market.connect(userWallet));
    provider = new Provider(market.connect(providerWallet));

    file = crypto.randomBytes(fileSize);
    const blob = user.prepare(file);
    provider.store(blob);
    ({ dealId } = await user.createDeal({
      provider: providerWallet.address, numPeriods: PERIODS, periodBlocks: PERIOD_BLOCKS,
      pricePerPeriod: PRICE, collateral: COLLATERAL,
    }));
    if (accept) await provider.accept(dealId);
    return blob;
  }

  // The chunks and proofs a provider would send for this period's challenge.
  async function challengeAnswer() {
    const indices = (await market.getChallenge(dealId)).map(Number);
    return { indices, chunks: indices.map((i) => provider.chunks[i]), proofs: indices.map((i) => getProof(provider.tree, i)) };
  }

  describe("honest provider", function () {
    it("1 MB file: paid period by period, collateral returned, user can decrypt", async function () {
      const blob = await setup();
      expect((await market.getDeal(dealId)).numChunks).to.equal(1025n); // 1 MB + 28 bytes IV/tag
      expect((await market.getDeal(dealId)).depth).to.equal(11n);
      expect(blob.includes(file.subarray(0, 64))).to.equal(false);      // provider never sees plaintext

      for (let k = 1; k <= PERIODS; k++) {
        await goToNextPeriod();
        await provider.prove(dealId);
        const extra = k === PERIODS ? COLLATERAL : 0n; // collateral comes back after the last proof
        expect(await market.balances(providerWallet.address)).to.equal(PRICE * BigInt(k) + extra);
      }
      expect((await market.getDeal(dealId)).status).to.equal(3n); // Completed

      const before = await ethers.provider.getBalance(providerWallet.address);
      const r = await provider.withdraw();
      const after = await ethers.provider.getBalance(providerWallet.address);
      expect(after - before + r.gasUsed * r.gasPrice).to.equal(PRICE * 5n + COLLATERAL);

      expect(user.retrieve(blob).equals(file)).to.equal(true);
    });

    it("works for tiny and non-power-of-two files", async function () {
      for (const size of [1, 1023, 1025, 5000]) {
        await setup(size);
        await goToNextPeriod();
        await provider.prove(dealId);
        expect((await market.getDeal(dealId)).nextPeriod).to.equal(1n);
      }
    });
  });

  describe("dishonest provider", function () {
    it("silent in period 2: user gets collateral + unpaid periods, provider keeps what it earned", async function () {
      await setup();
      for (let k = 0; k < 2; k++) { await goToNextPeriod(); await provider.prove(dealId); }
      await goToNextPeriod();

      await expect(market.claimFailure(dealId)).to.be.revertedWith("window still open");
      await mine(RESPONSE_BLOCKS + 1);
      await market.connect(stranger).claimFailure(dealId); // anyone may trigger it

      expect(await market.balances(userWallet.address)).to.equal(COLLATERAL + PRICE * 3n);
      expect(await market.balances(providerWallet.address)).to.equal(PRICE * 2n);
      expect((await market.getDeal(dealId)).status).to.equal(4n); // Failed
    });

    it("deleted exactly the challenged chunks: cannot prove", async function () {
      await setup();
      await goToNextPeriod();
      provider.forget((await market.getChallenge(dealId)).map(Number));
      await expect(provider.prove(dealId)).to.be.rejectedWith("was deleted");
    });

    it("random bytes instead of the real chunk are rejected", async function () {
      await setup();
      await goToNextPeriod();
      const { indices, proofs } = await challengeAnswer();
      const fake = indices.map(() => crypto.randomBytes(1024));
      await expect(market.connect(providerWallet).submitProof(dealId, fake, proofs))
        .to.be.revertedWith("invalid merkle proof");
    });

    it("a real chunk with a real proof from the WRONG position is rejected", async function () {
      await setup();
      await goToNextPeriod();
      const indices = (await market.getChallenge(dealId)).map(Number);
      const wrong = indices.map((i) => (i + 1) % provider.chunks.length);
      await expect(market.connect(providerWallet).submitProof(
        dealId, wrong.map((i) => provider.chunks[i]), wrong.map((i) => getProof(provider.tree, i))
      )).to.be.revertedWith("invalid merkle proof");
    });

    it("answering after the window closed is rejected", async function () {
      await setup();
      await goToNextPeriod();
      await mine(RESPONSE_BLOCKS + 1);
      await expect(provider.prove(dealId)).to.be.revertedWith("outside response window");
    });

    it("only the named provider can post proofs", async function () {
      await setup();
      await goToNextPeriod();
      const { chunks, proofs } = await challengeAnswer();
      await expect(market.connect(stranger).submitProof(dealId, chunks, proofs))
        .to.be.revertedWith("not the provider");
    });
  });

  describe("deal setup", function () {
    it("rejects the wrong escrow amount", async function () {
      [userWallet, providerWallet] = await ethers.getSigners();
      market = await (await ethers.getContractFactory("StorageMarket")).deploy();
      await expect(market.createDeal(providerWallet.address, ethers.ZeroHash, 10, PERIODS, PERIOD_BLOCKS, PRICE, COLLATERAL, { value: PRICE }))
        .to.be.revertedWith("wrong escrow amount");
    });

    it("provider refuses a deal whose root does not match its data", async function () {
      await setup(5000, false);
      const other = new Provider(market.connect(providerWallet));
      other.store(crypto.randomBytes(5028));
      await expect(other.accept(dealId)).to.be.rejectedWith("root mismatch");
    });

    it("provider must post exactly the agreed collateral", async function () {
      await setup(5000, false);
      await expect(market.connect(providerWallet).acceptDeal(dealId, { value: 1n }))
        .to.be.revertedWith("wrong collateral");
    });

    it("user is refunded if the provider never accepts", async function () {
      await setup(5000, false);
      await expect(market.cancelProposal(dealId)).to.be.revertedWith("still waiting for provider");
      await mine(ACCEPT_BLOCKS + 1);
      await market.cancelProposal(dealId);
      expect(await market.balances(userWallet.address)).to.equal(PRICE * 5n);
    });
  });
});
