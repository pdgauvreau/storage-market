// Narrated end-to-end run on a local in-memory chain:   npx hardhat run scripts/demo.js
const { ethers } = require("hardhat");
const { mine } = require("@nomicfoundation/hardhat-network-helpers");
const crypto = require("crypto");
const { User } = require("../offchain/user");
const { Provider } = require("../offchain/provider");
const { getProof } = require("../offchain/merkle");

const PERIODS = 5, PERIOD_BLOCKS = 100, RESPONSE_BLOCKS = 50;
const PRICE = ethers.parseEther("1"), COLLATERAL = ethers.parseEther("3");
const eth = (wei) => ethers.formatEther(wei) + " ETH";

async function goToNextPeriod(market, dealId) {
  const d = await market.getDeal(dealId);
  const target = Number(d.startBlock) + Number(d.nextPeriod) * PERIOD_BLOCKS + 1;
  const now = await ethers.provider.getBlockNumber();
  if (target > now) await mine(target - now);
}

async function main() {
  const [userWallet, honestWallet, cheaterWallet] = await ethers.getSigners();
  const market = await (await ethers.getContractFactory("StorageMarket")).deploy();
  const terms = { numPeriods: PERIODS, periodBlocks: PERIOD_BLOCKS, pricePerPeriod: PRICE, collateral: COLLATERAL };
  const file = crypto.randomBytes(1024 * 1024); // 1 MB of private data

  console.log("\n=== A: honest provider ===");
  const user = new User(market.connect(userWallet));
  const provider = new Provider(market.connect(honestWallet));
  const blob = user.prepare(file);
  console.log(`1 MB file -> ${blob.length} byte ciphertext -> ${user.numChunks} chunks. User keeps only root ${user.root}`);

  provider.store(blob);
  const created = await user.createDeal({ provider: honestWallet.address, ...terms });
  console.log(`createDeal: ${eth(PRICE * BigInt(PERIODS))} locked in escrow (gas ${created.gasUsed})`);
  const accepted = await provider.accept(created.dealId);
  console.log(`acceptDeal: provider checked the root and locked ${eth(COLLATERAL)} collateral (gas ${accepted.gasUsed})`);

  let proofGas = 0n;
  for (let k = 0; k < PERIODS; k++) {
    await goToNextPeriod(market, created.dealId);
    const indices = (await market.getChallenge(created.dealId)).map(Number);
    const r = await provider.prove(created.dealId);
    proofGas += r.gasUsed;
    console.log(`period ${k}: challenged chunks [${indices}] -> proof accepted (gas ${r.gasUsed}), provider balance ${eth(await market.balances(honestWallet.address))}`);
  }
  console.log(`user retrieved + decrypted file correctly: ${user.retrieve(blob).equals(file)}`);

  console.log("\n=== B: cheating provider ===");
  const user2 = new User(market.connect(userWallet));
  const cheater = new Provider(market.connect(cheaterWallet));
  cheater.store(user2.prepare(file));
  const deal2 = await user2.createDeal({ provider: cheaterWallet.address, ...terms });
  await cheater.accept(deal2.dealId);
  await goToNextPeriod(market, deal2.dealId);
  await cheater.prove(deal2.dealId); // period 0: still has the data

  await goToNextPeriod(market, deal2.dealId);
  const indices = (await market.getChallenge(deal2.dealId)).map(Number);
  console.log(`period 1 challenge [${indices}]. Cheater no longer has those chunks, so it tries to fake it:`);

  const wrong = indices.map((i) => (i + 1) % cheater.chunks.length); // real chunks from the wrong position
  try {
    await market.connect(cheaterWallet).submitProof(deal2.dealId, wrong.map((i) => cheater.chunks[i]), wrong.map((i) => getProof(cheater.tree, i)));
  } catch { console.log("  chunk from the wrong position -> rejected (invalid merkle proof)"); }
  try {
    await market.connect(cheaterWallet).submitProof(deal2.dealId, indices.map(() => crypto.randomBytes(1024)), indices.map((i) => getProof(cheater.tree, i)));
  } catch { console.log("  random bytes -> rejected (invalid merkle proof)"); }

  await mine(RESPONSE_BLOCKS + 1);
  const failed = await user2.claimFailure(deal2.dealId);
  console.log(`window closed, user called claimFailure (gas ${failed.gasUsed})`);
  console.log(`  user ledger:    ${eth(await market.balances(userWallet.address))} (collateral 3 + refund of 4 unpaid periods)`);
  console.log(`  cheater earned: ${eth(await market.balances(cheaterWallet.address))} (only period 0)`);

  console.log("\n=== gas (1 MB file, depth 11, 3 challenges) ===");
  console.log(`createDeal ${created.gasUsed} | acceptDeal ${accepted.gasUsed} | submitProof avg ${proofGas / BigInt(PERIODS)} | claimFailure ${failed.gasUsed}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
