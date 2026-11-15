// End-to-end demo on a local in-memory chain:  npx hardhat run scripts/demo.js
const { ethers } = require("hardhat");
const { mine } = require("@nomicfoundation/hardhat-network-helpers");
const crypto = require("crypto");
const { User } = require("../offchain/user");
const { Provider } = require("../offchain/provider");
const { getProof } = require("../offchain/merkle");

const eth = (wei) => ethers.formatEther(wei) + " ETH";
const log = (...a) => console.log(...a);

async function advanceToNextPeriod(market, dealId) {
  const d = await market.getDeal(dealId);
  const target = Number(d.startBlock) + Number(d.nextPeriod) * Number(d.periodBlocks) + 1;
  const now = await ethers.provider.getBlockNumber();
  if (target > now) await mine(target - now);
}

async function main() {
  const [userS, providerS, cheaterS] = await ethers.getSigners();
  const market = await (await ethers.getContractFactory("StorageMarket")).deploy();

  const terms = {
    numPeriods: 5, periodBlocks: 100, responseBlocks: 50, numChallenges: 3, acceptWindowBlocks: 20,
    pricePerPeriod: ethers.parseEther("1"), collateral: ethers.parseEther("3"),
  };
  const file = crypto.randomBytes(1024 * 1024); // 1 MB of "private" data

  // ------------------------------------------------------------------
  log("\n=== SCENARIO A: honest provider, 1 MB file, 5 periods ===");
  const user = new User(market.connect(userS));
  const provider = new Provider(market.connect(providerS));

  let t0 = Date.now();
  const blob = user.prepare(file);
  log(`User encrypted + chunked + built Merkle tree in ${Date.now() - t0} ms`);
  log(`  file: ${file.length} bytes -> ciphertext blob: ${blob.length} bytes -> ${user.numChunks} chunks of 1024 B`);
  log(`  user keeps only: root ${user.root} (+ the secret AES key)`);

  provider.store(blob);
  const { dealId, gasUsed: gasCreate } = await user.createDeal({ provider: providerS.address, ...terms });
  log(`Deal #${dealId} created, escrow locked: ${eth(terms.pricePerPeriod * BigInt(terms.numPeriods))}   (gas ${gasCreate})`);

  const acc = await provider.accept(dealId);
  log(`Provider verified the root, locked collateral ${eth(terms.collateral)}   (gas ${acc.gasUsed})`);

  const proofGas = [];
  for (let k = 0; k < terms.numPeriods; k++) {
    await advanceToNextPeriod(market, dealId);
    const idx = (await market.getChallenge(dealId)).map(Number);
    const r = await provider.prove(dealId);
    proofGas.push(r.gasUsed);
    const bal = await market.balances(providerS.address);
    log(`Period ${k}: challenged chunks [${idx.join(", ")}] -> proof accepted (gas ${r.gasUsed}); provider balance ${eth(bal)}`);
  }
  const d = await market.getDeal(dealId);
  log(`Deal status: ${["None","Proposed","Active","Completed","Failed","Cancelled"][Number(d.status)]}`);
  const back = user.retrieve(blob);
  log(`User retrieved blob, root matched, decrypted == original: ${back.equals(file)}`);
  const proofBytes = Number(d.depth) * 32;
  log(`Proof size per challenge: ${d.depth} siblings x 32 B = ${proofBytes} B (+ 1024 B chunk)`);

  // ------------------------------------------------------------------
  log("\n=== SCENARIO B: cheating provider (threw the data away) ===");
  const user2 = new User(market.connect(userS));
  const cheater = new Provider(market.connect(cheaterS));
  const blob2 = user2.prepare(file);
  cheater.store(blob2);
  const r2 = await user2.createDeal({ provider: cheaterS.address, ...terms });
  await cheater.accept(r2.dealId);
  log(`Deal #${r2.dealId} active. Cheater proves period 0 honestly...`);
  await advanceToNextPeriod(market, r2.dealId);
  await cheater.prove(r2.dealId);

  await advanceToNextPeriod(market, r2.dealId);
  const idx = (await market.getChallenge(r2.dealId)).map(Number);
  log(`Period 1 challenge: [${idx.join(", ")}]. Cheater no longer holds those chunks and tries to fake it:`);

  // Attack 1: answer with a different chunk that it still has, plus that chunk's real proof.
  const other = idx.map((i) => (i + 1) % cheater.chunks.length);
  try {
    await market.connect(cheaterS).submitProof(r2.dealId, other.map((i) => cheater.chunks[i]), other.map((i) => getProof(cheater.tree, i)));
    log("  attack 1 (wrong position) -> ACCEPTED?!  BUG");
  } catch (e) { log("  attack 1 (valid chunk from the wrong position) -> rejected: invalid merkle proof"); }

  // Attack 2: random bytes
  try {
    await market.connect(cheaterS).submitProof(r2.dealId, idx.map(() => crypto.randomBytes(1024)), idx.map((i) => getProof(cheater.tree, i)));
    log("  attack 2 (random bytes) -> ACCEPTED?!  BUG");
  } catch (e) { log("  attack 2 (random bytes) -> rejected: invalid merkle proof"); }

  log("Cheater cannot produce a valid proof, so it stays silent. Waiting for the window to close...");
  await mine(terms.responseBlocks + 1);
  const rc = await user2.claimFailure(r2.dealId);
  log(`User called claimFailure (gas ${rc.gasUsed})`);
  log(`  user ledger:     ${eth(await market.balances(userS.address))}   (expected 7: collateral 3 + refund of 4 unpaid periods)`);
  log(`  cheater earned:  ${eth(await market.balances(cheaterS.address))}   (only period 0)`);

  // ------------------------------------------------------------------
  const avg = proofGas.reduce((a, b) => a + b, 0n) / BigInt(proofGas.length);
  log("\n=== GAS SUMMARY (1 MB file, depth 11, 3 challenges) ===");
  log(`createDeal          ${gasCreate}`);
  log(`acceptDeal          ${acc.gasUsed}`);
  log(`submitProof (avg)   ${avg}   <- one per period`);
  log(`claimFailure        ${rc.gasUsed}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
