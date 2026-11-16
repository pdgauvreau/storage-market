# Decentralized Storage Marketplace (Task 3, Solidity)

A user rents storage for one file from an untrusted provider. The payment is escrowed up
front and released one period at a time, only after the provider proves on-chain that it
still holds a randomly chosen part of the file. If the provider fails, it loses its
collateral to the user and the unspent payment is refunded.

Implemented: everything in the required list (1 MB file tested). Not implemented: the optional
"edit the file during the deal" extension (see the last section for how it would work).

## How to run

```bash
npm install
npx hardhat test          # 12 tests
npx hardhat run scripts/demo.js   # narrated end-to-end run with gas numbers
```

If your network blocks `binaries.soliditylang.org` (Hardhat downloads the compiler from there),
use `USE_SOLCJS=1 npx hardhat test`. That uses the pure-JS compiler from npm instead.
The code is identical either way.

## Files

| File | Role |
|---|---|
| `contracts/StorageMarket.sol` | The smart contract: escrow, deal lifecycle, challenges, Merkle verification, slashing |
| `offchain/merkle.js` | Chunking and Merkle tree (must hash exactly like the contract) |
| `offchain/user.js` | User program: AES-256-GCM encryption, commit, open deal, claim failure, retrieve and decrypt |
| `offchain/provider.js` | Provider program: store, verify root, accept, answer challenges |
| `test/StorageMarket.test.js` | Automated tests including cheating providers |
| `scripts/demo.js` | Narrated demo, prints gas costs |

## The protocol in plain words

1. **Prepare (user, off-chain).** Encrypt the file with a random AES-256-GCM key. Cut the
   ciphertext into 1 KB chunks. Build a Merkle tree over the chunks. Keep the 32-byte root and
   the key. Throw everything else away.
2. **Hand over (off-chain).** Send the ciphertext to the provider.
3. **Open the deal (on-chain).** `createDeal` records the root and the terms and locks
   `pricePerPeriod * numPeriods` in escrow.
4. **Accept (provider).** The provider recomputes the root from the data it received and refuses
   unless it matches. Then `acceptDeal` locks the collateral. Period 0 starts at this block.
5. **Each period.** The contract picks `NUM_CHALLENGES` (3) random chunk positions from the hash of the
   period's start block. The provider calls `getChallenge` (read-only) to learn them, then
   `submitProof` with those chunks and their Merkle paths. The contract verifies each path against
   the stored root. If all pass, that period's payment is credited to the provider.
6. **Success.** After the last period the collateral is credited back to the provider.
7. **Failure.** If the response window of the next unproven period closes with no valid proof,
   anyone calls `claimFailure`. The user is credited the collateral plus the payment for all
   unproven periods.
8. **Money out.** Credits are paid with `withdraw()` (pull payments).

## Design decisions and why

**Confidentiality: encrypt first, commit to the ciphertext.** The Merkle tree is built over the
encrypted blob, so the provider and anyone reading the chain only see ciphertext. Proofs post
raw chunks on-chain, which is fine because those chunks are ciphertext. The AES key never leaves
the user. GCM also gives tamper detection when the user decrypts later, and the Merkle root
independently checks that the provider returned the same bytes.

**Chunk size: 1024 bytes.** A 1 MB file becomes 1025 chunks (the extra 28 bytes are the IV and GCM
tag), so tree depth is 11. Bigger chunks mean fewer leaves and shorter proofs but more calldata
per challenge and a coarser spot check. Smaller chunks mean longer proofs and a bigger tree to
store. 1 KB is a middle point: a challenge costs about 1024 B + 352 B of calldata.

**Merkle tree rules.** `leaf = keccak256(0x00 || chunk)` and `node = keccak256(0x01 || left || right)`.
The tree is padded with zero hashes up to a power of two. Depth is computed inside the contract from
`numChunks`, not trusted from the user.
- *Domain separation* (the 0x00 and 0x01 prefixes) stops a chunk from being passed off as an
  internal node (second-preimage attack).
- *Position binding.* The bits of the challenged index decide whether the running hash is the left
  or right child at each level, and the proof length must equal the depth. A valid proof for chunk 5
  therefore cannot be replayed for chunk 9. One test covers exactly this attack.
- Challenge indices are taken `% numChunks`, so padding leaves are never challenged.

**Challenge generation.** `seed = keccak256(blockhash(periodStart), dealId, period)` and
`index_j = keccak256(seed, j) % numChunks`. The period start block is fixed by the schedule, so
nobody can grind the seed by choosing when to send a transaction, and nobody knows the positions
before that block exists. The provider therefore cannot keep only the chunks it expects to be
asked about. Limitation: a block producer has a small influence on a block hash. Production
systems use a VRF or a randomness beacon (drand, Chainlink VRF).

**Deadlines.** Period `k` starts at `startBlock + k * periodBlocks`. The provider may answer in
the next `RESPONSE_BLOCKS` (50) blocks (this constant must stay at or below 255, because `blockhash` only works for the last 256
blocks). Deadlines use block numbers, not timestamps, because timestamps can be nudged by block
producers and blocks are deterministic in tests.

**Number of challenges.** If a provider has deleted a fraction `f` of the chunks, one period with
`c` challenges catches it with probability `1 - (1 - f)^c`. With c = 3:

| Deleted | Caught per period | Caught within 5 periods |
|---|---|---|
| 10% | 27% | 79% |
| 50% | 87.5% | 99.997% |

Each extra challenge adds one more chunk plus its proof to the calldata and about 11 more hashes
on-chain, so gas per period grows roughly linearly with `c`. Losing a
single chunk is only caught with probability c/n per period. This is a probabilistic guarantee,
which is the standard tradeoff in proof-of-retrievability systems.

**Collateral.** Set by the user per deal (the only economic knob besides price and length). It should exceed what the provider could gain by
cheating, and a cheater only earns the periods it passes before being caught. The demo uses a
collateral of 3x the per-period price and a total payment of 5x.

**Pull payments.** The contract only sends ether inside `withdraw()`, which zeroes the balance
before the transfer. That removes re-entrancy risk from the payout paths.

**Named provider.** The user names the provider address in `createDeal`. This avoids front-running
of an open "first to accept" auction and keeps the state machine simple.

**Protocol constants vs. per-deal terms.** Chunk size, number of challenges, response window and
accept window are fixed constants at the top of the contract, not per-deal options. Every one of them
is a choice the provider, user and contract must agree on, and fewer knobs means less to explain and
less to get wrong. Per deal, the user only picks the provider, the number and length of periods, the
price, and the collateral. The simple flat storage layout costs a bit more gas than a packed one
(about 90k more on `createDeal`), which I judged worth it for readability.

## Measured costs (1 MB file, depth 11, 3 challenges)

| Operation | Gas |
|---|---|
| `createDeal` | ~297k |
| `acceptDeal` | ~56k |
| `submitProof` (one period) | ~192k |
| `claimFailure` | ~66k |

Off-chain, encrypting and building the tree for 1 MB took about 220 ms.

## Security notes and limitations (be ready to discuss)

- **Outsourcing attack.** A provider could keep nothing and fetch challenged chunks from another
  provider at challenge time. Proofs of retrievability cannot prevent this alone. Proofs of
  replication or timing-based checks address it.
- **Probabilistic.** A provider missing a few chunks may pass for a while.
- **Randomness source.** Block hash is acceptable for a class project, weaker than a VRF.
- **Liveness is the provider's job.** The provider has to be online inside the window. A real
  system would also let the user fetch the data back with an on-chain dispute path.
- **User honesty at setup.** A user could commit to a root that does not match what was sent.
  The provider's check before `acceptDeal` removes that risk.
- **Data availability for retrieval** is not enforced by this contract. A provider that passes
  every proof but refuses to hand the file back is not punished here.

## Likely viva questions, with short answers

**Why did you pick this task?** The core idea (spot-check random pieces, bind each answer to a
position with a Merkle path, release money only on success) is explainable end to end, and I
could test every claim with attacks.

**Why a Merkle tree and not just hashing the whole file?** A whole-file hash would force the
provider to send the whole file for each proof. A Merkle root lets me verify one chunk with
about log2(n) hashes while still committing to every chunk.

**What stops the provider from answering with a different chunk?** The index decides left or
right at every level and the proof length is fixed to the depth. A proof for another position
climbs to a different root. Test: "valid chunk + valid proof from the WRONG position".

**Why prefix leaves and nodes differently?** Without it, a 64-byte chunk equal to two child
hashes could be treated as an internal node, which breaks the binding between the root and the
leaves.

**How is the file kept confidential?** AES-256-GCM before chunking. The chain only sees
ciphertext chunks. The key stays with the user.

**Why can't the provider predict the challenge?** It depends on the hash of a block that did not
exist yet when the deal terms were fixed, at a block number fixed by the schedule.

**Why must the response window be at most 255 blocks?** `blockhash` returns zero for blocks older
than 256, which would make the challenge predictable.

**What if the provider disappears?** Nobody posts a proof, the window closes, and `claimFailure`
pays the user the collateral plus every unpaid period. Anyone can trigger it.

**What if the user disappears?** The provider still gets paid after each proof because the whole
payment is already in escrow. The user cannot withdraw it.

**What if the provider never accepts?** After `ACCEPT_BLOCKS` (20 blocks), the user calls
`cancelProposal` and gets the escrow back.

**What does a proof cost and how does it scale?** Gas grows with `NUM_CHALLENGES * (chunk size +
32 * log2(n))` of calldata plus about `log2(n)` hashes per challenge. Doubling the file adds one
32-byte sibling per challenge.

**Why pull payments?** To avoid re-entrancy: balances are updated in the normal functions, and
ether leaves only in `withdraw()`, after the balance is zeroed.

**What would you change for production?** Use a VRF for randomness, add proof of replication or a
timing defense against outsourcing, add retrieval disputes, and add the update extension below.

## Extension (not implemented): editing the file during the deal

Keep only the root on-chain. To change chunk `i` from `old` to `new`, the user submits `old`, `new`
and the sibling path of `i`. The contract (1) verifies the path against the current root using
`old`, then (2) recomputes the root by walking the same path with `new`, and stores it. Both steps
walk `log2(n)` nodes, so gas grows logarithmically. Appending works similarly using the next empty
(zero) leaf, with the size bumped. A provider that kept the old version fails from the next period
on, because proofs are checked against the new root. The provider would need to receive the new
chunk off-chain, and the user must not change the root mid-period (apply updates at period boundaries).
