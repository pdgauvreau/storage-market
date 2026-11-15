// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * StorageMarket: rent storage from an untrusted provider and pay only while
 * the provider keeps proving it still holds the file.
 *
 * THE BIG PICTURE (good thing to say first in your viva)
 * ------------------------------------------------------
 * 1. The user ENCRYPTS the file, cuts the ciphertext into 1 KB chunks, and builds a
 *    Merkle tree over the chunks. The user keeps only the 32-byte Merkle ROOT
 *    (plus the secret key, which never leaves the user).
 * 2. The user hands the ciphertext to the provider (off-chain) and opens a DEAL on
 *    this contract, locking the whole payment in ESCROW.
 * 3. The provider checks the data matches the root, then ACCEPTS by locking
 *    COLLATERAL.
 * 4. Time is split into PERIODS (measured in blocks). In every period the contract
 *    derives random chunk positions from a block hash. The provider must post those
 *    chunks plus Merkle proofs inside a short RESPONSE WINDOW. A valid proof releases
 *    that period's payment to the provider.
 * 5. If the provider misses a window or posts a bad proof (so no valid proof arrives
 *    in time), anybody can call claimFailure(). The user gets the provider's
 *    collateral plus a refund of every period not yet paid.
 * 6. If the provider proves every period, the deal completes and the collateral is
 *    returned to the provider.
 *
 * Confidentiality: the chain and the provider only ever see CIPHERTEXT chunks.
 */
contract StorageMarket {
    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    /// Size of one chunk in bytes. Fixed for the whole protocol so the user,
    /// the provider and the contract all agree on how the tree is built.
    /// 1 MB file -> ~1025 chunks -> proof depth 11 (11 * 32 = 352 bytes of siblings).
    uint256 public constant CHUNK_SIZE = 1024;

    /// blockhash() only works for the most recent 256 blocks, so the response
    /// window has to fit inside that.
    uint256 public constant MAX_RESPONSE_BLOCKS = 255;

    // ------------------------------------------------------------------
    // Data
    // ------------------------------------------------------------------

    enum Status {
        None,       // id does not exist
        Proposed,   // user created + funded the deal, provider has not accepted
        Active,     // provider accepted and posted collateral
        Completed,  // provider proved every period
        Failed,     // provider missed a deadline, collateral slashed
        Cancelled   // provider never accepted, user took the money back
    }

    /// What the user chooses when creating a deal.
    struct Terms {
        address provider;        // who is allowed to accept and prove
        bytes32 root;            // Merkle root of the ciphertext chunks
        uint32 numChunks;        // number of real chunks in the file
        uint32 numPeriods;       // how many proof rounds the deal lasts
        uint32 periodBlocks;     // length of one period in blocks
        uint32 responseBlocks;   // blocks the provider has to answer in each period
        uint32 numChallenges;    // random chunks checked per period
        uint32 acceptWindowBlocks; // how long the provider has to accept
        uint256 pricePerPeriod;  // wei paid for each proven period
        uint256 collateral;      // wei the provider must lock to accept
    }

    struct Deal {
        address user;
        address provider;
        bytes32 root;
        uint256 pricePerPeriod;
        uint256 collateral;
        uint32 numChunks;
        uint32 numPeriods;
        uint32 periodBlocks;
        uint32 responseBlocks;
        uint32 numChallenges;
        uint32 nextPeriod;       // index of the next period the provider must prove
        uint64 startBlock;       // block where period 0 begins (set on accept)
        uint64 acceptDeadline;   // last block the provider may accept
        uint8 depth;             // Merkle tree height = ceil(log2(numChunks))
        Status status;
    }

    uint256 public dealCount;
    mapping(uint256 => Deal) private deals;

    /// Pull-payment ledger. The contract never pushes ether to anyone except
    /// inside withdraw(), which avoids re-entrancy trouble.
    mapping(address => uint256) public balances;

    // ------------------------------------------------------------------
    // Events (handy for the demo output and for off-chain programs)
    // ------------------------------------------------------------------

    event DealProposed(uint256 indexed dealId, address indexed user, address indexed provider, bytes32 root);
    event DealAccepted(uint256 indexed dealId, uint64 startBlock);
    event ProofAccepted(uint256 indexed dealId, uint32 period);
    event DealCompleted(uint256 indexed dealId);
    event DealFailed(uint256 indexed dealId, uint32 missedPeriod);
    event DealCancelled(uint256 indexed dealId);

    // ------------------------------------------------------------------
    // 1. User opens a deal and escrows the full payment
    // ------------------------------------------------------------------

    function createDeal(Terms calldata t) external payable returns (uint256 dealId) {
        require(t.provider != address(0), "no provider");
        require(t.numChunks > 0 && t.numPeriods > 0 && t.numChallenges > 0, "zero param");
        require(t.responseBlocks > 0 && t.responseBlocks <= MAX_RESPONSE_BLOCKS, "bad response window");
        require(t.responseBlocks < t.periodBlocks, "window must be shorter than period");
        // The ENTIRE payment is locked up front. This is the "escrow".
        require(msg.value == t.pricePerPeriod * t.numPeriods, "wrong escrow amount");

        // Tree height: smallest d with 2^d >= numChunks. We compute it here instead
        // of trusting a value from the user.
        uint8 depth = 0;
        while ((uint256(1) << depth) < t.numChunks) depth++;

        dealId = ++dealCount;
        Deal storage d = deals[dealId];
        d.user = msg.sender;
        d.provider = t.provider;
        d.root = t.root;
        d.pricePerPeriod = t.pricePerPeriod;
        d.collateral = t.collateral;
        d.numChunks = t.numChunks;
        d.numPeriods = t.numPeriods;
        d.periodBlocks = t.periodBlocks;
        d.responseBlocks = t.responseBlocks;
        d.numChallenges = t.numChallenges;
        d.acceptDeadline = uint64(block.number + t.acceptWindowBlocks);
        d.depth = depth;
        d.status = Status.Proposed;

        emit DealProposed(dealId, msg.sender, t.provider, t.root);
    }

    // ------------------------------------------------------------------
    // 2. Provider accepts and locks collateral
    // ------------------------------------------------------------------

    /// The provider should first download the ciphertext and check that its own
    /// Merkle root equals deals[dealId].root. Accepting means "I hold this data".
    function acceptDeal(uint256 dealId) external payable {
        Deal storage d = deals[dealId];
        require(d.status == Status.Proposed, "not proposed");
        require(msg.sender == d.provider, "not the provider");
        require(block.number <= d.acceptDeadline, "accept window over");
        require(msg.value == d.collateral, "wrong collateral");

        d.status = Status.Active;
        d.startBlock = uint64(block.number); // period 0 starts now
        emit DealAccepted(dealId, d.startBlock);
    }

    /// If the provider never shows up, the user gets the escrow back.
    function cancelProposal(uint256 dealId) external {
        Deal storage d = deals[dealId];
        require(d.status == Status.Proposed, "not proposed");
        require(msg.sender == d.user, "not the user");
        require(block.number > d.acceptDeadline, "still waiting for provider");

        d.status = Status.Cancelled;
        balances[d.user] += d.pricePerPeriod * d.numPeriods;
        emit DealCancelled(dealId);
    }

    // ------------------------------------------------------------------
    // 3. Challenges
    // ------------------------------------------------------------------
    //
    // Timeline for period k (all in blocks):
    //
    //   periodStart(k) = startBlock + k * periodBlocks
    //   challenge seed = blockhash(periodStart(k))      <- unknown until that block exists
    //   provider may answer in blocks (periodStart, periodStart + responseBlocks]
    //
    // Why a block hash? Nobody (not the user, not the provider) can know the random
    // chunk positions before periodStart is mined, so the provider cannot keep just
    // "the chunks it expects to be asked about". The caller of any function cannot
    // choose or grind the seed: it is fixed by the schedule, not by who calls when.
    // (Limitation: a block producer has a tiny influence on a block hash. Real systems
    //  use a VRF or a beacon like drand. Good viva point.)

    function periodStart(Deal storage d, uint32 period) private view returns (uint256) {
        return uint256(d.startBlock) + uint256(period) * d.periodBlocks;
    }

    /// Which chunk positions must be proven in the CURRENT period.
    /// Providers call this off-chain (eth_call) to know what to fetch from disk.
    /// It works once the chain has moved at least one block past periodStart, because
    /// the seed is the hash of that block and a block cannot know its own hash.
    function getChallenge(uint256 dealId) public view returns (uint256[] memory indices) {
        Deal storage d = deals[dealId];
        require(d.status == Status.Active, "not active");
        uint256 ps = periodStart(d, d.nextPeriod);
        require(block.number > ps, "period not started");
        require(block.number - ps <= 256, "seed expired");

        bytes32 seed = keccak256(abi.encode(blockhash(ps), dealId, d.nextPeriod));
        indices = new uint256[](d.numChallenges);
        for (uint256 j = 0; j < d.numChallenges; j++) {
            // `% numChunks` guarantees we only ever ask for REAL chunks, never padding.
            indices[j] = uint256(keccak256(abi.encode(seed, j))) % d.numChunks;
        }
    }

    // ------------------------------------------------------------------
    // 4. Provider posts proofs; payment is released period by period
    // ------------------------------------------------------------------

    /// chunks[j]  = the raw ciphertext bytes of challenged chunk j
    /// proofs[j]  = the sibling hashes from that chunk's leaf up to the root
    function submitProof(uint256 dealId, bytes[] calldata chunks, bytes32[][] calldata proofs) external {
        Deal storage d = deals[dealId];
        require(d.status == Status.Active, "not active");
        require(msg.sender == d.provider, "not the provider");

        uint32 k = d.nextPeriod;
        uint256 ps = periodStart(d, k);
        require(block.number > ps && block.number <= ps + d.responseBlocks, "outside response window");
        require(chunks.length == d.numChallenges && proofs.length == d.numChallenges, "wrong proof count");

        uint256[] memory idx = getChallenge(dealId);
        for (uint256 j = 0; j < idx.length; j++) {
            require(chunks[j].length <= CHUNK_SIZE, "chunk too big");
            require(_verify(d.root, d.depth, idx[j], chunks[j], proofs[j]), "invalid merkle proof");
        }

        // All checks passed: release this period's payment to the provider.
        d.nextPeriod = k + 1;
        balances[d.provider] += d.pricePerPeriod;
        emit ProofAccepted(dealId, k);

        if (d.nextPeriod == d.numPeriods) {
            d.status = Status.Completed;
            balances[d.provider] += d.collateral; // collateral comes back
            emit DealCompleted(dealId);
        }
    }

    // ------------------------------------------------------------------
    // 5. Failure: missed deadline -> slash collateral, refund unspent payment
    // ------------------------------------------------------------------

    /// Anyone may call this once the response window for the next unproven
    /// period has closed. (The user will, since they get the money.)
    function claimFailure(uint256 dealId) external {
        Deal storage d = deals[dealId];
        require(d.status == Status.Active, "not active");

        uint32 k = d.nextPeriod;
        require(block.number > periodStart(d, k) + d.responseBlocks, "window still open");

        d.status = Status.Failed;
        // Provider already received k * price. The remaining periods were never earned.
        uint256 refund = d.pricePerPeriod * (d.numPeriods - k);
        balances[d.user] += d.collateral + refund;
        emit DealFailed(dealId, k);
    }

    // ------------------------------------------------------------------
    // Withdraw (pull payment)
    // ------------------------------------------------------------------

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0; // zero BEFORE sending (checks-effects-interactions)
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // ------------------------------------------------------------------
    // Merkle proof verification
    // ------------------------------------------------------------------
    //
    // Tree rules (the off-chain code in offchain/merkle.js must match exactly):
    //   leaf  = keccak256(0x00 || chunkBytes)
    //   node  = keccak256(0x01 || left || right)
    //   the tree is padded with bytes32(0) leaves up to 2^depth leaves
    //
    // Two safety ideas:
    //  * DOMAIN SEPARATION (0x00 vs 0x01 prefix): a 64-byte chunk can never be
    //    mistaken for "two child hashes", which blocks second-preimage tricks.
    //  * POSITION BINDING: the bits of `index` decide whether our running hash is the
    //    LEFT or RIGHT child at each level. The proof length is forced to equal the
    //    tree depth. So a valid proof for chunk 5 cannot be passed off as chunk 9:
    //    walking up with index 9's bits would land on a different root.

    function _verify(
        bytes32 root,
        uint8 depth,
        uint256 index,
        bytes calldata chunk,
        bytes32[] calldata proof
    ) private pure returns (bool) {
        if (proof.length != depth) return false;

        bytes32 h = keccak256(abi.encodePacked(bytes1(0x00), chunk));
        for (uint256 level = 0; level < depth; level++) {
            if (index & 1 == 0) {
                h = keccak256(abi.encodePacked(bytes1(0x01), h, proof[level])); // we are the left child
            } else {
                h = keccak256(abi.encodePacked(bytes1(0x01), proof[level], h)); // we are the right child
            }
            index >>= 1;
        }
        return h == root;
    }

    // ------------------------------------------------------------------
    // Views for off-chain programs
    // ------------------------------------------------------------------

    function getDeal(uint256 dealId) external view returns (Deal memory) {
        return deals[dealId];
    }
}
