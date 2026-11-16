// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * StorageMarket: rent storage from an untrusted provider, pay only while it proves it still
 * holds the file.
 *
 * Flow in one breath:
 *   user encrypts file -> chunks -> Merkle root (user keeps only root + key)
 *   user createDeal()   -> full payment locked in escrow
 *   provider acceptDeal() -> collateral locked
 *   each period: provider submitProof() for random chunks -> that period's payment released
 *   miss a deadline: claimFailure() -> user gets collateral + refund of unpaid periods
 *   all periods proven: provider gets collateral back
 *
 * The chain and the provider only ever see CIPHERTEXT chunks (the user encrypts first).
 */
contract StorageMarket {
    // ------------------------------------------------------------------
    // PROTOCOL CHOICES (the decisions you should be able to defend)
    // ------------------------------------------------------------------

    /// Bytes per chunk. Bigger chunks = shorter proofs but more bytes posted per challenge and a
    /// coarser spot check. Smaller = longer proofs. 1 KB makes a 1 MB file ~1025 chunks, proof
    /// depth 11, so one challenge posts about 1024 + 11*32 = 1376 bytes.
    uint256 public constant CHUNK_SIZE = 1024;

    /// Random chunks checked per period. If a provider deleted a fraction f of the file, one period
    /// catches it with probability 1 - (1-f)^3 (f = 10% -> 27%, f = 50% -> 87.5%). More challenges
    /// = better detection but more gas per period.
    uint256 public constant NUM_CHALLENGES = 3;

    /// Blocks the provider has to answer once a period starts. Must stay <= 255 because the
    /// challenge is derived from blockhash(), which only works for the last 256 blocks.
    uint256 public constant RESPONSE_BLOCKS = 50;

    /// Blocks the provider has to accept a new deal before the user can cancel and get a refund.
    uint256 public constant ACCEPT_BLOCKS = 20;

    // ------------------------------------------------------------------
    // Data
    // ------------------------------------------------------------------

    enum Status { None, Proposed, Active, Completed, Failed, Cancelled }

    struct Deal {
        address user;
        address provider;
        bytes32 root;            // Merkle root of the ciphertext chunks
        uint256 numChunks;       // real chunks in the file
        uint256 depth;           // tree height = ceil(log2(numChunks)), computed here, not trusted
        uint256 numPeriods;      // how many proof rounds the deal lasts
        uint256 periodBlocks;    // blocks per period (must be > RESPONSE_BLOCKS)
        uint256 pricePerPeriod;  // wei released for each proven period
        uint256 collateral;      // wei the provider locks to accept
        uint256 nextPeriod;      // next period the provider must prove (0-based)
        uint256 startBlock;      // block where period 0 begins (set when accepted)
        uint256 acceptDeadline;  // last block the provider may accept
        Status status;
    }

    uint256 public dealCount;
    mapping(uint256 => Deal) private deals;

    /// Pull-payment ledger: money sits here until its owner calls withdraw().
    mapping(address => uint256) public balances;

    event DealProposed(uint256 indexed dealId, address indexed user, address indexed provider);
    event DealAccepted(uint256 indexed dealId);
    event ProofAccepted(uint256 indexed dealId, uint256 period);
    event DealCompleted(uint256 indexed dealId);
    event DealFailed(uint256 indexed dealId, uint256 missedPeriod);

    // ------------------------------------------------------------------
    // 1. User opens a deal and escrows the full payment
    // ------------------------------------------------------------------

    function createDeal(
        address provider,
        bytes32 root,
        uint256 numChunks,
        uint256 numPeriods,
        uint256 periodBlocks,
        uint256 pricePerPeriod,
        uint256 collateral
    ) external payable returns (uint256 dealId) {
        require(provider != address(0), "no provider");
        require(numChunks > 0 && numPeriods > 0, "empty deal");
        require(periodBlocks > RESPONSE_BLOCKS, "period must be longer than response window");
        require(msg.value == pricePerPeriod * numPeriods, "wrong escrow amount"); // escrow = whole payment

        // Smallest depth with 2^depth >= numChunks.
        uint256 depth = 0;
        while ((uint256(1) << depth) < numChunks) depth++;

        dealId = ++dealCount;
        deals[dealId] = Deal({
            user: msg.sender,
            provider: provider,
            root: root,
            numChunks: numChunks,
            depth: depth,
            numPeriods: numPeriods,
            periodBlocks: periodBlocks,
            pricePerPeriod: pricePerPeriod,
            collateral: collateral,
            nextPeriod: 0,
            startBlock: 0,
            acceptDeadline: block.number + ACCEPT_BLOCKS,
            status: Status.Proposed
        });
        emit DealProposed(dealId, msg.sender, provider);
    }

    // ------------------------------------------------------------------
    // 2. Provider accepts and locks collateral (or user cancels if it never shows up)
    // ------------------------------------------------------------------

    /// Provider should first check its own Merkle root equals deals[dealId].root.
    function acceptDeal(uint256 dealId) external payable {
        Deal storage d = deals[dealId];
        require(d.status == Status.Proposed, "not proposed");
        require(msg.sender == d.provider, "not the provider");
        require(block.number <= d.acceptDeadline, "accept window over");
        require(msg.value == d.collateral, "wrong collateral");

        d.status = Status.Active;
        d.startBlock = block.number; // period 0 starts now
        emit DealAccepted(dealId);
    }

    function cancelProposal(uint256 dealId) external {
        Deal storage d = deals[dealId];
        require(d.status == Status.Proposed, "not proposed");
        require(msg.sender == d.user, "not the user");
        require(block.number > d.acceptDeadline, "still waiting for provider");

        d.status = Status.Cancelled;
        balances[d.user] += d.pricePerPeriod * d.numPeriods; // refund the escrow
    }

    // ------------------------------------------------------------------
    // 3. Challenges
    //
    //   period k starts at block   start_k = startBlock + k * periodBlocks
    //   random seed              = blockhash(start_k)   (nobody knows it before that block exists)
    //   provider may answer in blocks (start_k, start_k + RESPONSE_BLOCKS]
    //
    // The seed depends only on the schedule, so neither side can pick or grind it by choosing
    // when to send a transaction. Limitation: a block producer can nudge a block hash slightly;
    // real systems use a VRF or a beacon such as drand.
    // ------------------------------------------------------------------

    function periodStart(Deal storage d, uint256 k) private view returns (uint256) {
        return d.startBlock + k * d.periodBlocks;
    }

    /// Chunk positions to prove in the CURRENT period. Providers read this off-chain.
    /// Needs the chain to be at least one block past the period start (a block can't know its own hash).
    function getChallenge(uint256 dealId) public view returns (uint256[] memory indices) {
        Deal storage d = deals[dealId];
        require(d.status == Status.Active, "not active");
        uint256 start = periodStart(d, d.nextPeriod);
        require(block.number > start, "period not started");

        bytes32 seed = keccak256(abi.encode(blockhash(start), dealId, d.nextPeriod));
        indices = new uint256[](NUM_CHALLENGES);
        for (uint256 j = 0; j < NUM_CHALLENGES; j++) {
            // "% numChunks" means we only ever ask for real chunks, never padding.
            indices[j] = uint256(keccak256(abi.encode(seed, j))) % d.numChunks;
        }
    }

    // ------------------------------------------------------------------
    // 4. Provider posts proofs, payment is released period by period
    // ------------------------------------------------------------------

    /// chunks[j] = raw ciphertext of challenged chunk j; proofs[j] = its Merkle sibling hashes.
    function submitProof(uint256 dealId, bytes[] calldata chunks, bytes32[][] calldata proofs) external {
        Deal storage d = deals[dealId];
        require(d.status == Status.Active, "not active");
        require(msg.sender == d.provider, "not the provider");

        uint256 start = periodStart(d, d.nextPeriod);
        require(block.number > start && block.number <= start + RESPONSE_BLOCKS, "outside response window");
        require(chunks.length == NUM_CHALLENGES && proofs.length == NUM_CHALLENGES, "wrong proof count");

        uint256[] memory indices = getChallenge(dealId);
        for (uint256 j = 0; j < NUM_CHALLENGES; j++) {
            require(chunks[j].length <= CHUNK_SIZE, "chunk too big");
            require(_verify(d.root, d.depth, indices[j], chunks[j], proofs[j]), "invalid merkle proof");
        }

        // Everything checked: pay this period.
        emit ProofAccepted(dealId, d.nextPeriod);
        d.nextPeriod++;
        balances[d.provider] += d.pricePerPeriod;

        if (d.nextPeriod == d.numPeriods) {
            d.status = Status.Completed;
            balances[d.provider] += d.collateral; // collateral comes back
            emit DealCompleted(dealId);
        }
    }

    // ------------------------------------------------------------------
    // 5. Failure: window closed with no valid proof
    // ------------------------------------------------------------------

    /// Anyone can call this once the response window of the next unproven period is over.
    function claimFailure(uint256 dealId) external {
        Deal storage d = deals[dealId];
        require(d.status == Status.Active, "not active");
        uint256 k = d.nextPeriod;
        require(block.number > periodStart(d, k) + RESPONSE_BLOCKS, "window still open");

        d.status = Status.Failed;
        // Provider already got k periods. The rest were never earned, so refund them,
        // and the user also takes the provider's collateral.
        balances[d.user] += d.collateral + d.pricePerPeriod * (d.numPeriods - k);
        emit DealFailed(dealId, k);
    }

    // ------------------------------------------------------------------
    // Withdraw (the only place ether leaves the contract)
    // ------------------------------------------------------------------

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0; // zero first, then send (stops re-entrancy)
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // ------------------------------------------------------------------
    // Merkle verification. Tree rules (offchain/merkle.js must match):
    //   leaf = keccak256(0x00 || chunk)        node = keccak256(0x01 || left || right)
    //   tree padded with zero hashes up to 2^depth leaves
    //
    // * 0x00 vs 0x01 prefixes: a chunk can never be mistaken for an inner node.
    // * Position binding: the bits of `index` say whether we are the left or right child at each
    //   level, and the proof must have exactly `depth` siblings. A valid proof for chunk 5 climbs
    //   to a different root if replayed as chunk 9.
    // ------------------------------------------------------------------

    function _verify(
        bytes32 root,
        uint256 depth,
        uint256 index,
        bytes calldata chunk,
        bytes32[] calldata proof
    ) private pure returns (bool) {
        if (proof.length != depth) return false;

        bytes32 h = keccak256(abi.encodePacked(bytes1(0x00), chunk));
        for (uint256 level = 0; level < depth; level++) {
            if (index % 2 == 0) {
                h = keccak256(abi.encodePacked(bytes1(0x01), h, proof[level]));  // we are the left child
            } else {
                h = keccak256(abi.encodePacked(bytes1(0x01), proof[level], h));  // we are the right child
            }
            index /= 2;
        }
        return h == root;
    }

    function getDeal(uint256 dealId) external view returns (Deal memory) {
        return deals[dealId];
    }
}
