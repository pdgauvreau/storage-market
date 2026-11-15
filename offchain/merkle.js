// Merkle tree helpers. These rules MUST match StorageMarket._verify exactly:
//   leaf  = keccak256(0x00 || chunkBytes)
//   node  = keccak256(0x01 || left || right)
//   tree is padded with 32 zero bytes up to 2^depth leaves
const { keccak256, concat, ZeroHash } = require("ethers");

const CHUNK_SIZE = 1024; // must equal StorageMarket.CHUNK_SIZE

/** Cut a byte array into CHUNK_SIZE pieces (the last one may be shorter). */
function splitIntoChunks(bytes) {
  const chunks = [];
  for (let off = 0; off < bytes.length; off += CHUNK_SIZE) {
    chunks.push(bytes.subarray(off, Math.min(off + CHUNK_SIZE, bytes.length)));
  }
  return chunks;
}

const leafHash = (chunk) => keccak256(concat(["0x00", chunk]));
const nodeHash = (l, r) => keccak256(concat(["0x01", l, r]));

/** smallest d such that 2^d >= n (same loop as the contract) */
function treeDepth(n) {
  let d = 0;
  while (2 ** d < n) d++;
  return d;
}

/**
 * Build every layer of the tree.
 * layers[0] = leaves (padded), layers[depth] = [root]
 */
function buildTree(chunks) {
  const depth = treeDepth(chunks.length);
  const leaves = chunks.map(leafHash);
  while (leaves.length < 2 ** depth) leaves.push(ZeroHash); // padding
  const layers = [leaves];
  for (let level = 0; level < depth; level++) {
    const prev = layers[level];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) next.push(nodeHash(prev[i], prev[i + 1]));
    layers.push(next);
  }
  return { layers, depth, root: layers[depth][0] };
}

/** Sibling hashes from leaf `index` up to the root. Length == depth. */
function getProof(tree, index) {
  const proof = [];
  let i = index;
  for (let level = 0; level < tree.depth; level++) {
    proof.push(tree.layers[level][i ^ 1]); // flip the last bit to get the sibling
    i >>= 1;
  }
  return proof;
}

/** Same check the contract does, handy for tests and for the provider's sanity checks. */
function verifyProof(root, depth, index, chunk, proof) {
  if (proof.length !== depth) return false;
  let h = leafHash(chunk);
  for (let level = 0; level < depth; level++) {
    h = (index & 1) === 0 ? nodeHash(h, proof[level]) : nodeHash(proof[level], h);
    index >>= 1;
  }
  return h === root;
}

module.exports = { CHUNK_SIZE, splitIntoChunks, buildTree, getProof, verifyProof, treeDepth, leafHash };
