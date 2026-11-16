// Merkle tree. The rules MUST match StorageMarket._verify exactly:
//   leaf = keccak256(0x00 || chunk)      node = keccak256(0x01 || left || right)
//   the leaf list is padded with zero hashes up to a power of two
const { keccak256, concat, ZeroHash } = require("ethers");

const CHUNK_SIZE = 1024; // same as StorageMarket.CHUNK_SIZE

function splitIntoChunks(bytes) {
  const chunks = [];
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) chunks.push(bytes.subarray(i, i + CHUNK_SIZE));
  return chunks;
}

const hashLeaf = (chunk) => keccak256(concat(["0x00", chunk]));
const hashNode = (left, right) => keccak256(concat(["0x01", left, right]));

/** layers[0] = padded leaves, layers[depth] = [root] */
function buildTree(chunks) {
  let depth = 0;
  while (2 ** depth < chunks.length) depth++;

  const leaves = chunks.map(hashLeaf);
  while (leaves.length < 2 ** depth) leaves.push(ZeroHash);

  const layers = [leaves];
  for (let level = 0; level < depth; level++) {
    const below = layers[level];
    const above = [];
    for (let i = 0; i < below.length; i += 2) above.push(hashNode(below[i], below[i + 1]));
    layers.push(above);
  }
  return { layers, depth, root: layers[depth][0] };
}

/** The sibling hash at every level on the way from leaf `index` to the root. */
function getProof(tree, index) {
  const proof = [];
  for (let level = 0; level < tree.depth; level++) {
    proof.push(tree.layers[level][index ^ 1]); // flipping the last bit gives the sibling
    index = index >> 1;
  }
  return proof;
}

module.exports = { splitIntoChunks, buildTree, getProof };
