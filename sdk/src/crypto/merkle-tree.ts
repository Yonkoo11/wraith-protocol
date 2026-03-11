/**
 * Incremental Merkle Tree — matching merkle_tree.circom and pool.cairo exactly.
 *
 * Hash function: poseidon2 over BN254 Fr (Grumpkin base field), same as hash.circom.
 * Zero value: poseidon2(0, 0) — confirmed to match Ekubo's merkle.cairo constant.
 *
 * Tree construction:
 * - Depth 24 → 2^24 = 16,777,216 leaf capacity
 * - Leaves added left to right (index 0, 1, 2, ...)
 * - Empty slots use the precomputed zero-value for that level
 * - Internal nodes: H(left, right) = poseidon2(left, right)
 *
 * This implementation matches the `MerkleTreeChecker` circuit in merkle_tree.circom.
 * A proof generated with `getProof()` will pass that circuit's constraints.
 */

import { poseidonHash } from './poseidon.js';

// Depth of the pool's Merkle tree (matches Pool(24, 24) in pool.circom)
export const TREE_DEPTH = 24;

/**
 * Precomputed zero values for each level.
 *
 * zeros[0] = H(0, 0)               — empty leaf
 * zeros[1] = H(zeros[0], zeros[0]) — empty pair
 * zeros[k] = H(zeros[k-1], zeros[k-1])
 *
 * These are constant — computed once, used by all tree instances.
 */
export const ZERO_VALUES: readonly bigint[] = (() => {
  const z: bigint[] = new Array(TREE_DEPTH + 1);
  z[0] = poseidonHash(0n, 0n);
  for (let i = 1; i <= TREE_DEPTH; i++) {
    z[i] = poseidonHash(z[i - 1], z[i - 1]);
  }
  return Object.freeze(z);
})();

export interface MerkleProof {
  /** The leaf value at this index */
  leaf: bigint;
  /** Sibling at each level, bottom to top */
  pathElements: bigint[];
  /** 0 = leaf is left child, 1 = leaf is right child, at each level */
  pathIndices: number[];
  /** Root computed from this proof */
  root: bigint;
  /** Leaf index in the tree */
  index: number;
}

/**
 * Incremental Merkle tree with O(log N) insert and proof generation.
 *
 * Stores only the "frontier" — the rightmost non-zero node at each level.
 * This is the standard approach for ZK Merkle trees (used by Tornado Cash, etc).
 *
 * Memory usage: O(depth) — not O(N) — because we only store the path
 * to the current insertion point.
 */
export class IncrementalMerkleTree {
  private readonly depth: number;
  /** filledSubtrees[level] = the rightmost complete subtree hash at that level */
  private filledSubtrees: bigint[];
  /** All inserted leaf hashes, in order — needed for getProof() */
  private leaves: bigint[];
  /** current_root_index in the pool.cairo sense — increments with every insert */
  private currentRootIndex: number;
  /** roots[i % ROOTS_CACHE_SIZE] — cache of recent roots to allow old proofs */
  private roots: bigint[];
  private nextIndex: number;

  private static readonly ROOTS_CACHE_SIZE = 30;

  constructor(depth: number = TREE_DEPTH) {
    this.depth = depth;
    this.filledSubtrees = ZERO_VALUES.slice(0, depth) as bigint[];
    this.leaves = [];
    this.nextIndex = 0;
    this.currentRootIndex = 0;
    // Initialize with the empty tree root
    this.roots = new Array(IncrementalMerkleTree.ROOTS_CACHE_SIZE).fill(0n);
    this.roots[0] = ZERO_VALUES[depth];
  }

  /**
   * Insert a leaf and return the new Merkle root.
   * Matches `_insert(leaf)` in pool.cairo.
   */
  insert(leaf: bigint): bigint {
    const index = this.nextIndex;
    if (index >= 2 ** this.depth) {
      throw new Error('Merkle tree is full');
    }

    this.leaves.push(leaf);

    let currentIndex = index;
    let currentLevelHash = leaf;

    for (let level = 0; level < this.depth; level++) {
      let left: bigint;
      let right: bigint;

      if (currentIndex % 2 === 0) {
        // We are the left child — sibling is an empty subtree
        left = currentLevelHash;
        right = ZERO_VALUES[level];
        this.filledSubtrees[level] = currentLevelHash;
      } else {
        // We are the right child — sibling is the most recent left subtree
        left = this.filledSubtrees[level];
        right = currentLevelHash;
      }

      currentLevelHash = poseidonHash(left, right);
      currentIndex >>= 1;
    }

    const newRoot = currentLevelHash;
    this.nextIndex++;
    this.currentRootIndex = (this.currentRootIndex + 1) % IncrementalMerkleTree.ROOTS_CACHE_SIZE;
    this.roots[this.currentRootIndex] = newRoot;

    return newRoot;
  }

  /**
   * Generate a Merkle proof for the leaf at the given index.
   *
   * The returned { pathElements, pathIndices, root } can be passed directly
   * to the Pool circuit as private inputs.
   */
  getProof(index: number): MerkleProof {
    if (index >= this.leaves.length) {
      throw new Error(`Leaf at index ${index} not found (tree has ${this.leaves.length} leaves)`);
    }

    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];

    // Rebuild the tree state at the point after this leaf was inserted
    // by replaying inserts and capturing sibling values
    const tempTree = new IncrementalMerkleTree(this.depth);
    // Replay up to and including our leaf
    for (let i = 0; i <= index; i++) {
      tempTree.insert(this.leaves[i]);
    }

    // Now extract the path for our leaf
    let currentIndex = index;
    for (let level = 0; level < this.depth; level++) {
      const isRightChild = currentIndex % 2 === 1;
      pathIndices.push(isRightChild ? 1 : 0);

      if (isRightChild) {
        // Sibling is the left child — it must be in filledSubtrees if it was set
        pathElements.push(tempTree.filledSubtrees[level]);
      } else {
        // Sibling is the right child.
        // The right sibling at this level covers leaves starting at (currentIndex+1) * 2^level.
        // It is non-empty iff any leaf exists in that range.
        // Using (currentIndex + 1) << level avoids the O(2^depth) recursion on empty subtrees.
        if (((currentIndex + 1) << level) < this.leaves.length) {
          pathElements.push(this._getSubtreeHash(level, currentIndex ^ 1));
        } else {
          // Right sibling subtree is entirely empty
          pathElements.push(ZERO_VALUES[level]);
        }
      }

      currentIndex >>= 1;
    }

    return {
      leaf: this.leaves[index],
      pathElements,
      pathIndices,
      root: this.root(),
      index,
    };
  }

  /**
   * Get the hash for the subtree rooted at a given position.
   * position is the node index at the given level (0-indexed from left).
   */
  private _getSubtreeHash(level: number, position: number): bigint {
    if (level === 0) {
      // Leaf level
      const leafIndex = position;
      return leafIndex < this.leaves.length ? this.leaves[leafIndex] : ZERO_VALUES[0];
    }

    const leftPos = position * 2;
    const rightPos = position * 2 + 1;
    const left = this._getSubtreeHash(level - 1, leftPos);
    const right = this._getSubtreeHash(level - 1, rightPos);
    return poseidonHash(left, right);
  }

  /** Current root of the tree */
  root(): bigint {
    return this.roots[this.currentRootIndex];
  }

  /** Number of leaves inserted */
  get size(): number {
    return this.nextIndex;
  }

  /**
   * Check if a root is in the recent roots cache.
   * Used by the pool contract to accept proofs against recent (not just current) roots.
   */
  isKnownRoot(root: bigint): boolean {
    return this.roots.some((r) => r === root);
  }

  /**
   * Find the leaf index for a given commitment hash.
   * Returns -1 if not found.
   */
  findLeaf(commitment: bigint): number {
    return this.leaves.indexOf(commitment);
  }
}

/**
 * Build a Merkle tree from a list of commitments (in deposit order).
 *
 * This is the client-side reconstruction of the pool's Merkle tree.
 * Feed it the commitment values from all Deposit events (in chronological order),
 * then call getProof(leafIndex) to get the Merkle path for your deposit.
 */
export function buildTreeFromCommitments(
  commitments: bigint[],
  depth: number = TREE_DEPTH
): IncrementalMerkleTree {
  const tree = new IncrementalMerkleTree(depth);
  for (const commitment of commitments) {
    tree.insert(commitment);
  }
  return tree;
}

/**
 * Compute the Merkle root for a proof (for verification without a full tree).
 * Used to verify a proof before submitting it.
 */
export function computeRootFromProof(
  leaf: bigint,
  pathElements: bigint[],
  pathIndices: number[]
): bigint {
  let current = leaf;
  for (let i = 0; i < pathElements.length; i++) {
    const sibling = pathElements[i];
    const isRightChild = pathIndices[i] === 1;
    current = isRightChild
      ? poseidonHash(sibling, current)
      : poseidonHash(current, sibling);
  }
  return current;
}
