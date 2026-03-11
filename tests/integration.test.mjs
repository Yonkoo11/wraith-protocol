/**
 * Integration test: full withdrawal proof pipeline
 *
 * Tests the complete flow from (secret, nullifier, amount) to a verified Groth16 proof.
 * Does NOT require a deployed pool — exercises the SDK proof generation end to end.
 *
 * What this tests:
 *   1. CommitmentHasher matches pool.circom exactly (key invariant)
 *   2. Merkle proof construction produces correct root
 *   3. Groth16 proof generates and verifies locally
 *   4. Serialized proofFelts have correct length (for pool.withdraw() calldata)
 *
 * What this does NOT test:
 *   - Actual pool contract deposit/withdrawal (requires deployed pool)
 *   - Lit Protocol encryption/decryption (requires Lit network)
 *   - Starknet transaction submission (requires devnet/testnet)
 *
 * Run: node tests/integration.test.mjs
 *
 * Requires:
 *   CIRCUIT_WASM_PATH and CIRCUIT_ZKEY_PATH env vars (or defaults used)
 *   node_modules installed (npm install)
 */

import { poseidon2 } from '../node_modules/poseidon-lite/poseidon2.js';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { strict as assert_strict } from 'assert';

const { IncrementalMerkleTree, ZERO_VALUES } = await import('../dist/index.js');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.join(__dirname, '..');

const snarkjs = createRequire(import.meta.url)(
  path.join(projectRoot, 'node_modules/snarkjs/build/main.cjs')
);

const WASM_PATH = process.env.CIRCUIT_WASM_PATH ||
  path.join(projectRoot, 'circuits/target/pool_js/pool.wasm');
const ZKEY_PATH = process.env.CIRCUIT_ZKEY_PATH ||
  path.join(projectRoot, 'circuits/target/pool_final.zkey');
const VK_PATH = path.join(projectRoot, 'circuits/target/verification_key.json');

// ─── Helpers matching pool.circom exactly ─────────────────────────────────────

function hash(a, b) {
  return poseidon2([a, b]);
}

function hashOne(x) {
  // HashOne(x) = Hash([x, x]) from hash.circom
  return poseidon2([x, x]);
}

function computeCommitment(secret, nullifier, amount) {
  // CommitmentHasher from association.circom:
  //   temp       = Hash([secret, nullifier])
  //   commitment = Hash([temp, amount])
  const temp = hash(secret, nullifier);
  return hash(temp, amount);
}

function buildMerkleProof(leaf, depth = 24) {
  // Use ZERO_VALUES[level] at each level — matches pool contract exactly.
  // ZERO_VALUES[0] = H(0,0), ZERO_VALUES[1] = H(ZERO_VALUES[0], ZERO_VALUES[0]), etc.
  const pathElements = [];
  const pathIndices = [];
  let current = leaf;
  for (let i = 0; i < depth; i++) {
    const sibling = ZERO_VALUES[i];
    pathElements.push(sibling.toString());
    pathIndices.push(0);
    current = hash(current, sibling);
  }
  return { pathElements, pathIndices, root: current };
}

// ─── Test runner ──────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    console.log(`  ✓ ${msg}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${msg}`);
    failed++;
  }
}

async function runTests() {
  console.log('Wraith Protocol — Integration Tests\n');

  // ─── Test 1: Circuit artifacts exist ───────────────────────────────────────
  console.log('Test 1: Circuit artifacts');
  assert(fs.existsSync(WASM_PATH), `pool.wasm exists at ${WASM_PATH}`);
  assert(fs.existsSync(ZKEY_PATH), `pool_final.zkey exists at ${ZKEY_PATH}`);
  assert(fs.existsSync(VK_PATH), 'verification_key.json exists');

  const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
  assert(vk.protocol === 'groth16', 'protocol is groth16');
  assert(vk.curve === 'bn128', 'curve is bn128');
  assert(vk.nPublic === 7, `nPublic is 7 (got ${vk.nPublic})`);

  // ─── Test 2: Hash correctness ─────────────────────────────────────────────
  console.log('\nTest 2: Poseidon hash correctness');

  // ZERO_LEAF from Ekubo's merkle.cairo: poseidon2([0, 0])
  const EXPECTED_ZERO = 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864n;
  assert(hash(0n, 0n) === EXPECTED_ZERO, 'poseidon2([0,0]) matches Ekubo zero leaf constant');

  const secret = 11111111111111111111111111111111n;
  const nullifier = 22222222222222222222222222222222n;
  const amount = 1_000_000n; // 1 USDC

  const commitment = computeCommitment(secret, nullifier, amount);
  assert(commitment > 0n, 'commitment is non-zero');

  const nullifierHash = hashOne(nullifier);
  const nullifierHashDirect = hash(nullifier, nullifier);
  assert(nullifierHash === nullifierHashDirect, 'hashOne(n) === hash(n, n)');

  // ─── Test 3: Merkle proof correctness ─────────────────────────────────────
  console.log('\nTest 3: Merkle proof construction');

  const { pathElements, pathIndices, root } = buildMerkleProof(commitment);
  assert(pathElements.length === 24, 'pathElements length is 24');
  assert(pathIndices.every(i => i === 0), 'all pathIndices are 0 (leaf at index 0)');
  assert(root > 0n, 'root is non-zero');

  // Verify: rebuilding root from leaf + path should give same root
  const ZERO = hash(0n, 0n);
  let rebuildRoot = commitment;
  for (const sibling of pathElements) {
    rebuildRoot = hash(rebuildRoot, BigInt(sibling));
  }
  assert(rebuildRoot === root, 'root recomputed from leaf + path matches');

  // ─── Test 3b: Cross-check with IncrementalMerkleTree ─────────────────────
  console.log('\nTest 3b: Cross-check proof with IncrementalMerkleTree');

  const tree = new IncrementalMerkleTree();
  tree.insert(commitment);
  const treeProof = tree.getProof(0);

  assert(treeProof.root === root, 'IncrementalMerkleTree root matches manual buildMerkleProof root');
  assert(
    treeProof.pathElements.every((e, i) => e.toString() === pathElements[i]),
    'IncrementalMerkleTree pathElements match buildMerkleProof'
  );
  assert(
    treeProof.pathIndices.every((idx, i) => idx === pathIndices[i]),
    'IncrementalMerkleTree pathIndices match buildMerkleProof'
  );

  // ─── Test 4: Groth16 proof generation and verification ────────────────────
  console.log('\nTest 4: Groth16 proof generation (~20s)');
  const t0 = Date.now();

  const input = {
    root: root.toString(),
    nullifierHash: nullifierHash.toString(),
    recipient: '1234',
    fee: '0',
    refundCommitmentHash: '0',
    amount: amount.toString(),
    associatedSetRoot: root.toString(),
    secret: secret.toString(),
    nullifier: nullifier.toString(),
    refund: '0',
    commitmentAmount: amount.toString(),
    pathElements,
    pathIndices,
    associatedSetPathElements: pathElements,
    associatedSetPathIndices: pathIndices,
  };

  let proof, publicSignals;
  try {
    ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH));
  } catch (err) {
    console.error(`  ✗ FAIL: proof generation threw: ${err.message.split('\n')[0]}`);
    failed++;
    return;
  }

  const elapsed = Date.now() - t0;
  assert(proof.pi_a.length >= 2, 'proof has pi_a');
  assert(proof.pi_b.length >= 2, 'proof has pi_b');
  assert(proof.pi_c.length >= 2, 'proof has pi_c');
  assert(publicSignals.length === 7, `publicSignals has 7 values (got ${publicSignals.length})`);
  console.log(`  ✓ proof generated in ${elapsed}ms`);

  // Public signal order: [root, nullifierHash, recipient, fee, refundCommitmentHash, amount, associatedSetRoot]
  assert(BigInt(publicSignals[0]) === root, 'publicSignals[0] = root');
  assert(BigInt(publicSignals[1]) === nullifierHash, 'publicSignals[1] = nullifierHash');
  assert(BigInt(publicSignals[5]) === amount, 'publicSignals[5] = amount');

  // ─── Test 5: Local proof verification ─────────────────────────────────────
  console.log('\nTest 5: Local proof verification');
  const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
  assert(valid === true, 'proof verifies locally');

  // ─── Test 6: Serialized proof length ──────────────────────────────────────
  console.log('\nTest 6: Proof serialization (felt252 format)');

  function toBigInt(hex) {
    return BigInt(hex.startsWith('0x') ? hex : '0x' + hex);
  }
  function u256ToFelts(value) {
    const low = value & ((1n << 128n) - 1n);
    const high = value >> 128n;
    return [low, high];
  }

  const felts = [];
  for (const coord of [proof.pi_a[0], proof.pi_a[1]]) {
    felts.push(...u256ToFelts(toBigInt(coord)));
  }
  for (const pair of [proof.pi_b[0], proof.pi_b[1]]) {
    for (const coord of pair) {
      felts.push(...u256ToFelts(toBigInt(coord)));
    }
  }
  for (const coord of [proof.pi_c[0], proof.pi_c[1]]) {
    felts.push(...u256ToFelts(toBigInt(coord)));
  }
  for (const sig of publicSignals) {
    felts.push(...u256ToFelts(BigInt(sig)));
  }

  // Expected: 2 (pi_a) + 4 (pi_b) + 2 (pi_c) + 7 (publicSignals) = 15 field elements
  //           each as u256 (low, high) = 30 felt252 values
  assert(felts.length === 30, `proofFelts length is 30 (got ${felts.length})`);
  assert(felts.every(f => f >= 0n), 'all felts are non-negative');

  // ─── Summary ──────────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log('ALL TESTS PASSED — Proof pipeline is end-to-end correct.');
    console.log('');
    console.log('What was verified:');
    console.log('  - CommitmentHasher matches pool.circom');
    console.log('  - HashOne matches hash.circom');
    console.log('  - Merkle proof structure correct (depth=24)');
    console.log('  - Groth16 proof generates and verifies locally');
    console.log('  - Proof serialization: 30 felt252 values (correct for pool.withdraw())');
    console.log('');
    console.log('What was NOT tested:');
    console.log('  - Pool contract deposit/withdrawal (requires deployed pool)');
    console.log('  - Lit Protocol encryption (requires Lit network)');
    console.log('  - Starknet tx submission (requires devnet/testnet)');
  } else {
    console.error(`${failed} test(s) failed.`);
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('FATAL:', err);
  process.exit(1);
});
