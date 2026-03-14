/**
 * On-chain end-to-end test: deposit + withdrawal against local devnet
 *
 * Self-contained: resets devnet + redeploys contracts on every run.
 *
 * Requires:
 *   - starknet-devnet binary at ~/bin/starknet-devnet
 *   - rpc-proxy.mjs running on :5051 (rewrites "pending" → "latest")
 *   - starkli on PATH
 *   - garaga on PATH
 *   - Compiled Sierra + CASM in /tmp/cipher-pol-deploy/target/dev/
 *
 * Run: node tests/onchain.test.mjs
 */

import { poseidon2 } from '../node_modules/poseidon-lite/poseidon2.js';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.join(__dirname, '..');

const snarkjs = createRequire(import.meta.url)(
  path.join(projectRoot, 'node_modules/snarkjs/build/main.cjs')
);

const { RpcProvider, Account, constants, CallData, stark } = await import(
  path.join(projectRoot, 'node_modules/starknet/dist/index.js')
);

// ─── Config ───────────────────────────────────────────────────────────────────

const RPC_URL   = 'http://127.0.0.1:5051';
const ETH_ADDR  = '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';
const ACC_ADDR  = '0x34ba56f92265f0868c57d3fe72ecab144fc96f97954bbbc4252cef8e8a979ba';
const ACC_PK    = '0xb137668388dbe9acdfa3bc734cc2c469';

const VERIFIER_SIERRA     = '/tmp/cipher-pol-deploy/target/dev/pool_Groth16VerifierBN254.contract_class.json';
const POOL_SIERRA         = '/tmp/cipher-pol-deploy/target/dev/pool_Pool.contract_class.json';
const ECIP_SIERRA         = '/tmp/cipher-pol-deploy/target/dev/pool_UniversalECIP.contract_class.json';
const STARKLI_ACCT        = '/tmp/devnet-account.json';
// CASM hashes that devnet 0.7.2's bundled compiler produces for these Sierra files.
// Starkli 0.4.2 bundles a different compiler (2.9.4) than devnet, so we bypass
// starkli's recompilation with --casm-hash and let devnet verify against its own.
// Verifier rebuilt with new verification_key.json (refundCommitmentHash constraint added 2026-03-12).
// ECIP + Pool unchanged; their CASM hashes still match devnet 0.7.2's bundled compiler.
const VERIFIER_CASM_HASH  = '0x5a4520f3c48d98c3090e68df7aee9e60e2c28543fe8b1ce8d25152caecb5906';
const POOL_CASM_HASH      = '0x668d8e903eaf4a0199c302fb03f64b2474b2fc323c222d57a48a45234b40e76';
const ECIP_CASM_HASH      = '0x763b4a30ba03df108a073f0380af6a1397eaac70e8bd78caf6a4127e9a5f245';

const WASM_PATH = path.join(projectRoot, 'circuits/target/pool_js/pool.wasm');
const ZKEY_PATH = path.join(projectRoot, 'circuits/target/pool_final.zkey');
const VK_PATH   = path.join(projectRoot, 'circuits/target/verification_key.json');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hash(a, b) { return poseidon2([a, b]); }
function hashOne(x) { return poseidon2([x, x]); }

// Precomputed zero subtree hashes from pool/src/merkle.cairo
// precomputed[0] = 0x0 (zero leaf); precomputed[i+1] = hash(precomputed[i], precomputed[i])
const POOL_PRECOMPUTED = [
  0x0n,
  0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864n,
  0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1n,
  0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238n,
  0x7f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952an,
  0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55n,
  0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78n,
  0x78295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349dn,
  0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61n,
  0xe884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747n,
  0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2n,
  0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636n,
  0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85an,
  0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0n,
  0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80cn,
  0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92n,
  0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323n,
  0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992n,
  0xf57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10fn,
  0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72ccan,
  0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3en,
  0x19df90ec844ebc4ffeebd866f33859b0c051d8c958ee3aa88f8f8df3db91a5b1n,
  0x18cca2a66b5c0787981e69aefd84852d74af0e93ef4912b4648c05f722efe52bn,
  0x2388909415230d1b4d1304d2d54f473a628338f2efad83fadf05644549d2538dn,
];

function buildMerkleProof(leaf, depth = 24) {
  // Proof for leaf at index 0 in an otherwise-empty tree.
  // Siblings are the pool's precomputed zero subtree hashes.
  const pathElements = [];
  const pathIndices = [];
  let current = leaf;
  for (let i = 0; i < depth; i++) {
    pathElements.push(POOL_PRECOMPUTED[i].toString());
    pathIndices.push(0);
    current = hash(current, POOL_PRECOMPUTED[i]);
  }
  return { pathElements, pathIndices, root: current };
}

function toBigInt(hex) { return BigInt(hex.startsWith('0x') ? hex : '0x' + hex); }

function u256Calldata(value) {
  const low  = value & ((1n << 128n) - 1n);
  const high = value >> 128n;
  return [low.toString(), high.toString()];
}

function u256ToFelts(value) {
  const low  = value & ((1n << 128n) - 1n);
  const high = value >> 128n;
  return [low, high];
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── Devnet + contract setup ──────────────────────────────────────────────────

async function setupFreshDevnet(provider, account) {
  const { execSync, spawn } = await import('child_process');

  const devnetBin = `${process.env.HOME}/bin/starknet-devnet`;

  // 1. Kill any existing devnet
  console.log('  Stopping existing devnet...');
  try { execSync('pkill -f "starknet-devnet"', { stdio: 'ignore' }); } catch {}
  await sleep(1500);

  // 2. Start fresh devnet (seed 42 = deterministic predeployed accounts)
  console.log('  Starting fresh devnet (seed 42)...');
  const devnet = spawn(devnetBin, ['--host', '127.0.0.1', '--port', '5050', '--seed', '42'], {
    detached: true,
    stdio: 'ignore',
  });
  devnet.unref();

  // 3. Wait until devnet is ready
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch('http://127.0.0.1:5050/is_alive');
      if (res.ok) { console.log(`  Devnet ready`); break; }
    } catch {}
    await sleep(500);
    if (i === 59) throw new Error('Devnet did not start in 30s');
  }

  // 4. Declare both classes via starkli
  const starkli = `${process.env.HOME}/.starkli/bin/starkli`;
  function declare(sierra, casmHash) {
    // Use --casm-hash to bypass starkli's bundled compiler (2.9.4), which produces
    // a different CASM hash than devnet 0.7.2's bundled compiler expects.
    const out = execSync(
      `${starkli} declare \
        --rpc http://127.0.0.1:5051 \
        --account ${STARKLI_ACCT} \
        --private-key ${ACC_PK} \
        --casm-hash ${casmHash} \
        ${sierra} \
        --watch 2>&1`,
      { encoding: 'utf8', timeout: 120000 }
    );
    const m = out.match(/[Cc]lass hash.*?:\n?(0x[0-9a-fA-F]+)/);
    if (!m) {
      const m2 = out.match(/0x[0-9a-fA-F]{40,}/);
      if (!m2) throw new Error(`Could not parse class hash from starkli output:\n${out}`);
      return m2[0];
    }
    return m[1];
  }

  console.log('  Declaring UniversalECIP (library for pairing hints)...');
  const ECIP_CLASS = declare(ECIP_SIERRA, ECIP_CASM_HASH);
  console.log(`  UniversalECIP class: ${ECIP_CLASS}`);

  console.log('  Declaring verifier (may take ~20s)...');
  const VERIFIER_CLASS = declare(VERIFIER_SIERRA, VERIFIER_CASM_HASH);
  console.log(`  Verifier class: ${VERIFIER_CLASS}`);

  console.log('  Declaring pool (may take ~20s)...');
  const POOL_CLASS = declare(POOL_SIERRA, POOL_CASM_HASH);
  console.log(`  Pool class: ${POOL_CLASS}`);

  // 5. Deploy verifier
  console.log('  Deploying verifier...');
  const verifierDeploy = await account.deployContract({
    classHash: VERIFIER_CLASS,
    constructorCalldata: [],
    salt: stark.randomAddress(),
    unique: false,
  });
  await provider.waitForTransaction(verifierDeploy.transaction_hash);
  const verifierAddr = verifierDeploy.contract_address;
  console.log(`  Verifier: ${verifierAddr}`);

  // 6. Deploy pool
  console.log('  Deploying pool...');
  const poolConstructor = CallData.compile({
    owner:    ACC_ADDR,
    token:    ETH_ADDR,
    verifier: verifierAddr,
    min_fee:  { low: 0n, high: 0n },
  });
  const poolDeploy = await account.deployContract({
    classHash: POOL_CLASS,
    constructorCalldata: poolConstructor,
    salt: stark.randomAddress(),
    unique: false,
  });
  await provider.waitForTransaction(poolDeploy.transaction_hash);
  const poolAddr = poolDeploy.contract_address;
  console.log(`  Pool: ${poolAddr}`);

  return { poolAddr, verifierAddr };
}

// ─── Test runner ──────────────────────────────────────────────────────────────

let passed = 0, failed = 0;
function assert(cond, msg) {
  if (cond) { console.log(`  ✓ ${msg}`); passed++; }
  else       { console.error(`  ✗ FAIL: ${msg}`); failed++; }
}

async function run() {
  console.log('Cipher Pol — On-Chain End-to-End Test\n');

  // ─── Setup ─────────────────────────────────────────────────────────────────
  const provider = new RpcProvider({ nodeUrl: RPC_URL });
  const account  = new Account(provider, ACC_ADDR, ACC_PK, undefined, constants.TRANSACTION_VERSION.V3);

  console.log('Setup: Reset devnet + deploy fresh contracts');
  const { poolAddr } = await setupFreshDevnet(provider, account);
  console.log(`  Using pool: ${poolAddr}\n`);

  // ─── Step 1: Sanity check pool is alive ────────────────────────────────────
  console.log('Step 1: Verify pool is deployed');
  const rootResult = await provider.callContract({
    contractAddress: poolAddr,
    entrypoint: 'current_root',
    calldata: [],
  });
  const initialRoot = (BigInt(rootResult[0]) | (BigInt(rootResult[1]) << 128n));
  console.log(`  Pool initial root: 0x${initialRoot.toString(16)}`);
  assert(initialRoot > 0n, 'pool returns non-zero initial root');

  // ─── Step 2: Prepare deposit values ────────────────────────────────────────
  console.log('\nStep 2: Prepare deposit');
  const secret    = 0xdeadbeefdeadbeefdeadbeef01234567n;
  const nullifier = 0xfeedface0123456789abcdef12345678n;
  const amount    = 1_000_000_000_000_000n; // 0.001 ETH in wei

  const secretAndNullifierHash = hash(secret, nullifier);
  const commitmentHash         = hash(secretAndNullifierHash, amount);
  const nullifierHash          = hashOne(nullifier);

  console.log(`  secretAndNullifierHash: 0x${secretAndNullifierHash.toString(16)}`);
  console.log(`  commitmentHash:         0x${commitmentHash.toString(16)}`);
  console.log(`  nullifierHash:          0x${nullifierHash.toString(16)}`);

  // ─── Step 3: Approve ETH spend ─────────────────────────────────────────────
  console.log('\nStep 3: Approve ETH spend');
  const approveTx = await account.execute({
    contractAddress: ETH_ADDR,
    entrypoint: 'approve',
    calldata: [poolAddr, ...u256Calldata(amount)],
  });
  console.log(`  approve tx: ${approveTx.transaction_hash}`);
  await provider.waitForTransaction(approveTx.transaction_hash);
  assert(true, 'approve confirmed');

  // ─── Step 4: Deposit ───────────────────────────────────────────────────────
  console.log('\nStep 4: Deposit');
  const depositTx = await account.execute({
    contractAddress: poolAddr,
    entrypoint: 'deposit',
    calldata: [...u256Calldata(secretAndNullifierHash), ...u256Calldata(amount)],
  });
  console.log(`  deposit tx: ${depositTx.transaction_hash}`);
  await provider.waitForTransaction(depositTx.transaction_hash);
  assert(true, 'deposit confirmed');

  // ─── Step 5: Check new root ────────────────────────────────────────────────
  console.log('\nStep 5: Verify root changed after deposit');
  const rootAfter = await provider.callContract({
    contractAddress: poolAddr,
    entrypoint: 'current_root',
    calldata: [],
  });
  const newRoot = (BigInt(rootAfter[0]) | (BigInt(rootAfter[1]) << 128n));
  console.log(`  Root after deposit: 0x${newRoot.toString(16)}`);
  assert(newRoot !== initialRoot, 'root changed after deposit');

  // ─── Step 6: Build Merkle proof ────────────────────────────────────────────
  // Fresh pool: our deposit is at index 0. Siblings = precomputed zero hashes.
  console.log('\nStep 6: Build Merkle proof (index 0)');
  const { pathElements, pathIndices, root: computedRoot } = buildMerkleProof(commitmentHash);

  console.log(`  Computed root: 0x${computedRoot.toString(16)}`);
  console.log(`  Pool root:     0x${newRoot.toString(16)}`);
  const rootMatch = computedRoot === newRoot;
  assert(rootMatch, 'computed Merkle root matches pool root');

  if (!rootMatch) {
    console.error('  Root mismatch — cannot generate valid proof. Stopping.');
    process.exit(1);
  }

  // ─── Step 7: Generate Groth16 proof ────────────────────────────────────────
  console.log('\nStep 7: Generate Groth16 proof (~20s)');
  const recipient            = BigInt(ACC_ADDR);
  const fee                  = 0n;
  const refundCommitmentHash = 0n;
  const associatedSetRoot    = computedRoot;

  const input = {
    root:               computedRoot.toString(),
    nullifierHash:      nullifierHash.toString(),
    recipient:          recipient.toString(),
    fee:                fee.toString(),
    refundCommitmentHash: refundCommitmentHash.toString(),
    amount:             amount.toString(),
    associatedSetRoot:  associatedSetRoot.toString(),
    // Private
    secret:             secret.toString(),
    nullifier:          nullifier.toString(),
    refund:             '0',
    commitmentAmount:   amount.toString(),
    pathElements,
    pathIndices,
    associatedSetPathElements: pathElements,
    associatedSetPathIndices:  pathIndices,
  };

  const t0 = Date.now();
  let proof, publicSignals;
  try {
    ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH));
  } catch (err) {
    console.error(`  ✗ FAIL: proof generation threw: ${err.message}`);
    process.exit(1);
  }
  console.log(`  Proof generated in ${Date.now() - t0}ms`);

  const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
  const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
  assert(valid, 'proof verifies locally');

  // ─── Step 8: Generate garaga calldata (full_proof_with_hints) ────────────
  // Must use garaga 0.15.3 (matching the compiled verifier contract).
  // garaga 1.0.1 CLI dropped include_digits_decomposition=True in MSM calldata,
  // making it incompatible with the 0.15.3-compiled verifier's expected format.
  // We call garaga 0.15.3 hydra directly via Python 3.10 (Homebrew).
  console.log('\nStep 8: Generate garaga 0.15.3 calldata (full_proof_with_hints)');

  const proofPath = '/tmp/onchain-proof.json';
  const pubPath   = '/tmp/onchain-public.json';
  const cdOutPath = '/tmp/onchain-garaga015-calldata.json';
  fs.writeFileSync(proofPath, JSON.stringify(proof));
  fs.writeFileSync(pubPath, JSON.stringify(publicSignals));

  const pyScript = `
import sys, json
sys.path.insert(0, '/tmp/garaga-v0.15.3/hydra')
from garaga.starknet.groth16_contract_generator.calldata import groth16_calldata_from_vk_and_proof
from garaga.starknet.groth16_contract_generator.parsing_utils import Groth16Proof, Groth16VerifyingKey
vk = Groth16VerifyingKey.from_json('${VK_PATH}')
proof = Groth16Proof.from_json(proof_path='${proofPath}', public_inputs_path='${pubPath}')
calldata = groth16_calldata_from_vk_and_proof(vk, proof)
# Serialize as strings to preserve full integer precision (felt252 values exceed JSON float range)
json.dump([str(x) for x in calldata], open('${cdOutPath}', 'w'))
print(len(calldata))
`;

  const { execFileSync } = await import('child_process');
  const lenStr = execFileSync('/opt/homebrew/bin/python3.10', ['-c', pyScript], {
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  }).trim();
  const numFelts = parseInt(lenStr, 10);
  assert(!isNaN(numFelts) && numFelts > 30, `garaga 0.15.3 generated ${numFelts} felts`);
  console.log(`  Calldata length: ${numFelts} felts (garaga 0.15.3 format, with digit decomp)`);

  const calldataRaw = JSON.parse(fs.readFileSync(cdOutPath, 'utf8'));
  // calldataRaw[0] is the span length; calldataRaw is [span_len, elem1, ..., elemN]
  const withdrawCalldata = calldataRaw.map(n => n.toString());

  // ─── Step 9: Withdraw ──────────────────────────────────────────────────────
  console.log('\nStep 9: Withdraw');
  console.log(`  calldata[0] (span len): ${withdrawCalldata[0]}`);
  console.log(`  calldata total felts:   ${withdrawCalldata.length}`);
  let withdrawTx;
  try {
    withdrawTx = await account.execute({
      contractAddress: poolAddr,
      entrypoint: 'withdraw',
      calldata: withdrawCalldata,
    });
  } catch (err) {
    // Extract the actual error from devnet (not the request params dump)
    const msg = err.message || '';
    const match = msg.match(/error['":\s]+(.+?)(?=\n|$)/i)
                || msg.match(/"message":\s*"([^"]+)"/i)
                || msg.match(/'([^']+)'/i);
    console.error(`  ✗ FAIL: withdraw threw`);
    console.error(`  Error code: ${err.code}`);
    console.error(`  Error data: ${JSON.stringify(err.data ?? null).substring(0, 400)}`);
    console.error(`  Short message: ${msg.substring(0, 600)}`);
    process.exit(1);
  }
  console.log(`  withdraw tx: ${withdrawTx.transaction_hash}`);
  await provider.waitForTransaction(withdrawTx.transaction_hash);
  assert(true, 'withdrawal confirmed');

  // ─── Summary ───────────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log('\nFULL ON-CHAIN END-TO-END FLOW VERIFIED:');
    console.log('  pool deployed + responded to current_root()');
    console.log('  ERC20 approve succeeded');
    console.log('  deposit() accepted, Merkle root updated');
    console.log('  Groth16 proof generated against on-chain root');
    console.log('  garaga calldata (full_proof_with_hints) generated');
    console.log('  withdraw() accepted proof and transferred tokens');
  } else {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  }
}

run().catch(err => {
  console.error('FATAL:', err);
  process.exit(1);
});
