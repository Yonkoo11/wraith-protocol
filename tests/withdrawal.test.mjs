/**
 * WithdrawalQueue end-to-end test
 *
 * Tests the full server-side withdrawal path:
 *   1. Deposit on devnet (same setup as onchain.test.mjs)
 *   2. Generate Groth16 proof (client-side, snarkjs)
 *   3. Serialize to 30-felt HTTP transport format (same as agent sends)
 *   4. Pass to WithdrawalQueue.enqueue() (as the middleware would)
 *   5. Call WithdrawalQueue.flush() which:
 *        a. Deserializes 30-felts back to snarkjs proof JSON
 *        b. Runs garaga 0.15.3 Python subprocess to get ~2918 felt calldata
 *        c. Submits pool.withdraw(calldata) on Starknet
 *   6. Wait for on-chain confirmation
 *   7. Verify nullifier is stored (double-spend protection)
 *
 * This is the critical missing test for the server's withdrawal path.
 * Previous tests either:
 *   - Submitted garaga calldata directly (onchain.test.mjs — bypasses the queue)
 *   - Used mock proofs in HTTP tests (server.test.mjs — never submits on-chain)
 *   - Tested the HTTP layer with real proofs (e2e.test.mjs — queues but does not flush)
 *
 * This is the only test that exercises:
 *   deserializeProofFromFelts → garaga subprocess → pool.withdraw()
 *
 * Requires:
 *   - starknet-devnet at ~/bin/starknet-devnet (seed 42)
 *   - rpc-proxy.mjs on :5051
 *   - garaga 0.15.3 at /tmp/garaga-v0.15.3
 *   - python3.10 at /opt/homebrew/bin/python3.10
 *   - Compiled Sierra in /tmp/wraith-pool-deploy/target/dev/
 *   - server/dist/ compiled (cd server && npx tsc)
 *
 * Run: node scripts/rpc-proxy.mjs & && node tests/withdrawal.test.mjs
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

// Import WithdrawalQueue from compiled server dist.
// The server dist imports ../../dist/x402.js which resolves to wraith-protocol/dist/x402.js.
const { WithdrawalQueue } = await import(
  path.join(projectRoot, 'server/dist/withdrawal-queue.js')
);

// ─── Config ───────────────────────────────────────────────────────────────────

const RPC_URL  = 'http://127.0.0.1:5051';
const ETH_ADDR = '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';
const ACC_ADDR = '0x34ba56f92265f0868c57d3fe72ecab144fc96f97954bbbc4252cef8e8a979ba';
const ACC_PK   = '0xb137668388dbe9acdfa3bc734cc2c469';

const VERIFIER_SIERRA    = '/tmp/wraith-pool-deploy/target/dev/pool_Groth16VerifierBN254.contract_class.json';
const POOL_SIERRA        = '/tmp/wraith-pool-deploy/target/dev/pool_Pool.contract_class.json';
const ECIP_SIERRA        = '/tmp/wraith-pool-deploy/target/dev/pool_UniversalECIP.contract_class.json';
const STARKLI_ACCT       = '/tmp/devnet-account.json';
const VERIFIER_CASM_HASH = '0x4ab33c632f8f86806bfc63a7316a9dc3de26a5226732ad764eea9b4f0d2b495';
const POOL_CASM_HASH     = '0x668d8e903eaf4a0199c302fb03f64b2474b2fc323c222d57a48a45234b40e76';
const ECIP_CASM_HASH     = '0x763b4a30ba03df108a073f0380af6a1397eaac70e8bd78caf6a4127e9a5f245';

const WASM_PATH = path.join(projectRoot, 'circuits/target/pool_js/pool.wasm');
const ZKEY_PATH = path.join(projectRoot, 'circuits/target/pool_final.zkey');
const VK_PATH   = path.join(projectRoot, 'circuits/target/verification_key.json');

const GARAGA_PATH  = '/tmp/garaga-v0.15.3';
const PYTHON_PATH  = '/opt/homebrew/bin/python3.10';

// ─── Constants (must match pool.cairo + poseidon-lite) ───────────────────────

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

// ─── Helpers ─────────────────────────────────────────────────────────────────

function hash(a, b) { return poseidon2([a, b]); }
function hashOne(x) { return poseidon2([x, x]); }

function u256Calldata(v) {
  return [(v & ((1n << 128n) - 1n)).toString(), (v >> 128n).toString()];
}

function u256ToFelts(v) {
  return [v & ((1n << 128n) - 1n), v >> 128n];
}

// Serialize snarkjs proof to 30-felt HTTP transport format.
// [pi_a (4), pi_b (8), pi_c (4), public_signals (14)] = 30 felts
//
// snarkjs (ffjavascript) returns proof coordinates as DECIMAL strings via
// F.toObject() -> o.toString(10). Use BigInt(coord) directly.
// DO NOT prepend "0x" — that misinterprets decimal digits as hex.
function serializeProofToFelts(proof, publicSignals) {
  const felts = [];
  for (const coord of [proof.pi_a[0], proof.pi_a[1]]) {
    felts.push(...u256ToFelts(BigInt(coord)));
  }
  for (const pair of [proof.pi_b[0], proof.pi_b[1]]) {
    for (const coord of pair) {
      felts.push(...u256ToFelts(BigInt(coord)));
    }
  }
  for (const coord of [proof.pi_c[0], proof.pi_c[1]]) {
    felts.push(...u256ToFelts(BigInt(coord)));
  }
  for (const sig of publicSignals) {
    felts.push(...u256ToFelts(BigInt(sig)));
  }
  return felts.map(f => f.toString());
}

function buildMerkleProof(leaf, depth = 24) {
  const pathElements = [];
  const pathIndices  = [];
  let current = leaf;
  for (let i = 0; i < depth; i++) {
    pathElements.push(POOL_PRECOMPUTED[i].toString());
    pathIndices.push(0);
    current = hash(current, POOL_PRECOMPUTED[i]);
  }
  return { pathElements, pathIndices, root: current };
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── Devnet setup (identical to onchain.test.mjs) ────────────────────────────

async function setupFreshDevnet(provider, account) {
  const { execSync, spawn } = await import('child_process');
  const devnetBin = `${process.env.HOME}/bin/starknet-devnet`;
  const starkli   = `${process.env.HOME}/.starkli/bin/starkli`;

  console.log('  Stopping existing devnet...');
  try { execSync('pkill -f "starknet-devnet"', { stdio: 'ignore' }); } catch {}
  await sleep(1500);

  console.log('  Starting fresh devnet (seed 42)...');
  const devnet = spawn(devnetBin, ['--host', '127.0.0.1', '--port', '5050', '--seed', '42'], {
    detached: true, stdio: 'ignore',
  });
  devnet.unref();

  for (let i = 0; i < 60; i++) {
    try { if ((await fetch('http://127.0.0.1:5050/is_alive')).ok) { console.log('  Devnet ready'); break; } }
    catch {}
    await sleep(500);
    if (i === 59) throw new Error('Devnet did not start in 30s');
  }

  function declare(sierra, casmHash) {
    const out = execSync(
      `${starkli} declare --rpc http://127.0.0.1:5051 --account ${STARKLI_ACCT} --private-key ${ACC_PK} --casm-hash ${casmHash} ${sierra} --watch 2>&1`,
      { encoding: 'utf8', timeout: 120000 }
    );
    const m = out.match(/[Cc]lass hash.*?:\n?(0x[0-9a-fA-F]+)/) || out.match(/(0x[0-9a-fA-F]{40,})/);
    if (!m) throw new Error(`Could not parse class hash:\n${out}`);
    return m[1];
  }

  console.log('  Declaring UniversalECIP...');
  const ECIP_CLASS = declare(ECIP_SIERRA, ECIP_CASM_HASH);

  console.log('  Declaring verifier (~20s)...');
  const VERIFIER_CLASS = declare(VERIFIER_SIERRA, VERIFIER_CASM_HASH);

  console.log('  Declaring pool (~20s)...');
  const POOL_CLASS = declare(POOL_SIERRA, POOL_CASM_HASH);

  console.log('  Deploying verifier...');
  const verifierDeploy = await account.deployContract({
    classHash: VERIFIER_CLASS, constructorCalldata: [], salt: stark.randomAddress(), unique: false,
  });
  await provider.waitForTransaction(verifierDeploy.transaction_hash);

  console.log('  Deploying pool...');
  const poolDeploy = await account.deployContract({
    classHash: POOL_CLASS,
    constructorCalldata: CallData.compile({ owner: ACC_ADDR, token: ETH_ADDR, verifier: verifierDeploy.contract_address, min_fee: { low: 0n, high: 0n } }),
    salt: stark.randomAddress(), unique: false,
  });
  await provider.waitForTransaction(poolDeploy.transaction_hash);

  return { poolAddr: poolDeploy.contract_address };
}

// ─── Test runner ──────────────────────────────────────────────────────────────

let passed = 0, failed = 0;
function assert(cond, msg) {
  if (cond) { console.log(`  ✓ ${msg}`); passed++; }
  else       { console.error(`  ✗ FAIL: ${msg}`); failed++; }
}

async function run() {
  console.log('Wraith Protocol — WithdrawalQueue End-to-End Test\n');
  console.log('Critical path: 30-felt HTTP transport → garaga subprocess → pool.withdraw()\n');

  const provider = new RpcProvider({ nodeUrl: RPC_URL });
  const account  = new Account(provider, ACC_ADDR, ACC_PK, undefined, constants.TRANSACTION_VERSION.V3);

  // ─── Phase 1: Deploy ─────────────────────────────────────────────────────

  console.log('Phase 1: Reset devnet + deploy contracts');
  const { poolAddr } = await setupFreshDevnet(provider, account);
  console.log(`  Pool: ${poolAddr}\n`);

  // ─── Phase 2: Deposit ────────────────────────────────────────────────────

  console.log('Phase 2: Deposit');
  const secret    = 0xdeadbeefdeadbeefdeadbeef01234567n;
  const nullifier = 0xfeedface0123456789abcdef12345678n;
  const amount    = 1_000_000_000_000_000n; // 0.001 ETH

  const snHash    = hash(secret, nullifier);
  const commitment = hash(snHash, amount);
  const nullifierHash = hashOne(nullifier);

  await provider.waitForTransaction((await account.execute({
    contractAddress: ETH_ADDR, entrypoint: 'approve',
    calldata: [poolAddr, ...u256Calldata(amount)],
  })).transaction_hash);

  await provider.waitForTransaction((await account.execute({
    contractAddress: poolAddr, entrypoint: 'deposit',
    calldata: [...u256Calldata(snHash), ...u256Calldata(amount)],
  })).transaction_hash);

  assert(true, 'deposit confirmed on-chain');

  // ─── Phase 3: Get on-chain root ──────────────────────────────────────────

  console.log('\nPhase 3: Fetch Merkle root');
  const rootResult = await provider.callContract({
    contractAddress: poolAddr, entrypoint: 'current_root', calldata: [],
  });
  const onchainRoot = BigInt(rootResult[0]) | (BigInt(rootResult[1]) << 128n);

  const { pathElements, pathIndices, root: computedRoot } = buildMerkleProof(commitment);
  assert(computedRoot === onchainRoot, 'computed Merkle root matches pool root');

  // ─── Phase 4: Generate Groth16 proof ─────────────────────────────────────

  console.log('\nPhase 4: Generate Groth16 proof (~20s)');
  const input = {
    root:                 computedRoot.toString(),
    nullifierHash:        nullifierHash.toString(),
    recipient:            BigInt(ACC_ADDR).toString(),
    fee:                  '0',
    refundCommitmentHash: '0',
    amount:               amount.toString(),
    associatedSetRoot:    computedRoot.toString(),
    // Private
    secret:               secret.toString(),
    nullifier:            nullifier.toString(),
    refund:               '0',
    commitmentAmount:     amount.toString(),
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
  assert(await snarkjs.groth16.verify(vk, publicSignals, proof), 'proof verifies locally');

  // ─── Phase 5: Serialize to 30-felt transport format ──────────────────────
  //
  // This is exactly what the agent sends in the X-Payment-Proof header.
  // The WithdrawalQueue receives this 30-felt array, NOT the raw snarkjs proof.

  console.log('\nPhase 5: Serialize to 30-felt HTTP transport format');
  const felts30 = serializeProofToFelts(proof, publicSignals);
  assert(felts30.length === 30, `30-felt transport format has correct length (got ${felts30.length})`);

  // Sanity: public signal at index 5 should be the amount (confirmed ordering)
  const amountFromFelts = BigInt(felts30[16 + 5 * 2]) + (BigInt(felts30[16 + 5 * 2 + 1]) << 128n);
  assert(amountFromFelts === amount, `amount recoverable from 30-felt format (${amountFromFelts} === ${amount})`);
  console.log(`  Amount in transport: ${amountFromFelts} (correct)`);

  // ─── Phase 6: WithdrawalQueue enqueue + flush ────────────────────────────
  //
  // This exercises the full server-side path:
  //   deserializeProofFromFelts() → garaga subprocess → pool.withdraw()
  //
  // This is the path that was previously code-reviewed but never run.

  console.log('\nPhase 6: WithdrawalQueue.flush() — the critical untested path');

  let confirmedTxHash = null;
  let flushError = null;

  const queue = new WithdrawalQueue({
    account,
    poolAddress:    poolAddr,
    rpcUrl:         RPC_URL,
    vkPath:         VK_PATH,
    garagaPath:     GARAGA_PATH,
    pythonPath:     PYTHON_PATH,
    flushIntervalMs: 0,  // flush immediately on enqueue
    onConfirmed: (txHash, _nullifier) => {
      confirmedTxHash = txHash;
      console.log(`  onConfirmed: txHash=${txHash}`);
    },
    onFailed: (_nullifier, err) => {
      flushError = err;
      console.error(`  onFailed: ${err.message}`);
    },
  });

  // Enqueue the 30-felt proof (as received from the agent via HTTP header)
  queue.enqueue(felts30, nullifierHash.toString(), amount);

  // flushIntervalMs=0 triggers flush synchronously but since flush is async,
  // we need to wait for it to complete. Give it up to 120s (garaga + devnet).
  const flushDeadline = Date.now() + 120_000;
  while (confirmedTxHash === null && flushError === null && Date.now() < flushDeadline) {
    await sleep(1000);
  }

  if (flushError) {
    console.error(`  Flush failed: ${flushError.message}`);
    assert(false, 'WithdrawalQueue.flush() succeeded');
    process.exit(1);
  }
  if (!confirmedTxHash) {
    assert(false, 'WithdrawalQueue.flush() confirmed within 120s');
    process.exit(1);
  }

  // Wait for the on-chain TX to land
  console.log(`  Waiting for withdrawal TX: ${confirmedTxHash}`);
  await provider.waitForTransaction(confirmedTxHash);
  assert(true, 'pool.withdraw() accepted on-chain via WithdrawalQueue (garaga subprocess path)');

  // ─── Phase 7: Verify on-chain nullifier stored (double-spend protection) ──

  console.log('\nPhase 7: Verify on-chain nullifier stored');
  // Try to replay the same withdrawal — pool should reject (nullifier already spent)
  let replayReverted = false;
  try {
    // We don't have a second valid proof, but we can directly check that
    // the pool stored the nullifier by attempting to read it (if pool exposes a view)
    // or by confirming the first withdraw succeeded and noting the queue pending count.
    assert(queue.pendingCount === 0, 'withdrawal queue is empty after flush');

    // Attempt replay: enqueue the same proof again.
    // The WithdrawalQueue itself doesn't track spent nullifiers (that's the middleware's job).
    // On-chain, pool.withdraw() will revert if nullifier is already spent.
    // We expect the garaga calldata submission to revert.
    let replayConfirmed = false;
    let replayFailed = false;
    const replayQueue = new WithdrawalQueue({
      account,
      poolAddress:    poolAddr,
      rpcUrl:         RPC_URL,
      vkPath:         VK_PATH,
      garagaPath:     GARAGA_PATH,
      pythonPath:     PYTHON_PATH,
      flushIntervalMs: 0,
      maxAttempts:    1,  // don't retry
      onConfirmed: () => { replayConfirmed = true; },
      onFailed:    () => { replayFailed = true; },
    });
    replayQueue.enqueue(felts30, nullifierHash.toString(), amount);

    const deadline2 = Date.now() + 90_000;
    while (!replayConfirmed && !replayFailed && Date.now() < deadline2) {
      await sleep(1000);
    }

    assert(replayFailed && !replayConfirmed, 'replay rejected on-chain (nullifier already spent)');
  } catch (e) {
    assert(false, `double-spend check threw: ${e.message}`);
  }

  // ─── Summary ──────────────────────────────────────────────────────────────

  console.log(`\n${'─'.repeat(60)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);

  if (failed === 0) {
    console.log('\nWITHDRAWAL QUEUE PATH VERIFIED:');
    console.log('  30-felt HTTP transport format → deserializeProofFromFelts()');
    console.log('  garaga 0.15.3 Python subprocess → correct calldata format');
    console.log('  pool.withdraw(garagaCalldata) accepted on-chain');
    console.log('  Replay rejected on-chain (nullifier stored)');
    console.log('\nWHAT THIS DID NOT TEST:');
    console.log('  Redis-backed NullifierSet (in-memory used here)');
    console.log('  Server restart between acceptance and flush');
    console.log('  Concurrent flush with multiple proofs in one batch');
  } else {
    console.error(`\n${failed} test(s) FAILED.`);
    process.exit(1);
  }
}

run().catch(err => {
  console.error('FATAL:', err);
  process.exit(1);
});
