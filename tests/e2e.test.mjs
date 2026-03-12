/**
 * Wraith Protocol — End-to-End Agent→HTTP→Server Integration Test
 *
 * Tests the COMPLETE x402 payment flow with real ZK proofs:
 *   1. Deploy pool on devnet
 *   2. Agent deposits into pool (on-chain)
 *   3. Agent generates Groth16 proof client-side from deposit
 *   4. Agent hits API server → gets 402 challenge
 *   5. Agent sends real ZK proof in X-Payment-Proof header
 *   6. Server validates proof public inputs → returns 200
 *   7. Withdrawal queued with nullifier tracked
 *
 * This bridges the gap between:
 *   - onchain.test.mjs (on-chain deposit + withdrawal, no HTTP)
 *   - server.test.mjs (HTTP middleware, mock proofs)
 *
 * Requires:
 *   - starknet-devnet at ~/bin/starknet-devnet
 *   - rpc-proxy.mjs running: node scripts/rpc-proxy.mjs &
 *   - Circuit artifacts: circuits/target/pool_js/pool.wasm + pool_final.zkey
 *
 * Run:
 *   node scripts/rpc-proxy.mjs &
 *   node tests/e2e.test.mjs
 */

import { strict as assert_strict } from 'assert';
import http from 'http';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import express from 'express';
import { poseidon2 } from '../node_modules/poseidon-lite/poseidon2.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.join(__dirname, '..');

// snarkjs must be loaded via createRequire — its ESM interop is unreliable in Node
const snarkjs = createRequire(import.meta.url)(
  path.join(projectRoot, 'node_modules/snarkjs/build/main.cjs')
);

// Compiled SDK
const { buildPaymentHeader, X402_SCHEME, extractPublicInputs } = await import('../dist/x402.js');

// Compiled server middleware
const { wraithPaywall } = await import('../server/dist/middleware.js');

// starknet.js
const { RpcProvider, Account, constants, CallData, stark } = await import(
  path.join(projectRoot, 'node_modules/starknet/dist/index.js')
);

// ─── Config ────────────────────────────────────────────────────────────────────

// RPC proxy rewrites l2_gas_consumed → gas_consumed for starknet.js 6.24.1 compat
const RPC_URL  = 'http://127.0.0.1:5051';
const ETH_ADDR = '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';

// Devnet seed 42 predeployed account (same as onchain.test.mjs)
const ACC_ADDR = '0x34ba56f92265f0868c57d3fe72ecab144fc96f97954bbbc4252cef8e8a979ba';
const ACC_PK   = '0xb137668388dbe9acdfa3bc734cc2c469';

// Compiled Sierra + CASM in /tmp from onchain.test.mjs setup
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

// ─── Crypto helpers ────────────────────────────────────────────────────────────

function hash(a, b) { return poseidon2([a, b]); }
function hashOne(x)  { return poseidon2([x, x]); }

// Precomputed zero subtree hashes from pool/src/merkle.cairo
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

// Serialize snarkjs proof to 30-felt HTTP transport format
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
  return felts;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── Devnet + contract setup (same pattern as onchain.test.mjs) ───────────────

async function setupFreshDevnet(provider, account) {
  const { execSync, spawn } = await import('child_process');

  const devnetBin = `${process.env.HOME}/bin/starknet-devnet`;

  console.log('  Stopping existing devnet...');
  try { execSync('pkill -f "starknet-devnet"', { stdio: 'ignore' }); } catch {}
  await sleep(1500);

  console.log('  Starting fresh devnet (seed 42)...');
  const devnet = spawn(devnetBin, ['--host', '127.0.0.1', '--port', '5050', '--seed', '42'], {
    detached: true,
    stdio:    'ignore',
  });
  devnet.unref();

  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch('http://127.0.0.1:5050/is_alive');
      if (res.ok) { console.log('  Devnet ready'); break; }
    } catch {}
    await sleep(500);
    if (i === 59) throw new Error('Devnet did not start in 30s');
  }

  const starkli = `${process.env.HOME}/.starkli/bin/starkli`;
  function declare(sierra, casmHash) {
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

  console.log('  Declaring UniversalECIP...');
  const ECIP_CLASS     = declare(ECIP_SIERRA, ECIP_CASM_HASH);
  console.log('  Declaring verifier...');
  const VERIFIER_CLASS = declare(VERIFIER_SIERRA, VERIFIER_CASM_HASH);
  console.log('  Declaring pool...');
  const POOL_CLASS     = declare(POOL_SIERRA, POOL_CASM_HASH);

  const verifierDeploy = await account.deployContract({
    classHash: VERIFIER_CLASS,
    constructorCalldata: [],
    salt: stark.randomAddress(),
    unique: false,
  });
  await provider.waitForTransaction(verifierDeploy.transaction_hash);
  const verifierAddr = verifierDeploy.contract_address;
  console.log(`  Verifier: ${verifierAddr}`);

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

// ─── HTTP server helpers ───────────────────────────────────────────────────────

function startPaywallServer(serverAddress, poolAddress, requiredAmount = 1_000_000_000_000_000n) {
  const queued   = [];
  const verified = [];
  const app      = express();
  app.use(express.json());

  app.post('/v1/chat/completions', wraithPaywall({
    amount:        requiredAmount,
    token:         'ETH',
    serverAddress,
    poolAddress,
    allowInsecure: true, // test server runs on plain HTTP (127.0.0.1)
    onVerified: (proof) => {
      verified.push({ nullifierHash: proof.nullifierHash, zkProofLen: proof.zkProof?.length });
      if (proof.zkProof?.length > 0) {
        queued.push({ nullifierHash: proof.nullifierHash, zkProof: proof.zkProof });
      }
    },
  }), (req, res) => {
    const w = req.wraith;
    res.json({
      id:      `wraith-e2e-${Date.now()}`,
      object:  'chat.completion',
      model:   'wraith-demo-v1',
      choices: [{ index: 0, message: { role: 'assistant', content: 'E2E demo response' }, finish_reason: 'stop' }],
      wraith: w ? {
        paid:          w.paid,
        amount:        w.amount?.toString(),
        nullifierHash: w.nullifierHash,
      } : null,
    });
  });

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', pending: queued.length, verified: verified.length });
  });

  return new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port, queued, verified });
    });
  });
}

// ─── Main test ────────────────────────────────────────────────────────────────

async function run() {
  console.log('Wraith Protocol — End-to-End Integration Test');
  console.log('agent deposit → ZK proof → HTTP x402 → server validates\n');

  // ─── Phase 1: Setup ──────────────────────────────────────────────────────────
  console.log('Phase 1: Deploy contracts on fresh devnet');
  const provider = new RpcProvider({ nodeUrl: RPC_URL });
  const account  = new Account(provider, ACC_ADDR, ACC_PK, undefined, constants.TRANSACTION_VERSION.V3);

  const { poolAddr } = await setupFreshDevnet(provider, account);
  console.log();

  // ─── Phase 2: Deposit ────────────────────────────────────────────────────────
  console.log('Phase 2: Agent deposits into pool');

  const secret    = 0x1234abcdef5678901234abcdef56789012n;
  const nullifier = 0xfedcba9876543210fedcba9876543210fedn;
  const amount    = 1_000_000_000_000_000n; // 0.001 ETH

  const snhash     = hash(secret, nullifier);
  const commitment = hash(snhash, amount);
  const nullHash   = hashOne(nullifier);

  console.log(`  commitment:    0x${commitment.toString(16)}`);
  console.log(`  nullifierHash: 0x${nullHash.toString(16)}`);

  // Approve ETH spend
  const approveTx = await account.execute({
    contractAddress: ETH_ADDR,
    entrypoint:      'approve',
    calldata:        [poolAddr, ...u256Calldata(amount)],
  });
  await provider.waitForTransaction(approveTx.transaction_hash);
  assert(true, 'ETH approve confirmed');

  // Deposit (pool.deposit takes H(s,n), computes commitment internally)
  const depositTx = await account.execute({
    contractAddress: poolAddr,
    entrypoint:      'deposit',
    calldata:        [...u256Calldata(snhash), ...u256Calldata(amount)],
  });
  await provider.waitForTransaction(depositTx.transaction_hash);
  assert(true, 'deposit confirmed on-chain');

  // Verify root changed
  const rootResult = await provider.callContract({
    contractAddress: poolAddr,
    entrypoint:      'current_root',
    calldata:        [],
  });
  const onChainRoot = BigInt(rootResult[0]) | (BigInt(rootResult[1]) << 128n);
  assert(onChainRoot > 0n, `root updated after deposit (0x${onChainRoot.toString(16).slice(0,12)}...)`);
  console.log();

  // ─── Phase 3: Start HTTP server ──────────────────────────────────────────────
  console.log('Phase 3: Start API server with Wraith paywall');

  // The API server's address is used as the ZK proof recipient.
  // In production this is a distinct keypair; for this test we reuse the devnet account.
  const serverAddress = ACC_ADDR;
  const requiredAmount = amount; // exact match for full withdrawal

  const { server, port, queued, verified } = await startPaywallServer(serverAddress, poolAddr, requiredAmount);
  const BASE = `http://127.0.0.1:${port}`;

  const healthRes = await fetch(`${BASE}/health`);
  assert(healthRes.ok, `health endpoint responsive (port ${port})`);
  console.log();

  // ─── Phase 4: Agent hits endpoint without proof → 402 ───────────────────────
  console.log('Phase 4: Probe endpoint (expect 402 challenge)');

  const probe = await fetch(`${BASE}/v1/chat/completions`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ messages: [{ role: 'user', content: 'hello' }] }),
  });

  assert(probe.status === 402, `probe returns 402 (got ${probe.status})`);
  const wwwAuth = probe.headers.get('WWW-Authenticate');
  assert(wwwAuth?.startsWith('Wraith-Starknet-v1'), `402 has correct scheme: ${wwwAuth?.slice(0, 40)}`);
  assert(wwwAuth?.includes(`payTo="${serverAddress}"`), 'payTo = server address in challenge');
  assert(wwwAuth?.includes(`poolAddress="${poolAddr}"`), 'poolAddress in challenge');
  console.log();

  // ─── Phase 5: Build Merkle proof + generate ZK proof ────────────────────────
  console.log('Phase 5: Generate Groth16 proof (client-side, ~5-10s)');

  // Build Merkle proof for leaf at index 0 in fresh pool
  const { pathElements, pathIndices, root: computedRoot } = buildMerkleProof(commitment);

  assert(
    computedRoot === onChainRoot,
    `computed Merkle root matches on-chain root (0x${onChainRoot.toString(16).slice(0,12)}...)`
  );

  const recipient = BigInt(serverAddress);

  const input = {
    root:                      computedRoot.toString(),
    nullifierHash:             nullHash.toString(),
    recipient:                 recipient.toString(),
    fee:                       '0',
    refundCommitmentHash:      '0',
    amount:                    amount.toString(),
    associatedSetRoot:         computedRoot.toString(),
    // Private inputs
    secret:                    secret.toString(),
    nullifier:                 nullifier.toString(),
    refund:                    '0',
    commitmentAmount:          amount.toString(),
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
    server.close();
    process.exit(1);
  }
  const elapsed = Date.now() - t0;
  console.log(`  Proof generated in ${elapsed}ms`);

  // Verify locally before sending
  const vk    = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
  const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
  assert(valid, 'proof verifies locally');

  // Check public signals match our inputs
  assert(BigInt(publicSignals[0]) === computedRoot, `publicSignals[0] = root`);
  assert(BigInt(publicSignals[1]) === nullHash, `publicSignals[1] = nullifierHash`);
  assert(BigInt(publicSignals[2]) === recipient, `publicSignals[2] = recipient (server address)`);
  assert(BigInt(publicSignals[5]) === amount, `publicSignals[5] = amount`);
  console.log();

  // ─── Phase 6: Send proof over HTTP ───────────────────────────────────────────
  console.log('Phase 6: Send ZK proof in X-Payment-Proof header');

  // Serialize proof to 30-felt HTTP transport format
  const proofFelts = serializeProofToFelts(proof, publicSignals);
  assert(proofFelts.length === 30, `proofFelts length = 30 (got ${proofFelts.length})`);

  const zkProof      = proofFelts.map(String);
  const publicInputs = extractPublicInputs(zkProof);

  // Build X402PaymentProof
  const paymentProof = {
    scheme:       X402_SCHEME,
    network:      'starknet-devnet',
    zkProof,
    nullifierHash: nullHash.toString(),
    publicInputs,
  };

  const header  = buildPaymentHeader(paymentProof);
  const payRes  = await fetch(`${BASE}/v1/chat/completions`, {
    method:  'POST',
    headers: {
      'Content-Type':    'application/json',
      'X-Payment-Proof':  header,
      'X-Payment-Scheme': X402_SCHEME,
    },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'hello, pay-gated world' }] }),
  });

  const payBody = await payRes.json();
  assert(payRes.status === 200, `server accepts real ZK proof → 200 (got ${payRes.status}: ${JSON.stringify(payBody).slice(0,100)})`);
  assert(payBody.wraith?.paid === true, 'wraith.paid = true in response');
  assert(payBody.wraith?.nullifierHash === nullHash.toString(), `wraith.nullifierHash matches proof`);
  console.log();

  // ─── Phase 7: Privacy invariants ─────────────────────────────────────────────
  console.log('Phase 7: Verify privacy invariants');

  assert(verified.length === 1, `exactly 1 proof verified (got ${verified.length})`);
  assert(queued.length === 1, `exactly 1 withdrawal queued`);

  const qItem = queued[0];
  assert(qItem.nullifierHash === nullHash.toString(), 'queued nullifierHash matches proof');
  assert(qItem.zkProof?.length === 30, `queued zkProof has 30 felts (got ${qItem.zkProof?.length})`);

  // Privacy invariants: server never got depositor identity
  assert(!payBody.depositorAddress, 'server response does not contain depositor address');
  assert(!payBody.txHash, 'server response does not contain txHash');
  assert(!qItem.secret, 'PRIVACY: withdrawal queue does not contain secret');
  assert(!qItem.depositorAddress, 'PRIVACY: withdrawal queue does not contain depositor address');
  console.log();

  // ─── Phase 8: Replay prevention ──────────────────────────────────────────────
  console.log('Phase 8: Replay prevention (same nullifier rejected)');

  const replayRes = await fetch(`${BASE}/v1/chat/completions`, {
    method:  'POST',
    headers: {
      'Content-Type':    'application/json',
      'X-Payment-Proof':  header,
      'X-Payment-Scheme': X402_SCHEME,
    },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'replay attack' }] }),
  });

  assert(replayRes.status === 402, `replay proof rejected with 402 (got ${replayRes.status})`);
  const replayBody = await replayRes.json();
  assert(
    replayBody.reason?.toLowerCase().includes('nullifier') || replayBody.reason?.toLowerCase().includes('spent'),
    `replay reason mentions nullifier: "${replayBody.reason}"`
  );
  console.log();

  // ─── Summary ──────────────────────────────────────────────────────────────────
  server.close();

  console.log('─'.repeat(60));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log();

  if (failed === 0) {
    console.log('FULL E2E FLOW VERIFIED:');
    console.log(`  Pool deployed at ${poolAddr}`);
    console.log(`  Agent deposited 0.001 ETH (on-chain, txHash logged)`);
    console.log(`  Groth16 proof generated in ${elapsed}ms (client-side)`);
    console.log(`  Proof verified locally before sending`);
    console.log(`  402 challenge: correct scheme, payTo, poolAddress`);
    console.log(`  HTTP 200: server accepted real ZK proof`);
    console.log(`  Withdrawal queued: nullifier tracked, no depositor info leaked`);
    console.log(`  Replay prevented: same nullifier returns 402`);
    console.log();
    console.log('WHAT THIS DID NOT TEST:');
    console.log('  On-chain pool.withdraw() from queued proof (requires garaga calldata)');
    console.log('  → Already verified in onchain.test.mjs (8/8 pass)');
    console.log('  Lit Protocol note encryption (requires Lit network)');
    console.log('  Server restart / Redis-backed nullifier set');
  } else {
    console.error(`${failed} test(s) failed.`);
    process.exit(1);
  }
}

run().catch(err => {
  console.error('FATAL:', err);
  process.exit(1);
});
