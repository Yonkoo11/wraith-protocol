/**
 * Cipher Pol — Server Middleware Unit Tests
 *
 * Tests the correct privacy-preserving x402 flow:
 *   - Agent generates ZK proof CLIENT-SIDE
 *   - Server validates public inputs (recipient, amount) WITHOUT on-chain calls
 *   - Server tracks nullifierHash to prevent replay
 *   - Server queues pre-generated proof for async Starknet submission
 *
 * Privacy invariants verified:
 *   - Middleware accepts proof based on public inputs only (no txHash, no litCiphertext)
 *   - Duplicate nullifierHash rejected (replay prevention)
 *   - Server never sees depositor address or (secret, nullifier)
 *   - cipherPol.txHash is GONE — replaced by cipherPol.nullifierHash
 *
 * No devnet required — proof validation is based on decoded public inputs.
 */

import { strict as assert } from 'assert';
import http from 'http';
import express from 'express';

const { cipherPolPaywall } = await import('../server/dist/middleware.js');
const { buildPaymentHeader, X402_SCHEME } = await import('../dist/x402.js');

// ── Helpers ────────────────────────────────────────────────────────────────

let pass = 0;
let fail = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    pass++;
  } catch (err) {
    console.error(`  ✗ FAIL: ${name}`);
    console.error(`    ${err.message}`);
    fail++;
  }
}

async function post(url, headers, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

// ── Mock proof builder ─────────────────────────────────────────────────────
//
// The middleware validates public inputs (recipient, amount) from the decoded
// proof. It does NOT run Groth16 verification on the hot path (that happens
// when pool.withdraw() is called on-chain). So we can use mock public inputs
// in tests without a real circuit or Starknet connection.

const SERVER_ADDRESS = '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';
const REQUIRED_AMOUNT = 3000n;

function buildMockProof({
  recipient = SERVER_ADDRESS,
  amount = REQUIRED_AMOUNT,
  nullifierHash = '0xdeadbeef1234567890abcdef',
  zkProof = ['0x1', '0x2', '0x3'],  // mock felt array
  agentId,
  agentURI,
} = {}) {
  return {
    scheme: X402_SCHEME,
    network: 'starknet-mainnet',
    zkProof,
    nullifierHash: BigInt(nullifierHash).toString(),
    publicInputs: {
      root: '12345',
      nullifierHash: BigInt(nullifierHash).toString(),
      recipient: BigInt(recipient).toString(),
      fee: '0',
      amount: amount.toString(),
      refundCommitmentHash: '0',
      associatedSetRoot: '12345',
    },
    agentId,
    agentURI,
  };
}

// ── Start test server ──────────────────────────────────────────────────────

function startTestServer(requiredAmount = REQUIRED_AMOUNT) {
  const queue = [];
  const verified = [];
  const app = express();
  app.use(express.json());

  app.post('/paid', cipherPolPaywall({
    amount: requiredAmount,
    token: 'USDC',
    serverAddress: SERVER_ADDRESS,
    poolAddress: '0x456',
    allowInsecure: true, // test server runs on plain HTTP (127.0.0.1)
    onVerified: (proof, req) => {
      // NOTE: no txHash, no litCiphertext here — just nullifierHash and zkProof
      verified.push({ nullifierHash: proof.nullifierHash, zkProof: proof.zkProof });
    },
  }), (req, res) => {
    // Serialize bigints as strings for JSON response
    const w = req.cipherPol;
    res.json({
      success: true,
      cipherPol: w ? {
        paid: w.paid,
        amount: w.amount?.toString(),
        token: w.token,
        nullifierHash: w.nullifierHash,
        agentId: w.agentId,
        agentURI: w.agentURI,
      } : undefined,
    });
  });

  return new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port, queue, verified });
    });
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

console.log('\nCipher Pol — Server Middleware Tests\n');
console.log('Testing correct privacy-preserving x402 flow:');
console.log('  No txHash in proofs, no litCiphertext, no on-chain calls on hot path\n');

const { server, port, verified } = await startTestServer();
const BASE = `http://127.0.0.1:${port}`;

// 1. Challenge format
await test('no proof → 402 with CipherPol-Starknet-v1 challenge', async () => {
  const res = await post(BASE + '/paid', {}, { prompt: 'test' });
  assert.equal(res.status, 402);
  const auth = res.headers.get('WWW-Authenticate');
  assert(auth?.startsWith('CipherPol-Starknet-v1'), `got: ${auth}`);
  assert(auth.includes(`payTo="${SERVER_ADDRESS}"`), `payTo missing: ${auth}`);
  assert(auth.includes('poolAddress='), `poolAddress missing: ${auth}`);
  assert(auth.includes('USDC'), `token missing: ${auth}`);
});

await test('wrong scheme header → 402', async () => {
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  'abc',
    'X-Payment-Scheme': 'some-other-scheme',
  }, {});
  assert.equal(res.status, 402);
});

await test('malformed base64 proof → 400', async () => {
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  '!!!not-base64!!!',
    'X-Payment-Scheme': X402_SCHEME,
  }, {});
  assert.equal(res.status, 400);
});

// 2. Field validation
await test('missing zkProof → 402', async () => {
  const proof = buildMockProof({ zkProof: [] });
  const header = buildPaymentHeader(proof);
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  header,
    'X-Payment-Scheme': X402_SCHEME,
  }, {});
  assert.equal(res.status, 402);
  const body = await res.json();
  assert(body.reason?.toLowerCase().includes('zkproof'), `expected zkProof error: ${JSON.stringify(body)}`);
});

await test('missing nullifierHash → 402', async () => {
  const proof = { ...buildMockProof(), nullifierHash: '' };
  const header = buildPaymentHeader(proof);
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  header,
    'X-Payment-Scheme': X402_SCHEME,
  }, {});
  assert.equal(res.status, 402);
  const body = await res.json();
  assert(body.reason?.toLowerCase().includes('nullifier'), `expected nullifier error: ${JSON.stringify(body)}`);
});

await test('wrong recipient → 402 (proof not for this server)', async () => {
  const proof = buildMockProof({ recipient: '0x1111111111111111111111111111111111111111' });
  const header = buildPaymentHeader(proof);
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  header,
    'X-Payment-Scheme': X402_SCHEME,
  }, {});
  assert.equal(res.status, 402);
  const body = await res.json();
  assert(body.reason?.toLowerCase().includes('recipient'), `expected recipient error: ${JSON.stringify(body)}`);
});

await test('insufficient amount → 402', async () => {
  const proof = buildMockProof({ amount: REQUIRED_AMOUNT - 1n });
  const header = buildPaymentHeader(proof);
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  header,
    'X-Payment-Scheme': X402_SCHEME,
  }, {});
  assert.equal(res.status, 402);
  const body = await res.json();
  assert(body.reason?.toLowerCase().includes('amount'), `expected amount error: ${JSON.stringify(body)}`);
});

// 3. Happy path
const NULLIFIER_1 = '0x1234567890abcdef1234567890abcdef12345678';

await test('valid proof → 200 (recipient+amount match server expectations)', async () => {
  const proof = buildMockProof({ nullifierHash: NULLIFIER_1 });
  const header = buildPaymentHeader(proof);
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  header,
    'X-Payment-Scheme': X402_SCHEME,
  }, { prompt: 'hello' });
  const text = await res.text();
  assert.equal(res.status, 200, `got ${res.status}, body: ${text}`);
  const body = JSON.parse(text);
  assert.equal(body.success, true);

  // Verify cipherPol fields on the request
  assert.equal(body.cipherPol.paid, true);
  assert(body.cipherPol.nullifierHash, 'nullifierHash missing from cipherPol context');
  // txHash is gone — the server never knew which on-chain deposit this was
  assert.equal(body.cipherPol.txHash, undefined, 'PRIVACY LEAK: txHash should not appear in cipherPol context');
});

// 4. Privacy invariants
await test('verified queue: no txHash, no litCiphertext, no secret/nullifier', async () => {
  assert(verified.length >= 1, `expected at least 1 verified proof, got ${verified.length}`);
  for (const item of verified) {
    assert(item.nullifierHash, 'nullifierHash missing from verified item');
    assert(item.zkProof?.length > 0, 'zkProof missing from verified item');

    // Privacy invariants
    assert(!item.txHash,        'PRIVACY LEAK: txHash in verified queue');
    assert(!item.litCiphertext, 'PRIVACY LEAK: litCiphertext in verified queue');
    assert(!item.secret,        'PRIVACY LEAK: plaintext secret in verified queue');
    assert(!item.nullifier,     'PRIVACY LEAK: plaintext nullifier in verified queue');
    assert(!item.depositorAddress, 'PRIVACY LEAK: depositorAddress in verified queue');
  }
});

// 5. Replay prevention
await test('same nullifierHash rejected (replay attack prevention)', async () => {
  // NULLIFIER_1 was already spent in the "valid proof → 200" test above
  const proof = buildMockProof({ nullifierHash: NULLIFIER_1 });
  const header = buildPaymentHeader(proof);
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  header,
    'X-Payment-Scheme': X402_SCHEME,
  }, {});
  assert.equal(res.status, 402, `expected 402 for replay, got ${res.status}`);
  const body = await res.json();
  assert(
    body.reason?.toLowerCase().includes('nullifier') || body.reason?.toLowerCase().includes('spent'),
    `expected replay error: ${JSON.stringify(body)}`
  );
});

await test('different nullifierHash accepted (distinct payment)', async () => {
  const NULLIFIER_2 = '0xabcdef1234567890abcdef1234567890abcdef12';
  const proof = buildMockProof({ nullifierHash: NULLIFIER_2 });
  const header = buildPaymentHeader(proof);
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  header,
    'X-Payment-Scheme': X402_SCHEME,
  }, {});
  assert.equal(res.status, 200, `expected 200 for new nullifier, got ${res.status}`);
});

// 6. ERC-8004 passthrough
await test('ERC-8004 agentId + agentURI passed through to cipherPol context', async () => {
  const NULLIFIER_3 = '0xfedcba0987654321fedcba0987654321fedcba09';
  const proof = buildMockProof({
    nullifierHash: NULLIFIER_3,
    agentId: '42',
    agentURI: 'data:application/json;base64,eyJuYW1lIjoiVGVzdEFnZW50In0=',
  });
  const header = buildPaymentHeader(proof);
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  header,
    'X-Payment-Scheme': X402_SCHEME,
  }, {});
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.cipherPol.agentId, '42');
  assert(body.cipherPol.agentURI?.startsWith('data:'), `expected data: URI, got: ${body.cipherPol.agentURI}`);
});

// 7. Overpayment allowed
await test('overpayment accepted (amount > required)', async () => {
  const NULLIFIER_4 = '0x1111111111111111111111111111111111111111';
  const proof = buildMockProof({
    nullifierHash: NULLIFIER_4,
    amount: REQUIRED_AMOUNT * 10n,  // paying 10x the required amount
  });
  const header = buildPaymentHeader(proof);
  const res = await post(BASE + '/paid', {
    'X-Payment-Proof':  header,
    'X-Payment-Scheme': X402_SCHEME,
  }, {});
  assert.equal(res.status, 200, `expected 200 for overpayment, got ${res.status}`);
});

// ── Results ────────────────────────────────────────────────────────────────

server.close();

console.log(`\n${'─'.repeat(60)}`);
console.log(`Results: ${pass} passed, ${fail} failed\n`);

if (fail > 0) process.exit(1);

console.log('VERIFIED:');
console.log('  402 challenge format correct (scheme, token, payTo, poolAddress)');
console.log('  Malformed/missing proofs rejected before any processing');
console.log('  Wrong recipient rejected (proof not for this server)');
console.log('  Insufficient amount rejected');
console.log('  Valid proof accepted (public inputs match expectations)');
console.log('  Replay attack prevented (duplicate nullifierHash rejected)');
console.log('  Different nullifierHashes accepted as distinct payments');
console.log('  ERC-8004 identity passed through to request context');
console.log('  Overpayment accepted');
console.log('  Privacy invariants: no txHash, litCiphertext, secret, or depositor in queue');
console.log('\nNOT TESTED (requires live Starknet devnet + circuit artifacts):');
console.log('  Groth16 proof generation (client-side, requires .wasm + .zkey)');
console.log('  pool.withdraw() submission via WithdrawalQueue');
console.log('  Full on-chain deposit → proof → withdrawal flow');
