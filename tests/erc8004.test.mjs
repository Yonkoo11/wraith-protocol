/**
 * ERC-8004 (Trustless Agents) unit tests
 *
 * Tests the agent identity and receipt generation without any network calls.
 * All assertions run against the compiled dist/ output.
 */

import { strict as assert } from 'assert';

const {
  createAgentManifest,
  manifestToDataURI,
  generatePaymentReceipt,
  validateReceipt,
} = await import('../dist/erc8004.js');

const GR = (s) => '\x1b[32m' + s + '\x1b[0m';
const RD = (s) => '\x1b[31m' + s + '\x1b[0m';

let pass = 0, fail = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(GR(`  ✓ ${name}`));
    pass++;
  } catch (e) {
    console.error(RD(`  ✗ ${name}`));
    console.error(`    ${e.message}`);
    fail++;
  }
}

console.log('\nERC-8004 (Trustless Agents) — Unit Tests\n');

// ── Agent Manifest ────────────────────────────────────────────────────────────
await test('createAgentManifest: correct type field (EIP-8004 registration-v1)', () => {
  const manifest = createAgentManifest(
    { name: 'TestAgent', description: 'Test agent for Cipher Pol' },
    'privacy-pools',
    'demo'
  );
  assert.equal(
    manifest.type,
    'https://eips.ethereum.org/EIPS/eip-8004#registration-v1'
  );
});

await test('createAgentManifest: x402Support is true', () => {
  const manifest = createAgentManifest(
    { name: 'TestAgent', description: 'Test' },
    'privacy-pools',
    'demo'
  );
  assert.equal(manifest.x402Support, true);
});

await test('createAgentManifest: cipherPol extension fields present', () => {
  const manifest = createAgentManifest(
    {
      name: 'WeatherAgent',
      description: 'Fetches weather data autonomously',
      starknetAddress: '0xdeadbeef',
    },
    'privacy-pools',
    'demo'
  );
  assert.equal(manifest.cipherPol.adapter, 'privacy-pools');
  assert.equal(manifest.cipherPol.privacyLevel, 'demo');
  assert.equal(manifest.cipherPol.starknetAddress, '0xdeadbeef');
  assert.equal(manifest.cipherPol.sdkVersion, '0.1.0');
});

await test('createAgentManifest: services includes x402 entry', () => {
  const manifest = createAgentManifest(
    { name: 'TestAgent', description: 'Test' },
    'strk20',
    'zk-native'
  );
  const x402 = manifest.services.find((s) => s.name === 'x402');
  assert.ok(x402, 'No x402 service entry found');
  assert.equal(x402.version, 'cipher-pol-v1');
});

await test('createAgentManifest: registrations populated when agentId + registry provided', () => {
  const manifest = createAgentManifest(
    {
      name: 'TestAgent',
      description: 'Test',
      agentId: 42,
      registryAddress: 'eip155:1:0xabcdef',
    },
    'privacy-pools',
    'demo'
  );
  assert.ok(manifest.registrations);
  assert.equal(manifest.registrations[0].agentId, 42);
  assert.equal(manifest.registrations[0].agentRegistry, 'eip155:1:0xabcdef');
});

await test('createAgentManifest: no registrations when agentId not provided', () => {
  const manifest = createAgentManifest(
    { name: 'TestAgent', description: 'Test' },
    'privacy-pools',
    'demo'
  );
  assert.equal(manifest.registrations, undefined);
});

// ── Data URI ──────────────────────────────────────────────────────────────────
await test('manifestToDataURI: produces valid data: URI', () => {
  const manifest = createAgentManifest(
    { name: 'TestAgent', description: 'Test' },
    'privacy-pools',
    'demo'
  );
  const uri = manifestToDataURI(manifest);
  assert.ok(uri.startsWith('data:application/json;base64,'), `URI starts incorrectly: ${uri.slice(0, 50)}`);
});

await test('manifestToDataURI: roundtrips correctly', () => {
  const manifest = createAgentManifest(
    { name: 'RoundtripAgent', description: 'Test roundtrip' },
    'privacy-pools',
    'demo'
  );
  const uri = manifestToDataURI(manifest);
  const b64 = uri.replace('data:application/json;base64,', '');
  const decoded = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
  assert.equal(decoded.name, 'RoundtripAgent');
  assert.equal(decoded.x402Support, true);
});

// ── Payment Receipts ──────────────────────────────────────────────────────────
await test('generatePaymentReceipt: required fields present', () => {
  const receipt = generatePaymentReceipt(
    '0xabc123',
    'starknet-sepolia',
    '0xpool',
    'https://api.example.com/chat',
    3000n,
    'USDC'
  );
  assert.equal(receipt.schema, 'erc8004-cipher-pol-receipt-v1');
  assert.equal(receipt.paymentProof.txHash, '0xabc123');
  assert.equal(receipt.paymentProof.chainId, 'starknet-sepolia');
  assert.equal(receipt.paymentProof.toAddress, '0xpool');
  assert.equal(receipt.service, 'https://api.example.com/chat');
  assert.equal(receipt.amount, '3000');
  assert.equal(receipt.token, 'USDC');
  assert.ok(typeof receipt.timestamp === 'number');
});

await test('generatePaymentReceipt: includes agent identity when config provided', () => {
  const receipt = generatePaymentReceipt(
    '0xabc123',
    'starknet-sepolia',
    '0xpool',
    'https://api.example.com/chat',
    3000n,
    'USDC',
    {
      name: 'MyAgent',
      description: 'Test agent',
      starknetAddress: '0xagent',
      agentId: 7,
    }
  );
  assert.equal(receipt.agentId, '7');
  assert.equal(receipt.agentStarknetAddress, '0xagent');
  assert.ok(receipt.agentURI?.startsWith('data:application/json;base64,'));
});

await test('generatePaymentReceipt: no agent fields without config', () => {
  const receipt = generatePaymentReceipt(
    '0xabc123', 'starknet-sepolia', '0xpool',
    'https://api.example.com', 1000n, 'USDC'
  );
  assert.equal(receipt.agentId, undefined);
  assert.equal(receipt.agentURI, undefined);
});

// ── Receipt Validation ────────────────────────────────────────────────────────
await test('validateReceipt: accepts valid receipt', () => {
  const receipt = generatePaymentReceipt(
    '0xabc123', 'starknet', '0xpool', 'https://test.com', 1000n, 'USDC'
  );
  assert.ok(validateReceipt(receipt));
});

await test('validateReceipt: rejects null', () => {
  assert.equal(validateReceipt(null), false);
});

await test('validateReceipt: rejects wrong schema', () => {
  assert.equal(validateReceipt({ schema: 'wrong', service: 'x', paymentProof: { txHash: 'x' }, timestamp: 1 }), false);
});

await test('validateReceipt: rejects missing txHash', () => {
  assert.equal(validateReceipt({
    schema: 'erc8004-cipher-pol-receipt-v1',
    service: 'x',
    paymentProof: {},
    timestamp: 1,
  }), false);
});

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(60)}`);
console.log(`Results: ${pass} passed, ${fail} failed\n`);
if (fail > 0) process.exit(1);
