/**
 * Lit Protocol roundtrip test — real Datil network
 *
 * What this tests:
 *   1. LitNodeClient connects to Datil
 *   2. encryptString encrypts (secret, nullifier) with an EVM access condition
 *   3. getSessionSigs authenticates with the server's ETH key (SIWE flow)
 *   4. decryptToString decrypts and recovers original (secret, nullifier)
 *   5. Wrong signer is rejected by the access condition
 *
 * Capacity Credits (required for decryption on Datil production):
 *   Run `node scripts/lit-setup.mjs` once to mint a Capacity Credits NFT.
 *   The test auto-loads .lit-capacity.json and .lit-test-wallet.json if present.
 *   Without capacity credits, steps 4 and 5 are rate-limited (logged, not failed).
 */

import { LitNodeClient } from '@lit-protocol/lit-node-client';
import { encryptString, decryptToString } from '@lit-protocol/encryption';
import { createSiweMessage, generateAuthSig, LitAccessControlConditionResource } from '@lit-protocol/auth-helpers';
import { LIT_ABILITY, LIT_RPC } from '@lit-protocol/constants';
import { ethers } from 'ethers';
import { existsSync, readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT  = join(__dir, '..');

const GR = (s) => '\x1b[32m' + s + '\x1b[0m';
const RD = (s) => '\x1b[31m' + s + '\x1b[0m';
const YL = (s) => '\x1b[33m' + s + '\x1b[0m';
const BD = (s) => '\x1b[1m'  + s + '\x1b[0m';

let pass = 0, fail = 0, skip = 0;
async function test(name, fn) {
  try { await fn(); console.log(GR(`  ✓ ${name}`)); pass++; }
  catch (e) { console.error(RD(`  ✗ ${name}`)); console.error(`    ${e.message?.slice(0, 200)}`); fail++; }
}
function skipTest(name, reason) {
  console.log(YL(`  ~ ${name}`));
  console.log(`    ${reason}`);
  skip++;
}

console.log('\nLit Protocol — Real Datil Roundtrip Test\n');

// ── Load capacity credits config (if set up) ─────────────────────────────────
const WALLET_FILE   = join(ROOT, '.lit-test-wallet.json');
const CAPACITY_FILE = join(ROOT, '.lit-capacity.json');

let capacityWallet = null;
let capacityTokenId = null;

if (existsSync(CAPACITY_FILE) && existsSync(WALLET_FILE)) {
  const savedCapacity = JSON.parse(readFileSync(CAPACITY_FILE, 'utf8'));
  const savedWallet   = JSON.parse(readFileSync(WALLET_FILE, 'utf8'));
  capacityTokenId = savedCapacity.tokenId;
  const provider = new ethers.providers.JsonRpcProvider(LIT_RPC.CHRONICLE_YELLOWSTONE);
  capacityWallet = new ethers.Wallet(savedWallet.privateKey, provider);
  console.log(GR(`Capacity Credits NFT: token ${capacityTokenId} (owner: ${capacityWallet.address})`));
} else {
  console.log(YL('No capacity credits — decrypt steps will be attempted but may be rate-limited.'));
  console.log(`  Run: node scripts/lit-setup.mjs  (then fund wallet from faucet)\n`);
}

// ── Test wallet (throwaway — no funds needed) ─────────────────────────────────
const wallet = ethers.Wallet.createRandom();
console.log(`Server ETH address: ${wallet.address}`);
console.log(`(throwaway key, discarded after test)\n`);

// Test data
const SECRET    = 0xdeadbeef1234567890abcdefn;
const NULLIFIER = 0xfeedface0987654321n;

let ciphertext, dataToEncryptHash, accessControlConditions;

// ── Step 1: Connect to Lit Datil ─────────────────────────────────────────────
let client;
await test('connect to Lit Datil', async () => {
  client = new LitNodeClient({ litNetwork: 'datil', debug: false });
  await client.connect();
  const nodes = Object.keys(client.connectedNodes ?? client.serverKeys ?? {}).length;
  console.log(`  connected to ${nodes} nodes`);
});
if (fail > 0) { console.error('Cannot reach Lit Datil — aborting.'); process.exit(1); }

// ── Step 2: Encrypt ───────────────────────────────────────────────────────────
await test('encrypt (secret, nullifier) with EVM access condition', async () => {
  accessControlConditions = [{
    contractAddress: '',
    standardContractType: '',
    chain: 'ethereum',
    method: '',
    parameters: [':userAddress'],
    returnValueTest: { comparator: '=', value: wallet.address.toLowerCase() },
  }];

  const plaintext = JSON.stringify({
    secret:    SECRET.toString(16),
    nullifier: NULLIFIER.toString(16),
  });

  const result = await encryptString(
    { accessControlConditions, dataToEncrypt: plaintext },
    client
  );
  ciphertext        = result.ciphertext;
  dataToEncryptHash = result.dataToEncryptHash;

  if (!ciphertext || !dataToEncryptHash) throw new Error('encrypt returned empty values');
  console.log(`  ciphertext length: ${ciphertext.length} chars`);
});

// ── Step 3: Get session sigs (SIWE flow) ──────────────────────────────────────
let sessionSigs;
let capacityDelegationAuthSig;

// If we have capacity credits, create a delegation auth sig first
if (capacityTokenId && capacityWallet) {
  await test('create capacity delegation auth sig', async () => {
    capacityDelegationAuthSig = (await client.createCapacityDelegationAuthSig({
      uses: '100',
      dAppOwnerWallet: capacityWallet,
      capacityTokenId,
      delegateeAddresses: [wallet.address],
    })).capacityDelegationAuthSig;
    console.log(`  delegation created for ${wallet.address}`);
  });
}

await test('getSessionSigs with server ETH key (SIWE flow)', async () => {
  const latestBlockhash = await client.getLatestBlockhash();
  const getSessionSigsParams = {
    chain: 'ethereum',
    expiration: new Date(Date.now() + 60 * 60 * 1000).toISOString(), // 1h
    resourceAbilityRequests: [{
      resource: new LitAccessControlConditionResource('*'),
      ability:  LIT_ABILITY.AccessControlConditionDecryption,
    }],
    authNeededCallback: async (params) => {
      const toSign = await createSiweMessage({
        uri:           params.uri ?? 'https://localhost',
        expiration:    params.expiration,
        resources:     params.resourceAbilityRequests,
        walletAddress: wallet.address,
        nonce:         latestBlockhash,
        litNodeClient: client,
      });
      return generateAuthSig({ signer: wallet, toSign });
    },
  };

  // Pass capacity delegation if available
  if (capacityDelegationAuthSig) {
    getSessionSigsParams.capacityDelegationAuthSig = capacityDelegationAuthSig;
  }

  sessionSigs = await client.getSessionSigs(getSessionSigsParams);
  const nodeCount = Object.keys(sessionSigs).length;
  if (nodeCount < 2) throw new Error(`only ${nodeCount} node session sigs — need threshold`);
  console.log(`  session sigs from ${nodeCount} nodes`);
});

// ── Step 4: Decrypt ───────────────────────────────────────────────────────────
let decryptSucceeded = false;
if (!capacityTokenId) {
  // Attempt anyway — might work on first call of the session
  await test('decrypt and recover (secret, nullifier)', async () => {
    let decrypted;
    let lastErr;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) {
        console.log(`  (rate limited, retrying in 8s...)`);
        await new Promise(r => setTimeout(r, 8000));
      }
      try {
        decrypted = await decryptToString({
          accessControlConditions, ciphertext, dataToEncryptHash,
          chain: 'ethereum', sessionSigs,
        }, client);
        break;
      } catch (e) {
        lastErr = e;
        if (!e.message?.includes('rate_limit') && !e.message?.includes('Rate limit')) throw e;
      }
    }

    if (!decrypted) {
      // Rate-limited: log clearly, mark test as skipped (not failed)
      console.log(YL(`  RATE LIMITED — decryptToString requires Capacity Credits on Datil`));
      console.log(`  Run: node scripts/lit-setup.mjs  to set up capacity credits`);
      pass--; skip++; // undo auto-pass, mark as skipped
      return;
    }

    _verifyDecrypted(decrypted);
    decryptSucceeded = true;
  });
} else {
  await test('decrypt and recover (secret, nullifier) — with Capacity Credits', async () => {
    const decrypted = await decryptToString({
      accessControlConditions, ciphertext, dataToEncryptHash,
      chain: 'ethereum', sessionSigs,
    }, client);
    _verifyDecrypted(decrypted);
    decryptSucceeded = true;
  });
}

function _verifyDecrypted(decrypted) {
  const parsed = JSON.parse(decrypted);
  const recoveredSecret    = BigInt('0x' + parsed.secret);
  const recoveredNullifier = BigInt('0x' + parsed.nullifier);
  if (recoveredSecret    !== SECRET)    throw new Error(`secret mismatch: ${recoveredSecret}`);
  if (recoveredNullifier !== NULLIFIER) throw new Error(`nullifier mismatch: ${recoveredNullifier}`);
  console.log(`  secret:   0x${recoveredSecret.toString(16)}`);
  console.log(`  nullifier: 0x${recoveredNullifier.toString(16)}`);
}

// ── Step 5: Wrong signer is rejected ─────────────────────────────────────────
// Only run if decrypt succeeded — otherwise rate limit will swallow the rejection.
await new Promise(r => setTimeout(r, 3000));

if (!decryptSucceeded) {
  skipTest(
    'wrong signer is rejected (access condition enforced)',
    'Skipped — decrypt is rate-limited, cannot distinguish rejection from rate limit'
  );
} else {
  await test('wrong signer is rejected (access condition enforced)', async () => {
    const attacker = ethers.Wallet.createRandom();
    const latestBlockhash = await client.getLatestBlockhash();

    let attackerCapacityDelegationAuthSig;
    if (capacityTokenId && capacityWallet) {
      attackerCapacityDelegationAuthSig = (await client.createCapacityDelegationAuthSig({
        uses: '10',
        dAppOwnerWallet: capacityWallet,
        capacityTokenId,
        delegateeAddresses: [attacker.address],
      })).capacityDelegationAuthSig;
    }

    const attackerSigsParams = {
      chain: 'ethereum',
      expiration: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      resourceAbilityRequests: [{
        resource: new LitAccessControlConditionResource('*'),
        ability:  LIT_ABILITY.AccessControlConditionDecryption,
      }],
      authNeededCallback: async (params) => {
        const toSign = await createSiweMessage({
          uri: params.uri ?? 'https://localhost', expiration: params.expiration,
          resources: params.resourceAbilityRequests, walletAddress: attacker.address,
          nonce: latestBlockhash, litNodeClient: client,
        });
        return generateAuthSig({ signer: attacker, toSign });
      },
    };
    if (attackerCapacityDelegationAuthSig) {
      attackerSigsParams.capacityDelegationAuthSig = attackerCapacityDelegationAuthSig;
    }

    const attackerSigs = await client.getSessionSigs(attackerSigsParams);

    let threw = false;
    let errMsg = '';
    try {
      await decryptToString({
        accessControlConditions, ciphertext, dataToEncryptHash,
        chain: 'ethereum', sessionSigs: attackerSigs,
      }, client);
    } catch (e) {
      threw = true;
      errMsg = e.message ?? '';
    }

    if (!threw) throw new Error('attacker should NOT have been able to decrypt');
    if (errMsg.includes('rate_limit') || errMsg.includes('Rate limit')) {
      console.log(YL(`  (rate limited — access control not verified this run)`));
      pass--; skip++;
      return;
    }
    console.log(`  rejection reason: ${errMsg.slice(0, 120)}`);
  });
}

await client.disconnect();

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(60)}`);
console.log(`Results: ${pass} passed, ${fail} failed, ${skip} skipped\n`);

if (fail > 0) {
  process.exit(1);
}

if (skip > 0) {
  console.log(YL('PARTIAL VERIFICATION (Capacity Credits not set up):'));
  console.log('  ✓ LitNodeClient connects to Datil');
  console.log('  ✓ encryptString with EVM access condition');
  console.log('  ✓ getSessionSigs SIWE flow');
  console.log('  ~ decryptToString — rate-limited (not a code failure)');
  console.log('  ~ Access condition enforcement — inconclusive (rate-limited)');
  console.log('');
  console.log('TO VERIFY DECRYPT:');
  console.log('  node scripts/lit-setup.mjs   # follow the faucet instructions');
  console.log('  node tests/lit.test.mjs      # re-run with capacity credits');
  process.exit(0);  // not a failure — infrastructure constraint
}

console.log(GR(BD('FULLY VERIFIED (against live Lit Datil):')));
console.log('  ✓ LitNodeClient connects to Datil');
console.log('  ✓ encryptString with EVM access condition');
console.log('  ✓ getSessionSigs SIWE flow');
console.log('  ✓ decryptToString recovers exact (secret, nullifier)');
console.log('  ✓ Wrong signer rejected by access condition');
