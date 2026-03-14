/**
 * ERC-8004 Agent Example — Cipher Pol
 *
 * Demonstrates an AI agent with:
 *   - ERC-8004 (Trustless Agents) identity
 *   - x402 private payments via Starknet ZK privacy pool
 *   - Verifiable payment receipts for on-chain reputation
 *
 * ERC-8004 is live on Ethereum mainnet as of January 29, 2026.
 * Spec: https://eips.ethereum.org/EIPS/eip-8004
 *
 * Run: npx ts-node examples/erc8004-agent.ts
 */

import { Account, RpcProvider } from 'starknet';
import {
  CipherPolAgent,
  createAgentManifest,
  manifestToDataURI,
  generatePaymentReceipt,
  validateReceipt,
} from '../sdk/src/index.js';

// ── Step 1: Create an ERC-8004 agent identity ─────────────────────────────────
//
// Every Cipher Pol agent can have an ERC-8004 identity that resolves to a
// registration file. This file is indexed by identity registries, making
// the agent discoverable and its payments verifiable.
//
// The registration file uses the official EIP-8004 schema:
// https://eips.ethereum.org/EIPS/eip-8004#registration-v1

const manifest = createAgentManifest(
  {
    name: 'WeatherAgent',
    description:
      'Autonomous agent that fetches premium weather data and pays per API call ' +
      'using ZK-private Starknet transactions via x402 payment protocol.',
    starknetAddress: '0x06c7f95e9f9d9c35b3a44b5c7f56fca45ad5c6a1234567890abcdef01234567',
    // If registered on Ethereum Identity Registry:
    // agentId: 42,
    // registryAddress: 'eip155:1:0x...',
  },
  'privacy-pools',  // Ekubo privacy pool (Groth16 ZK proofs)
  'demo'           // Honest privacy level: depositor address is visible
);

console.log('=== ERC-8004 Agent Manifest ===');
console.log(JSON.stringify(manifest, null, 2));
console.log();

// The manifest can be hosted anywhere and registered on Ethereum:
//   identityRegistry.register(agentURI)
const agentURI = manifestToDataURI(manifest);
console.log('Agent URI (for Identity Registry registration):');
console.log(agentURI.slice(0, 80) + '...');
console.log();

// ── Step 2: Create a Cipher PolAgent with ERC-8004 identity ───────────────────────
//
// When erc8004 is configured, the agent automatically:
//   - Attaches its agentURI to every X-Payment-Proof header
//   - Enables receipt generation after successful payments

const provider = new RpcProvider({ nodeUrl: 'https://starknet-mainnet.public.blastapi.io' });
// const account = new Account(provider, process.env.STARKNET_ADDRESS!, process.env.STARKNET_KEY!);

const agent = new CipherPolAgent(
  {
    adapter: 'privacy-pools',
    starknetRpcUrl: 'https://starknet-mainnet.public.blastapi.io',
    erc8004: {
      name: 'WeatherAgent',
      description: 'Autonomous weather data agent',
      starknetAddress: '0x06c7f95e9f9d9c35b3a44b5c7f56fca45ad5c6a1234567890abcdef01234567',
      // agentId and registryAddress when registered on Ethereum
    },
  }
  // account  // Starknet account for signing transactions
);

// Show the agent manifest
const identity = agent.getAgentManifest();
if (identity) {
  console.log('=== Agent Identity from CipherPolAgent ===');
  console.log(`Name: ${identity.manifest.name}`);
  console.log(`x402Support: ${identity.manifest.x402Support}`);
  console.log(`Adapter: ${identity.manifest.cipherPol.adapter}`);
  console.log(`Privacy Level: ${identity.manifest.cipherPol.privacyLevel}`);
  console.log();
}

// ── Step 3: Make an x402 payment and generate a receipt ──────────────────────
//
// In a real scenario, call agent.pay() or agent.payWithReceipt() to:
//   1. Deposit into Ekubo privacy pool (Starknet tx, ZK commitment)
//   2. Attach Lit-encrypted (secret, nullifier) for server withdrawal
//   3. Attach ERC-8004 agent identity to payment proof
//   4. Receive service response + verifiable payment receipt

// Simulate a payment receipt (without live network connection)
const simulatedReceipt = generatePaymentReceipt(
  '0x03d6a2e4f5c8b9a1234567890abcdef01234567890abcdef0123456789abcdef',
  'starknet-mainnet',
  '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
  'https://api.weather-premium.io/v1/forecast',
  3000n,
  'USDC',
  {
    name: 'WeatherAgent',
    description: 'Autonomous weather data agent',
    starknetAddress: '0x06c7f95e9f9d9c35b3a44b5c7f56fca45ad5c6a1234567890abcdef01234567',
  }
);

console.log('=== ERC-8004 Payment Receipt ===');
console.log(JSON.stringify(
  { ...simulatedReceipt, agentURI: simulatedReceipt.agentURI?.slice(0, 50) + '...' },
  null,
  2
));
console.log();

// Validate the receipt
const isValid = validateReceipt(simulatedReceipt);
console.log(`Receipt valid: ${isValid}`);
console.log();

// ── Step 4: Submit receipt to ERC-8004 Reputation Registry ──────────────────
//
// (Ethereum mainnet — requires ETH gas)
// The receipt can be submitted as feedback, building the agent's reputation:
//
//   await reputationRegistry.giveFeedback(
//     agentId,                         // ERC-8004 agent ID
//     100,                             // value (1.00 = satisfied)
//     2,                               // decimals
//     'x402',                          // tag1: payment type
//     'weather',                       // tag2: service category
//     'https://api.weather-premium.io',// endpoint
//     receiptURI,                      // feedbackURI: IPFS/HTTPS of receipt JSON
//     receiptHash                      // feedbackHash: keccak256 of receipt
//   );

console.log('=== How to Register This Agent on ERC-8004 Identity Registry ===');
console.log('');
console.log('// Ethereum (via ethers.js or viem):');
console.log('const identityRegistry = new Contract(IDENTITY_REGISTRY_ADDRESS, ABI, signer);');
console.log(`const agentId = await identityRegistry.register("${agentURI.slice(0, 30)}...");`);
console.log('');
console.log('// After registration, set your Starknet address as agent wallet metadata:');
console.log('await identityRegistry.setMetadata(agentId, "starknetAddress", encodedAddress);');
console.log('');
console.log('The agent\'s x402Support: true field in the manifest signals to');
console.log('other agents and protocols that this agent accepts/makes x402 payments.');
