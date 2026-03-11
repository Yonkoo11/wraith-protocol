/**
 * Example: LangChain agent making private API payments via Wraith
 *
 * This shows how an AI agent (LangChain) can call paid API endpoints
 * (Perplexity, OpenAI, etc.) without linking its identity to its payments.
 *
 * Run: npx ts-node examples/langchain-agent.ts
 */

import { Account, RpcProvider } from 'starknet';
import { WraithAgent } from '../sdk/src/index.js';

// --- Setup ---

const provider = new RpcProvider({
  nodeUrl: process.env.STARKNET_RPC_URL ?? 'https://starknet-mainnet.public.blastapi.io',
});

// In production: load from secure secret management, never hardcode
const account = new Account(
  provider,
  process.env.AGENT_ADDRESS ?? '0x0',
  process.env.AGENT_PRIVATE_KEY ?? '0x0'
);

const agent = new WraithAgent(
  {
    adapter: 'privacy-pools', // Use 'strk20' when repo ships
    starknetRpcUrl: process.env.STARKNET_RPC_URL,
  },
  account
);

// --- Show the user what privacy they actually have ---

const score = agent.getPrivacyScore();
console.log('\n=== Wraith Privacy Score ===');
console.log(`Adapter:          ${score.adapter}`);
console.log(`Depositor visible: ${score.depositorVisible}`);
console.log(`Proof system:      ${score.proofSystem}`);
console.log(`Quantum resistant: ${score.quantumResistant}`);
console.log(`Anonymity set:     ${score.anonymitySetSize}`);
console.log(`Guarantee:         ${score.guarantee}`);
if (score.recommendation) {
  console.log(`Note: ${score.recommendation}`);
}
console.log('');

// --- Make a private payment to a paid API ---

async function askPerplexity(question: string): Promise<string> {
  // Wraith handles the 402 challenge/response automatically
  const response = await agent.pay(
    'https://api.perplexity.ai/chat/completions',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama-3.1-sonar-small-128k-online',
        messages: [{ role: 'user', content: question }],
      }),
      amount: 3000n, // 0.003 USDC (6 decimals)
      token: 'USDC',
      maxLatencyMs: 3000, // Force payment within 3s even though batch window is 60s
    }
  );

  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${await response.text()}`);
  }

  const data = await response.json() as { choices: Array<{ message: { content: string } }> };
  return data.choices[0].message.content;
}

// --- Run ---

async function main() {
  console.log('Asking Perplexity a question via private payment...\n');
  try {
    const answer = await askPerplexity('What are the main privacy protocols on Starknet?');
    console.log('Answer:', answer);
  } catch (err) {
    // Perplexity doesn't actually support x402 yet — this will fail
    // until Wraith's API server middleware is deployed
    console.log('Expected: Perplexity does not yet support x402/Wraith middleware');
    console.log('This example shows the agent-side code. Server-side middleware is next.');
  }
}

main().catch(console.error);
